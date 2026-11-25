use std::{
    fmt,
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use sitecmd_protocol::engine_abi::{EngineInfo, LocalSiteAnswer, LocalSiteRequest};
use wasmtime::{Engine as WasmtimeEngine, Module};

use crate::build_support::engine_config;
use crate::session::{Guest, Interrupt, ModuleSession};
use crate::workers::worker_count;

pub const MODULE_MEMORY_LIMIT: usize = 1 << 30;
pub const MODULE_TABLE_ELEMENT_LIMIT: usize = 1 << 16;
pub const LOCAL_SITE_DEADLINE: Duration = Duration::from_secs(30);

// A single clock advances all stores without sharing their cancellation state.
const EPOCH_INTERVAL: Duration = Duration::from_millis(25);
static EMBEDDED: OnceLock<Result<Engine, EngineError>> = OnceLock::new();
const EMBEDDED_SHA256: &str = env!("SITECMD_ENGINE_BUILD_SHA256");
const COMPILED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/local-engine.cwasm"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    DigestMismatch,
    HasImports(usize),
    AbiMismatch { module: u32, host: u32 },
    Trap { module_version: String },
    Interrupted,
    TimedOut,
    InvalidWorkerCount,
    Malformed(String),
}

impl EngineError {
    pub(crate) fn malformed(reason: &str) -> Self {
        Self::Malformed(reason.into())
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch => f.write_str("Engine module digest mismatch"),
            Self::HasImports(count) => write!(f, "Engine module has {count} imports"),
            Self::AbiMismatch { module, host } => {
                write!(
                    f,
                    "Engine module ABI {module} is incompatible with host ABI {host}"
                )
            }
            Self::Trap { module_version } => write!(f, "Engine module {module_version} trapped"),
            Self::Interrupted => f.write_str("Engine execution interrupted"),
            Self::TimedOut => f.write_str("Engine execution timed out"),
            Self::InvalidWorkerCount => {
                f.write_str("SITECMD_ENGINE_WORKERS must be a whole number.")
            }
            Self::Malformed(reason) => write!(f, "Invalid engine module or message: {reason}"),
        }
    }
}

impl std::error::Error for EngineError {}

#[derive(Clone, Debug)]
pub struct Engine {
    module: Module,
    info: Arc<EngineInfo>,
    version: Arc<str>,
}

pub fn embedded_module() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/local-engine.wasm"))
}

pub fn unpinned() -> bool {
    EMBEDDED_SHA256.is_empty()
}

pub fn load() -> Result<Engine, EngineError> {
    EMBEDDED
        .get_or_init(|| {
            verify_digest(embedded_module(), expected_digest(EMBEDDED_SHA256)?)?;
            load_precompiled(COMPILED)
        })
        .clone()
}

fn load_precompiled(bytes: &[u8]) -> Result<Engine, EngineError> {
    let config = engine_config(None);
    #[cfg(any(test, feature = "compile"))]
    let config = {
        let mut config = config;
        config.enable_compiler(false);
        config
    };
    let runtime = WasmtimeEngine::new(&config)
        .map_err(|_| EngineError::malformed("could not initialize the runtime"))?;
    // SAFETY: The embedded bytes are this build's own output for the original WebAssembly module.
    // Tests supply only their own output from Wasmtime's precompiler.
    let module = unsafe { Module::deserialize(&runtime, bytes) }
        .map_err(|_| EngineError::malformed("could not load the compiled WebAssembly module"))?;
    finish_load(module)
}

fn expected_digest(value: &str) -> Result<Option<[u8; 32]>, EngineError> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut digest = [0; 32];
    hex::decode_to_slice(value, &mut digest).map_err(|_| EngineError::DigestMismatch)?;
    Ok(Some(digest))
}

fn verify_digest(bytes: &[u8], expected_sha256: Option<[u8; 32]>) -> Result<(), EngineError> {
    if expected_sha256.is_some_and(|expected| Sha256::digest(bytes).as_slice() != expected) {
        return Err(EngineError::DigestMismatch);
    }
    Ok(())
}

#[cfg(any(test, feature = "compile"))]
pub fn load_bytes(bytes: &[u8], expected_sha256: Option<[u8; 32]>) -> Result<Engine, EngineError> {
    verify_digest(bytes, expected_sha256)?;
    let runtime = WasmtimeEngine::new(&engine_config(None))
        .map_err(|_| EngineError::malformed("could not initialize the runtime"))?;
    let module = Module::from_binary(&runtime, bytes)
        .map_err(|_| EngineError::malformed("could not compile the WebAssembly module"))?;
    finish_load(module)
}

fn finish_load(module: Module) -> Result<Engine, EngineError> {
    let imports = module.imports().count();
    if imports != 0 {
        return Err(EngineError::HasImports(imports));
    }

    start_epoch_clock(module.engine())?;
    let info = Guest::instantiate(
        &module,
        &Interrupt::new(),
        Some(Instant::now() + LOCAL_SITE_DEADLINE),
        Arc::from("unknown"),
    )?
    .info()?;
    Ok(Engine {
        module,
        version: Arc::from(info.module_version.as_str()),
        info: Arc::new(info),
    })
}

fn start_epoch_clock(runtime: &WasmtimeEngine) -> Result<(), EngineError> {
    let runtime = runtime.weak();
    thread::Builder::new()
        .name("sitecmd-engine-clock".into())
        .spawn(move || loop {
            thread::sleep(EPOCH_INTERVAL);
            let Some(runtime) = runtime.upgrade() else {
                break;
            };
            runtime.increment_epoch();
        })
        .map_err(|_| EngineError::malformed("could not start the engine clock"))?;
    Ok(())
}

impl Engine {
    pub fn info(&self) -> &EngineInfo {
        &self.info
    }

    pub fn exports(&self) -> Vec<String> {
        self.module
            .exports()
            .map(|item| item.name().into())
            .collect()
    }

    pub fn session(&self, interrupt: &Interrupt) -> Result<ModuleSession, EngineError> {
        let count = worker_count()?;
        let guest = Guest::instantiate(&self.module, interrupt, None, self.version.clone())?;
        Ok(ModuleSession::new(guest, self.module.clone(), count))
    }

    pub fn session_with_cancellation(
        &self,
        interrupt: &Interrupt,
        cancelled: impl Fn() -> bool + Send + 'static,
    ) -> Result<ModuleSession, EngineError> {
        let mut session = self.session(interrupt)?;
        session.set_cancellation(cancelled);
        Ok(session)
    }

    pub fn local_site_evaluate(
        &self,
        request: &LocalSiteRequest,
        body: &[u8],
    ) -> Result<LocalSiteAnswer, EngineError> {
        self.local_site_with_deadline(request, body, LOCAL_SITE_DEADLINE)
    }

    pub(crate) fn local_site_with_deadline(
        &self,
        request: &LocalSiteRequest,
        body: &[u8],
        timeout: Duration,
    ) -> Result<LocalSiteAnswer, EngineError> {
        let deadline = Instant::now() + timeout;
        request
            .body
            .slice(body)
            .map_err(|_| EngineError::malformed("invalid local page body reference"))?;
        Guest::instantiate(
            &self.module,
            &Interrupt::new(),
            Some(deadline),
            self.version.clone(),
        )?
        .request("local_site_evaluate", request, body)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process::Command};

    use super::{expected_digest, EngineError};

    fn build_target_compiler() -> super::WasmtimeEngine {
        let target = env!("SITECMD_ENGINE_BUILD_TARGET");
        super::WasmtimeEngine::new(&super::engine_config(Some(target))).unwrap()
    }

    #[test]
    fn the_embedded_module_runs_an_audit_without_compiling() {
        // Bug: Loading the embedded module can require a compiler to run an audit.
        use sitecmd_protocol::engine_abi::{
            BodyRef, Done, EntryKind, ListingEntry, RelPath, Step, Want, WantAnswer,
        };

        let engine = super::load().unwrap();
        let empty_wasm = wat::parse_str("(module)").unwrap();
        assert!(engine
            .module
            .engine()
            .precompile_module(&empty_wasm)
            .is_err());

        let path = RelPath::parse("package.json").unwrap();
        let mut request = crate::load_tests::audit();
        request.host.root = "/workspace".into();
        request.text_budget = 1024;
        request.listing.entries.push(ListingEntry {
            path: path.clone(),
            size: 2,
            kind: EntryKind::File,
            ignored: false,
        });
        let mut session = engine.session(&crate::Interrupt::new()).unwrap();
        assert_eq!(
            session.begin(&request).unwrap(),
            Step::Wants {
                wants: vec![Want::File { path }]
            }
        );
        let answer = WantAnswer::File {
            body: BodyRef { at: 0, len: 2 },
        };
        assert!(matches!(
            session.resume(vec![answer], b"{}"),
            Ok(Step::Done {
                done: Done::Audit(_)
            })
        ));
    }

    #[test]
    fn a_compiled_module_for_another_configuration_is_refused() {
        // Bug: A compiled module can be loaded with incompatible interruption settings.
        let mut config = crate::build_support::engine_config(None);
        config.epoch_interruption(false);
        let compiler = super::WasmtimeEngine::new(&config).unwrap();
        let compiled = compiler
            .precompile_module(super::embedded_module())
            .unwrap();
        assert_eq!(
            super::load_precompiled(&compiled).unwrap_err(),
            EngineError::malformed("could not load the compiled WebAssembly module")
        );
    }

    #[test]
    fn build_and_runtime_share_one_configuration() {
        // Bug: A configuration mismatch can make the embedded module fail on every run.
        let compiled = build_target_compiler()
            .precompile_module(super::embedded_module())
            .unwrap();
        let engine = super::load_precompiled(&compiled).unwrap();
        assert_eq!(engine.info(), super::load().unwrap().info());
    }

    #[test]
    fn backtrace_environment_does_not_affect_precompiled_modules() {
        // Bug: A developer's environment variable breaks every audit.
        const BACKTRACE: &str = "WASMTIME_BACKTRACE_DETAILS";
        const PHASE: &str = "SITECMD_TEST_PRECOMPILE_BACKTRACE_PHASE";
        const TEST: &str = "load::tests::backtrace_environment_does_not_affect_precompiled_modules";

        let child = |phase| {
            let mut command = Command::new(env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--nocapture"])
                .env(PHASE, phase);
            command
        };

        match env::var(PHASE).as_deref() {
            Ok("compile") => {
                assert_eq!(env::var(BACKTRACE).as_deref(), Ok("1"));
                let wasm = crate::load_tests::Fixture::default().build();
                let compiled = build_target_compiler().precompile_module(&wasm).unwrap();
                println!("\ncompiled:{}", hex::encode(compiled));
            }
            Ok("load") => {
                assert!(env::var_os(BACKTRACE).is_none());
                let output = child("compile").env(BACKTRACE, "1").output().unwrap();
                assert!(output.status.success(), "{output:?}");
                let stdout = String::from_utf8(output.stdout).unwrap();
                let compiled = stdout
                    .lines()
                    .find_map(|line| line.strip_prefix("compiled:"))
                    .unwrap();
                let engine = super::load_precompiled(&hex::decode(compiled).unwrap()).unwrap();
                assert_eq!(engine.info().module_version, "test-version");
            }
            _ => {
                let output = child("load").env_remove(BACKTRACE).output().unwrap();
                assert!(output.status.success(), "{output:?}");
                assert!(String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("1 passed"));
            }
        }
    }

    #[test]
    fn empty_build_digest_is_unpinned() {
        assert_eq!(expected_digest(""), Ok(None));
    }

    #[test]
    fn valid_build_digest_decodes_to_32_bytes() {
        let hex_digest = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let expected = std::array::from_fn(|index| index as u8);
        assert_eq!(expected_digest(hex_digest), Ok(Some(expected)));
    }

    #[test]
    fn malformed_build_digest_is_refused() {
        for invalid in ["zz".repeat(32), "ab".repeat(31), "ab".repeat(33)] {
            assert_eq!(expected_digest(&invalid), Err(EngineError::DigestMismatch));
        }
    }
}
