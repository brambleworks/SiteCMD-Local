use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sitecmd_protocol::engine_abi::{
    decode_answer, encode_request, EngineInfo, ErrorAnswer, FileAnalysisContext,
    FileAnalysisResult, FileAnalysisSource, FileLocation, SessionBegin, SessionContinue, Step,
    WantAnswer, ENGINE_ABI_VERSION,
};
use wasmtime::{
    Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, UpdateDeadline,
};

use crate::load::{EngineError, MODULE_MEMORY_LIMIT, MODULE_TABLE_ELEMENT_LIMIT};
use crate::workers::{self, AnalysisFile};

/// Maximum JSON answer size in bytes, checked before parsing.
///
/// Findings have no count cap, so the limit follows the text one audit may
/// read (`CODE_SCAN_MAX_TEXT_BYTES`, 64 MB) rather than measured answers: the
/// largest across the 30 golden checkouts was 161,290 bytes.
pub const MODULE_ANSWER_LIMIT: usize = 64 << 20;

#[derive(Clone)]
pub struct Interrupt(InterruptFlag);

#[derive(Clone)]
enum InterruptFlag {
    Owned(Arc<AtomicBool>),
    Static(&'static AtomicBool),
}

impl Default for Interrupt {
    fn default() -> Self {
        Self(InterruptFlag::Owned(Arc::default()))
    }
}

impl Interrupt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_signal_flag(flag: &'static AtomicBool) -> Self {
        Self(InterruptFlag::Static(flag))
    }

    fn flag(&self) -> &AtomicBool {
        match &self.0 {
            InterruptFlag::Owned(flag) => flag,
            InterruptFlag::Static(flag) => flag,
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.flag().load(Ordering::Relaxed)
    }

    pub fn trigger(&self) {
        self.flag().store(true, Ordering::Relaxed);
    }
}

type Cancellation = Arc<Mutex<dyn Fn() -> bool + Send>>;

#[derive(Clone)]
struct RunControl {
    interrupt: Interrupt,
    cancelled: Option<Cancellation>,
    abort: Option<Interrupt>,
}

impl RunControl {
    fn new(interrupt: &Interrupt) -> Self {
        Self {
            interrupt: interrupt.clone(),
            cancelled: None,
            abort: None,
        }
    }

    fn is_interrupted(&self) -> bool {
        self.interrupt.is_triggered()
            || self.abort.as_ref().is_some_and(Interrupt::is_triggered)
            || self.cancelled.as_ref().is_some_and(|probe| {
                probe
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)()
            })
    }
}

struct Execution {
    limits: StoreLimits,
    control: RunControl,
    deadline: Option<Instant>,
    version: Arc<str>,
    #[cfg(test)]
    loop_entry: Option<(wasmtime::Global, std::sync::mpsc::Sender<()>)>,
}

impl Execution {
    fn stop_reason(&self) -> Option<EngineError> {
        if self.control.is_interrupted() {
            Some(EngineError::Interrupted)
        } else if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some(EngineError::TimedOut)
        } else {
            None
        }
    }

    fn check(&self) -> Result<(), EngineError> {
        self.stop_reason().map_or(Ok(()), Err)
    }

    fn trap(&self, error: wasmtime::Error) -> EngineError {
        if error.downcast_ref::<Trap>() == Some(&Trap::Interrupt) {
            if let Some(reason) = self.stop_reason() {
                return reason;
            }
        }
        EngineError::Trap {
            module_version: self.version.to_string(),
        }
    }
}

pub(crate) struct Guest {
    store: Store<Execution>,
    instance: Instance,
    memory: Memory,
}

impl Guest {
    pub(crate) fn instantiate(
        module: &Module,
        interrupt: &Interrupt,
        deadline: Option<Instant>,
        version: Arc<str>,
    ) -> Result<Self, EngineError> {
        Self::instantiate_with_control(module, RunControl::new(interrupt), deadline, version)
    }

    fn instantiate_with_control(
        module: &Module,
        control: RunControl,
        deadline: Option<Instant>,
        version: Arc<str>,
    ) -> Result<Self, EngineError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(MODULE_MEMORY_LIMIT)
            .table_elements(MODULE_TABLE_ELEMENT_LIMIT)
            .memories(1)
            .tables(1)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            module.engine(),
            Execution {
                limits,
                control,
                deadline,
                version,
                #[cfg(test)]
                loop_entry: None,
            },
        );
        store.limiter(|execution| &mut execution.limits);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|store| {
            let update = if store.data().stop_reason().is_some() {
                UpdateDeadline::Interrupt
            } else {
                UpdateDeadline::Continue(1)
            };
            #[cfg(test)]
            signal_loop_entry(store);
            Ok(update)
        });

        store.data().check()?;
        let instance = Linker::new(module.engine())
            .instantiate(&mut store, module)
            .map_err(|error| store.data().trap(error))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| EngineError::malformed("missing memory export"))?;
        Ok(Self {
            store,
            instance,
            memory,
        })
    }

    pub(crate) fn set_cancellation(&mut self, cancelled: impl Fn() -> bool + Send + 'static) {
        self.store.data_mut().control.cancelled = Some(Arc::new(Mutex::new(cancelled)));
    }

    pub(crate) fn info(&mut self) -> Result<EngineInfo, EngineError> {
        self.store.data().check()?;
        let info = self
            .instance
            .get_typed_func::<(), u32>(&mut self.store, "engine_info")
            .map_err(|_| EngineError::malformed("invalid engine_info export"))?;
        let pointer = info
            .call(&mut self.store, ())
            .map_err(|error| self.store.data().trap(error))?;
        self.answer(pointer, |json| {
            #[derive(Deserialize)]
            struct AbiHeader {
                abi_version: u32,
            }
            let AbiHeader { abi_version } = parse_answer(json)?;
            if abi_version != ENGINE_ABI_VERSION {
                return Err(EngineError::AbiMismatch {
                    module: abi_version,
                    host: ENGINE_ABI_VERSION,
                });
            }
            parse_answer(json)
        })
    }

    pub(crate) fn request<T: Serialize, R: DeserializeOwned>(
        &mut self,
        export: &str,
        request: &T,
        region: &[u8],
    ) -> Result<R, EngineError> {
        self.store.data().check()?;
        let json = serde_json::to_vec(request)
            .map_err(|_| EngineError::malformed("could not encode the engine request"))?;
        let len = 4usize
            .checked_add(json.len())
            .and_then(|len| len.checked_add(region.len()))
            .filter(|&len| len <= MODULE_MEMORY_LIMIT)
            .ok_or_else(|| EngineError::malformed("engine request exceeds the memory limit"))?;
        let len = len as u32;
        let frame = encode_request(&json, region);
        let call = self
            .instance
            .get_typed_func::<(u32, u32), u32>(&mut self.store, export)
            .map_err(|_| EngineError::Malformed(format!("invalid {export} export")))?;
        let alloc = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "engine_alloc")
            .map_err(|_| EngineError::malformed("invalid engine_alloc export"))?;
        let pointer = alloc
            .call(&mut self.store, len)
            .map_err(|error| self.store.data().trap(error))?;
        if pointer == 0 {
            return Err(EngineError::malformed(
                "engine_alloc returned a null pointer",
            ));
        }
        self.memory
            .write(&mut self.store, pointer as usize, &frame)
            .map_err(|_| EngineError::malformed("engine allocation is outside memory"))?;
        // The guest takes ownership of the request buffer.
        let answer = call
            .call(&mut self.store, (pointer, len))
            .map_err(|error| self.store.data().trap(error))?;
        self.answer(answer, parse_answer)
    }

    fn answer<R>(
        &mut self,
        pointer: u32,
        parse: impl FnOnce(&[u8]) -> Result<R, EngineError>,
    ) -> Result<R, EngineError> {
        let (len, answer) = {
            let memory = self.memory.data(&self.store);
            let tail = memory
                .get(pointer as usize..)
                .filter(|_| pointer != 0)
                .ok_or_else(|| EngineError::malformed("invalid answer pointer"))?;
            let prefix = tail
                .first_chunk::<4>()
                .ok_or_else(|| EngineError::malformed("missing answer length"))?;
            let json_len = u32::from_le_bytes(*prefix);
            let len = json_len
                .checked_add(4)
                .ok_or_else(|| EngineError::malformed("invalid answer length"))?;
            if json_len as usize > MODULE_ANSWER_LIMIT {
                return Err(EngineError::malformed(
                    "answer exceeds the module answer limit",
                ));
            }
            let frame = tail
                .get(..len as usize)
                .ok_or_else(|| EngineError::malformed("answer exceeds engine memory"))?;
            let json =
                decode_answer(frame).map_err(|_| EngineError::malformed("invalid answer frame"))?;
            let answer = if let Ok(error) = serde_json::from_slice::<ErrorAnswer>(json) {
                Err(EngineError::Malformed(format!(
                    "engine returned {:?}",
                    error.error
                )))
            } else {
                parse(json)
            };
            (len, answer)
        };
        let free = self
            .instance
            .get_typed_func::<(u32, u32), ()>(&mut self.store, "engine_free")
            .map_err(|_| EngineError::malformed("invalid engine_free export"))?;
        free.call(&mut self.store, (pointer, len))
            .map_err(|error| self.store.data().trap(error))?;
        self.store.data().check()?;
        answer
    }
}

fn parse_answer<R: DeserializeOwned>(json: &[u8]) -> Result<R, EngineError> {
    serde_json::from_slice(json).map_err(|_| EngineError::malformed("invalid engine answer"))
}

#[cfg(test)]
fn signal_loop_entry(mut store: wasmtime::StoreContextMut<'_, Execution>) {
    if let Some((flag, _)) = store.data().loop_entry.as_ref() {
        let flag = *flag;
        if flag.get(&mut store).i32() == Some(1) {
            let (_, sender) = store.data_mut().loop_entry.take().unwrap();
            let _ = sender.send(());
        }
    }
}

pub struct ModuleSession {
    guest: Option<Guest>,
    module: Module,
    worker_count: usize,
}

impl fmt::Debug for ModuleSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModuleSession")
            .field("open", &self.guest.is_some())
            .finish()
    }
}

impl ModuleSession {
    pub(crate) fn new(guest: Guest, module: Module, worker_count: usize) -> Self {
        Self {
            guest: Some(guest),
            module,
            worker_count,
        }
    }

    pub(crate) fn worker_factory(
        &self,
    ) -> Result<impl Fn(&Interrupt) -> Result<Guest, EngineError> + Sync + 'static, EngineError>
    {
        let module = self.module.clone();
        let execution = self
            .guest
            .as_ref()
            .ok_or_else(|| EngineError::malformed("engine session is closed"))?
            .store
            .data();
        let control = execution.control.clone();
        let version = execution.version.clone();
        Ok(move |abort: &Interrupt| {
            let mut control = control.clone();
            control.abort = Some(abort.clone());
            Guest::instantiate_with_control(&module, control, None, version.clone())
        })
    }

    pub fn analyze_files(
        &mut self,
        files: &[FileAnalysisSource],
        context: &FileAnalysisContext,
        mut read_snapshot: impl FnMut(&FileLocation) -> Option<Vec<u8>>,
    ) -> Result<Vec<FileAnalysisResult>, EngineError> {
        let inputs = files
            .iter()
            .map(|file| {
                let bytes = read_snapshot(&file.location)
                    .ok_or_else(|| EngineError::malformed("missing file analysis input"))?;
                Ok(AnalysisFile {
                    path: file.path.clone(),
                    bytes,
                })
            })
            .collect::<Result<_, _>>();
        let result = inputs.and_then(|inputs| self.analyze(inputs, context));
        if result.is_err() {
            self.guest = None;
        }
        result
    }

    fn analyze(
        &self,
        files: Vec<AnalysisFile>,
        context: &FileAnalysisContext,
    ) -> Result<Vec<FileAnalysisResult>, EngineError> {
        let guest = self
            .guest
            .as_ref()
            .ok_or_else(|| EngineError::malformed("engine session is closed"))?;
        guest.store.data().check()?;
        workers::analyze_batches(
            workers::batches(files, self.worker_count),
            context,
            &guest.store.data().control.interrupt,
            self.worker_factory()?,
        )
    }

    pub(crate) fn set_cancellation(&mut self, cancelled: impl Fn() -> bool + Send + 'static) {
        if let Some(guest) = &mut self.guest {
            guest.set_cancellation(cancelled);
        }
    }

    pub fn is_interrupted(&self) -> bool {
        self.guest
            .as_ref()
            .is_some_and(|guest| guest.store.data().control.is_interrupted())
    }

    pub fn begin(&mut self, request: &SessionBegin) -> Result<Step, EngineError> {
        self.advance("session_begin", request, &[])
    }

    pub fn resume(&mut self, answers: Vec<WantAnswer>, region: &[u8]) -> Result<Step, EngineError> {
        for answer in &answers {
            if let WantAnswer::File { body } = answer {
                body.slice(region)
                    .map_err(|_| EngineError::malformed("invalid session body reference"))?;
            }
        }
        self.advance("session_continue", &SessionContinue { answers }, region)
    }

    fn advance<T: Serialize>(
        &mut self,
        export: &str,
        request: &T,
        region: &[u8],
    ) -> Result<Step, EngineError> {
        // Drop the store on failure because a guest trap can leave it half-mutated.
        let mut guest = self
            .guest
            .take()
            .ok_or_else(|| EngineError::malformed("engine session is closed"))?;
        let answer = guest.request(export, request, region)?;
        self.guest = Some(guest);
        Ok(answer)
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
