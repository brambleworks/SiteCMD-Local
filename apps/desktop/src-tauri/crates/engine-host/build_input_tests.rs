use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const MODULE_BYTES: &[u8] = b"wasm fixture";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "sitecmd-engine-input-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("engine")).unwrap();
        Self(root)
    }

    fn module(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("engine/local-engine.wasm");
        fs::write(&path, bytes).unwrap();
        path
    }

    fn lock(&self, sha256: &str) -> PathBuf {
        let path = self.0.join("engine.lock");
        fs::write(&path, serde_json::json!({ "sha256": sha256 }).to_string()).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn missing_module_reports_the_override_and_default_paths() {
    // Bug: A missing engine build input can be accepted or leave its sources unclear.
    let fixture = Fixture::new();
    let missing = fixture.0.join("override.wasm");
    let error = engine_input(&fixture.0, Some(missing.clone().into_os_string()), true).unwrap_err();
    assert!(error.contains(&missing.display().to_string()));
    assert!(error.contains(
        &fixture
            .0
            .join("engine/local-engine.wasm")
            .display()
            .to_string()
    ));
    assert!(error.contains("SITECMD_ENGINE_WASM"));
    assert!(error.contains("pnpm engine:fetch"));
}

#[test]
fn empty_module_is_refused() {
    // Bug: A zero-byte input can be embedded as the engine.
    let fixture = Fixture::new();
    fixture.module(&[]);
    assert_eq!(
        engine_input(&fixture.0, None, true).unwrap_err(),
        "Engine module is empty"
    );
}

#[test]
fn wrong_pin_is_refused() {
    // Bug: Module bytes whose digest differs from the lock can be embedded.
    let fixture = Fixture::new();
    fixture.module(MODULE_BYTES);
    fixture.lock(&"0".repeat(64));
    assert_eq!(
        engine_input(&fixture.0, None, false).unwrap_err(),
        "Engine module SHA-256 does not match engine.lock"
    );
}

#[test]
fn right_pin_is_exported_and_tracks_both_inputs() {
    // Bug: A correct override can fail to embed, lose its runtime pin, or miss a rerun input.
    let fixture = Fixture::new();
    fixture.module(b"unused default");
    let module = fixture.0.join("override.wasm");
    fs::write(&module, MODULE_BYTES).unwrap();
    let digest = hex::encode(Sha256::digest(MODULE_BYTES));
    let lock = fixture.lock(&digest);
    let input = engine_input(&fixture.0, Some(module.clone().into_os_string()), false).unwrap();
    assert_eq!(input.bytes, MODULE_BYTES);
    assert_eq!(input.sha256.as_deref(), Some(digest.as_str()));
    assert_eq!(input.rerun_paths, [module, lock]);
}

#[test]
fn unpinned_build_does_not_need_a_lock() {
    // Bug: A local build without engine.lock can be refused or given a runtime pin.
    let fixture = Fixture::new();
    fixture.module(MODULE_BYTES);
    let input = engine_input(&fixture.0, None, true).unwrap();
    assert_eq!(input.bytes, MODULE_BYTES);
    assert_eq!(input.sha256, None);
    assert!(engine_input(&fixture.0, None, false)
        .unwrap_err()
        .contains("Cannot read engine.lock"));
}

#[test]
fn unpinned_build_without_a_lock_only_tracks_the_module() {
    // Bug: Watching a missing engine.lock makes Cargo rebuild on every command.
    let fixture = Fixture::new();
    let module = fixture.module(MODULE_BYTES);
    let input = engine_input(&fixture.0, None, true).unwrap();
    assert_eq!(input.rerun_paths, [module]);
}
