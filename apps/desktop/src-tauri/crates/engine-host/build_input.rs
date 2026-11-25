use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct EngineLock {
    sha256: String,
}

#[derive(Debug)]
pub(crate) struct EngineInput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: Option<String>,
    pub(crate) rerun_paths: Vec<PathBuf>,
}

pub(crate) fn engine_input(
    root: &Path,
    module_override: Option<OsString>,
    unpinned: bool,
) -> Result<EngineInput, String> {
    let local_module = root.join("engine/local-engine.wasm");
    let module = module_override
        .map(PathBuf::from)
        .unwrap_or_else(|| local_module.clone());
    let bytes = fs::read(&module).map_err(|error| {
        format!(
            "Cannot read the engine module at {}: {error}. Set SITECMD_ENGINE_WASM or provide {}. Use pnpm engine:fetch for a pinned module or build the stand-in for tests.",
            module.display(),
            local_module.display(),
        )
    })?;
    if bytes.is_empty() {
        return Err("Engine module is empty".into());
    }

    let mut rerun_paths = vec![module];
    let sha256 = if unpinned {
        None
    } else {
        let lock = root.join("engine.lock");
        let lock_json = fs::read(&lock).map_err(|error| {
            format!("Cannot read engine.lock: {error}. For a local build, set SITECMD_ENGINE_UNPINNED=1.")
        })?;
        let pin: EngineLock = serde_json::from_slice(&lock_json)
            .map_err(|error| format!("Invalid engine.lock: {error}"))?;
        if hex::encode(Sha256::digest(&bytes)) != pin.sha256 {
            return Err("Engine module SHA-256 does not match engine.lock".into());
        }
        rerun_paths.push(lock);
        Some(pin.sha256)
    };
    Ok(EngineInput {
        bytes,
        sha256,
        rerun_paths,
    })
}

#[cfg(test)]
#[path = "build_input_tests.rs"]
mod tests;
