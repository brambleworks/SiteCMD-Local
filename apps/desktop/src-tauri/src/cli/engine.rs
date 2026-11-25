//! Inspect or save the engine embedded in this binary.

use serde::Serialize;
use sha2::{Digest, Sha256};
use sitecmd_engine_host::load;
use std::{path::PathBuf, time::Instant};

pub use sitecmd_engine_host::{embedded_module, unpinned, Interrupt};

pub const HELP: &str = "Usage: sitecmd engine info [--json] [--save <path>]";

#[derive(Serialize)]
struct EngineInfo<'a> {
    version: &'a str,
    sha256: String,
    abi: u32,
    imports: u32,
    exports: Vec<String>,
    load_ms: u128,
}

pub fn run(mut args: impl Iterator<Item = String>) -> Result<String, String> {
    if args.next().as_deref() != Some("info") {
        return Err(HELP.into());
    }
    let mut json = false;
    let mut save = None;
    while let Some(option) = args.next() {
        match option.as_str() {
            "--json" => json = true,
            "--save" => {
                save = Some(
                    args.next()
                        .filter(|value| !value.starts_with("--"))
                        .map(PathBuf::from)
                        .ok_or("Missing path for --save")?,
                );
            }
            _ => return Err(format!("Unknown option: {option}")),
        }
    }

    let start = Instant::now();
    let engine = load().map_err(|error| error.to_string())?;
    let load_ms = start.elapsed().as_millis();
    let info = EngineInfo {
        version: &engine.info().module_version,
        sha256: module_sha256(embedded_module()),
        abi: engine.info().abi_version,
        imports: 0,
        exports: engine.exports(),
        load_ms,
    };
    if let Some(path) = save {
        std::fs::write(&path, embedded_module())
            .map_err(|error| format!("Could not save the engine to {}: {error}", path.display()))?;
    }
    if json {
        serde_json::to_string_pretty(&info).map_err(|error| error.to_string())
    } else {
        Ok(format!(
            "version: {}\nsha256: {}\nabi: {}\nimports: {}\nexports: {}\nload_ms: {}",
            info.version,
            info.sha256,
            info.abi,
            info.imports,
            info.exports.join(", "),
            info.load_ms
        ))
    }
}

pub fn module_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
