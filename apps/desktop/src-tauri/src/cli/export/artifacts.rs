use std::path::Path;

use crate::core::scan_types::ScanResult;

pub(in crate::cli) fn write_file(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    let path = dir.join(name);
    std::fs::write(&path, contents)
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))
}

pub(super) fn build_last_scan_json(result: &ScanResult) -> Result<String, String> {
    serde_json::to_string_pretty(result)
        .map_err(|e| format!("failed to serialize scan result: {}", e))
}
