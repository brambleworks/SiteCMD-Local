#[cfg(test)]
use std::path::Path;

pub(super) use sitecmd_protocol::engine_abi::AUDIT_MAX_FILE_BYTES as MAX_FILE_BYTES;

/// Test-only byte-level wrapper for the shared bounded project reader.
/// The UTF-8 wrapper below also caps the byte count.
#[cfg(test)]
pub(super) fn read_under_root(root: &Path, path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    crate::core::safe_fs::read_bounded_file_under_root(root, path, max_bytes)
}

/// `read_under_root` for UTF-8 text, capped at `MAX_FILE_BYTES`. Returns `None`
/// for non-UTF-8 or oversized content.
#[cfg(test)]
pub(super) fn read_text_under_root(root: &Path, path: &Path) -> Option<String> {
    crate::core::safe_fs::read_bounded_text_under_root(root, path, MAX_FILE_BYTES)
}
