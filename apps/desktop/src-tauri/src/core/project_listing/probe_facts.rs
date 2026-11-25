use crate::core::safe_fs::open_project_subdir;
use cap_std::fs::Dir;
use std::path::{Path, PathBuf};

pub(super) fn disk_children(root: &Dir, relative: &Path, path: &Path) -> Vec<PathBuf> {
    open_project_subdir(root, relative)
        .and_then(|dir| dir.entries())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| path.join(entry.file_name()))
        .collect()
}
