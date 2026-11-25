//! Fixtures for operations that require paths within the user's home.

use std::path::Path;

#[cfg(test)]
pub(crate) fn tempdir() -> tempfile::TempDir {
    let home = std::env::var_os("HOME").expect("HOME must be set for tests");
    let home = std::path::PathBuf::from(home).canonicalize().expect("home");
    if let Some(cwd) = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .ok()
        .filter(|cwd| cwd.starts_with(&home))
    {
        return tempdir_in_worktree(&cwd);
    }
    tempfile::tempdir_in(home).expect("temporary fixture within home")
}

pub fn tempdir_in_worktree(root: &Path) -> tempfile::TempDir {
    // Keep fixtures outside guardrail walks while preserving relative paths from the working directory.
    let scratch = root.join("target");
    std::fs::create_dir_all(&scratch).expect("fixture scratch directory");
    tempfile::tempdir_in(scratch).expect("temporary fixture within the working directory")
}
