//! Host configuration and filesystem support for template fixes.

pub mod build_check;
pub mod hosts;
pub mod subprocess;
pub mod writers;

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cap_std::fs::File;
use sitecmd_protocol::engine_abi::{Patch, AUDIT_MAX_FILE_BYTES};

use super::safe_fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Vercel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTarget {
    pub kind: HostKind,
    /// Relative to the checkout root.
    pub config_path: PathBuf,
}

pub(crate) struct PreparedPatch {
    patch: Patch,
    file: File,
}

/// `security.headers.x_content_type_options` becomes `x-content-type-options`:
/// the branch name and the PR title vocabulary.
pub fn slug(check_id: &str) -> String {
    check_id
        .rsplit('.')
        .next()
        .unwrap_or(check_id)
        .replace('_', "-")
}

pub(crate) fn prepare(root: &Path, patch: Patch) -> Result<PreparedPatch, String> {
    let path = Path::new(patch.path.as_str());
    let directory = safe_fs::open_project_dir(root).map_err(|error| {
        format!(
            "{} could not open {}: {error}",
            path.display(),
            root.display()
        )
    })?;
    let mut file = open_patch_file(&directory, path)?;
    let bytes = safe_fs::read_file_limited(&mut file, AUDIT_MAX_FILE_BYTES)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    if bytes.len() as u64 > AUDIT_MAX_FILE_BYTES || Patch::hash_base(&bytes) != patch.base_sha256 {
        return Err(format!(
            "{} changed since the patch was planned",
            path.display()
        ));
    }
    std::str::from_utf8(&bytes)
        .map_err(|error| format!("{} is not UTF-8: {error}", path.display()))?;
    Ok(PreparedPatch { patch, file })
}

/// The refusal for a write path that passes through a symbolic link.
pub(crate) fn symlink_refusal(path: impl std::fmt::Display) -> String {
    format!("{path} contains a symbolic link")
}

fn open_patch_file(directory: &cap_std::fs::Dir, path: &Path) -> Result<File, String> {
    safe_fs::open_writable_project_file(directory, path).map_err(|error| {
        if safe_fs::project_path_is_symlink(directory, path) {
            symlink_refusal(path.display())
        } else {
            format!("{} could not be opened: {error}", path.display())
        }
    })
}

pub(crate) fn apply(prepared: PreparedPatch) -> Result<Patch, String> {
    let PreparedPatch { patch, mut file } = prepared;
    let content = patch.content.as_bytes();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(content))
        .and_then(|_| file.set_len(content.len() as u64))
        .map_err(|error| format!("{} could not be written: {error}", patch.path.as_str()))?;
    Ok(patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sitecmd_protocol::engine_abi::RelPath;

    fn patch(before: &str, after: &str) -> Patch {
        Patch {
            path: RelPath::parse("vercel.json").unwrap(),
            base_sha256: Patch::hash_base(before.as_bytes()),
            content: after.into(),
        }
    }

    #[cfg(unix)]
    fn link(target: &Path, path: &Path) {
        std::os::unix::fs::symlink(target, path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_targets_and_parent_directories() {
        // Bug M2: regenerated template patches write through checkout symlinks.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("vercel.json"), "{}\n").unwrap();
        link(
            &outside.path().join("vercel.json"),
            &root.path().join("vercel.json"),
        );
        assert!(prepare(root.path(), patch("{}\n", "{\"headers\":[]}")).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("vercel.json")).unwrap(),
            "{}\n"
        );
        link(outside.path(), &root.path().join("config"));
        let directory = safe_fs::open_project_dir(root.path()).unwrap();
        assert!(open_patch_file(&directory, Path::new("config/new.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_swapped_in_before_writing_cannot_redirect_the_patch() {
        // Bug: A target swapped for a symlink after validation redirects the write.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = root.path().join("vercel.json");
        let target = outside.path().join("vercel.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::write(&target, "{}").unwrap();
        let prepared = prepare(root.path(), patch("{}", "{\"headers\":[]}")).unwrap();
        let original = root.path().join("original.json");
        std::fs::rename(&path, &original).unwrap();
        link(&target, &path);

        apply(prepared).unwrap();

        assert_eq!(
            std::fs::read_to_string(original).unwrap(),
            "{\"headers\":[]}"
        );
        assert_eq!(std::fs::read_to_string(target).unwrap(), "{}");
    }

    #[test]
    fn slug_takes_the_last_segment_with_dashes() {
        assert_eq!(
            slug("security.headers.x_content_type_options"),
            "x-content-type-options"
        );
        assert_eq!(slug("code_scan.open-redirect"), "open-redirect");
    }

    #[test]
    fn apply_refuses_a_patch_whose_before_no_longer_matches() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vercel.json"), "{}").unwrap();
        let error = prepare(temp.path(), patch("{ }", "{\"a\":1}"))
            .err()
            .unwrap();
        assert!(error.contains("changed"), "{error}");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("vercel.json")).unwrap(),
            "{}"
        );
    }

    #[test]
    fn apply_writes_matching_patches_and_reports_them() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vercel.json"), "{}").unwrap();
        let applied = apply(prepare(temp.path(), patch("{}", "{\"a\":1}")).unwrap()).unwrap();
        assert_eq!(applied.path.as_str(), "vercel.json");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("vercel.json")).unwrap(),
            "{\"a\":1}"
        );
        apply(prepare(temp.path(), patch("{\"a\":1}", "{}")).unwrap()).unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("vercel.json")).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn apply_refuses_paths_that_escape_the_root() {
        let parent = tempfile::tempdir().unwrap();
        let checkout = parent.path().join("checkout");
        std::fs::create_dir(&checkout).unwrap();
        let outside = parent.path().join("escape.json");
        std::fs::write(&outside, "{}").unwrap();
        let directory = safe_fs::open_project_dir(&checkout).unwrap();
        assert!(RelPath::parse("../escape.json").is_err());
        assert!(open_patch_file(&directory, Path::new("../escape.json")).is_err());
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "{}");
    }
}
