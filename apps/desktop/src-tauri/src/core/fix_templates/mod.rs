//! The template fix engine: host detection, per-check fixers that decline
//! rather than guess, and formatting-preserving writers.

pub mod build_check;
pub mod fixers;
pub mod hosts;
pub mod subprocess;
pub mod writers;

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check_id: String,
    pub identity: String,
}

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

/// A fixer's refusal: its prerequisites are not met on this checkout, with
/// the reason a person can act on. Never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// Relative to the checkout root.
    pub path: PathBuf,
    /// The file's content before the edit, or None when the file is created.
    pub before: Option<String>,
    pub after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Applied {
    pub written: Vec<PathBuf>,
}

pub trait Fixer: Sync {
    fn check_id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    /// The files this fixer may write on this target: the publish job refuses
    /// a patch that reaches outside it.
    fn write_set(&self, target: &HostTarget) -> Vec<PathBuf>;
    fn prerequisites(
        &self,
        finding: &Finding,
        target: &HostTarget,
        root: &Path,
    ) -> Result<(), Unsupported>;
    fn plan(
        &self,
        finding: &Finding,
        target: &HostTarget,
        root: &Path,
    ) -> Result<Option<Patch>, Unsupported>;
}

// Fixers register here as they land.
static FIXERS: &[&dyn Fixer] = &[];

pub fn all_fixers() -> &'static [&'static dyn Fixer] {
    FIXERS
}

pub fn fixer_for(check_id: &str) -> Option<&'static dyn Fixer> {
    FIXERS
        .iter()
        .copied()
        .find(|fixer| fixer.check_id() == check_id)
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

fn safe_relative(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!(
            "{} reaches outside the checkout",
            relative.display()
        ));
    }
    Ok(root.join(relative))
}

pub fn apply(patches: &[Patch], root: &Path) -> Result<Applied, String> {
    let mut applied = Applied::default();
    for patch in patches {
        let path = safe_relative(root, &patch.path)?;
        let current = match std::fs::read_to_string(&path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "{} could not be read: {error}",
                    patch.path.display()
                ))
            }
        };
        if current != patch.before {
            return Err(format!(
                "{} changed since the patch was planned",
                patch.path.display()
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::write(&path, &patch.after)
            .map_err(|error| format!("{} could not be written: {error}", patch.path.display()))?;
        applied.written.push(patch.path.clone());
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let patch = Patch {
            after: "{\"a\":1}".into(),
            before: Some("{ }".into()),
            path: "vercel.json".into(),
        };
        let error = apply(&[patch], temp.path()).unwrap_err();
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
        let patch = Patch {
            after: "{\"a\":1}".into(),
            before: Some("{}".into()),
            path: "vercel.json".into(),
        };
        let applied = apply(&[patch], temp.path()).unwrap();
        assert_eq!(
            applied.written,
            vec![std::path::PathBuf::from("vercel.json")]
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("vercel.json")).unwrap(),
            "{\"a\":1}"
        );
    }

    #[test]
    fn apply_refuses_paths_that_escape_the_root() {
        let temp = tempfile::tempdir().unwrap();
        let patch = Patch {
            after: "x".into(),
            before: None,
            path: "../escape.json".into(),
        };
        assert!(apply(&[patch], temp.path())
            .unwrap_err()
            .contains("outside"));
    }
}
