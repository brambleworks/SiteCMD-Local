//! Scope decisions for the Code Scan walker.
//! Ignore rules bound issue-emitting analysis, while individually ignored files remain
//! visible to hygiene, manifest, and lockfile checks.

use super::filesystem::read_text_under_root;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use std::fs;
use std::path::Path;

mod rust_modules;
pub(super) use rust_modules::{
    normalize as normalize_rust_module_path, strip_rust_test_modules, RustModuleGraph,
};

pub(super) const CARGO_MANIFEST_MAX_BYTES: u64 = 250_000;

pub(super) fn cargo_build_script(content: &str) -> Option<std::path::PathBuf> {
    let document = content.parse::<toml_edit::DocumentMut>().ok()?;
    let package = document.get("package")?;
    let script = match package.get("build") {
        None => "build.rs",
        Some(build) if build.as_bool() == Some(true) => "build.rs",
        Some(build) => build.as_str()?,
    };
    Some(script.into())
}

/// Detect repository roots represented by either a `.git` directory or file.
/// The walker skips nested repositories, including submodules.
pub(super) fn has_git_entry(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(".git")).is_ok()
}

/// Detect Rust files whose first non-comment line is `#![cfg(test)]`.
/// These files are excluded from production-source analysis regardless of name.
pub(super) fn is_rust_test_only_file(path: &Path, content: &str) -> bool {
    let is_rust = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
    if !is_rust {
        return false;
    }
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        return trimmed.starts_with("#![cfg(test)]");
    }
    false
}

/// Directory-scoped `.gitignore` chain with deepest-match precedence.
/// Negated patterns restore ignored paths.
pub(super) struct GitignoreChain<'a> {
    matcher: Option<Gitignore>,
    parent: Option<&'a GitignoreChain<'a>>,
}

impl<'a> GitignoreChain<'a> {
    /// Chain root for the scan root directory, loading `root/.gitignore`.
    pub(super) fn for_root(root: &Path) -> GitignoreChain<'static> {
        GitignoreChain {
            matcher: load_dir_gitignore(root, root),
            parent: None,
        }
    }

    /// Scope for a subdirectory the walker is descending into, loading that
    /// directory's own `.gitignore` when present.
    pub(super) fn enter(&'a self, root: &Path, dir: &Path) -> GitignoreChain<'a> {
        GitignoreChain {
            matcher: load_dir_gitignore(root, dir),
            parent: Some(self),
        }
    }

    /// True when `path` is excluded by the nearest governing `.gitignore`
    /// rule. Gitignored paths are, by the project's own declaration, build
    /// output / codegen / third-party working trees - not first-party source.
    pub(super) fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        let mut node = Some(self);
        while let Some(scope) = node {
            if let Some(matcher) = &scope.matcher {
                match matcher.matched(path, is_dir) {
                    Match::Ignore(_) => return true,
                    Match::Whitelist(_) => return false,
                    Match::None => {}
                }
            }
            node = scope.parent;
        }
        false
    }
}

/// Compile `dir/.gitignore` with the ripgrep gitignore engine. The file is
/// read through `read_text_under_root` so a planted symlink `.gitignore`
/// inside an untrusted tree is refused like every other fixed-path read.
fn load_dir_gitignore(root: &Path, dir: &Path) -> Option<Gitignore> {
    let content = read_text_under_root(root, &dir.join(".gitignore"))?;
    let mut builder = GitignoreBuilder::new(dir);
    for line in content.lines() {
        // Invalid glob lines are skipped (git ignores them too), never fatal.
        let _ = builder.add_line(None, line);
    }
    builder.build().ok()
}

#[cfg(test)]
mod tests {
    use super::{has_git_entry, is_rust_test_only_file, GitignoreChain};
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn git_entry_detection_covers_directories_and_worktree_files() {
        let temp = tempdir().expect("temp dir");
        let plain = temp.path().join("plain");
        let repo = temp.path().join("repo");
        let worktree = temp.path().join("worktree");
        fs::create_dir_all(&plain).expect("mkdir");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::create_dir_all(&worktree).expect("mkdir");
        fs::write(worktree.join(".git"), "gitdir: ../repo/.git/worktrees/w\n").expect("git file");

        assert!(!has_git_entry(&plain));
        assert!(has_git_entry(&repo), ".git directory marks a nested repo");
        assert!(has_git_entry(&worktree), ".git FILE marks a worktree root");
    }

    #[test]
    fn rust_test_only_file_requires_leading_cfg_test_attribute() {
        let path = Path::new("src/scoring/calculator_scan_tests.rs");
        assert!(is_rust_test_only_file(
            path,
            "// sibling test file\n\n#![cfg(test)]\nuse super::*;\n"
        ));
        // A trailing test module does not make the whole file test-only.
        assert!(!is_rust_test_only_file(
            path,
            "pub fn real() {}\n#[cfg(test)]\nmod tests {}\n"
        ));
        // Non-Rust files never match, whatever they contain.
        assert!(!is_rust_test_only_file(
            Path::new("src/app.ts"),
            "#![cfg(test)]\n"
        ));
    }

    #[test]
    fn gitignore_chain_matches_root_and_nested_rules() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        fs::write(root.join(".gitignore"), "generated/\nlegacy.ts\n").expect("root gitignore");
        fs::create_dir_all(root.join("tools/bench")).expect("mkdir");
        fs::write(root.join("tools/bench/.gitignore"), ".work/\n").expect("nested gitignore");

        let chain = GitignoreChain::for_root(root);
        assert!(chain.is_ignored(&root.join("generated"), true));
        assert!(chain.is_ignored(&root.join("legacy.ts"), false));
        assert!(!chain.is_ignored(&root.join("src"), true));
        assert!(!chain.is_ignored(&root.join("app.ts"), false));

        // The nested.gitignore only applies once its directory is entered.
        let tools = chain.enter(root, &root.join("tools"));
        let bench = tools.enter(root, &root.join("tools/bench"));
        assert!(bench.is_ignored(&root.join("tools/bench/.work"), true));
        assert!(!tools.is_ignored(&root.join("tools/bench"), true));
    }

    #[test]
    fn gitignore_chain_honors_whitelist_negation() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        fs::write(root.join(".gitignore"), "*.gen.ts\n!keep.gen.ts\n").expect("gitignore");

        let chain = GitignoreChain::for_root(root);
        assert!(chain.is_ignored(&root.join("other.gen.ts"), false));
        assert!(!chain.is_ignored(&root.join("keep.gen.ts"), false));
    }

    /// A planted symlink `.gitignore` must not be read: fixed-path reads of
    /// an untrusted tree always refuse symlinks (matches read_under_root).
    #[cfg(unix)]
    #[test]
    fn symlinked_gitignore_is_refused() {
        use std::os::unix::fs::symlink;

        let project = tempdir().expect("temp dir");
        let outside = tempdir().expect("temp dir");
        let target = outside.path().join("patterns");
        fs::write(&target, "src/\n").expect("write target");
        symlink(&target, project.path().join(".gitignore")).expect("symlink");

        let chain = GitignoreChain::for_root(project.path());
        assert!(
            !chain.is_ignored(&project.path().join("src"), true),
            "a symlinked .gitignore must be ignored entirely"
        );
    }
}
