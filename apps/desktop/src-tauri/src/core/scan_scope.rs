//! Scope decisions for the Code Scan walker.
//! Ignore rules bound issue-emitting analysis, while individually ignored files remain
//! visible to hygiene, manifest, and lockfile checks.

use crate::core::filesystem::MAX_FILE_BYTES;
use crate::core::safe_fs::read_file_nofollow;
use cap_std::fs::Dir;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use std::ffi::OsStr;
use std::path::Path;

/// A nested repository can use either a directory or a worktree file.
pub(super) fn has_git_entry(dir: &Dir) -> bool {
    dir.symlink_metadata(".git").is_ok()
}

/// Directory-scoped `.gitignore` chain with deepest-match precedence.
/// Negated patterns restore ignored paths.
pub(super) struct GitignoreChain<'a> {
    matcher: Option<Gitignore>,
    parent: Option<&'a GitignoreChain<'a>>,
}

impl<'a> GitignoreChain<'a> {
    /// Chain root for the scan root directory, loading `root/.gitignore`.
    pub(super) fn for_root(dir: &Dir) -> GitignoreChain<'static> {
        GitignoreChain {
            matcher: load_dir_gitignore(Path::new(""), dir),
            parent: None,
        }
    }

    /// Scope for a subdirectory the walker is descending into, loading that
    /// directory's own `.gitignore` when present.
    pub(super) fn enter(&'a self, relative: &Path, dir: &Dir) -> GitignoreChain<'a> {
        GitignoreChain {
            matcher: load_dir_gitignore(relative, dir),
            parent: Some(self),
        }
    }

    /// True when the project-relative path is excluded by the nearest `.gitignore`
    /// rule. Gitignored paths are, by the project's own declaration, build
    /// output / codegen / third-party working trees - not first-party source.
    pub(super) fn is_ignored(&self, relative: &Path, is_dir: bool) -> bool {
        let mut node = Some(self);
        while let Some(scope) = node {
            if let Some(matcher) = &scope.matcher {
                match matcher.matched(relative, is_dir) {
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

fn load_dir_gitignore(path: &Path, dir: &Dir) -> Option<Gitignore> {
    let bytes = read_file_nofollow(dir, OsStr::new(".gitignore"), MAX_FILE_BYTES).ok()?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    let content = String::from_utf8(bytes).ok()?;
    let mut builder = GitignoreBuilder::new(path);
    for line in content.lines() {
        // Invalid glob lines are skipped (git ignores them too), never fatal.
        let _ = builder.add_line(None, line);
    }
    builder.build().ok()
}

#[cfg(test)]
mod tests {
    use crate::core::safe_fs::open_project_dir;
    use crate::core::scan_scope::{has_git_entry, GitignoreChain};
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

        assert!(!has_git_entry(&open_project_dir(&plain).unwrap()));
        assert!(
            has_git_entry(&open_project_dir(&repo).unwrap()),
            ".git directory marks a nested repo"
        );
        assert!(
            has_git_entry(&open_project_dir(&worktree).unwrap()),
            ".git FILE marks a worktree root"
        );
    }

    #[test]
    fn gitignore_chain_matches_root_and_nested_rules() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        fs::write(root.join(".gitignore"), "generated/\nlegacy.ts\n").expect("root gitignore");
        fs::create_dir_all(root.join("tools/bench")).expect("mkdir");
        fs::write(root.join("tools/bench/.gitignore"), ".work/\n").expect("nested gitignore");

        let chain = GitignoreChain::for_root(&open_project_dir(root).unwrap());
        assert!(chain.is_ignored(Path::new("generated"), true));
        assert!(chain.is_ignored(Path::new("legacy.ts"), false));
        assert!(!chain.is_ignored(Path::new("src"), true));
        assert!(!chain.is_ignored(Path::new("app.ts"), false));

        // The nested.gitignore only applies once its directory is entered.
        let tools = chain.enter(
            Path::new("tools"),
            &open_project_dir(&root.join("tools")).unwrap(),
        );
        let bench = tools.enter(
            Path::new("tools/bench"),
            &open_project_dir(&root.join("tools/bench")).unwrap(),
        );
        assert!(bench.is_ignored(Path::new("tools/bench/.work"), true));
        assert!(!tools.is_ignored(Path::new("tools/bench"), true));
    }

    #[test]
    fn gitignore_chain_honors_whitelist_negation() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        fs::write(root.join(".gitignore"), "*.gen.ts\n!keep.gen.ts\n").expect("gitignore");

        let chain = GitignoreChain::for_root(&open_project_dir(root).unwrap());
        assert!(chain.is_ignored(Path::new("other.gen.ts"), false));
        assert!(!chain.is_ignored(Path::new("keep.gen.ts"), false));
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

        let chain = GitignoreChain::for_root(&open_project_dir(project.path()).unwrap());
        assert!(
            !chain.is_ignored(Path::new("src"), true),
            "a symlinked .gitignore must be ignored entirely"
        );
    }
}
