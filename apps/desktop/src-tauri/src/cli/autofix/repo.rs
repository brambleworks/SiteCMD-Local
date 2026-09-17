//! The git operations the two job halves need, all through the hardened
//! runner in `core::git`.

use std::path::Path;

use super::artifact::MAX_PATCH_BYTES;
use crate::core::git::{run_git_command, GitRun, HttpsTransport};

/// The diff headers that move a file instead of editing it in place. A
/// template fixer never emits one. `rename old` and `rename new` are the
/// legacy spelling git still parses, so a patch cannot reach the tree by
/// writing its move that way instead.
const MOVE_HEADERS: &[&str] = &[
    "rename from ",
    "rename to ",
    "rename old ",
    "rename new ",
    "copy from ",
    "copy to ",
];

/// The file modes that make a patch write a symbolic link. A template fix
/// writes text into a host's configuration file and never a link out of the
/// tree.
const SYMLINK_MODES: &[&str] = &["new file mode 120000", "new mode 120000"];

fn expect_ok(run: GitRun, what: &str) -> Result<GitRun, String> {
    if run.ok() {
        Ok(run)
    } else {
        Err(format!("{what} failed: {}", run.stderr.trim()))
    }
}

pub fn head_sha(root: &Path) -> Result<String, String> {
    let run = expect_ok(
        run_git_command(
            root,
            &["rev-parse", "HEAD"],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git rev-parse HEAD",
    )?;
    let sha = run.stdout.trim().to_string();
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("git rev-parse HEAD did not name a commit".into());
    }
    Ok(sha)
}

pub fn stage(root: &Path, paths: &[String]) -> Result<(), String> {
    let mut args = vec!["add", "--"];
    args.extend(paths.iter().map(String::as_str));
    expect_ok(
        run_git_command(root, &args, crate::constants::AUTOFIX_GIT_TIMEOUT, None)?,
        "git add",
    )
    .map(|_| ())
}

pub fn staged_patch(root: &Path) -> Result<String, String> {
    expect_ok(
        run_git_command(
            root,
            // The hardening blanks `diff.external`, which git reads as a
            // configured external command and then fails to run, so the
            // patch is always taken from git's own diff.
            &[
                "diff",
                "--cached",
                "--binary",
                "--no-color",
                "--no-ext-diff",
            ],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git diff --cached",
    )
    .map(|run| run.stdout)
}

pub fn is_shallow(root: &Path) -> bool {
    run_git_command(
        root,
        &["rev-parse", "--is-shallow-repository"],
        crate::constants::AUTOFIX_GIT_TIMEOUT,
        None,
    )
    .is_ok_and(|run| run.ok() && run.stdout.trim() == "true")
}

pub fn unshallow(root: &Path, transport: &HttpsTransport) -> Result<(), String> {
    expect_ok(
        run_git_command(
            root,
            &["fetch", "--unshallow", "--no-tags"],
            crate::constants::AUTOFIX_GIT_NETWORK_TIMEOUT,
            Some(transport),
        )?,
        "git fetch --unshallow",
    )
    .map(|_| ())
}

pub fn apply_patch(root: &Path, patch_path: &Path) -> Result<(), String> {
    let patch = patch_path.to_string_lossy().to_string();
    expect_ok(
        run_git_command(
            root,
            &["apply", "--check", "--", &patch],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git apply --check",
    )?;
    expect_ok(
        run_git_command(
            root,
            &["apply", "--", &patch],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git apply",
    )
    .map(|_| ())
}

/// A `diff --git` header names one file twice, `a/<path> b/<path>`. Two
/// different names in one header delete the first and rewrite the second with
/// no rename line to give it away, so anything this cannot read as one path
/// named twice, including the quoted form git writes for an unusual name, is
/// refused.
fn names_one_path(header: &str) -> bool {
    header
        .strip_prefix("a/")
        .and_then(|rest| rest.split_once(" b/"))
        .is_some_and(|(old, new)| old == new)
}

/// A patch that does anything but edit files in place is refused before git
/// ever reads it. `git apply --numstat` prints a rename's destination and
/// nothing else, so a rename out of `.github/workflows/` would show the
/// publish job only the harmless-looking destination while the source left
/// the tree; a mismatched header does the same with no rename line at all;
/// and a symbolic link is not a fix a template writes.
fn refuse_unsupported_patch(patch_path: &Path) -> Result<(), String> {
    let metadata = std::fs::metadata(patch_path)
        .map_err(|error| format!("patch could not be read: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_PATCH_BYTES {
        return Err("patch is not a bounded regular file".into());
    }
    let patch = std::fs::read_to_string(patch_path)
        .map_err(|error| format!("patch could not be read: {error}"))?;
    // Each reason is looked for across the whole patch before the next, so a
    // move is named a move even though its header also names two paths.
    let lines = || patch.lines().map(str::trim_end);
    if lines().any(|line| MOVE_HEADERS.iter().any(|header| line.starts_with(header))) {
        return Err("patch renames or copies a file, which a template fix never does".into());
    }
    if lines().any(|line| SYMLINK_MODES.iter().any(|mode| line.starts_with(mode))) {
        return Err("patch creates a symbolic link, which a template fix never does".into());
    }
    if lines().any(|line| {
        line.strip_prefix("diff --git ")
            .is_some_and(|header| !names_one_path(header))
    }) {
        return Err("patch names two paths in one header, which a template fix never does".into());
    }
    Ok(())
}

/// The paths a patch touches, from `git apply --numstat`, which reads the
/// diff and runs nothing.
pub fn patch_paths(root: &Path, patch_path: &Path) -> Result<Vec<String>, String> {
    refuse_unsupported_patch(patch_path)?;
    let patch = patch_path.to_string_lossy().to_string();
    let run = expect_ok(
        run_git_command(
            root,
            &["apply", "--numstat", "--", &patch],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git apply --numstat",
    )?;
    Ok(run
        .stdout
        .lines()
        .filter_map(|line| line.split('\t').nth(2).map(str::to_string))
        .collect())
}

/// Every path the working tree shows as changed, tracked or not, so the
/// publish job can prove an applied patch touched nothing it did not declare.
/// A rename line names both sides.
pub fn changed_paths(root: &Path) -> Result<Vec<String>, String> {
    let run = expect_ok(
        run_git_command(
            root,
            &["status", "--porcelain", "--untracked-files=all"],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git status --porcelain",
    )?;
    let mut paths = Vec::new();
    for line in run.stdout.lines() {
        // Two status characters and a space, then the path, or `old -> new`.
        let Some(rest) = line.get(3..) else { continue };
        for path in rest.split(" -> ") {
            if !path.is_empty() {
                paths.push(path.to_string());
            }
        }
    }
    Ok(paths)
}

/// What an applied patch changed without declaring it: every path the tree
/// shows now that the patch did not declare and the checkout did not already
/// show before it was applied. The baseline matters because a runner's
/// checkout is not always pristine, and a file that was already there is not
/// the patch's doing. A rename line contributes both of its sides to each
/// list, so each side is judged on its own.
pub fn undeclared_paths(before: &[String], after: &[String], declared: &[String]) -> Vec<String> {
    after
        .iter()
        .filter(|path| !declared.contains(path) && !before.contains(path))
        .cloned()
        .collect()
}

pub fn commit(
    root: &Path,
    paths: &[String],
    name: &str,
    email: &str,
    message: &str,
) -> Result<String, String> {
    stage(root, paths)?;
    let user_name = format!("user.name={name}");
    let user_email = format!("user.email={email}");
    expect_ok(
        run_git_command(
            root,
            &[
                "-c",
                &user_name,
                "-c",
                &user_email,
                "commit",
                "--quiet",
                "--no-verify",
                "-m",
                message,
            ],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git commit",
    )?;
    head_sha(root)
}

/// Push the job's branch, replacing whatever is at its tip. The `sitecmd/`
/// namespace belongs to the App and a branch name carries no attempt number,
/// so a retry of the same job replaces the stale tip an earlier attempt left
/// behind instead of failing on a non-fast-forward for good.
pub fn push_branch(
    root: &Path,
    remote_url: &str,
    branch: &str,
    transport: &HttpsTransport,
) -> Result<(), String> {
    let refspec = format!("HEAD:refs/heads/{branch}");
    expect_ok(
        run_git_command(
            root,
            &["push", "--force", "--", remote_url, &refspec],
            crate::constants::AUTOFIX_GIT_NETWORK_TIMEOUT,
            Some(transport),
        )?,
        "git push",
    )
    .map(|_| ())
}

#[cfg(test)]
pub fn init_test_repo(files: &[(&str, &str)]) -> Result<(tempfile::TempDir, String), String> {
    let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
    for (name, content) in files {
        let path = temp.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(path, content).map_err(|error| error.to_string())?;
    }
    expect_ok(
        run_git_command(
            temp.path(),
            &["init", "-q", "-b", "main"],
            crate::constants::AUTOFIX_GIT_TIMEOUT,
            None,
        )?,
        "git init",
    )?;
    let head = commit(
        temp.path(),
        &[".".to_string()],
        "Test",
        "test@example.com",
        "Initial",
    )?;
    Ok((temp, head))
}
