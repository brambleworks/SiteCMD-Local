//! The git operations the two job halves need, all through the hardened
//! runner in `core::git`.

use std::path::Path;

use crate::core::git::{run_git_command, GitRun, HttpsTransport};

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

/// What an unshallow fetch runs. The remote is named by URL rather than left
/// to `origin`, so the deepening goes to the very repository this job pushes
/// to and carries the transport's own credential, whatever the checkout's
/// remotes happen to say.
pub fn unshallow_args(remote_url: &str) -> [&str; 5] {
    ["fetch", "--unshallow", "--no-tags", "--", remote_url]
}

pub fn unshallow(root: &Path, remote_url: &str, transport: &HttpsTransport) -> Result<(), String> {
    expect_ok(
        run_git_command(
            root,
            &unshallow_args(remote_url),
            crate::constants::AUTOFIX_GIT_NETWORK_TIMEOUT,
            Some(transport),
        )?,
        "git fetch --unshallow",
    )
    .map(|_| ())
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

#[cfg(any(test, feature = "test-support"))]
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
