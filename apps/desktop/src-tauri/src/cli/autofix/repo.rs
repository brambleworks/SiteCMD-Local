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

/// The paths a patch touches, from `git apply --numstat`, which reads the
/// diff and runs nothing.
pub fn patch_paths(root: &Path, patch_path: &Path) -> Result<Vec<String>, String> {
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
            &["push", "--", remote_url, &refspec],
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
