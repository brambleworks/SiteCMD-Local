//! Checkout and GitHub repository identity for connection setup.

use std::path::{Path, PathBuf};

pub(super) const NO_REPOSITORY: &str = "Could not tell which GitHub repository this is. Run it from a checkout whose origin is on GitHub, or pass --repo owner/name.";
const NO_CHECKOUT: &str = "Run sitecmd connect from a checkout of the site's repository.";

/// Accept only an owner and repository, so neither can change an API path.
pub(super) fn repository_name(value: &str) -> Option<String> {
    let (owner, name) = value.split_once('/')?;
    let valid = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    };
    (owner.len() <= 39 && name.len() <= 100 && valid(owner) && valid(name))
        .then(|| value.to_string())
}

/// Read GitHub's HTTPS, scp-style SSH and URL-style SSH remote spellings.
pub fn github_repository(remote_url: &str) -> Option<String> {
    let remote = remote_url.trim();
    let path = if let Some(path) = remote.strip_prefix("git@github.com:") {
        path.to_string()
    } else {
        let url = url::Url::parse(remote).ok()?;
        if url.host_str()? != "github.com"
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(
                (url.scheme(), url.username()),
                ("https", "") | ("ssh", "git")
            )
        {
            return None;
        }
        url.path().strip_prefix('/')?.to_string()
    };
    repository_name(path.strip_suffix(".git").unwrap_or(&path))
}

fn git(path: &Path, args: &[&str]) -> Option<String> {
    let output =
        crate::core::git::run_git_command(path, args, crate::constants::AUTOFIX_GIT_TIMEOUT, None)
            .ok()?;
    output.ok().then(|| output.stdout.trim().to_string())
}

/// Audit the checkout root, even when invoked from one of its subdirectories.
pub(super) fn checkout(path: Option<&Path>) -> Result<(PathBuf, String), String> {
    let directory = path
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|_| NO_CHECKOUT)?;
    let root = git(&directory, &["rev-parse", "--show-toplevel"]).ok_or(NO_CHECKOUT)?;
    let root = std::fs::canonicalize(root).map_err(|_| NO_CHECKOUT)?;
    let head = crate::core::git::checkout_head_and_clean(&root.to_string_lossy())
        .ok_or(NO_CHECKOUT)?
        .0;
    Ok((root, head))
}

pub(super) fn repository(root: &Path, flag: Option<&str>) -> Result<String, String> {
    if let Some(flag) = flag {
        return repository_name(flag).ok_or_else(|| NO_REPOSITORY.into());
    }
    git(root, &["remote", "get-url", "origin"])
        .as_deref()
        .and_then(github_repository)
        .ok_or_else(|| NO_REPOSITORY.into())
}
