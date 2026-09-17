//! Git integration - reads commit history by shelling out to `git log`.
//!
//! Used for deploy tracking: detects new commits since last scan.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use ts_rs::TS;

use crate::db::{EventSeverity, EventSource, EventType, SiteEvent};

// allow-inline-duration: git-command wall-clock timeout is private to
// this module and has no constants.rs equivalent.
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_GIT_OUTPUT_BYTES: usize = 1024 * 1024;

/// Command-line overrides applied to every git spawn. A registered project
/// tree may carry a hostile `.git/config`, so every repository key that names
/// an executable is neutralized before the subcommand, optional index writes
/// are skipped, and no transport protocol may be negotiated.
const GIT_HARDENING_ARGS: &[&str] = &[
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=",
    "-c",
    "core.sshCommand=",
    "-c",
    "diff.external=",
    "-c",
    "protocol.allow=never",
];

/// An empty config file for `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM`. Git
/// for Windows maps `/dev/null` to `NUL` internally, but naming the device
/// directly keeps the intent obvious on both platforms.
#[cfg(windows)]
const GIT_NULL_CONFIG_FILE: &str = "NUL";
#[cfg(not(windows))]
const GIT_NULL_CONFIG_FILE: &str = "/dev/null";

/// The only variables a git child may inherit. Everything else, including
/// every `GIT_*`, `SSH_*`, `LD_PRELOAD`, and shell hook variable, is dropped.
/// PATH is required to locate git; the rest keep git's own startup working.
const GIT_INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
];

/// Variables set explicitly on every git child.
const GIT_FIXED_ENV: &[(&str, &str)] = &[
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", GIT_NULL_CONFIG_FILE),
    ("GIT_CONFIG_SYSTEM", GIT_NULL_CONFIG_FILE),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("LC_ALL", "C"),
];

/// The one place git is spawned. Every caller goes through `run_git`, which
/// a source-scanning test in `lib_tests.rs` enforces.
fn hardened_git_command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for key in GIT_INHERITED_ENV {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for (key, value) in GIT_FIXED_ENV {
        command.env(key, value);
    }
    command.args(GIT_HARDENING_ARGS).args(args).current_dir(dir);
    command
}

/// A git commit from the project's log
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct GitCommit {
    pub hash: String,
    pub short_hash: String,
    pub message: String,
    pub author: String,
    pub date: String,          // ISO 8601
    pub relative_date: String, // "2 hours ago"
}

/// Git status for a project directory
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct GitStatus {
    pub is_git_repo: bool,
    pub branch: Option<String>,
    pub commits: Vec<GitCommit>,
    pub total_commits: u32,
    pub has_uncommitted: bool,
}

/// Build the shared deploy-event shape from a git commit.
pub fn commit_to_deploy_event(commit: &GitCommit, project_id: i64) -> SiteEvent {
    SiteEvent {
        id: 0,
        project_id,
        event_type: EventType::Deploy,
        severity: EventSeverity::Info,
        // Git author dates (%aI) are RFC 3339 with the author's local offset;
        // epoch ms normalizes them.
        occurred_at_ms: crate::db::timestamp_text_to_ms(&commit.date)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        title: commit
            .message
            .lines()
            .next()
            .unwrap_or(&commit.message)
            .to_string(),
        summary: format!("{} - {}", commit.short_hash, commit.author),
        detail: Some(
            serde_json::json!({
                "hash": commit.hash,
                "short_hash": commit.short_hash,
                "author": commit.author,
                "message": commit.message,
            })
            .to_string(),
        ),
        source: EventSource::Git,
        source_id: Some(commit.hash.clone()),
        metadata: None,
        // Git deploy events do not map to a specific check_id.
        affected_check_ids: None,
    }
}

/// `git log --format=...%x1f...` emits ASCII Unit Separator (`\x1f`) between
/// fields. `\x1f` is forbidden in well-formed commit messages, so it's safe
/// even when messages contain `|`, tabs, or other prose punctuation. Returns
/// None for malformed lines.
const FIELD_SEPARATOR: char = '\x1f';

fn parse_log_line(line: &str) -> Option<GitCommit> {
    let parts: Vec<&str> = line.splitn(6, FIELD_SEPARATOR).collect();
    if parts.len() < 6 {
        return None;
    }
    Some(GitCommit {
        hash: parts[0].to_string(),
        short_hash: parts[1].to_string(),
        message: parts[2].to_string(),
        author: parts[3].to_string(),
        date: parts[4].to_string(),
        relative_date: parts[5].to_string(),
    })
}

/// Parse multi-line `git log` output into commits, dropping blank/malformed lines.
fn parse_log_output(output: &str) -> Vec<GitCommit> {
    output
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(parse_log_line)
        .collect()
}

/// Read git log from a project directory
#[tracing::instrument(skip(project_path), fields(project_path_len = project_path.len(), limit))]
pub fn get_git_status(project_path: &str, limit: u32) -> GitStatus {
    let dir = Path::new(project_path);
    let limit = limit.clamp(1, 200);

    if !dir.join(".git").exists() && !has_git_dir(dir) {
        return GitStatus {
            is_git_repo: false,
            branch: None,
            commits: Vec::new(),
            total_commits: 0,
            has_uncommitted: false,
        };
    }

    let branch = run_git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]).map(|s| s.trim().to_string());

    let has_uncommitted = run_git(dir, &["status", "--porcelain"])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    // Use ASCII Unit Separator (\x1f) instead of `|` so commit messages
    // that contain `|` don't break field parsing.
    let log_format = "--format=%H%x1f%h%x1f%s%x1f%an%x1f%aI%x1f%ar";
    let log_output = run_git(
        dir,
        &["log", log_format, &format!("-{}", limit), "--no-merges"],
    );

    let commits = log_output
        .as_deref()
        .map(parse_log_output)
        .unwrap_or_default();

    let total_commits = run_git(dir, &["rev-list", "--count", "HEAD"])
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(commits.len() as u32);

    GitStatus {
        is_git_repo: true,
        branch,
        commits,
        total_commits,
        has_uncommitted,
    }
}

/// Get commits since a specific date (for detecting new deploys)
#[tracing::instrument(skip(project_path), fields(project_path_len = project_path.len(), since = %since))]
pub fn get_commits_since(project_path: &str, since: &str) -> Vec<GitCommit> {
    let dir = Path::new(project_path);
    // Use ASCII Unit Separator (\x1f) instead of `|` so commit messages
    // that contain `|` don't break field parsing.
    let log_format = "--format=%H%x1f%h%x1f%s%x1f%an%x1f%aI%x1f%ar";
    let since_arg = format!("--since={}", since);

    let output = run_git(dir, &["log", log_format, &since_arg, "--no-merges"]);
    output.as_deref().map(parse_log_output).unwrap_or_default()
}

/// Return commits in the inclusive window, newest first, plus the uncapped count.
/// The list is whole-or-empty and capped at 200; failures return an empty list.
#[tracing::instrument(skip(project_path), fields(project_path_len = project_path.len(), since = %since, until = %until))]
pub fn get_commits_between(project_path: &str, since: &str, until: &str) -> (Vec<GitCommit>, u32) {
    let dir = Path::new(project_path);
    let log_format = "--format=%H%x1f%h%x1f%s%x1f%an%x1f%aI%x1f%ar";
    let since_arg = format!("--since={}", since);
    let until_arg = format!("--until={}", until);

    let output = run_git(
        dir,
        &[
            "log",
            log_format,
            &since_arg,
            &until_arg,
            "--no-merges",
            "-n",
            "200",
        ],
    );
    let commits = output.as_deref().map(parse_log_output).unwrap_or_default();
    let total = run_git(
        dir,
        &[
            "rev-list",
            "--count",
            "--no-merges",
            &since_arg,
            &until_arg,
            "HEAD",
        ],
    )
    .and_then(|s| s.trim().parse::<u32>().ok())
    .unwrap_or(commits.len() as u32);
    (commits, total)
}

fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    let mut child = hardened_git_command(dir, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut exceeded_limit = false;
        let mut buf = [0_u8; 8192];

        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let remaining = MAX_GIT_OUTPUT_BYTES.saturating_sub(output.len());
                    if n > remaining {
                        exceeded_limit = true;
                    }
                    if remaining > 0 {
                        output.extend_from_slice(&buf[..n.min(remaining)]);
                    }
                }
                Err(_) => {
                    exceeded_limit = true;
                    break;
                }
            }
        }

        let _ = tx.send((output, exceeded_limit));
    });

    let started_at = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started_at.elapsed() >= GIT_COMMAND_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    };

    if !status.success() {
        return None;
    }

    let (stdout, exceeded_limit) = rx.recv_timeout(Duration::from_millis(250)).ok()?;
    if exceeded_limit {
        return None;
    }
    String::from_utf8(stdout).ok()
}

// Only the tests exercise the runner until the fix engine's commands call it.

/// A git invocation whose status and both streams the caller reads, for the
/// fix engine's apply, commit and push, which need the error text and a
/// timeout of their own.
#[allow(dead_code)]
pub(crate) struct GitRun {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[allow(dead_code)]
impl GitRun {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// One https push or fetch credential, carried through `http.extraheader`
/// so it never appears in a URL, an argument list a process table shows, or
/// a remote git stores.
#[allow(dead_code)]
pub(crate) struct HttpsTransport {
    pub authorization_header: String,
}

#[allow(dead_code)]
impl HttpsTransport {
    pub fn for_token(token: &str) -> Self {
        use base64::Engine as _;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        Self {
            authorization_header: format!("AUTHORIZATION: basic {encoded}"),
        }
    }
}

#[allow(dead_code)]
pub(crate) fn run_git_command(
    dir: &Path,
    args: &[&str],
    timeout: Duration,
    transport: Option<&HttpsTransport>,
) -> Result<GitRun, String> {
    let extra_header;
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 4);
    if let Some(transport) = transport {
        // The hardening forbids every transport; https alone is re-enabled for
        // this one invocation, and only with the header the caller supplied.
        extra_header = format!("http.extraheader={}", transport.authorization_header);
        full.extend([
            "-c",
            "protocol.https.allow=always",
            "-c",
            extra_header.as_str(),
        ]);
    }
    full.extend_from_slice(args);
    let mut child = hardened_git_command(dir, &full)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("git could not be started: {error}"))?;
    let stdout = child.stdout.take().ok_or("git stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("git stderr unavailable")?;
    let read_all = |mut stream: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let mut buf = [0_u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let remaining =
                            crate::constants::AUTOFIX_MAX_LOG_BYTES.saturating_sub(output.len());
                        output.extend_from_slice(&buf[..n.min(remaining)]);
                    }
                }
            }
            output
        })
    };
    let stdout_reader = read_all(Box::new(stdout));
    let stderr_reader = read_all(Box::new(stderr));
    let started_at = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started_at.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "git {} timed out after {}s",
                        args.first().unwrap_or(&""),
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(format!("git could not be waited on: {error}")),
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "git stdout reader failed".to_string())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "git stderr reader failed".to_string())?;
    Ok(GitRun {
        status: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

fn has_git_dir(dir: &Path) -> bool {
    // Check if we're inside a git repo (even if.git is in a parent)
    run_git(dir, &["rev-parse", "--git-dir"]).is_some()
}

/// The exact checkout a file walk would observe, without applying the commit
/// history view's `--no-merges` filter. Merge commits are ordinary checkout
/// heads and must remain eligible for exact deployment provenance.
pub fn checkout_head_and_clean(project_path: &str) -> Option<(String, bool)> {
    let dir = Path::new(project_path);
    let head = run_git(dir, &["rev-parse", "HEAD"])?;
    let head = head.trim();
    if head.len() < 7
        || head.len() > 64
        || !head
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return None;
    }
    let status = run_git(dir, &["status", "--porcelain"])?;
    Some((head.to_string(), status.trim().is_empty()))
}

/// Get recent commits (convenience wrapper for backfill)
#[tracing::instrument(skip(project_path), fields(project_path_len = project_path.len(), limit))]
pub fn get_recent_commits(project_path: &str, limit: u32) -> Vec<GitCommit> {
    get_git_status(project_path, limit).commits
}

/// Async entry points for runtime callers. `run_git` polls its child with a
/// sleep loop that must never run on a runtime worker, so these move the
/// sync helpers to the blocking pool and surface a failed blocking task as an
/// error instead of an empty result.
pub async fn get_git_status_async(project_path: String, limit: u32) -> Result<GitStatus, String> {
    tokio::task::spawn_blocking(move || get_git_status(&project_path, limit))
        .await
        .map_err(|error| format!("Git status task failed: {error}"))
}

pub async fn get_commits_since_async(
    project_path: String,
    since: String,
) -> Result<Vec<GitCommit>, String> {
    tokio::task::spawn_blocking(move || get_commits_since(&project_path, &since))
        .await
        .map_err(|error| format!("Git commits task failed: {error}"))
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
