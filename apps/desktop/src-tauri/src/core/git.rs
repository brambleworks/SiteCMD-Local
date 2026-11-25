//! Hardened Git commands for project files and checkout provenance.
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// allow-inline-duration: git-command wall-clock timeout is private to
// this module and has no constants.rs equivalent.
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_GIT_OUTPUT_BYTES: usize = 1024 * 1024;

/// Command-line overrides applied to every git spawn. A registered project
/// tree may carry a hostile `.git/config`, so every repository key that names
/// an executable is neutralized before the subcommand, optional index writes
/// are skipped, and no transport protocol may be negotiated. `run_git_command`
/// re-enables https alone, for one authenticated invocation, as the single
/// documented exception.
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

/// The one place git is spawned. Both runners over it, `run_git` and
/// `run_git_command`, go through here, which a source-scanning test in
/// `lib_tests.rs` enforces.
fn hardened_git_command(dir: &Path, args: &[impl AsRef<std::ffi::OsStr>]) -> Command {
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

/// Indexed paths among the candidates, or none when tracking cannot be established.
pub(crate) fn tracked_files(dir: &Path, paths: &[&str]) -> HashSet<String> {
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut args = vec!["--literal-pathspecs", "ls-files", "--cached", "-z", "--"];
    args.extend_from_slice(paths);
    run_git(dir, &args)
        .unwrap_or_default()
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn tracked_native_files(dir: &Path, paths: &[&std::ffi::OsStr]) -> HashSet<Vec<u8>> {
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut args = ["--literal-pathspecs", "ls-files", "--cached", "-z", "--"]
        .map(std::ffi::OsStr::new)
        .to_vec();
    args.extend_from_slice(paths);
    run_git_bytes(dir, &args)
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    String::from_utf8(run_git_bytes(dir, args)?).ok()
}

fn run_git_bytes(dir: &Path, args: &[impl AsRef<std::ffi::OsStr>]) -> Option<Vec<u8>> {
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
    Some(stdout)
}

/// A git invocation whose status and both streams the caller reads, for the
/// fix engine's apply, commit and push, which need the error text and a
/// timeout of their own.
pub(crate) struct GitRun {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl GitRun {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// One https push or fetch credential. It reaches git as `http.extraheader`
/// through the config environment of the single process that needs it, so it
/// never appears in a URL, in the argument list a process table shows, or in
/// any config file or remote git stores.
pub struct HttpsTransport {
    pub(crate) authorization_header: String,
}

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

pub(crate) fn run_git_command(
    dir: &Path,
    args: &[&str],
    timeout: Duration,
    transport: Option<&HttpsTransport>,
) -> Result<GitRun, String> {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 6);
    if transport.is_some() {
        // The hardening forbids every transport; https alone is re-enabled for
        // this one invocation. The protocol name is not a secret, so it rides
        // in the argument list. The credential helper and the askpass hook are
        // blanked beside it, so an authenticated fetch or push can never read a
        // credential someone else stored or prompt for one.
        full.extend([
            "-c",
            "protocol.https.allow=always",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
        ]);
    }
    full.extend_from_slice(args);
    let mut command = hardened_git_command(dir, &full);
    if let Some(transport) = transport {
        // A process table and `/proc/<pid>/cmdline` are world readable, so the
        // credential travels in git's config environment, which is not. The
        // hardening sets no `GIT_CONFIG_COUNT` of its own, leaving index 0 free.
        // `GIT_CONFIG_COUNT` needs git 2.31 or newer, which every GitHub-hosted
        // runner has.
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraheader")
            .env("GIT_CONFIG_VALUE_0", &transport.authorization_header);
    }
    let mut child = command
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

/// Capture the current checkout, including merge heads, and whether it is clean.
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

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
