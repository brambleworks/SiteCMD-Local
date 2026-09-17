//! Every build and package-manager child of the fix job runs with an explicit
//! deny-by-default environment: PATH, HOME and CI, nothing else, so no
//! INPUT_*, SITECMD_* or ACTIONS_ID_TOKEN_REQUEST_* value reaches
//! repository-controlled code.

use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The only parent variables a fix-job child may inherit. PATH locates the
/// package manager and HOME keeps its cache and config lookups working.
pub const ALLOWED_ENV: &[&str] = &["PATH", "HOME"];

// allow-inline-duration: the output-drain poll interval is private to this runner.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long output a finished child left behind is still collected. It bounds
/// an orphan that inherited the pipes and never closes them.
// allow-inline-duration: a drain grace private to this runner, not a product timeout.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// The allowed names present in the parent, plus the `CI=true` every package
/// manager reads to pick its non-interactive behavior.
pub fn allowlisted_env(parent: impl Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = ALLOWED_ENV
        .iter()
        .filter_map(|name| parent(name).map(|value| (name.to_string(), value)))
        .collect();
    env.push(("CI".to_string(), "true".to_string()));
    env
}

/// A command whose environment is built from nothing, so a variable has to be
/// on the allowlist to exist at all. Stdin is closed: nothing may prompt.
pub fn allowlisted_command(program: &str, args: &[&str], root: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for (name, value) in allowlisted_env(|name| std::env::var(name).ok()) {
        command.env(name, value);
    }
    command.args(args).current_dir(root).stdin(Stdio::null());
    command
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub status: Option<i32>,
    pub log: String,
}

/// Runs to completion or the timeout; the log is both streams by line,
/// capped and redacted, and the caller decides what to do with the status.
/// A timeout is an outcome, not an error: it answers `status: None` with the
/// output collected so far, so a hung step still explains itself.
pub fn run_captured(mut command: Command, timeout: Duration) -> Result<Captured, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{program} could not be started: {error}"))?;
    let (tx, rx) = mpsc::channel::<String>();
    for stream in [
        child
            .stdout
            .take()
            .map(|stream| Box::new(stream) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|stream| Box::new(stream) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || forward_lines(stream, &tx));
    }
    drop(tx);
    let started_at = Instant::now();
    let mut log = String::new();
    let mut truncated = false;
    let status = loop {
        while let Ok(line) = rx.try_recv() {
            truncated |= !append_line(&mut log, &line);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started_at.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    while let Ok(line) = rx.try_recv() {
                        truncated |= !append_line(&mut log, &line);
                    }
                    let marker = format!("... {program} timed out after {}s\n", timeout.as_secs());
                    return Ok(finished(log, truncated, &marker, None));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(format!("{program} could not be waited on: {error}")),
        }
    };
    let deadline = Instant::now() + DRAIN_GRACE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                if !append_line(&mut log, &line) {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Ok(finished(log, truncated, "", status.code()))
}

/// Reads whole lines as bytes, so one invalid UTF-8 byte cannot end a stream
/// early, and keeps reading to EOF even once nobody is listening: closing a
/// pipe under a running child would signal it mid-build.
fn forward_lines(stream: Box<dyn std::io::Read + Send>, tx: &mpsc::Sender<String>) {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                while buffer
                    .last()
                    .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
                {
                    buffer.pop();
                }
                let _ = tx.send(String::from_utf8_lossy(&buffer).into_owned());
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Appends the line unless it would carry the log past its cap.
fn append_line(log: &mut String, line: &str) -> bool {
    if log.len() + line.len() + 1 > crate::constants::AUTOFIX_MAX_LOG_BYTES {
        return false;
    }
    log.push_str(line);
    log.push('\n');
    true
}

/// Every exit shares the cap marker, its trailer, and the redaction pass.
fn finished(mut log: String, truncated: bool, trailer: &str, status: Option<i32>) -> Captured {
    if truncated {
        log.push_str("... (log truncated)\n");
    }
    log.push_str(trailer);
    Captured {
        log: crate::log_sanitizer::redact_secrets(&log),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_child_environment_is_deny_by_default() {
        let parent = |name: &str| match name {
            "PATH" => Some("/usr/bin".to_string()),
            "HOME" => Some("/home/runner".to_string()),
            "INPUT_CONNECTION_EXPORT"
            | "SITECMD_CI_TOKEN"
            | "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
            | "GITHUB_TOKEN" => Some("secret".to_string()),
            _ => None,
        };
        let env = allowlisted_env(parent);
        assert_eq!(
            env,
            vec![
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("HOME".to_string(), "/home/runner".to_string()),
                ("CI".to_string(), "true".to_string()),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_spawned_child_sees_only_the_allowlist() {
        std::env::set_var("SITECMD_SUBPROCESS_PROBE", "leak");
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_PROBE", "leak");
        let temp = tempfile::tempdir().unwrap();
        let captured = run_captured(
            allowlisted_command("env", &[], temp.path()),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(captured.status, Some(0));
        for line in captured.log.lines() {
            let name = line.split('=').next().unwrap_or("");
            assert!(
                matches!(name, "PATH" | "HOME" | "CI" | "PWD" | "_"),
                "leaked {name}"
            );
        }
        assert!(!captured.log.contains("PROBE"));
    }

    #[cfg(unix)]
    #[test]
    fn an_invalid_byte_does_not_end_the_stream() {
        let temp = tempfile::tempdir().unwrap();
        let captured = run_captured(
            allowlisted_command(
                "sh",
                &["-c", r"printf 'first\n\377bad\nlast\n'"],
                temp.path(),
            ),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(captured.status, Some(0));
        assert!(captured.log.contains("first"), "{}", captured.log);
        assert!(captured.log.contains("last"), "{}", captured.log);
    }

    #[cfg(unix)]
    #[test]
    fn a_timeout_keeps_the_output_so_far_and_reports_no_status() {
        let temp = tempfile::tempdir().unwrap();
        let captured = run_captured(
            allowlisted_command("sh", &["-c", "echo partial; sleep 5"], temp.path()),
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(captured.status, None);
        assert!(captured.log.contains("partial"), "{}", captured.log);
        assert!(
            captured.log.contains("timed out after 1s"),
            "{}",
            captured.log
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_background_process_holding_the_pipes_cannot_stall_the_drain() {
        let temp = tempfile::tempdir().unwrap();
        let started_at = std::time::Instant::now();
        let captured = run_captured(
            allowlisted_command("sh", &["-c", "echo done; (sleep 6 &)"], temp.path()),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let elapsed = started_at.elapsed();
        assert_eq!(captured.status, Some(0));
        assert!(captured.log.contains("done"), "{}", captured.log);
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn output_is_capped_and_redacted() {
        let temp = tempfile::tempdir().unwrap();
        let mut command = allowlisted_command(
            "sh",
            &[
                "-c",
                "echo token=ghp_abcdefghijklmnopqrstuvwxyz0123456789; exit 3",
            ],
            temp.path(),
        );
        command.env("PATH", std::env::var("PATH").unwrap_or_default());
        let captured = run_captured(command, std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(captured.status, Some(3));
        assert!(
            !captured
                .log
                .contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            "{}",
            captured.log
        );
    }
}
