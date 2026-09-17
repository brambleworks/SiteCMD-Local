//! Every build and package-manager child of the fix job runs with an explicit
//! deny-by-default environment: PATH, HOME and CI, nothing else, so no
//! INPUT_*, SITECMD_* or ACTIONS_ID_TOKEN_REQUEST_* value reaches
//! repository-controlled code.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The only parent variables a fix-job child may inherit. PATH locates the
/// package manager and HOME keeps its cache and config lookups working.
pub const ALLOWED_ENV: &[&str] = &["PATH", "HOME"];

// allow-inline-duration: the output-drain poll interval is private to this runner.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

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
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let started_at = Instant::now();
    let mut log = String::new();
    let mut truncated = false;
    let status = loop {
        while let Ok(line) = rx.try_recv() {
            if !append_line(&mut log, &line) {
                truncated = true;
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started_at.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{program} timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(format!("{program} could not be waited on: {error}")),
        }
    };
    for line in rx.iter() {
        if !append_line(&mut log, &line) {
            truncated = true;
            break;
        }
    }
    if truncated {
        log.push_str("... (log truncated)\n");
    }
    Ok(Captured {
        log: crate::log_sanitizer::redact_secrets(&log),
        status: status.code(),
    })
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
