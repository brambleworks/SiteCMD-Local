use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
use cli_binary::cli_binary;

#[test]
fn an_invalid_worker_count_reports_the_setting_and_exits_with_two() {
    // Bug: A malformed worker setting can look like a broken engine and leave a report.
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("package.json"), "{}").unwrap();
    let report = directory.path().join("report.json");
    let output = Command::new(cli_binary())
        .arg("audit")
        .arg(directory.path())
        .args(["--format", "json", "--output"])
        .arg(&report)
        .env("SITECMD_ENGINE_WORKERS", "eight")
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Error: Code Scan audit failed: SITECMD_ENGINE_WORKERS must be a whole number.\n"
    );
    assert!(output.stdout.is_empty());
    assert!(!report.exists());
}

#[test]
fn engine_info_save_writes_the_embedded_bytes() {
    // An engine export can differ from the module loaded by the CLI.
    let directory = tempfile::tempdir().unwrap();
    let saved = directory.path().join("engine.wasm");
    let output = Command::new(cli_binary())
        .args(["engine", "info", "--json", "--save"])
        .arg(&saved)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let bytes = std::fs::read(saved).unwrap();
    assert_eq!(bytes, sitecmd_runtime::cli::engine::embedded_module());
    let info = String::from_utf8(output.stdout).unwrap();
    for member in ["version", "sha256", "abi", "imports", "exports", "load_ms"] {
        assert!(info.contains(&format!("\"{member}\":")), "{info}");
    }
    let digest = sitecmd_runtime::cli::engine::module_sha256(&bytes);
    assert!(
        info.lines()
            .any(|line| line.trim() == format!(r#""sha256": "{digest}","#)),
        "{info}"
    );
    assert!(
        info.lines().any(|line| line.trim() == r#""imports": 0,"#),
        "{info}"
    );
}

#[test]
fn engine_commands_work_with_wasmtime_backtrace_details_enabled() {
    // Bug: A developer's environment variable breaks every audit.
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("package.json"), "{}").unwrap();
    let mut info = Command::new(cli_binary());
    info.args(["engine", "info"]);
    let mut audit = Command::new(cli_binary());
    audit
        .arg("audit")
        .arg(directory.path())
        .env_remove("SITECMD_ENGINE_WORKERS");
    for mut command in [info, audit] {
        let output = command
            .env("WASMTIME_BACKTRACE_DETAILS", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{command:?}: {output:?}");
    }
}

#[cfg(unix)]
#[path = "support/interrupt.rs"]
mod interrupt;

#[cfg(unix)]
mod signals {
    use super::interrupt::{assert_interrupted, send_interrupt};
    use super::{cli_binary, Command};
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::process::{Child, Stdio};
    use std::time::Duration;

    fn audit_command(project: &Path, report: &Path) -> Command {
        let mut command = Command::new(cli_binary());
        command
            .arg("audit")
            .arg(project)
            .args(["--format", "json", "--output"])
            .arg(report);
        command
    }

    fn start_audit(project: &Path, report: &Path, marker: &'static str) -> Child {
        let mut child = audit_command(project, report)
            .env("RUST_LOG", "sitecmd_runtime=debug")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if line.contains(marker) {
                    let _ = sender.send(());
                }
            }
        });
        if let Err(error) = receiver.recv_timeout(Duration::from_secs(120)) {
            let _ = child.kill();
            child.wait().unwrap();
            panic!("the audit did not reach {marker}: {error}");
        }
        child
    }

    #[test]
    fn ctrl_c_during_audit_exits_like_today_and_writes_no_output_file() {
        // Ctrl-C during a long audit can leave the module running or write a report.
        let info = sitecmd_runtime::cli::engine::run(std::iter::once("info".into())).unwrap();
        if info.lines().next() != Some("version: standin") {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("spin.txt"), "").unwrap();
        let report = directory.path().join("report.json");
        let child = start_audit(
            directory.path(),
            &report,
            "Running Code Scan in the engine module",
        );
        send_interrupt(&child);
        assert_interrupted(child);
        assert!(!report.exists());
    }
}
