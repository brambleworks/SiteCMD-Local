#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

mod support;

struct Project {
    dir: tempfile::TempDir,
    db_path: PathBuf,
    launches: PathBuf,
}

impl Project {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sitecmd.db");
        let launches = dir.path().join("launches.log");
        drop(sitecmd_runtime::db::Database::open(db_path.clone()).unwrap());
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        for launcher in ["open", "xdg-open"] {
            let path = bin.join(launcher);
            std::fs::write(
                &path,
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$LAUNCH_LOG\"\n",
            )
            .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            dir,
            db_path,
            launches,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sitecmd_cli"));
        let mut paths = vec![self.dir.path().join("bin")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        command
            .current_dir(self.dir.path())
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("SITECMD_DB_PATH", &self.db_path)
            .env("LAUNCH_LOG", &self.launches);
        command
    }

    fn configure(&self, url: &str) {
        sitecmd_runtime::cli::write_config(
            &self.dir.path().join(".sitecmd"),
            &sitecmd_runtime::cli::CliConfig::new(url, "Fixture"),
        )
        .unwrap();
    }

    fn assert_no_handoff(&self, output: &str) {
        let launches = std::fs::read_to_string(&self.launches).unwrap_or_default();
        let db = sitecmd_runtime::db::Database::open(self.db_path.clone()).unwrap();
        let projects = db.get_projects().unwrap();
        assert!(
            launches.is_empty()
                && projects.is_empty()
                && !output.to_lowercase().contains("desktop")
                && !output.contains("sitecmd://"),
            "launches: {launches:?}; imported projects: {}; output: {output}",
            projects.len()
        );
    }
}

fn rendered(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn init_stays_local_and_preserves_project_files() {
    let project = Project::new();
    let output = project
        .command()
        .args(["init", "https://example.com", "--name", "Fixture", "--yes"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", rendered(&output));
    let config_dir = project.dir.path().join(".sitecmd");
    let config = sitecmd_runtime::cli::read_config(&config_dir).unwrap();
    assert_eq!(config.url, "https://example.com");
    assert_eq!(config.name, "Fixture");
    assert_eq!(
        std::fs::read_to_string(config_dir.join(".gitignore")).unwrap(),
        "# SiteCMD - only config.json is committed\n*\n!.gitignore\n!config.json\n"
    );
    project.assert_no_handoff(&rendered(&output));
}

#[test]
fn init_and_watch_help_exclude_handoff_and_init_rejects_removed_flag() {
    let project = Project::new();
    let mut help = String::new();
    for command in ["init", "watch"] {
        for flag in ["--help", "-h"] {
            let output = project.command().args([command, flag]).output().unwrap();
            assert!(output.status.success(), "{}", rendered(&output));
            help.push_str(&rendered(&output));
        }
    }
    let removed = project
        .command()
        .args(["init", "https://example.com", "--yes", "--no-deep-link"])
        .output()
        .unwrap();
    assert!(
        !help.to_lowercase().contains("desktop")
            && !help.contains("sitecmd://")
            && !help.contains("--no-deep-link")
            && removed.status.code() == Some(2)
            && rendered(&removed).contains("Unknown option: --no-deep-link"),
        "help: {help}; removed flag exit: {:?}; output: {}",
        removed.status.code(),
        rendered(&removed)
    );
    project.assert_no_handoff(&help);
    assert!(!project.dir.path().join(".sitecmd").exists());
}

struct RunningWatch(Child);

impl Drop for RunningWatch {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn watch_stays_local_across_scans_and_reports_score_changes() {
    let site = support::LocalSite::new();
    let project = Project::new();
    project.configure(&site.url);
    let stdout_path = project.dir.path().join("stdout.log");
    let stderr_path = project.dir.path().join("stderr.log");
    let watch = RunningWatch(
        project
            .command()
            .args(["watch", "--interval", "1"])
            .stdout(Stdio::from(std::fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    let output = loop {
        let output = std::fs::read_to_string(&stderr_path).unwrap();
        if output.contains("[#1] Baseline - Score:") {
            site.degrade();
        }
        if output.contains("[#2] Score:") {
            break output;
        }
        assert!(Instant::now() < deadline, "watch did not rescan: {output}");
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(watch);
    assert!(output.contains("Watching "), "{output}");
    assert!(
        output.contains("(interval: 1s, Ctrl+C to stop)"),
        "{output}"
    );
    assert!(project.dir.path().join(".sitecmd/last-scan.json").is_file());
    assert!(std::fs::read_to_string(stdout_path).unwrap().is_empty());
    project.assert_no_handoff(&output);
}

#[test]
fn scan_and_diff_export_results_without_handoff() {
    let site = support::LocalSite::new();
    let project = Project::new();
    project.configure(&site.url);
    let mut output = String::new();
    for args in [
        vec!["scan", "--timeout", "5"],
        vec!["scan", "--diff", "--timeout", "5"],
    ] {
        let result = project.command().args(args).output().unwrap();
        assert!(result.status.success(), "{}", rendered(&result));
        output.push_str(&rendered(&result));
        assert!(project.dir.path().join(".sitecmd/last-scan.json").is_file());
    }
    project.assert_no_handoff(&output);
}
