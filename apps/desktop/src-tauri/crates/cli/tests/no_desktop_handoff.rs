#![cfg(unix)]

use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
use cli_binary::cli_binary;

#[path = "support/handoff.rs"]
mod handoff;
use handoff::{rendered, Project};

#[path = "support/local_site.rs"]
mod local_site;

#[test]
fn connected_and_gate_help_describe_the_local_store() {
    // Bug: Help still attributes the local store and preview to the removed desktop app.
    for command in ["connected", "gate"] {
        let output = Command::new(cli_binary())
            .args([command, "--help"])
            .output()
            .unwrap();
        let help = rendered(&output);
        assert!(output.status.success(), "{help}");
        assert!(
            help.contains("Local SiteCMD SQLite database (sitecmd.db)"),
            "{help}"
        );
        assert!(!help.to_lowercase().contains("desktop"), "{help}");
        if command == "connected" {
            assert!(
                help.contains("stored-evidence submission payload"),
                "{help}"
            );
            assert!(help.contains("reserving no submission sequence"), "{help}");
        }
    }
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

#[test]
fn scan_and_diff_export_results_without_handoff() {
    let site = local_site::LocalSite::new("<html><body>Updated fixture</body></html>");
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
        site.degrade();
    }
    project.assert_no_handoff(&output);
}

#[test]
fn check_reports_only_actionable_criticals_from_the_cached_scan() {
    // A cached passing critical check can inflate the reported failure count.
    let project = Project::new();
    project.configure("http://127.0.0.1/");
    let config = project.dir.path().join(".sitecmd");
    std::fs::write(
        config.join("last-scan.json"),
        r#"{
            "url": "http://127.0.0.1/",
            "mode": "live",
            "scanType": "health",
            "overallScore": 55,
            "categories": [],
            "issues": [
                {"checkId":"security.env_leak","category":"security","title":"Environment leak","description":"Details","status":"fail","severity":"critical"},
                {"checkId":"security.source_maps","category":"security","title":"No public source maps","description":"Details","status":"pass","severity":"critical"}
            ],
            "durationMs": 100,
            "timestamp": "2099-01-01T00:00:00Z"
        }"#,
    ).unwrap();
    let output = project
        .command()
        .args(["check", "--threshold", "80"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", rendered(&output));
    assert!(rendered(&output).contains("score 55/100 is below threshold 80 (1 critical issues)"));
}
