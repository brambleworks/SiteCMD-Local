use super::*;
use tempfile::TempDir;

pub(super) fn run_audit(args: &AuditArgs) -> Result<AuditOutcome, String> {
    let outcome = run_with_interrupt(args, &crate::cli::engine::Interrupt::new())?;
    if let Some(path) = &args.output {
        write_report(path, &outcome.rendered)?;
    }
    Ok(outcome)
}

fn fixture_token() -> String {
    ["sk", "_live_", "abcdefghijklmnopqrstu"].concat()
}

fn report_project() -> TempDir {
    let project = TempDir::new().expect("temp project");
    std::fs::create_dir_all(project.path().join("src")).expect("source directory");
    std::fs::write(
        project.path().join("src/fixture-findings.txt"),
        format!("const key = \"{}\";\n", fixture_token()),
    )
    .expect("source fixture");
    project
}

#[test]
fn parses_every_supported_report_option() {
    let args = parse_args([
        ".".into(),
        "--format".into(),
        "review".into(),
        "--fail-on".into(),
        "high".into(),
        "--output".into(),
        "reports/sitecmd.md".into(),
    ])
    .expect("valid audit args");

    assert_eq!(args.project_path, PathBuf::from("."));
    assert_eq!(args.format, CodeScanReportFormat::Review);
    assert_eq!(args.fail_on, Some(Severity::High));
    assert_eq!(args.output, Some(PathBuf::from("reports/sitecmd.md")));
    assert!(!args.inspect_local_databases);
}

#[test]
fn local_database_inspection_requires_an_explicit_flag() {
    let args = parse_args([".".into(), "--inspect-local-databases".into()])
        .expect("valid local database opt-in");
    assert!(args.inspect_local_databases);
}

#[test]
fn mysql_inspection_fails_with_an_explicit_unsupported_engine_error() {
    let project = TempDir::new().expect("temp project");
    std::fs::write(
        project.path().join("package.json"),
        r#"{ "name": "mysql-inspection-fixture" }"#,
    )
    .expect("project manifest");
    std::fs::write(
        project.path().join(".env.local"),
        "DATABASE_URL=mysql://root:fixture@localhost:3306/example\n",
    )
    .expect("local env fixture");
    let args = AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Summary,
        fail_on: None,
        output: None,
        inspect_local_databases: true,
        baseline: None,
    };

    let error = run_audit(&args).expect_err("unsupported database inspection must fail closed");

    assert!(error.contains("DATABASE_URL from .env.local"), "{error}");
    assert!(
        error.contains("MySQL and MariaDB inspection is not supported"),
        "{error}"
    );
}

#[test]
fn rejects_missing_paths_and_unknown_formats() {
    assert!(parse_args(Vec::<String>::new())
        .expect_err("path is required")
        .contains("Missing project path"));
    assert!(parse_args([".".into(), "--format".into(), "xml".into()])
        .expect_err("format is bounded")
        .contains("Unknown format"));
}

#[test]
fn applies_the_threshold_to_the_module_finding() {
    // A failing finding can be rendered without failing the requested threshold.
    let project = report_project();
    let args = AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Json,
        fail_on: Some(Severity::Low),
        output: None,
        inspect_local_databases: false,
        baseline: None,
    };

    let outcome = run_audit(&args).expect("audit completes");
    let report: serde_json::Value =
        serde_json::from_str(&outcome.rendered).expect("valid report json");
    assert!(outcome.threshold_failed);
    assert!(report["issues"]
        .as_array()
        .is_some_and(|issues| !issues.is_empty()));
}

#[test]
fn redacts_detected_credentials_from_every_report_format() {
    // A module can include credential-shaped evidence in a report.
    let raw_token = fixture_token();
    let project = report_project();
    std::fs::rename(
        project.path().join("src/fixture-findings.txt"),
        project.path().join("src/fixture-evidence.txt"),
    )
    .unwrap();

    for format in [
        CodeScanReportFormat::Summary,
        CodeScanReportFormat::Json,
        CodeScanReportFormat::Markdown,
        CodeScanReportFormat::Review,
        CodeScanReportFormat::Github,
        CodeScanReportFormat::Sarif,
    ] {
        let args = AuditArgs {
            project_path: project.path().to_path_buf(),
            format,
            fail_on: None,
            output: None,
            inspect_local_databases: false,
            baseline: None,
        };

        let outcome = run_audit(&args).expect("audit completes");
        assert!(
            !outcome.rendered.contains(&raw_token),
            "{format:?} output exposed the detected credential"
        );
    }
}

#[test]
fn writes_the_requested_report_file() {
    let project = report_project();
    let output = project.path().join("reports/sitecmd-review.md");
    let args = AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Review,
        fail_on: None,
        output: Some(output.clone()),
        inspect_local_databases: false,
        baseline: None,
    };

    let outcome = run_audit(&args).expect("audit completes");
    assert_eq!(
        std::fs::read_to_string(output).expect("report file"),
        outcome.rendered
    );
}

#[test]
fn baseline_from_a_previous_json_report_keeps_old_findings_from_failing() {
    // An acknowledged finding can keep failing the threshold on later scans.
    let project = report_project();
    let first = run_audit(&AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Json,
        fail_on: Some(Severity::Low),
        output: None,
        inspect_local_databases: false,
        baseline: None,
    })
    .expect("first audit");
    assert!(first.threshold_failed);
    let baselines = TempDir::new().unwrap();
    let baseline_path = baselines.path().join("sitecmd-baseline.json");
    std::fs::write(&baseline_path, &first.rendered).expect("baseline file");

    let second = run_audit(&AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Json,
        fail_on: Some(Severity::Low),
        output: None,
        inspect_local_databases: false,
        baseline: Some(baseline_path),
    })
    .expect("baselined audit");
    let report: serde_json::Value = serde_json::from_str(&second.rendered).expect("json");
    assert!(
        !second.threshold_failed,
        "known findings must not fail forever"
    );
    assert_eq!(report["baselineCount"], 1);
    assert_eq!(report["issues"][0]["inBaseline"], true);
}

#[test]
fn the_json_report_omits_the_generating_machines_checkout_path() {
    // An active or suppressed finding can expose the machine path in a committed baseline,
    // or show a domain or emit category beside the rule's one category.
    let project = report_project();
    let project_dir = project.path().to_string_lossy().into_owned();
    let args = AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Json,
        fail_on: None,
        output: None,
        inspect_local_databases: false,
        baseline: None,
    };

    let active = run_audit(&args).expect("audit completes");
    let report: serde_json::Value =
        serde_json::from_str(&active.rendered).expect("valid report json");
    assert_eq!(
        report["issues"][0]["relativePath"],
        "src/fixture-findings.txt"
    );
    assert!(
        report["issues"][0].get("absolutePath").is_none(),
        "{}",
        active.rendered
    );
    assert_eq!(report["issues"][0]["category"], "reliability");
    assert!(report["issues"][0].get("domain").is_none());
    assert!(
        !active.rendered.contains(&project_dir),
        "a committed baseline would publish {project_dir}"
    );

    let sitecmd_dir = project.path().join(".sitecmd");
    std::fs::create_dir_all(&sitecmd_dir).expect("sitecmd config directory");
    std::fs::write(
        sitecmd_dir.join("config.json"),
        r#"{
  "version": 1,
  "url": "https://example.com",
  "name": "path disclosure fixture",
  "code_scan": {
    "suppressions": [
      {
        "match": {
          "rule": "code_scan.standin.rule",
          "path": "src/fixture-findings.txt"
        },
        "reason": "The credential-shaped value is an inert scanner fixture."
      }
    ]
  }
}"#,
    )
    .expect("suppression config");

    let suppressed = run_audit(&args).expect("suppressed audit completes");
    let suppressed_report: serde_json::Value =
        serde_json::from_str(&suppressed.rendered).expect("valid report json");
    assert_eq!(suppressed_report["ignoredCount"], 1);
    assert!(
        suppressed_report["ignoredFindings"][0]
            .get("absolutePath")
            .is_none(),
        "{}",
        suppressed.rendered
    );
    assert_eq!(
        suppressed_report["ignoredFindings"][0]["category"],
        "reliability"
    );
    assert!(suppressed_report["ignoredFindings"][0]
        .get("domain")
        .is_none());
    assert!(
        !suppressed.rendered.contains(&project_dir),
        "a committed baseline would publish {project_dir}"
    );
}

#[test]
fn standin_sarif_owns_rule_metadata_locations_and_fingerprints() {
    // SARIF can omit the module rule, fingerprint, or location needed by code hosting.
    let project = report_project();
    let outcome = run_audit(&AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Sarif,
        fail_on: None,
        output: None,
        inspect_local_databases: false,
        baseline: None,
    })
    .expect("sarif audit");
    let sarif: serde_json::Value = serde_json::from_str(&outcome.rendered).expect("json");
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "SiteCMD Code Scan");
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_eq!(rule["id"], "code_scan.standin.rule");
    let result = &run["results"][0];
    assert_eq!(result["ruleId"], "code_scan.standin.rule");
    assert_eq!(result["level"], "note");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/fixture-findings.txt"
    );
    assert_eq!(
        result["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
    assert!(result["partialFingerprints"]["sitecmd/v3"]
        .as_str()
        .is_some_and(|value| value.starts_with("sitecmd/v3:sha256:")));
    assert_eq!(result["baselineState"], "new");
    assert!(
        !outcome.rendered.contains(&fixture_token()),
        "SARIF must not leak the credential"
    );
}

#[test]
fn standin_sarif_keeps_suppressed_results() {
    // SARIF can silently discard suppressed results or mark them actionable.
    let project = report_project();
    let sitecmd_dir = project.path().join(".sitecmd");
    std::fs::create_dir_all(&sitecmd_dir).expect("config dir");
    std::fs::write(
        sitecmd_dir.join("config.json"),
        r#"{"version":1,"url":"https://example.com","name":"s","code_scan":{"suppressions":[{"match":{"rule":"code_scan.standin.rule","path":"src/fixture-findings.txt"},"reason":"Inert fixture."}]}}"#,
    )
    .expect("config");
    let outcome = run_audit(&AuditArgs {
        project_path: project.path().to_path_buf(),
        format: CodeScanReportFormat::Sarif,
        fail_on: Some(Severity::Low),
        output: None,
        inspect_local_databases: false,
        baseline: None,
    })
    .expect("sarif audit");
    let sarif: serde_json::Value = serde_json::from_str(&outcome.rendered).expect("json");
    assert!(!outcome.threshold_failed);
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["suppressions"][0]["kind"], "external");
    assert_eq!(
        results[0]["suppressions"][0]["justification"],
        "Configured suppression."
    );
}
