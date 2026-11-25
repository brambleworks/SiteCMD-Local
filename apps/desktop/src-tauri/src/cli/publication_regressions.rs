use sitecmd_protocol::time::CalendarDate;

use super::*;
use crate::core::audit::audit_project;

fn fixture_date() -> CalendarDate {
    CalendarDate::new(2026, 8, 31).unwrap()
}

fn fixture() -> (tempfile::TempDir, crate::core::audit::CodeScanReport) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"fixture","dependencies":{"react":"*"}}"#,
    )
    .unwrap();
    let report = audit_project(root.path()).unwrap();
    assert!(!report.issues.is_empty());
    (root, report)
}

#[test]
fn audit_suppression_stays_active_until_utc_midnight() {
    // A second clock read after midnight can expire a suppression on its last day.
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"fixture","dependencies":{"react":"*"}}"#,
    )
    .unwrap();
    std::fs::create_dir(root.path().join(".sitecmd")).unwrap();
    std::fs::write(
        root.path().join(".sitecmd/config.json"),
        r#"{
            "version": 1,
            "url": "https://example.com",
            "name": "fixture",
            "code_scan": {"suppressions": [{
                "match": {"rule": "code_scan.standin.rule", "path": "package.json"},
                "reason": "Reviewed fixture",
                "expires": "2026-08-31"
            }]}
        }"#,
    )
    .unwrap();
    let checked_at = "2026-08-31T23:59:59.999+00:00";
    let now_ms = sitecmd_protocol::time::UtcTimestamp::parse_from_rfc3339(checked_at)
        .unwrap()
        .timestamp_millis();
    let result = run_with_output_at(
        &AuditArgs {
            project_path: root.path().into(),
            format: CodeScanReportFormat::Json,
            fail_on: None,
            output: None,
            inspect_local_databases: false,
            baseline: None,
        },
        super::super::output::OutputContext {
            terminal: false,
            ci: false,
        },
        now_ms,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&result.rendered).unwrap();

    assert_eq!(json["suppressions"][0]["state"], "active");
    assert_eq!(json["ignoredFindings"].as_array().unwrap().len(), 1);
    assert_eq!(json["checkedAt"], checked_at);
}

#[test]
fn fingerprints_survive_line_shifts_and_reject_old_baselines() {
    // Bug N3: a test-only fingerprint helper hides line shifts in real report fingerprints.
    let (root, mut report) = fixture();
    report.issues.truncate(1);
    let fingerprint = |report| {
        let audit = apply_project_suppressions(root.path(), report, fixture_date()).unwrap();
        let json: serde_json::Value = serde_json::from_str(
            &format_audit_report(
                &audit,
                sitecmd_engine_host::load().unwrap().info(),
                root.path(),
                CodeScanReportFormat::Json,
                &Default::default(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
        json["issues"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    report.issues[0].line = Some(10);
    let first = fingerprint(report.clone());
    report.issues[0].line = Some(90);
    assert_eq!(first, fingerprint(report));
    assert!(first.starts_with("sitecmd/v3:sha256:"));
    let baseline = root.path().join("old.json");
    std::fs::write(&baseline, r#"{"issues":[{"fingerprint":"sha256:abc"}]}"#).unwrap();
    assert!(read_baseline_fingerprints(&baseline)
        .unwrap_err()
        .contains("regenerate"));
}

fn local_audit_summary_with_source_controls() -> String {
    let (root, _) = fixture();
    std::fs::create_dir_all(root.path().join("app/api/signin")).unwrap();
    let marker = "PRIVATE_TERMINAL_EXCERPT";
    std::fs::write(root.path().join("app/api/signin/fixture-evidence.txt"), format!(
        "export function GET(request: Request) {{\n const returnTo = new URL(request.url).searchParams.get('returnTo');\n return Response.redirect(new URL(returnTo, request.url), 302); // {marker}\u{1b}]52;c;Y2xpcGJvYXJk\u{7}\n}}\n"
    )).unwrap();
    let report = audit_project(root.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.relative_path == "app/api/signin/fixture-evidence.txt"));
    run_with_output(
        &AuditArgs {
            project_path: root.path().into(),
            format: CodeScanReportFormat::Summary,
            fail_on: None,
            output: None,
            inspect_local_databases: false,
            baseline: None,
        },
        super::super::output::OutputContext {
            terminal: true,
            ci: false,
        },
    )
    .unwrap()
    .rendered
}

#[test]
fn interactive_summary_does_not_gain_excerpts() {
    // Bug N4: the local audit path can re-add source excerpts after report projection.
    assert!(!local_audit_summary_with_source_controls().contains("PRIVATE_TERMINAL_EXCERPT"));
}

#[test]
#[cfg(unix)]
fn terminal_summary_does_not_emit_source_control_sequences() {
    // Bug M4: repository paths and suppression values reach the terminal with raw controls.
    let (root, _) = fixture();
    let controls = "\u{1b}]52;c;Y2xpcGJvYXJk\u{7}\u{85}";
    let relative = format!("app/api/{controls}/fixture-findings.txt");
    std::fs::create_dir_all(root.path().join(&relative).parent().unwrap()).unwrap();
    std::fs::write(root.path().join(&relative), "synthetic finding").unwrap();
    std::fs::create_dir_all(root.path().join(".sitecmd")).unwrap();
    std::fs::write(root.path().join(".sitecmd/config.json"), serde_json::json!({
        "version": 1, "url": "https://example.com", "name": "fixture",
        "code_scan": {"suppressions": [
            {"match": {"path": relative, "rule": "code_scan.standin.rule"}, "reason": format!("Reviewed {controls}")},
            {"match": {"rule": "code_scan.nonexistent"}, "reason": format!("Stale {controls}")}
        ]}
    }).to_string()).unwrap();
    for suppressed in [false, true] {
        if !suppressed {
            std::fs::rename(
                root.path().join(".sitecmd/config.json"),
                root.path().join(".sitecmd/config.saved"),
            )
            .unwrap();
        } else {
            std::fs::rename(
                root.path().join(".sitecmd/config.saved"),
                root.path().join(".sitecmd/config.json"),
            )
            .unwrap();
        }
        for format in [
            CodeScanReportFormat::Summary,
            CodeScanReportFormat::Markdown,
            CodeScanReportFormat::Review,
        ] {
            let rendered = run_with_output(
                &AuditArgs {
                    project_path: root.path().into(),
                    format,
                    fail_on: None,
                    output: None,
                    inspect_local_databases: false,
                    baseline: None,
                },
                super::super::output::OutputContext {
                    terminal: true,
                    ci: false,
                },
            )
            .unwrap()
            .rendered;
            assert!(rendered.contains("fixture-findings.txt"));
            if suppressed {
                assert!(rendered.contains("Suppressions"));
            }
            if suppressed && format == CodeScanReportFormat::Summary {
                assert!(rendered.contains("Reviewed"));
                assert!(rendered.contains("Stale"));
            }
            assert!(!rendered.contains('\u{1b}'));
            assert!(!rendered.contains('\u{7}'));
            assert!(!rendered.contains('\u{85}'));
        }
    }
    let mut report = audit_project(root.path()).unwrap();
    report.checked_at = format!("Checked {controls}");
    report.framework = Some(format!("Framework {controls}"));
    for issue in &mut report.issues {
        issue.title = format!("Title {controls}");
        issue.description = format!("Description {controls}");
        issue.evidence = Some(format!("Evidence {controls}"));
        issue.why_now = Some(format!("Why now {controls}"));
        issue.likely_fix = Some(format!("Fix {controls}"));
        issue.verify_hint = Some(format!("Verify {controls}"));
    }
    let project_path = root.path().join(format!("Project {controls}"));
    let engine = sitecmd_engine_host::load().unwrap();
    for format in [CodeScanReportFormat::Markdown, CodeScanReportFormat::Review] {
        let rendered = format_report(&report, engine.info(), &project_path, format).unwrap();
        assert!(rendered.contains("Checked"));
        assert!(rendered.contains("Framework"));
        assert!(rendered.contains("Project"));
        assert!(rendered.contains("fixture-findings.txt"));
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\u{85}'));
    }
    for (matcher, expires, expected) in [
        (
            serde_json::json!({"rule": "code_scan.standin.rule"}),
            Some(controls),
            "invalid expires date",
        ),
        (
            serde_json::json!({"path": format!("{controls}[z-a]")}),
            None,
            "invalid path pattern",
        ),
    ] {
        std::fs::write(root.path().join(".sitecmd/config.json"), serde_json::json!({
            "version": 1, "url": "https://example.com", "name": "fixture",
            "code_scan": {"suppressions": [{"match": matcher, "reason": "Reviewed", "expires": expires}]}
        }).to_string()).unwrap();
        let error = run_with_output(
            &AuditArgs {
                project_path: root.path().into(),
                format: CodeScanReportFormat::Summary,
                fail_on: None,
                output: None,
                inspect_local_databases: false,
                baseline: None,
            },
            super::super::output::OutputContext {
                terminal: true,
                ci: false,
            },
        )
        .expect_err("invalid suppression");
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains('\u{1b}'));
        assert!(!error.contains('\u{7}'));
        assert!(!error.contains('\u{85}'));
    }
}

#[test]
fn published_fix_guidance_addresses_the_repository_agent() {
    // Bug M10: GitHub issue guidance assumes the reader's local checkout.
    let (_, report) = fixture();
    let engine = sitecmd_engine_host::load().unwrap();
    let published = crate::core::audit::published_issue(&report.issues[0], engine.info()).unwrap();
    assert!(!published.likely_fix.unwrap().contains("local checkout"));
}

#[test]
fn publication_clears_absolute_paths_and_keeps_suppression_identity() {
    // Bug M11: publication retains machine paths and turns fingerprint matchers into empty objects.
    let (root, report) = fixture();
    let engine = sitecmd_engine_host::load().unwrap();
    assert!(
        crate::core::audit::published_issue(&report.issues[0], engine.info())
            .unwrap()
            .absolute_path
            .is_empty()
    );
    let mut audit = apply_project_suppressions(root.path(), report, fixture_date()).unwrap();
    audit
        .suppressions
        .push(crate::cli::audit_suppressions::SuppressionStatus {
            matcher: crate::cli::audit_suppressions::CodeScanSuppressionMatch {
                fingerprint: Some(issue_fingerprint(&audit.report.issues[0])),
                ..Default::default()
            },
            reason: "Reviewed".into(),
            expires: None,
            state: SuppressionState::Active,
            matched_findings: 1,
            count: 1,
        });
    let published = published_audit(&audit, engine.info()).unwrap();
    assert!(published.suppressions[0].matcher.fingerprint.is_some());
}

#[test]
fn baseline_counts_report_growth_and_staleness_including_lineless_findings() {
    // Bug I2: line-less findings and line shifts bypass baseline count changes.
    let (root, mut report) = fixture();
    let mut finding = report.issues.remove(0);
    finding.line = None;
    let mut first = report.clone();
    first.issues = vec![finding.clone(), finding.clone()];
    let audit = apply_project_suppressions(root.path(), first, fixture_date()).unwrap();
    let baseline_path = root.path().join("baseline.json");
    std::fs::write(
        &baseline_path,
        format_audit_report(
            &audit,
            sitecmd_engine_host::load().unwrap().info(),
            root.path(),
            CodeScanReportFormat::Json,
            &Default::default(),
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let baseline = read_baseline_fingerprints(&baseline_path).unwrap();
    assert_eq!(baseline.len(), 2);
    for (count, known, stale) in [(3, 2, 0), (1, 1, 1), (0, 0, 2)] {
        let mut current = report.clone();
        current.issues = vec![finding.clone(); count];
        let audit = apply_project_suppressions(root.path(), current, fixture_date()).unwrap();
        let json: serde_json::Value = serde_json::from_str(
            &format_audit_report(
                &audit,
                sitecmd_engine_host::load().unwrap().info(),
                root.path(),
                CodeScanReportFormat::Json,
                &baseline,
                false,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["baselineCount"], known);
        assert_eq!(json["staleBaselineCount"], stale);
        if count == 3 {
            assert_eq!(json["issues"][2]["inBaseline"], false);
        }
    }
}

#[test]
fn json_fingerprint_suppression_round_trips_without_hiding_the_extra_occurrence() {
    // Bug M1: a JSON-printed fingerprint must match once in both scan and fix guard.
    let (root, mut report) = fixture();
    let mut first = report.issues.remove(0);
    first.line = Some(10);
    let mut second = first.clone();
    second.line = Some(20);
    report.issues = vec![second, first];
    let audit = apply_project_suppressions(root.path(), report.clone(), fixture_date()).unwrap();
    let json: serde_json::Value = serde_json::from_str(
        &format_audit_report(
            &audit,
            sitecmd_engine_host::load().unwrap().info(),
            root.path(),
            CodeScanReportFormat::Json,
            &Default::default(),
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let fingerprint = json["issues"][1]["fingerprint"].as_str().unwrap();
    std::fs::create_dir(root.path().join(".sitecmd")).unwrap();
    std::fs::write(root.path().join(".sitecmd/config.json"), serde_json::json!({"version":1,"url":"https://example.com","name":"test","code_scan":{"suppressions":[{"match":{"fingerprint":fingerprint},"reason":"Reviewed fixture"}]}}).to_string()).unwrap();
    for finding in &mut report.issues {
        finding.line = finding.line.map(|line| line + 100);
    }
    let audit = apply_project_suppressions(root.path(), report, fixture_date()).unwrap();
    assert_eq!(audit.ignored_findings.len(), 1);
    assert_eq!(audit.ignored_findings[0].issue.line, Some(110));
    assert_eq!(audit.report.issues[0].line, Some(120));
    assert_eq!(audit.ignored_findings[0].fingerprint, fingerprint);
}

#[test]
fn suppression_counts_detect_extra_and_missing_lineless_findings() {
    // Bug I2: suppressions must have a bounded count, including findings without lines.
    let (root, mut report) = fixture();
    let mut finding = report.issues.remove(0);
    finding.line = None;
    std::fs::create_dir(root.path().join(".sitecmd")).unwrap();
    std::fs::write(root.path().join(".sitecmd/config.json"), serde_json::json!({"version":1,"url":"https://example.com","name":"test","code_scan":{"suppressions":[{"match":{"rule":finding.check_id,"path":finding.relative_path},"count":2,"reason":"Reviewed fixtures"}]}}).to_string()).unwrap();
    for (count, ignored, stale) in [(3, 2, 0), (1, 1, 1), (0, 0, 1)] {
        report.issues = vec![finding.clone(); count];
        let audit =
            apply_project_suppressions(root.path(), report.clone(), fixture_date()).unwrap();
        assert_eq!(audit.ignored_findings.len(), ignored);
        assert_eq!(audit.report.issues.len(), count - ignored);
        assert_eq!(audit.stale_suppression_count(), stale);
    }
}

#[test]
fn persisted_metadata_keeps_ordinals_before_suppression_filtering() {
    // Bug M1: filtered desktop and MCP rows must retain their original group position.
    let (_, mut report) = fixture();
    let mut first = report.issues.remove(0);
    first.line = Some(10);
    let mut second = first.clone();
    second.line = Some(20);
    report.issues = vec![second, first];
    let batch = crate::core::normalized_scan::normalize_code_scan_with_provenance(
        &report,
        1,
        1,
        None,
        "https://example.com".into(),
        "/tmp/project".into(),
        1,
        1,
        Some(crate::core::code_provenance::CodeCheckoutProvenance::default()),
    )
    .unwrap();
    for (index, expected) in [(0, 2), (1, 1)] {
        let detail: serde_json::Value =
            serde_json::from_str(batch.findings[index].detail_json.as_deref().unwrap()).unwrap();
        assert_eq!(detail["suppressionOrdinal"], expected);
    }
}

#[test]
fn published_finding_uses_the_modules_rule_metadata() {
    // An occurrence can carry an unrelated category and check ID into public output.
    let (root, mut report) = fixture();
    let engine = sitecmd_engine_host::load().unwrap();
    let mut rules = engine.info().clone();
    let mut rule = rules.code_rules[0].clone();
    rule.id = "example-rule".into();
    rule.check_id = "code_scan.example-rule".into();
    rule.category = sitecmd_protocol::vocab::Category::Performance;
    rules.code_rules = vec![rule];
    let issue = &mut report.issues[0];
    issue.id = "example-rule:src/app.py:1".into();
    issue.check_id = "code_scan.untrusted-check".into();
    issue.category = "untrusted-category".into();
    let published = crate::core::audit::published_issue(issue, &rules).unwrap();
    assert_eq!(published.category, "performance");
    assert_eq!(published.check_id, "code_scan.example-rule");
    issue.id = "unknown-rule:src/app.py:1".into();
    assert_eq!(
        format_report(&report, &rules, root.path(), CodeScanReportFormat::Json).unwrap_err(),
        "The engine reported an unknown Code Scan rule."
    );
}

#[test]
fn audit_formatting_refuses_an_unlisted_rule() {
    // An unlisted rule can panic during publication before the report is rendered.
    let (root, report) = fixture();
    let audit = apply_project_suppressions(root.path(), report, fixture_date()).unwrap();
    let engine = sitecmd_engine_host::load().unwrap();
    let mut rules = engine.info().clone();
    rules.code_rules.clear();
    for &(format, _) in CodeScanReportFormat::ALL {
        assert_eq!(
            format_audit_report(
                &audit,
                &rules,
                root.path(),
                format,
                &Default::default(),
                false
            )
            .unwrap_err(),
            "The engine reported an unknown Code Scan rule."
        );
    }
}
