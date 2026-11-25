use super::*;
use crate::core::scan_types::{CheckResult, CheckStatus};
use sitecmd_protocol::score::CategoryScore;

fn issue(check_id: &str, severity: Severity, status: CheckStatus) -> CheckResult {
    CheckResult {
        covered: false,
        check_id: check_id.to_string(),
        category: Some(Category::Security),
        title: format!("Title for {}", check_id),
        description: String::new(),
        status,
        severity,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: crate::core::scan_types::IssueConfidence::High,
        confidence_reason: None,
        skip_reason: None,
        why_it_matters: None,
    }
}

fn scan(issues: Vec<CheckResult>) -> ScanResult {
    ScanResult {
        url: "https://example.com".to_string(),
        mode: "live".to_string(),
        scan_type: ScanType::Health,
        overall_score: 80,
        categories: vec![],
        fix_points: vec![0; issues.len()],
        issues,
        detected_stack: None,
        duration_ms: 100,
        timestamp: "2026-01-05T10:00:00Z".to_string(),
    }
}

fn args() -> ScanArgs {
    ScanArgs {
        url: None,
        fail_under: None,
        fail_on: None,
        json: false,
        timeout: None,
        categories: None,
        diff: false,
        env_name: None,
        latest: false,
        connect_origin: None,
    }
}

fn bar(category: Category, issues_high: u32) -> CategoryScore {
    CategoryScore {
        category,
        score: 90,
        issues_total: issues_high,
        issues_critical: 0,
        issues_high,
        issues_medium: 0,
        issues_low: 0,
        issues_passed: 0,
    }
}

#[test]
fn only_actionable_results_count_in_cli_output() {
    // A covered summary or passing check can enter the scan diff and issue ranking.
    let previous = scan(vec![]);
    let detail = "security.env_leak";
    let current = scan(vec![
        CheckResult {
            covered: true,
            ..issue("summary", Severity::Critical, CheckStatus::Fail)
        },
        issue(detail, Severity::Critical, CheckStatus::Fail),
        issue(
            "security.source_maps",
            Severity::Critical,
            CheckStatus::Pass,
        ),
    ]);
    assert_eq!(failing_check_ids(&current), [detail].into_iter().collect());
    assert_eq!(introduced_critical_count(&previous, &current), 1);
    let ranked = crate::cli::impact::rank_issues(&current.issues, None);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].issue.check_id, detail);
    assert_eq!(ranked[0].actionable_index, 0);
}

#[test]
fn the_category_table_prints_labels_in_order() {
    // The terminal prints a Rust variant name as a category.
    let mut result = scan(vec![]);
    result.categories = vec![
        bar(Category::Seo, 1),
        bar(Category::Email, 1),
        bar(Category::DomainHttps, 1),
    ];
    let table = category_table(&result);
    assert!(
        table.find("Domain and HTTPS").expect("domain label")
            < table.find("Email").expect("email label")
    );
    assert!(table.find("Email").expect("email label") < table.find("SEO").expect("SEO label"));
    assert!(!table.contains("DomainHttps"));
    assert!(table.contains("SEO"));
    assert!(!table.contains("Seo"));
    assert!(table.contains("1 high"));
}

#[tokio::test]
async fn filtered_diff_is_refused_before_resolving_a_target_or_reading_a_baseline() {
    // A filtered diff compares a partial scan with a complete baseline.
    let args = ScanArgs {
        categories: Some(vec![Category::Email]),
        diff: true,
        ..args()
    };
    let Err(ScanFailure::Local(error)) = run(args).await else {
        panic!("a filtered diff must be refused locally");
    };
    assert_eq!(
        error,
        "--diff cannot be combined with --categories. Run an unfiltered scan --diff to compare the same scope."
    );
}

#[test]
fn diff_gate_counts_only_new_failing_criticals() {
    let old = scan(vec![
        issue("already.failing", Severity::Critical, CheckStatus::Fail),
        issue("was.passing", Severity::Critical, CheckStatus::Pass),
    ]);
    let new = scan(vec![
        issue("already.failing", Severity::Critical, CheckStatus::Fail),
        issue("was.passing", Severity::Critical, CheckStatus::Fail),
        issue("new.but.high", Severity::High, CheckStatus::Fail),
    ]);
    // "was.passing" flipped to failing: one new critical. The pre-existing
    // critical and the new high do not count.
    assert_eq!(introduced_critical_count(&old, &new), 1);
}

#[test]
fn diff_exit_code_fails_on_a_new_critical_without_fail_under() {
    let args = ScanArgs {
        diff: true,
        ..args()
    };
    let old = scan(vec![]);
    let new = scan(vec![issue(
        "fresh.critical",
        Severity::Critical,
        CheckStatus::Fail,
    )]);
    assert_eq!(diff_exit_code(&old, &new, &args), 1);
    assert_eq!(diff_exit_code(&old, &old, &args), 0);
}

#[test]
fn diff_gate_is_zero_when_nothing_new_fails() {
    let old = scan(vec![issue("a", Severity::Critical, CheckStatus::Fail)]);
    let new = scan(vec![issue("a", Severity::Critical, CheckStatus::Warn)]);
    assert_eq!(introduced_critical_count(&old, &new), 0);
}

#[test]
fn json_mode_skips_the_file_export_entirely() {
    let dir = tempfile::tempdir().expect("tempdir");
    let result = scan(vec![]);
    let exported = export_scan_files(&result, true, None, Some(dir.path().to_path_buf()));
    assert!(exported.is_none(), "--json must not export");
    assert!(
        !dir.path().join("last-scan.json").exists(),
        "--json must leave .sitecmd/ untouched"
    );
}

#[test]
fn non_json_mode_writes_the_sitecmd_artifacts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let result = scan(vec![]);
    let exported = export_scan_files(&result, false, None, Some(dir.path().to_path_buf()));
    assert!(exported.is_some(), "normal mode exports");
    for artifact in ["last-scan.json", "issues.md", "issues.json", "rules.md"] {
        assert!(
            dir.path().join(artifact).exists(),
            "{artifact} should be written"
        );
    }
}

#[test]
fn fail_on_exits_one_for_a_failing_issue_at_or_above_the_severity() {
    let mut args = ScanArgs {
        fail_on: Some(Severity::High),
        ..args()
    };
    let failing_high = scan(vec![issue("a", Severity::High, CheckStatus::Fail)]);
    assert_eq!(check_threshold(&failing_high, &args), 1);
    let passing_high = scan(vec![issue("a", Severity::High, CheckStatus::Pass)]);
    assert_eq!(check_threshold(&passing_high, &args), 0);
    let failing_low = scan(vec![issue("b", Severity::Low, CheckStatus::Fail)]);
    assert_eq!(check_threshold(&failing_low, &args), 0);
    args.fail_on = None;
    assert_eq!(check_threshold(&failing_high, &args), 0);
}

#[test]
fn filtered_scan_preserves_the_complete_baseline() {
    // A filtered scan overwrites the full baseline consumed by diff and check.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("last-scan.json");
    let baseline = serde_json::to_string(&scan(vec![issue(
        "security.headers.csp",
        Severity::High,
        CheckStatus::Fail,
    )]))
    .unwrap();
    std::fs::write(&path, &baseline).unwrap();
    export_scan_files(
        &scan(vec![]),
        false,
        Some(&[Category::Email]),
        Some(dir.path().into()),
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), baseline);
}

#[test]
fn diff_cache_with_retired_categories_explains_how_to_refresh() {
    // Diff refuses an old category without telling the user how to refresh the cache.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("last-scan.json"), serde_json::json!({
        "url": "https://example.com", "mode": "live", "scanType": "health", "overallScore": 90,
        "categories": [{"category": "compliance", "score": 90, "issuesTotal": 1,
            "issuesCritical": 0, "issuesHigh": 1, "issuesMedium": 0, "issuesLow": 0, "issuesPassed": 0}],
        "issues": [], "durationMs": 1, "timestamp": "2026-11-14T00:00:00Z"
    }).to_string()).unwrap();
    let error = load_diff_baseline(dir.path()).unwrap_err();
    assert!(error.contains("unknown variant"));
    assert!(error.contains("last-scan.json"));
    assert!(error.contains("Run `sitecmd scan` to refresh the cache."));
}
