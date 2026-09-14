use crate::core::scanner::ScanResult;
use crate::db::test_helpers::temp_db;
use crate::db::work_items::WorkItemInput;
use crate::db::work_items::WorkItemMetadata;

#[test]
fn count_issues_by_category_tallies_in_one_pass() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    fn issue(category: ScanCategory, severity: Severity, status: CheckStatus) -> CheckResult {
        CheckResult {
            check_id: "x".into(),
            category,
            title: "t".into(),
            description: "d".into(),
            status,
            severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    }

    let issues = vec![
        issue(
            ScanCategory::Security,
            Severity::Critical,
            CheckStatus::Fail,
        ),
        issue(ScanCategory::Security, Severity::High, CheckStatus::Warn),
        issue(
            ScanCategory::Security,
            Severity::Critical,
            CheckStatus::Skipped,
        ),
        issue(ScanCategory::Security, Severity::Medium, CheckStatus::Pass),
        issue(ScanCategory::Performance, Severity::Low, CheckStatus::Fail),
    ];

    let counts = super::count_issues_by_category(&issues);
    let sec = counts
        .get(&ScanCategory::Security)
        .copied()
        .unwrap_or_default();
    // total counts non-pass, non-skipped issues (Fail Critical + Warn High).
    assert_eq!(sec.total, 2);
    // Skipped checks contribute to neither failure nor pass counts,
    // matching scoring::calculator::calculate_scores.
    assert_eq!(sec.critical, 1);
    assert_eq!(sec.high, 1);
    assert_eq!(sec.medium, 0);
    assert_eq!(sec.passed, 1);

    let perf = counts
        .get(&ScanCategory::Performance)
        .copied()
        .unwrap_or_default();
    assert_eq!(perf.total, 1);
    assert_eq!(perf.low, 1);
}

fn make_scan_result(score: u32, ts: &str) -> ScanResult {
    ScanResult {
        page_signals: None,
        site_facts: None,
        url: "https://example.com".to_string(),
        mode: "full".to_string(),
        scan_type: crate::core::scanner::ScanType::Health,
        overall_score: score,
        categories: vec![],
        issues: vec![],
        detected_stack: None,
        duration_ms: 1000,
        timestamp: ts.to_string(),
    }
}

fn make_snapshot_issue(check_id: &str) -> crate::checks::CheckResult {
    crate::checks::CheckResult {
        check_id: check_id.into(),
        category: crate::checks::ScanCategory::Security,
        title: format!("Check {check_id}"),
        description: "test".into(),
        status: crate::checks::CheckStatus::Fail,
        severity: crate::checks::Severity::High,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

fn make_work_item(check_id: &str, severity: &str, scan_id: i64, project_id: i64) -> WorkItemInput {
    WorkItemInput {
        project_id,
        env_url: "https://example.com".to_string(),
        source: "web_scan".to_string(),
        signal_id: format!("web_scan:{}:https://example.com", check_id),
        check_id: check_id.to_string(),
        category: "performance".to_string(),
        severity: severity.parse().expect("valid severity"),
        title: format!("Check {}", check_id),
        description: "test".to_string(),
        detail_json: None,
        scan_ref: Some(scan_id),
        page_url: Some("https://example.com".to_string()),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    }
}

fn set_web_run_profile(
    db: &crate::db::Database,
    run_id: i64,
    requested_mode: crate::core::scan_execution::ScanExecutionMode,
    axe_enabled: bool,
    browser_ran: bool,
    axe_ran: bool,
) {
    db.execute(move |conn| {
        let (execution_id, diagnostics_json): (i64, String) = conn
            .query_row(
                "SELECT execution_id, diagnostics_json FROM scan_runs WHERE id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("stored Web run");
        let mut diagnostics: serde_json::Value =
            serde_json::from_str(&diagnostics_json).expect("run diagnostics");
        diagnostics["axeEnabled"] = serde_json::json!(axe_enabled);
        diagnostics["browserRan"] = serde_json::json!(browser_ran);
        diagnostics["axeRan"] = serde_json::json!(axe_ran);
        conn.execute(
            "UPDATE scan_runs SET diagnostics_json = ?1, axe_enabled = ?2 WHERE id = ?3",
            rusqlite::params![
                serde_json::to_string(&diagnostics).expect("serialize diagnostics"),
                i64::from(axe_enabled),
                run_id,
            ],
        )
        .expect("update Web run profile");
        conn.execute(
            "UPDATE scan_executions
                SET requested_mode = ?1,
                    trigger = 'scheduled'
              WHERE id = ?2",
            rusqlite::params![requested_mode.as_str(), execution_id],
        )
        .expect("update execution mode");
    })
    .expect("database worker");
}

fn set_execution_trigger_for_run(
    db: &crate::db::Database,
    run_id: i64,
    trigger: crate::core::scan_execution::ScanTrigger,
) {
    db.execute(move |conn| {
        conn.execute(
            "UPDATE scan_executions
                SET trigger = ?1
              WHERE id = (SELECT execution_id FROM scan_runs WHERE id = ?2)",
            rusqlite::params![trigger.as_str(), run_id],
        )
        .expect("update execution trigger");
    })
    .expect("database worker");
}

fn web_run_profile(
    axe_enabled: bool,
    browser_ran: bool,
    axe_ran: bool,
) -> crate::db::WebRunComparisonProfile {
    crate::db::WebRunComparisonProfile {
        axe_enabled,
        browser_ran,
        axe_ran,
    }
}

#[test]
fn latest_web_baseline_requires_the_same_execution_profile() {
    use crate::core::normalized_scan::ScanRunKind;
    use crate::core::scan_execution::ScanExecutionMode;
    use crate::core::scanner::ScanType;

    let db = temp_db();
    let url = "https://profile-baseline.example.com";
    let site_id = db.get_or_create_site(url).expect("site");
    let project_id = db
        .upsert_project("Profile baseline", "/tmp/sitecmd-profile-baseline", None)
        .expect("project");
    db.add_environment(project_id, url, "Production", "production", "manual")
        .expect("environment");

    let health_run = db
        .save_scan(site_id, &make_scan_result(91, "2026-08-28T12:00:00Z"))
        .expect("Health scan");
    set_web_run_profile(&db, health_run, ScanExecutionMode::Web, false, true, false);

    let full_run = db
        .save_scan(site_id, &make_scan_result(72, "2026-08-29T12:00:00Z"))
        .expect("Full scan");
    set_web_run_profile(&db, full_run, ScanExecutionMode::Full, true, true, true);

    let transport_only_full_run = db
        .save_scan(site_id, &make_scan_result(60, "2026-08-30T12:00:00Z"))
        .expect("transport-only Full scan");
    set_web_run_profile(
        &db,
        transport_only_full_run,
        ScanExecutionMode::Full,
        true,
        false,
        false,
    );

    let scope = vec![url.to_string()];
    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            ScanType::Health,
            ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &scope,
        )
        .expect("Health baseline"),
        Some((health_run, 91, 0))
    );
    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            ScanType::Health,
            ScanExecutionMode::Full,
            web_run_profile(true, true, true),
            &scope,
        )
        .expect("Full baseline"),
        Some((full_run, 72, 0))
    );
    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            ScanType::Health,
            ScanExecutionMode::Full,
            web_run_profile(false, true, false),
            &scope,
        )
        .expect("mismatched axe profile"),
        None
    );
}

#[test]
fn latest_web_baseline_ignores_newer_manual_executions() {
    use crate::core::normalized_scan::ScanRunKind;
    use crate::core::scan_execution::{ScanExecutionMode, ScanTrigger};
    use crate::core::scanner::ScanType;

    let db = temp_db();
    let url = "https://scheduled-baseline.example.com";
    let site_id = db.get_or_create_site(url).expect("site");
    let project_id = db
        .upsert_project(
            "Scheduled baseline",
            "/tmp/sitecmd-scheduled-baseline",
            None,
        )
        .expect("project");
    db.add_environment(project_id, url, "Production", "production", "manual")
        .expect("environment");

    let scheduled_run = db
        .save_scan(site_id, &make_scan_result(91, "2026-08-28T12:00:00Z"))
        .expect("scheduled scan");
    set_web_run_profile(
        &db,
        scheduled_run,
        ScanExecutionMode::Web,
        false,
        true,
        false,
    );
    set_execution_trigger_for_run(&db, scheduled_run, ScanTrigger::Scheduled);

    let manual_run = db
        .save_scan(site_id, &make_scan_result(42, "2026-08-29T12:00:00Z"))
        .expect("manual scan");
    set_web_run_profile(&db, manual_run, ScanExecutionMode::Web, false, true, false);
    set_execution_trigger_for_run(&db, manual_run, ScanTrigger::Manual);

    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            ScanType::Health,
            ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &[url.to_string()],
        )
        .expect("scheduled baseline"),
        Some((scheduled_run, 91, 0))
    );
}

#[test]
fn latest_code_baseline_ignores_newer_manual_executions() {
    use crate::core::code_scan::CodeScanReport;
    use crate::core::scan_execution::{ScanExecutionMode, ScanTrigger};

    let db = temp_db();
    let url = "https://scheduled-code-baseline.example.com";
    let project_path = "/tmp/sitecmd-scheduled-code-baseline";
    let project_id = db
        .upsert_project("Scheduled code baseline", project_path, None)
        .expect("project");
    db.add_environment(project_id, url, "Production", "production", "manual")
        .expect("environment");
    let report = |checked_at: &str| CodeScanReport {
        skipped_scopes: Default::default(),
        checked_at: checked_at.to_string(),
        framework: None,
        issue_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        issues: Vec::new(),
    };

    let scheduled_run = db
        .save_code_scan(
            project_id,
            Some(url.to_string()),
            project_path.to_string(),
            &report("2026-08-28T12:00:00Z"),
            10,
        )
        .expect("scheduled code scan");
    set_execution_trigger_for_run(&db, scheduled_run, ScanTrigger::Scheduled);

    let manual_run = db
        .save_code_scan(
            project_id,
            Some(url.to_string()),
            project_path.to_string(),
            &report("2026-08-29T12:00:00Z"),
            10,
        )
        .expect("manual code scan");
    set_execution_trigger_for_run(&db, manual_run, ScanTrigger::Manual);

    let baseline = db
        .get_latest_scheduled_code_run_baseline_for_project(
            project_id,
            url,
            ScanExecutionMode::Code,
        )
        .expect("scheduled code baseline")
        .expect("scheduled code run");
    assert_eq!(baseline.id, scheduled_run);
}

#[test]
fn score_comparison_rejects_changed_runtime_provenance() {
    let db = temp_db();
    let url = "https://runtime-baseline.example.com";
    let site_id = db.get_or_create_site(url).expect("site");
    let before = db
        .save_scan(site_id, &make_scan_result(91, "2026-08-28T12:00:00Z"))
        .expect("before scan");
    let after = db
        .save_scan(site_id, &make_scan_result(91, "2026-08-29T12:00:00Z"))
        .expect("after scan");

    assert!(db
        .scan_runs_have_matching_score_provenance(before, after)
        .expect("matching provenance"));

    db.execute(move |conn| {
        let profile_json: String = conn
            .query_row(
                "SELECT execution_profile_json FROM scan_runs WHERE id = ?1",
                [after],
                |row| row.get(0),
            )
            .expect("stored profile");
        let mut profile: serde_json::Value =
            serde_json::from_str(&profile_json).expect("profile json");
        profile["browser_engine"] = serde_json::json!("webkit");
        profile["browser_build"] = serde_json::json!("changed-build");
        profile["layers_run"] = serde_json::json!(["transport", "browser"]);
        conn.execute(
            "UPDATE scan_runs SET execution_profile_json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::to_string(&profile).expect("serialize profile"),
                after
            ],
        )
        .expect("change runtime profile");
    })
    .expect("database worker");

    assert!(!db
        .scan_runs_have_matching_score_provenance(before, after)
        .expect("changed provenance"));
}

#[test]
fn latest_web_baseline_preserves_trailing_slash_route_identity() {
    use crate::core::normalized_scan::ScanRunKind;
    use crate::core::scan_execution::ScanExecutionMode;
    use crate::core::scanner::ScanType;

    let db = temp_db();
    let url = "https://slash-baseline.example.com/checkout";
    let site_id = db.get_or_create_site(url).expect("site");
    let project_id = db
        .upsert_project("Slash baseline", "/tmp/sitecmd-slash-baseline", None)
        .expect("project");
    db.add_environment(project_id, url, "Production", "production", "manual")
        .expect("environment");

    let run_id = db
        .save_scan(site_id, &make_scan_result(88, "2026-08-28T12:00:00Z"))
        .expect("Web scan");
    set_web_run_profile(&db, run_id, ScanExecutionMode::Web, false, true, false);

    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            ScanType::Health,
            ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &["https://slash-baseline.example.com/checkout/".into()],
        )
        .expect("baseline lookup"),
        None
    );
}

#[test]
fn latest_multi_page_baseline_groups_critical_findings_per_page() {
    use crate::checks::Severity;
    use crate::core::normalized_scan::ScanRunKind;
    use crate::core::scan_execution::ScanExecutionMode;
    use crate::core::scanner::ScanType;

    let db = temp_db();
    let url = "https://count-baseline.example.com";
    let pricing_url = "https://count-baseline.example.com/pricing";
    let site_id = db.get_or_create_site(url).expect("site");
    let project_id = db
        .upsert_project("Count baseline", "/tmp/sitecmd-count-baseline", None)
        .expect("project");
    db.add_environment(project_id, url, "Production", "production", "manual")
        .expect("environment");

    let session_id = db.create_scan_session(site_id, 2, false).expect("session");
    let mut first_page = make_scan_result(80, "2026-08-28T12:00:00Z");
    let mut critical = make_snapshot_issue("shared-critical");
    critical.severity = Severity::Critical;
    first_page.issues = vec![critical];
    let first_page_run = db
        .save_scan_with_session(site_id, session_id, url, &first_page)
        .expect("first page");
    db.save_scan_with_session(
        site_id,
        session_id,
        pricing_url,
        &make_scan_result(80, "2026-08-28T12:00:01Z"),
    )
    .expect("second page");
    db.complete_scan_session(session_id, Some(80), 500)
        .expect("session score");
    set_web_run_profile(&db, session_id, ScanExecutionMode::Web, false, true, false);

    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO scan_findings (
                run_id, ordinal, occurrence_id, source, canonical_check_id,
                producer_check_id, category, producer_category, domain, verdict,
                severity, confidence, confidence_reason, title, description,
                fix_prompt, producer_fix_prompt, manual_fix, why_it_matters,
                verification_hint, raw_data, detail_json, location_kind,
                page_url, relative_path, line
             )
             SELECT run_id, ordinal + 1, occurrence_id || ':second', source,
                    canonical_check_id, producer_check_id, category,
                    producer_category, domain, verdict, severity, confidence,
                    confidence_reason, title, description, fix_prompt,
                    producer_fix_prompt, manual_fix, why_it_matters,
                    verification_hint, raw_data, detail_json, location_kind,
                    page_url, relative_path, line
               FROM scan_findings
              WHERE run_id = ?1
              LIMIT 1",
            [first_page_run],
        )
        .expect("duplicate producer finding");
        conn.execute(
            "UPDATE scan_runs SET issues_total = 2, issues_critical = 2 WHERE id = ?1",
            [first_page_run],
        )
        .expect("raw run counters");
    })
    .expect("database worker");

    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::MultiParent,
            ScanType::Health,
            ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &[url.into(), pricing_url.into()],
        )
        .expect("multi-page baseline"),
        Some((session_id, 80, 1))
    );
}

#[test]
fn latest_web_baseline_keeps_single_and_multi_runs_separate() {
    use crate::checks::Severity;
    use crate::core::normalized_scan::ScanRunKind;

    let db = temp_db();
    let url = "https://baseline.example.com";
    let site_id = db.get_or_create_site(url).expect("site");
    let project_id = db
        .upsert_project("Baseline", "/tmp/sitecmd-baseline", None)
        .expect("project");
    db.add_environment(project_id, url, "Production", "production", "manual")
        .expect("environment");

    let mut single = make_scan_result(82, "2026-08-28T12:00:00Z");
    let mut single_issue = make_snapshot_issue("single-critical");
    single_issue.severity = Severity::Critical;
    single.issues = vec![single_issue];
    let single_id = db.save_scan(site_id, &single).expect("single scan");
    set_web_run_profile(
        &db,
        single_id,
        crate::core::scan_execution::ScanExecutionMode::Web,
        false,
        true,
        false,
    );

    let session_id = db.create_scan_session(site_id, 2, false).expect("session");
    let mut first_page = make_scan_result(70, "2026-08-29T12:00:00Z");
    let mut page_issue = make_snapshot_issue("page-critical");
    page_issue.severity = Severity::Critical;
    first_page.issues = vec![page_issue];
    db.save_scan_with_session(site_id, session_id, url, &first_page)
        .expect("first page");
    db.save_scan_with_session(
        site_id,
        session_id,
        "https://baseline.example.com/pricing",
        &make_scan_result(64, "2026-08-29T12:00:01Z"),
    )
    .expect("second page");
    db.complete_scan_session(session_id, Some(67), 500)
        .expect("session score");
    let mut first_site_issue = make_snapshot_issue("site-critical-one");
    first_site_issue.severity = Severity::Critical;
    let mut second_site_issue = make_snapshot_issue("site-critical-two");
    second_site_issue.severity = Severity::Critical;
    db.save_session_issue_snapshot(session_id, &[first_site_issue, second_site_issue])
        .expect("session findings");
    set_web_run_profile(
        &db,
        session_id,
        crate::core::scan_execution::ScanExecutionMode::Web,
        false,
        true,
        false,
    );

    let mut security = make_scan_result(55, "2026-08-30T12:00:00Z");
    security.scan_type = crate::core::scanner::ScanType::Security;
    let security_id = db.save_scan(site_id, &security).expect("security scan");
    set_web_run_profile(
        &db,
        security_id,
        crate::core::scan_execution::ScanExecutionMode::Web,
        false,
        false,
        false,
    );

    let single_scope = vec![url.to_string()];
    let multi_scope = vec![
        url.to_string(),
        "https://baseline.example.com/pricing".to_string(),
    ];

    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            crate::core::scanner::ScanType::Health,
            crate::core::scan_execution::ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &single_scope,
        )
        .expect("single baseline"),
        Some((single_id, 82, 1))
    );
    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::Single,
            crate::core::scanner::ScanType::Security,
            crate::core::scan_execution::ScanExecutionMode::Web,
            web_run_profile(false, false, false),
            &single_scope,
        )
        .expect("security baseline"),
        Some((security_id, 55, 0))
    );
    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::MultiParent,
            crate::core::scanner::ScanType::Health,
            crate::core::scan_execution::ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &multi_scope,
        )
        .expect("multi baseline"),
        Some((session_id, 67, 3))
    );
    assert_eq!(
        db.get_latest_web_run_baseline_for_project(
            project_id,
            url,
            ScanRunKind::MultiParent,
            crate::core::scanner::ScanType::Health,
            crate::core::scan_execution::ScanExecutionMode::Web,
            web_run_profile(false, true, false),
            &[
                url.to_string(),
                "https://baseline.example.com/contact".to_string(),
            ],
        )
        .expect("mismatched scope"),
        None
    );
}

// Each immutable scan snapshot retains the guidance emitted in that scan;
// a later scan gets its refreshed copy without rewriting history.
#[test]
fn get_scan_detail_round_trips_guidance_per_immutable_snapshot() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    let db = temp_db();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let original = CheckResult {
        check_id: "security.csp".into(),
        category: ScanCategory::Security,
        severity: Severity::High,
        status: CheckStatus::Fail,
        title: "Check security.csp".into(),
        description: "test".into(),
        fix_prompt: Some("Add a Content-Security-Policy header.".into()),
        manual_fix: Some("Set the CSP header in your server config.".into()),
        raw_data: None,
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: Some("Without CSP, injected scripts run unrestricted.".into()),
    };
    let mut first_scan = make_scan_result(80, "2025-01-01T00:00:00Z");
    first_scan.issues = vec![original];
    let scan_id = db.save_scan(site_id, &first_scan).unwrap();

    let detail = db.get_scan_detail(scan_id).unwrap().expect("scan detail");
    assert_eq!(detail.issues.len(), 1);
    let issue = &detail.issues[0];
    // Value-pins the columns adjacent to the guidance params so a
    // positional transposition anywhere in the upsert row fails here.
    assert_eq!(issue.title, "Check security.csp");
    assert_eq!(issue.description, "test");
    assert_eq!(
        issue.fix_prompt.as_deref(),
        Some("Add a Content-Security-Policy header.")
    );
    assert_eq!(
        issue.manual_fix.as_deref(),
        Some("Set the CSP header in your server config.")
    );
    assert_eq!(
        issue.why_it_matters.as_deref(),
        Some("Without CSP, injected scripts run unrestricted.")
    );

    let mut updated = first_scan.issues[0].clone();
    updated.fix_prompt = Some("Updated fix prompt.".into());
    updated.manual_fix = Some("Updated manual fix.".into());
    updated.why_it_matters = Some("Updated why it matters.".into());
    let mut second_scan = make_scan_result(82, "2025-01-02T00:00:00Z");
    second_scan.issues = vec![updated];
    let second_id = db.save_scan(site_id, &second_scan).unwrap();

    let refreshed = db
        .get_scan_detail(second_id)
        .unwrap()
        .expect("second scan detail");
    let issue = &refreshed.issues[0];
    assert_eq!(issue.fix_prompt.as_deref(), Some("Updated fix prompt."));
    assert_eq!(issue.manual_fix.as_deref(), Some("Updated manual fix."));
    assert_eq!(
        issue.why_it_matters.as_deref(),
        Some("Updated why it matters.")
    );
    let original_again = db.get_scan_detail(scan_id).unwrap().expect("first scan");
    assert_eq!(
        original_again.issues[0].fix_prompt.as_deref(),
        Some("Add a Content-Security-Policy header.")
    );
}

#[test]
fn get_scan_detail_preserves_status_confidence_and_confidence_reason() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/test-issue-verdict", None)
        .unwrap();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let finding = CheckResult {
        check_id: "performance.third-party-script".into(),
        category: ScanCategory::Performance,
        title: "Third-party script needs review".into(),
        description: "A cross-origin script was observed.".into(),
        status: CheckStatus::Warn,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: Some("Confirm the script is necessary and measure its cost.".into()),
        raw_data: Some(serde_json::json!({"host": "cdn.example.test"})),
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: Some(
            "The static response does not establish runtime cost or business necessity.".into(),
        ),
        why_it_matters: Some("Third-party code can add latency and operational risk.".into()),
    };
    let mut scan = make_scan_result(92, "2025-01-01T00:00:00Z");
    scan.issues = vec![finding.clone()];
    let scan_id = db.save_scan(site_id, &scan).unwrap();
    let input = crate::core::work_item_projection::check_result_to_work_item_input(
        &finding,
        project_id,
        "https://example.com",
        scan_id,
        1_000,
        None,
    );
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![input],
        1_000,
    )
    .unwrap();

    let detail = db.get_scan_detail(scan_id).unwrap().expect("scan detail");
    let restored = detail.issues.first().expect("persisted finding");
    assert_eq!(restored.status, CheckStatus::Warn);
    assert_eq!(restored.confidence, IssueConfidence::NeedsReview);
    assert_eq!(restored.confidence_reason, finding.confidence_reason);
    assert_eq!(restored.raw_data, finding.raw_data);
}

#[test]
fn get_scan_detail_preserves_producer_identity_and_fix_prompt() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/test-producer-fields", None)
        .unwrap();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let finding = CheckResult {
        check_id: "security.headers.csp".into(),
        category: ScanCategory::Security,
        title: "Content Security Policy needs review".into(),
        description: "The response policy needs review.".into(),
        status: CheckStatus::Warn,
        severity: Severity::Low,
        fix_prompt: Some("Preserve this producer-authored remediation exactly.".into()),
        manual_fix: None,
        raw_data: None,
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: Some("The policy was observed but requires context.".into()),
        why_it_matters: None,
    };
    let mut scan = make_scan_result(75, "2025-01-01T00:00:00Z");
    scan.issues = vec![finding.clone()];
    let scan_id = db.save_scan(site_id, &scan).unwrap();
    let input = crate::core::work_item_projection::check_result_to_work_item_input(
        &finding,
        project_id,
        "https://example.com",
        scan_id,
        1_000,
        None,
    );
    assert_eq!(input.check_id, "security.csp");
    assert_ne!(input.fix_prompt, finding.fix_prompt);
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![input],
        1_000,
    )
    .unwrap();

    let detail = db.get_scan_detail(scan_id).unwrap().expect("scan detail");
    let restored = detail.issues.first().expect("persisted finding");
    assert_eq!(restored.check_id, finding.check_id);
    assert_eq!(restored.fix_prompt, finding.fix_prompt);
}

#[test]
fn get_scan_detail_preserves_producer_category() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/test-producer-category", None)
        .unwrap();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let finding = CheckResult {
        check_id: "config.favicon".into(),
        category: ScanCategory::Config,
        title: "Favicon configuration".into(),
        description: "The deployed favicon needs review.".into(),
        status: CheckStatus::Warn,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: Some("A default asset can still be intentional.".into()),
        why_it_matters: None,
    };
    let mut scan = make_scan_result(95, "2025-01-01T00:00:00Z");
    scan.issues = vec![finding.clone()];
    let scan_id = db.save_scan(site_id, &scan).unwrap();
    let input = crate::core::work_item_projection::check_result_to_work_item_input(
        &finding,
        project_id,
        "https://example.com",
        scan_id,
        1_000,
        None,
    );
    assert_eq!(input.category, "compliance");
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![input],
        1_000,
    )
    .unwrap();

    let detail = db.get_scan_detail(scan_id).unwrap().expect("scan detail");
    assert_eq!(detail.issues[0].category, ScanCategory::Config);
}

#[test]
fn scan_issue_snapshots_are_immutable_across_rescans_and_include_passes() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    fn finding(title: &str, status: CheckStatus) -> CheckResult {
        CheckResult {
            check_id: if status == CheckStatus::Pass {
                "seo.title"
            } else {
                "security.headers.csp"
            }
            .into(),
            category: if status == CheckStatus::Pass {
                ScanCategory::Seo
            } else {
                ScanCategory::Security
            },
            title: title.into(),
            description: format!("Description for {title}"),
            status,
            severity: if status == CheckStatus::Pass {
                Severity::Low
            } else {
                Severity::High
            },
            fix_prompt: (status != CheckStatus::Pass).then(|| format!("Producer fix for {title}")),
            manual_fix: None,
            raw_data: Some(serde_json::json!({ "title": title })),
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    }

    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/test-immutable-scan-issues", None)
        .unwrap();
    let site_id = db.get_or_create_site("https://example.com").unwrap();

    let original_fail = finding("Original CSP finding", CheckStatus::Fail);
    let original_pass = finding("Original title pass", CheckStatus::Pass);
    let mut first = make_scan_result(70, "2025-01-01T00:00:00Z");
    first.issues = vec![original_fail.clone(), original_pass.clone()];
    let first_id = db.save_scan(site_id, &first).unwrap();
    let first_work_item = crate::core::work_item_projection::check_result_to_work_item_input(
        &original_fail,
        project_id,
        "https://example.com",
        first_id,
        1_000,
        None,
    );
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![first_work_item],
        1_000,
    )
    .unwrap();

    let changed_fail = finding("Changed CSP finding", CheckStatus::Warn);
    let mut second = make_scan_result(80, "2025-01-02T00:00:00Z");
    second.issues = vec![changed_fail.clone()];
    let second_id = db.save_scan(site_id, &second).unwrap();
    let second_work_item = crate::core::work_item_projection::check_result_to_work_item_input(
        &changed_fail,
        project_id,
        "https://example.com",
        second_id,
        2_000,
        None,
    );
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![second_work_item],
        2_000,
    )
    .unwrap();

    let restored_first = db.get_scan_detail(first_id).unwrap().expect("first scan");
    assert_eq!(
        serde_json::to_value(&restored_first.issues).unwrap(),
        serde_json::to_value(&first.issues).unwrap()
    );
    let restored_second = db.get_scan_detail(second_id).unwrap().expect("second scan");
    assert_eq!(
        serde_json::to_value(&restored_second.issues).unwrap(),
        serde_json::to_value(&second.issues).unwrap()
    );
}

#[test]
fn session_scan_detail_preserves_page_url_and_all_category_scores() {
    let db = temp_db();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let session_id = db.create_scan_session(site_id, 1, false).unwrap();
    let mut scan = make_scan_result(88, "2025-01-01T00:00:00Z");
    scan.url = "https://example.com/about".into();
    scan.categories = vec![
        crate::scoring::calculator::CategoryScore {
            category: crate::checks::ScanCategory::Config,
            score: 91,
            issues_total: 1,
            issues_critical: 0,
            issues_high: 0,
            issues_medium: 0,
            issues_low: 1,
            issues_passed: 4,
        },
        crate::scoring::calculator::CategoryScore {
            category: crate::checks::ScanCategory::Polish,
            score: 73,
            issues_total: 2,
            issues_critical: 0,
            issues_high: 0,
            issues_medium: 1,
            issues_low: 1,
            issues_passed: 28,
        },
    ];
    scan.issues = vec![make_snapshot_issue("security.csp")];

    let scan_id = db
        .save_scan_with_session(site_id, session_id, "https://example.com/about", &scan)
        .unwrap();
    let restored = db.get_scan_detail(scan_id).unwrap().expect("scan detail");

    assert_eq!(restored.url, "https://example.com/about");
    assert_eq!(restored.issues.len(), 1);
    let config = restored
        .categories
        .iter()
        .find(|category| category.category == crate::checks::ScanCategory::Config)
        .expect("config score");
    let polish = restored
        .categories
        .iter()
        .find(|category| category.category == crate::checks::ScanCategory::Polish)
        .expect("polish score");
    assert_eq!(config.score, 91);
    assert_eq!(polish.score, 73);
}

#[test]
fn get_scan_detail_reports_corrupt_issue_evidence_instead_of_silently_dropping_it() {
    let db = temp_db();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let mut scan = make_scan_result(80, "2025-01-01T00:00:00Z");
    scan.issues = vec![make_snapshot_issue("security.csp")];
    let scan_id = db.save_scan(site_id, &scan).unwrap();
    db.execute(move |conn| {
        conn.execute(
            "UPDATE scan_findings SET raw_data = '{not-valid-json' WHERE run_id = ?1",
            rusqlite::params![scan_id],
        )
    })
    .unwrap()
    .unwrap();

    assert!(
        db.get_scan_detail(scan_id).is_err(),
        "corrupt persisted evidence must be reported, not returned as an empty raw_data field"
    );
}

#[test]
fn get_scan_detail_reports_corrupt_issue_enum_instead_of_reclassifying_it() {
    let db = temp_db();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let mut scan = make_scan_result(80, "2025-01-01T00:00:00Z");
    scan.issues = vec![make_snapshot_issue("security.csp")];
    let scan_id = db.save_scan(site_id, &scan).unwrap();
    db.execute(move |conn| {
        conn.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        conn.execute(
            "UPDATE scan_findings SET severity = 'urgent' WHERE run_id = ?1",
            rusqlite::params![scan_id],
        )
    })
    .unwrap()
    .unwrap();

    assert!(
        db.get_scan_detail(scan_id).is_err(),
        "an unknown severity must not silently become Medium"
    );
}

#[test]
fn get_scan_detail_reports_corrupt_detected_stack_json() {
    let db = temp_db();
    let site_id = db.get_or_create_site("https://example.com").unwrap();
    let scan_id = db
        .save_scan(site_id, &make_scan_result(80, "2025-01-01T00:00:00Z"))
        .unwrap();
    db.execute(move |conn| {
        conn.execute(
            "UPDATE scan_runs SET detected_stack = '{not-json' WHERE id = ?1",
            rusqlite::params![scan_id],
        )
    })
    .unwrap()
    .unwrap();

    assert!(
        db.get_scan_detail(scan_id).is_err(),
        "corrupt stack evidence must not silently disappear"
    );
}

#[test]
fn get_prior_scan_check_severities_returns_prior_scan_items() {
    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/test-prior-sevs", None)
        .unwrap();
    let site_id = db.get_or_create_site("https://example.com").unwrap();

    // Prior scan (older timestamp).
    let mut lcp = make_snapshot_issue("performance.lcp");
    lcp.category = crate::checks::ScanCategory::Performance;
    lcp.severity = crate::checks::Severity::Medium;
    let mut prior_result = make_scan_result(80, "2025-01-01T00:00:00Z");
    prior_result.issues = vec![lcp];
    let prior_id = db.save_scan(site_id, &prior_result).unwrap();
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![make_work_item(
            "performance.lcp",
            "medium",
            prior_id,
            project_id,
        )],
        1_000,
    )
    .unwrap();

    // Current scan (newer timestamp).
    let mut current_result = make_scan_result(70, "2025-01-02T00:00:00Z");
    let mut current_lcp = make_snapshot_issue("performance.lcp");
    current_lcp.category = crate::checks::ScanCategory::Performance;
    current_lcp.severity = crate::checks::Severity::High;
    current_result.issues = vec![current_lcp];
    let current_id = db.save_scan(site_id, &current_result).unwrap();
    // The active work item moves to the current scan. Historical severity
    // must still come from the prior immutable snapshot.
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![make_work_item(
            "performance.lcp",
            "high",
            current_id,
            project_id,
        )],
        2_000,
    )
    .unwrap();

    let prior_sevs = db
        .get_prior_scan_check_severities("https://example.com", current_id, "web_scan")
        .unwrap();

    assert_eq!(
        prior_sevs.get("performance.lcp").map(|s| s.as_str()),
        Some("medium"),
        "prior scan should have lcp at medium"
    );
    assert!(
        !prior_sevs.contains_key("performance.ttfb"),
        "ttfb was not in prior scan"
    );
}

#[test]
fn get_prior_code_scan_severities_uses_same_project_environment_snapshot() {
    use crate::checks::{IssueConfidence, Severity};
    use crate::core::code_scan::{CodeIssue, CodeScanReport};

    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/test-prior-code-sevs", None)
        .unwrap();
    let issue = |severity| CodeIssue {
        id: "ai-timeout".to_string(),
        check_id: String::new(),
        category: "ai-safety".to_string(),
        severity,
        title: "Missing timeout".to_string(),
        description: "AI request has no bounded timeout.".to_string(),
        relative_path: "app/api/chat/route.ts".to_string(),
        absolute_path: "/tmp/test-prior-code-sevs/app/api/chat/route.ts".to_string(),
        line: Some(42),
        source_excerpt: None,
        evidence: None,
        why_now: None,
        likely_fix: None,
        confidence: IssueConfidence::High,
        confidence_reason: None,
        verify_hint: None,
    };
    let report = |checked_at: &str, issue: CodeIssue| CodeScanReport {
        skipped_scopes: Default::default(),
        checked_at: checked_at.to_string(),
        framework: Some("Next.js".to_string()),
        issue_count: 1,
        critical_count: usize::from(issue.severity == Severity::Critical),
        high_count: usize::from(issue.severity == Severity::High),
        medium_count: usize::from(issue.severity == Severity::Medium),
        low_count: usize::from(issue.severity == Severity::Low),
        issues: vec![issue],
    };

    let prior = issue(Severity::Medium);
    db.save_code_scan(
        project_id,
        Some("https://example.com".to_string()),
        "/tmp/test-prior-code-sevs".to_string(),
        &report("2025-01-01T00:00:00Z", prior),
        100,
    )
    .unwrap();
    let current = issue(Severity::High);
    let current_id = db
        .save_code_scan(
            project_id,
            Some("https://example.com".to_string()),
            "/tmp/test-prior-code-sevs".to_string(),
            &report("2025-01-02T00:00:00Z", current.clone()),
            100,
        )
        .unwrap();
    let input = crate::core::work_item_projection::code_issue_to_work_item_input(
        &current,
        project_id,
        "https://example.com",
        current_id,
        2_000,
        None,
    );
    db.upsert_work_items_diff(
        "code_scan",
        project_id,
        "https://example.com",
        vec![input],
        2_000,
    )
    .unwrap();

    let prior_severities = db
        .get_prior_scan_check_severities("https://example.com", current_id, "code_scan")
        .unwrap();
    let canonical = crate::core::correlation::resolve_check_id("code_scan", "ai-timeout");
    assert_eq!(
        prior_severities.get(&canonical).map(String::as_str),
        Some("medium")
    );
}

#[test]
fn get_prior_scan_check_severities_returns_empty_when_no_prior_scan() {
    let db = temp_db();
    db.upsert_project("test", "/tmp/test-no-prior", None)
        .unwrap();
    let site_id = db.get_or_create_site("https://example.com").unwrap();

    let result = make_scan_result(80, "2025-01-01T00:00:00Z");
    let scan_id = db.save_scan(site_id, &result).unwrap();

    let prior_sevs = db
        .get_prior_scan_check_severities("https://example.com", scan_id, "web_scan")
        .unwrap();

    assert!(
        prior_sevs.is_empty(),
        "no prior scan should yield empty map"
    );
}
