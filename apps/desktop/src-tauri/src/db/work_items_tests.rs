use super::*;
use crate::checks::Severity;
use crate::core::types_work_items::{IssueStatus, VerifiedBy};
use crate::db::test_helpers::{temp_db, TestDb};
use crate::db::IssueLifecycle;

fn test_db() -> TestDb {
    let db = temp_db();
    db.upsert_project("test", "https://example.com", None)
        .expect("insert test project");
    db
}

fn make_input(signal_id: &str, severity: &str) -> WorkItemInput {
    WorkItemInput {
        project_id: 1,
        env_url: "https://example.com".into(),
        source: "psi".into(),
        signal_id: signal_id.into(),
        check_id: "performance.render_blocking".into(),
        category: "performance".into(),
        severity: severity.parse().expect("valid severity"),
        title: "Render-blocking resources".into(),
        description: "Eliminate render-blocking resources".into(),
        detail_json: Some(r#"{"savingsMs":800}"#.into()),
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    }
}

fn make_web_input(
    env_url: &str,
    page_url: &str,
    signal_id: &str,
    check_id: &str,
    scan_ref: i64,
    observed_at: i64,
) -> WorkItemInput {
    let mut input = make_input(signal_id, "medium");
    input.env_url = env_url.to_string();
    input.source = "web_scan".to_string();
    input.check_id = check_id.to_string();
    input.page_url = Some(page_url.to_string());
    input.scan_ref = Some(scan_ref);
    input.observed_at = observed_at;
    input
}

#[test]
fn upsert_inserts_new_rows() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![
            make_input("psi:a:/home", "high"),
            make_input("psi:b:/about", "medium"),
        ],
        1_000,
    )
    .unwrap();
    let rows = db.get_active_work_items(1, None).unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn upsert_updates_last_seen_on_reobserve() {
    let db = test_db();
    let mut first = make_input("psi:a:/home", "high");
    first.observed_at = 1_000;
    let mut second = make_input("psi:a:/home", "high");
    second.observed_at = 2_000;
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![first], 1_000)
        .unwrap();
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![second], 2_000)
        .unwrap();
    let rows = db.get_active_work_items(1, None).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].last_seen_at, 2_000);
    assert_eq!(rows[0].first_seen_at, 1_000);
}

#[test]
fn single_page_diff_preserves_other_pages_in_the_shared_environment() {
    let db = test_db();
    let base_url = "https://example.com";
    let page_a = "https://example.com/a";
    let page_b = "https://example.com/b";
    db.upsert_work_items_observe_only(
        "web_scan",
        1,
        base_url,
        vec![
            make_web_input(base_url, page_a, "web_scan:old-a", "seo.old-a", 1, 1_000),
            make_web_input(base_url, page_b, "web_scan:old-b", "seo.old-b", 2, 1_000),
        ],
        1_000,
    )
    .expect("seed page findings");

    db.upsert_work_items_diff_for_page_scan("web_scan", 1, base_url, page_a, vec![], 2_000, 3)
        .expect("diff page a");

    let active = db
        .get_active_work_items(1, Some(base_url))
        .expect("active shared environment");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].signal_id, "web_scan:old-b");
}

#[test]
fn reobservation_refreshes_every_mutable_issue_content_field() {
    use crate::checks::{CheckStatus, IssueConfidence, ScanCategory};
    use crate::core::code_scan::CodeScanDomain;

    let db = test_db();
    let first = make_input("psi:a:/home", "medium");
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![first], 1_000)
        .expect("seed issue");

    let mut current = make_input("psi:a:/home", "critical");
    current.category = "security".into();
    current.title = "Current title".into();
    current.description = "Current description".into();
    current.detail_json = Some(r#"{"evidence":"current"}"#.into());
    current.page_url = Some("https://example.com/current".into());
    current.fix_prompt = Some("Current generated prompt".into());
    current.manual_fix = Some("Current manual fix".into());
    current.why_it_matters = Some("Current impact explanation".into());
    current.observed_at = 2_000;
    current.metadata = WorkItemMetadata {
        confidence: Some(IssueConfidence::Confirmed),
        domain: Some(CodeScanDomain::Security),
        relative_path: Some("src/current.ts".into()),
        line: Some(42),
        check_status: Some(CheckStatus::Warn),
        confidence_reason: Some("Current confidence reason".into()),
        producer_check_id: Some("security.current-producer".into()),
        producer_fix_prompt: Some("Current producer prompt".into()),
        producer_category: Some(ScanCategory::Security),
    };
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![current], 2_000)
        .expect("refresh issue");

    let rows = db.get_active_work_items(1, None).expect("read issue");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.category, "security");
    assert_eq!(row.severity, Severity::Critical);
    assert_eq!(row.title, "Current title");
    assert_eq!(row.description, "Current description");
    assert_eq!(
        row.detail_json.as_deref(),
        Some(r#"{"evidence":"current"}"#)
    );
    assert_eq!(row.page_url.as_deref(), Some("https://example.com/current"));
    assert_eq!(row.fix_prompt.as_deref(), Some("Current generated prompt"));
    assert_eq!(row.manual_fix.as_deref(), Some("Current manual fix"));
    assert_eq!(
        row.why_it_matters.as_deref(),
        Some("Current impact explanation")
    );
    assert_eq!(row.metadata.confidence, Some(IssueConfidence::Confirmed));
    assert_eq!(row.metadata.domain, Some(CodeScanDomain::Security));
    assert_eq!(
        row.metadata.relative_path.as_deref(),
        Some("src/current.ts")
    );
    assert_eq!(row.metadata.line, Some(42));
    assert_eq!(row.metadata.check_status, Some(CheckStatus::Warn));
    assert_eq!(
        row.metadata.confidence_reason.as_deref(),
        Some("Current confidence reason")
    );
    assert_eq!(
        row.metadata.producer_check_id.as_deref(),
        Some("security.current-producer")
    );
    assert_eq!(
        row.metadata.producer_fix_prompt.as_deref(),
        Some("Current producer prompt")
    );
    assert_eq!(row.metadata.producer_category, Some(ScanCategory::Security));
    assert_eq!(
        row.first_seen_at, 1_000,
        "content refresh must retain first seen"
    );
    assert_eq!(row.last_seen_at, 2_000);

    let groups = db
        .get_active_issue_groups(1, Some("https://example.com"), 2_000)
        .expect("group issue");
    let instance = &groups[0].instances[0];
    assert_eq!(instance.category.as_deref(), Some("security"));
    assert_eq!(instance.check_status, Some(CheckStatus::Warn));
    assert_eq!(
        instance.fix_prompt.as_deref(),
        Some("Current generated prompt")
    );
    assert_eq!(instance.manual_fix.as_deref(), Some("Current manual fix"));
    assert_eq!(
        instance.why_it_matters.as_deref(),
        Some("Current impact explanation")
    );
    assert_eq!(
        instance.confidence_reason.as_deref(),
        Some("Current confidence reason")
    );
    assert_eq!(
        instance.producer_fix_prompt.as_deref(),
        Some("Current producer prompt")
    );
    assert_eq!(instance.producer_category, Some(ScanCategory::Security));
}

#[test]
fn active_group_representative_is_highest_severity_then_latest_then_stable_id() {
    let db = test_db();
    let mut medium = make_input("psi:z:/home", "medium");
    medium.title = "Newest but medium".into();
    medium.observed_at = 3_000;

    let mut high_older = make_input("psi:z-high:/home", "high");
    high_older.title = "Older high".into();
    high_older.observed_at = 1_000;

    let mut high_a = make_input("psi:a-high:/home", "high");
    high_a.title = "Stable high representative".into();
    high_a.observed_at = 2_000;

    let mut high_b = make_input("psi:b-high:/home", "high");
    high_b.title = "Same-time high alternate".into();
    high_b.observed_at = 2_000;

    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![medium, high_older, high_b, high_a],
        3_000,
    )
    .expect("seed grouped occurrences");

    let groups = db
        .get_active_issue_groups(1, Some("https://example.com"), 3_000)
        .expect("group issues");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].severity, Severity::High);
    assert_eq!(groups[0].title, "Stable high representative");
    assert_eq!(groups[0].instances[0].signal_id, "psi:a-high:/home");
}

#[test]
fn unobserved_rows_get_resolved() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![
            make_input("psi:a:/home", "high"),
            make_input("psi:b:/about", "medium"),
        ],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:a:/home", "high")],
        2_000,
    )
    .unwrap();
    let active = db.get_active_work_items(1, None).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].signal_id, "psi:a:/home");
}

#[test]
fn observe_only_refreshes_without_resolving_absent_rows() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![
            make_input("psi:a:/home", "high"),
            make_input("psi:b:/about", "medium"),
        ],
        1_000,
    )
    .unwrap();

    // A partial tick that observed NOTHING must leave both rows active.
    db.upsert_work_items_observe_only("psi", 1, "https://example.com", vec![], 2_000)
        .unwrap();
    assert_eq!(
        db.get_active_work_items(1, None).unwrap().len(),
        2,
        "observe-only with an empty batch must not resolve anything"
    );

    // A partial tick that observed only one signal must NOT resolve the other.
    db.upsert_work_items_observe_only(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:a:/home", "high")],
        3_000,
    )
    .unwrap();
    assert_eq!(
        db.get_active_work_items(1, None).unwrap().len(),
        2,
        "observe-only must not resolve the unobserved signal"
    );

    // Contrast: a COMPLETE poll (diff) observing only one signal resolves the other.
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:a:/home", "high")],
        4_000,
    )
    .unwrap();
    let active = db.get_active_work_items(1, None).unwrap();
    assert_eq!(active.len(), 1, "a complete poll resolves absent signals");
    assert_eq!(active[0].signal_id, "psi:a:/home");
}

#[test]
fn resolving_unobserved_rows_handles_large_observed_batches() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:stale:/home", "high")],
        1_000,
    )
    .unwrap();

    let observed = (0..1_100)
        .map(|index| make_input(&format!("psi:observed:{index}"), "medium"))
        .collect::<Vec<_>>();
    db.upsert_work_items_diff("psi", 1, "https://example.com", observed, 2_000)
        .unwrap();

    let active = db
        .get_active_work_items(1, Some("https://example.com"))
        .unwrap();
    assert_eq!(active.len(), 1_100);
    assert!(active
        .iter()
        .all(|item| item.signal_id != "psi:stale:/home"));
}

#[test]
fn resolved_signal_reappearing_inserts_new_row() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:a:/home", "high")],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![], 2_000)
        .unwrap();
    let mut recurrence = make_input("psi:a:/home", "high");
    recurrence.observed_at = 3_000;
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![recurrence], 3_000)
        .unwrap();
    let active = db.get_active_work_items(1, None).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(
        active[0].first_seen_at, 3_000,
        "new row after recurrence has fresh first_seen_at"
    );
}

#[test]
fn upsert_work_items_persists_fix_prompt() {
    let db = test_db();
    let project_id: i64 = 1;

    let input = WorkItemInput {
        project_id,
        env_url: "https://example.com".to_string(),
        source: "web_scan".to_string(),
        signal_id: "web_scan:security.csp:https://example.com".to_string(),
        check_id: "security.csp".to_string(),
        category: "security".to_string(),
        severity: Severity::High,
        title: "Missing CSP".to_string(),
        description: "Content-Security-Policy header is not set".to_string(),
        detail_json: None,
        scan_ref: Some(1),
        page_url: Some("https://example.com".to_string()),
        fix_prompt: Some("Add a Content-Security-Policy header to your responses.".to_string()),
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![input],
        1_000,
    )
    .unwrap();

    let rows = db
        .get_active_work_items(project_id, Some("https://example.com"))
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].fix_prompt.as_deref(),
        Some("Add a Content-Security-Policy header to your responses."),
    );
}

#[test]
fn active_work_item_idents_returns_check_id_source_for_active_rows_only() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![
            make_input("psi:a:/home", "high"),
            make_input("psi:b:/about", "medium"),
        ],
        1_000,
    )
    .unwrap();
    // Re-observe without psi:b so it diff-resolves; only psi:a stays active.
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:a:/home", "high")],
        2_000,
    )
    .unwrap();

    let idents = db.get_active_work_item_idents(1, None).unwrap();
    assert_eq!(idents.len(), 1, "resolved rows must be excluded");
    assert_eq!(
        idents[0],
        ("performance.render_blocking".to_string(), "psi".to_string()),
    );
}

// Issue history aggregates lifecycle timestamps and active environments project-wide.
#[test]
fn issue_check_memory_aggregates_lifecycle_across_environments() {
    let db = test_db();

    // first_seen/last_seen come from each item's observed_at; the call's
    // observed_at drives diff-resolution.
    let mut prod_first = make_input("psi:prod", "high");
    prod_first.observed_at = 1_000;
    let mut prod_again = make_input("psi:prod", "high");
    prod_again.observed_at = 3_000;
    let mut staging = make_input("psi:stg", "high");
    staging.env_url = "https://staging.example.com".into();
    staging.observed_at = 1_500;

    // Prod: first seen at 1000, still failing as of 3000 (stays active).
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![prod_first], 1_000)
        .unwrap();
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![prod_again], 3_000)
        .unwrap();

    // Staging: seen at 1500, then resolved at 2500 (diff-resolve via empty observe).
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://staging.example.com",
        vec![staging],
        1_500,
    )
    .unwrap();
    db.upsert_work_items_diff("psi", 1, "https://staging.example.com", vec![], 2_500)
        .unwrap();

    let memory = db
        .get_issue_check_memory(1, "performance.render_blocking")
        .expect("memory");

    assert_eq!(
        memory.first_seen,
        Some(1_000),
        "earliest first_seen across envs"
    );
    assert_eq!(
        memory.last_failed,
        Some(3_000),
        "latest last_seen across envs"
    );
    assert_eq!(memory.last_verified, Some(2_500), "staging resolution time");
    assert_eq!(
        memory.affected_env_urls.len(),
        1,
        "only prod is still active"
    );
    assert!(memory.affected_env_urls[0].contains("example.com"));
    assert!(!memory.affected_env_urls[0].contains("staging"));
}
#[test]
fn upsert_normalizes_env_url_on_insert_so_diff_resolution_matches() {
    let db = test_db();
    let mut input = make_input("psi:ghost:/home", "high");
    input.env_url = "https://Example.com/".into();
    db.upsert_work_items_diff("psi", 1, "https://Example.com/", vec![input], 1_000)
        .unwrap();

    let active = db
        .get_active_work_items(1, Some("https://example.com"))
        .unwrap();
    assert_eq!(active.len(), 1, "insert must land under the normalized key");

    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![], 2_000)
        .unwrap();
    let active = db
        .get_active_work_items(1, Some("https://example.com"))
        .unwrap();
    assert!(
        active.is_empty(),
        "row inserted under a raw URL must be resolvable: {active:?}"
    );
}

// Re-observation contract: verified regresses, ignored returns as new, and
// blocked remains suppressed across scans.
#[test]
fn reobservation_reopens_ignored_regresses_verified_and_preserves_blocked() {
    use crate::scoring::calculator::compute_current_score;

    let db = test_db();
    // One issue marked fixed, one ignored until the next scan, and one blocked
    // until an explicit restore.
    let fixed = make_input("psi:render:1", "high");
    let mut ignored = make_input("psi:lcp:1", "medium");
    ignored.check_id = "performance.lcp".into();
    let mut blocked = make_input("psi:cls:1", "low");
    blocked.check_id = "performance.cls".into();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![fixed.clone(), ignored.clone(), blocked.clone()],
        1_000,
    )
    .expect("seed items");

    db.set_issue_group_state(
        1,
        "https://example.com",
        "performance.render_blocking",
        IssueLifecycle::Verified {
            by: VerifiedBy::LocalScan,
        },
        2_000,
    )
    .expect("mark fixed");
    db.set_issue_group_state(
        1,
        "https://example.com",
        "performance.lcp",
        IssueLifecycle::Ignored,
        2_000,
    )
    .expect("ignore");
    db.set_issue_group_state(
        1,
        "https://example.com",
        "performance.cls",
        IssueLifecycle::Blocked {
            reason: Some("accepted exception".to_string()),
        },
        2_000,
    )
    .expect("block");

    let groups = db
        .get_active_issue_groups(1, Some("https://example.com"), 3_000)
        .expect("groups while suppressed");
    let score = compute_current_score(&groups, 3_000);
    assert_eq!(
        score.overall, 100.0,
        "verified, ignored, and blocked issues must not penalize while suppressed"
    );

    // The next scan still observes all three issues.
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![fixed, ignored, blocked],
        4_000,
    )
    .expect("re-observe");

    let state = db
        .get_issue_state(
            1,
            Some("https://example.com"),
            "performance.render_blocking",
        )
        .expect("get state")
        .expect("state row");
    assert_eq!(
        state.0,
        IssueStatus::Regressed,
        "a re-observed verified issue must flip to regressed"
    );
    assert_eq!(
        state.3, None,
        "the prover is cleared with the status; a regressed row is not verified by anyone"
    );

    let ignored_state = db
        .get_issue_state(1, Some("https://example.com"), "performance.lcp")
        .expect("get ignored state")
        .expect("ignored row");
    assert_eq!(
        ignored_state.0,
        IssueStatus::New,
        "ignored is temporary and must return on the next observation"
    );

    let blocked_state = db
        .get_issue_state(1, Some("https://example.com"), "performance.cls")
        .expect("get blocked state")
        .expect("blocked row");
    assert_eq!(
        blocked_state.0,
        IssueStatus::Blocked,
        "blocked must remain suppressed across future scans"
    );

    let inactive = db
        .get_inactive_check_ids(1, Some("https://example.com"), 5_000)
        .expect("inactive ids");
    assert_eq!(
        inactive,
        vec!["performance.cls".to_string()],
        "only the blocked issue stays hidden after re-observation"
    );

    let groups = db
        .get_active_issue_groups(1, Some("https://example.com"), 5_000)
        .expect("groups after regression");
    let score = compute_current_score(&groups, 5_000);
    assert!(
        score.overall < 100.0,
        "the regressed and re-opened issues must penalize the score again, got {}",
        score.overall
    );
    assert_eq!(score.high_count, 1);
    assert_eq!(score.medium_count, 1);
}

// Reobserved user-claimed fixes return to active without becoming regressions.
#[test]
fn a_claimed_fix_that_is_reobserved_returns_to_active_not_regressed() {
    let db = test_db();
    let item = make_input("psi:render:1", "high");
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![item.clone()], 1_000)
        .expect("seed item");
    db.set_issue_group_state(
        1,
        "https://example.com",
        "performance.render_blocking",
        IssueLifecycle::Verified {
            by: VerifiedBy::UserClaim,
        },
        2_000,
    )
    .expect("user marks it fixed");

    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![item], 3_000)
        .expect("the issue is observed again");

    let state = db
        .get_issue_state(
            1,
            Some("https://example.com"),
            "performance.render_blocking",
        )
        .expect("get state")
        .expect("state row");
    assert_eq!(state.0, IssueStatus::New);
    assert_eq!(state.3, None, "the claim did not survive the observation");
}

// The inverse case: when the re-scan comes back clean, verified stays
// verified - the flip only fires for check_ids the scan actually observed.
#[test]
fn verified_issue_not_reobserved_stays_verified() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:render:1", "high")],
        1_000,
    )
    .expect("seed item");
    db.set_issue_group_state(
        1,
        "https://example.com",
        "performance.render_blocking",
        IssueLifecycle::Verified {
            by: VerifiedBy::LocalScan,
        },
        2_000,
    )
    .expect("mark fixed");

    // The next scan for this source finds nothing.
    db.upsert_work_items_diff("psi", 1, "https://example.com", vec![], 3_000)
        .expect("clean re-scan");

    let state = db
        .get_issue_state(
            1,
            Some("https://example.com"),
            "performance.render_blocking",
        )
        .expect("get state")
        .expect("state row");
    assert_eq!(
        state.0,
        IssueStatus::Verified,
        "a fix confirmed by the scan must stay verified"
    );
}

#[test]
fn upsert_writes_promoted_columns_matching_the_code_issue_blob() {
    use crate::checks::IssueConfidence;
    use crate::core::code_scan::{code_issue_domain, CodeIssue};

    let db = test_db();
    let mut issue = CodeIssue {
        check_id: String::new(),
        id: "sql-injection".into(),
        category: "security".into(),
        severity: Severity::Critical,
        title: "SQL injection".into(),
        description: "d".into(),
        relative_path: "src/db.ts".into(),
        absolute_path: "/tmp/src/db.ts".into(),
        line: Some(12),
        source_excerpt: None,
        evidence: None,
        why_now: None,
        likely_fix: None,
        confidence: IssueConfidence::Confirmed,
        confidence_reason: None,
        verify_hint: None,
    };
    let input = crate::core::work_item_projection::code_issue_to_work_item_input(
        &issue,
        1,
        "https://example.com",
        7,
        1_000,
        None,
    );
    db.upsert_work_items_diff("code_scan", 1, "https://example.com", vec![input], 1_000)
        .expect("insert upsert");

    let row = &db.get_active_work_items(1, None).expect("read")[0];
    let blob: CodeIssue =
        serde_json::from_str(row.detail_json.as_deref().expect("blob")).expect("parse blob");
    assert_eq!(row.metadata.confidence, Some(blob.confidence));
    assert_eq!(row.metadata.domain, Some(code_issue_domain(&blob)));
    assert_eq!(
        row.metadata.relative_path.as_deref(),
        Some(blob.relative_path.as_str())
    );
    assert_eq!(row.metadata.line, blob.line);
    assert_eq!(row.metadata.confidence, Some(IssueConfidence::Confirmed));

    // Re-observation refreshes the columns together with the blob.
    issue.confidence = IssueConfidence::NeedsReview;
    let updated = crate::core::work_item_projection::code_issue_to_work_item_input(
        &issue,
        1,
        "https://example.com",
        8,
        2_000,
        None,
    );
    db.upsert_work_items_diff("code_scan", 1, "https://example.com", vec![updated], 2_000)
        .expect("update upsert");
    let row = &db.get_active_work_items(1, None).expect("re-read")[0];
    let blob: CodeIssue =
        serde_json::from_str(row.detail_json.as_deref().expect("blob")).expect("parse blob");
    assert_eq!(row.metadata.confidence, Some(IssueConfidence::NeedsReview));
    assert_eq!(row.metadata.confidence, Some(blob.confidence));
}

#[test]
fn web_upsert_populates_confidence_column_the_blob_never_carried() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory};

    let db = test_db();
    let cr = CheckResult {
        check_id: "security.csp".into(),
        category: ScanCategory::Security,
        status: CheckStatus::Fail,
        severity: Severity::High,
        title: "CSP missing".into(),
        description: "d".into(),
        raw_data: Some(serde_json::json!({"header": null})),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: None,
    };
    let input = crate::core::work_item_projection::check_result_to_work_item_input(
        &cr,
        1,
        "https://example.com",
        7,
        1_000,
        None,
    );
    db.upsert_work_items_diff("web_scan", 1, "https://example.com", vec![input], 1_000)
        .expect("upsert");

    let row = &db.get_active_work_items(1, None).expect("read")[0];
    assert_eq!(row.metadata.confidence, Some(IssueConfidence::NeedsReview));
    assert_eq!(row.metadata.domain, None);
    assert_eq!(row.metadata.relative_path, None);
    assert!(
        !row.detail_json
            .as_deref()
            .unwrap_or("")
            .contains("confidence"),
        "raw_data blob must not be where confidence lives"
    );
}

#[test]
fn active_issue_read_rejects_unknown_severity_instead_of_relabeling_it() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:corrupt-severity:/", "high")],
        1_000,
    )
    .expect("seed work item");
    db.execute(|conn| {
        conn.execute(
            "UPDATE work_items SET severity = 'urgent' WHERE signal_id = 'psi:corrupt-severity:/'",
            [],
        )
    })
    .expect("db worker")
    .expect("corrupt fixture");

    assert!(
        db.get_active_work_items(1, None).is_err(),
        "unknown severity must not silently become Medium"
    );
}

#[test]
fn active_issue_read_rejects_unknown_confidence_instead_of_erasing_it() {
    let db = test_db();
    db.upsert_work_items_diff(
        "psi",
        1,
        "https://example.com",
        vec![make_input("psi:corrupt-confidence:/", "high")],
        1_000,
    )
    .expect("seed work item");
    db.execute(|conn| {
        conn.execute(
            "UPDATE work_items SET confidence = 'maybe' WHERE signal_id = 'psi:corrupt-confidence:/'",
            [],
        )
    })
    .expect("db worker")
    .expect("corrupt fixture");

    assert!(
        db.get_active_work_items(1, None).is_err(),
        "unknown non-NULL confidence must not silently become unknown"
    );
}

#[test]
#[should_panic(expected = "empty unobserved signal prefix")]
fn diff_except_unobserved_rejects_an_empty_prefix_in_debug() {
    let db = test_db();
    let _ = db.upsert_work_items_diff_except_unobserved(
        "updates",
        1,
        "https://example.com",
        vec![],
        1_000,
        &[String::new()],
    );
}
