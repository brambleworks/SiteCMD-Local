use super::*;
use crate::checks::{CheckResult, IssueConfidence, ScanCategory, Severity};
use crate::core::code_scan::{CodeIssue, CodeScanReport};
use crate::core::normalized_scan::{normalize_code_scan, normalize_web_scan, ScanRunKind};
use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionClass, ScanComponentStatus, ScanExecutionMode, ScanTrigger,
};
use crate::core::scanner::{ScanResult, ScanType};
use crate::db::test_helpers::temp_db;

fn execution(db: &Database, project_id: i64, url: &str, key: &str) -> i64 {
    db.admit_scan_execution(
        NewScanExecution {
            project_id: Some(project_id),
            environment_id: None,
            environment_url: Some(url.into()),
            environment_scope_key: url.into(),
            requested_mode: ScanExecutionMode::Web,
            web_focus: Some(ScanType::Health),
            trigger: ScanTrigger::Manual,
            admission_class: ScanAdmissionClass::GeneralScan,
            idempotency_key: key.into(),
            request_fingerprint: format!("v1:{key}"),
            now_ms: 100,
            web_status: Some(ScanComponentStatus::Planned),
            web_detail: None,
            code_status: None,
            code_detail: None,
        },
        900,
    )
    .expect("execution")
    .execution
    .id
}

fn code_execution(db: &Database, project_id: i64, key: &str) -> i64 {
    db.admit_scan_execution(
        NewScanExecution {
            project_id: Some(project_id),
            environment_id: None,
            environment_url: None,
            environment_scope_key: format!("project:{project_id}"),
            requested_mode: ScanExecutionMode::Code,
            web_focus: None,
            trigger: ScanTrigger::Manual,
            admission_class: ScanAdmissionClass::GeneralScan,
            idempotency_key: key.into(),
            request_fingerprint: format!("v1:{key}"),
            now_ms: 100,
            web_status: None,
            web_detail: None,
            code_status: Some(ScanComponentStatus::Planned),
            code_detail: None,
        },
        900,
    )
    .expect("execution")
    .execution
    .id
}

fn check(check_id: &str, status: CheckStatus) -> CheckResult {
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
        title: check_id.into(),
        description: "detail".into(),
        status,
        severity: Severity::High,
        fix_prompt: Some("producer fix".into()),
        manual_fix: None,
        raw_data: Some(serde_json::json!({"header": check_id})),
        confidence: IssueConfidence::Confirmed,
        confidence_reason: Some("observed".into()),
        why_it_matters: Some("impact".into()),
    }
}

fn result(url: &str, check_id: &str, status: CheckStatus) -> ScanResult {
    results(url, &[(check_id, status)])
}

fn results(url: &str, checks: &[(&str, CheckStatus)]) -> ScanResult {
    ScanResult {
        url: url.into(),
        mode: "live".into(),
        scan_type: ScanType::Health,
        overall_score: 80,
        categories: Vec::new(),
        issues: checks
            .iter()
            .map(|(check_id, status)| check(check_id, *status))
            .collect(),
        detected_stack: None,
        duration_ms: 10,
        timestamp: "2026-07-21T00:00:00Z".into(),
        page_signals: None,
        site_facts: None,
    }
}

// Persist one web run over `url` and hand back its id.
fn persist(db: &Database, project_id: i64, site_id: i64, key: &str, scan: &ScanResult) -> i64 {
    let execution_id = execution(db, project_id, &scan.url, key);
    let batch = normalize_web_scan(
        scan,
        execution_id,
        None,
        Some(project_id),
        site_id,
        ScanRunKind::Single,
        100,
    )
    .expect("normalize");
    db.persist_normalized_scan_run(batch).expect("persist")
}

// The check ids still open for the project, in order.
fn open_checks(db: &Database) -> Vec<String> {
    db.execute(|conn| {
        let mut stmt = conn
            .prepare("SELECT check_id FROM work_items WHERE resolved_at IS NULL ORDER BY check_id")
            .expect("prepare");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect")
    })
    .expect("open checks")
}

#[test]
fn persistence_commits_immutable_findings_and_projection_together() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/canonical-persistence", None)
        .expect("project");
    let url = "https://example.com";
    let site_id = db.get_or_create_site(url).expect("site");
    let execution_id = execution(&db, project_id, url, "persist-one");
    let batch = normalize_web_scan(
        &result(url, "security.headers.csp", CheckStatus::Fail),
        execution_id,
        None,
        Some(project_id),
        site_id,
        ScanRunKind::Single,
        100,
    )
    .expect("normalize");
    let run_id = db.persist_normalized_scan_run(batch).expect("persist");

    db.execute(move |conn| {
        let run_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .expect("run count");
        let finding_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_findings WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .expect("finding count");
        let projection: (i64, i64, String) = conn
            .query_row(
                "SELECT scan_ref, first_seen_scan_ref, producer_check_id
                 FROM work_items WHERE resolved_at IS NULL",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("projection");
        assert_eq!(run_count, 1);
        assert_eq!(finding_count, 1);
        assert_eq!(projection, (run_id, run_id, "security.headers.csp".into()));
    })
    .expect("query");
}

#[test]
fn code_persistence_keeps_distinct_findings_at_the_same_location() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/code-occurrence-identity", None)
        .expect("project");
    let issue = |dependency: &str| CodeIssue {
        id: format!("unused-dependency:package.json:{dependency}"),
        check_id: String::new(),
        category: "supply-chain".into(),
        severity: Severity::Low,
        title: "Unused dependency".into(),
        description: "detail".into(),
        relative_path: "package.json".into(),
        absolute_path: "/tmp/code-occurrence-identity/package.json".into(),
        line: Some(90),
        source_excerpt: None,
        evidence: None,
        why_now: None,
        likely_fix: None,
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: None,
        verify_hint: None,
    };
    let report = CodeScanReport {
        checked_at: "2026-09-12T00:00:00Z".into(),
        framework: Some("typescript".into()),
        issue_count: 2,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 2,
        issues: vec![issue("first-package"), issue("second-package")],
        skipped_scopes: Default::default(),
    };
    let execution_id = code_execution(&db, project_id, "same-location-code-findings");
    let batch = normalize_code_scan(
        &report,
        execution_id,
        project_id,
        None,
        format!("project:{project_id}"),
        "/tmp/code-occurrence-identity".into(),
        90,
        10,
        100,
    )
    .expect("normalize");
    let run_id = db.persist_normalized_scan_run(batch).expect("persist");

    db.execute(move |conn| {
        let findings: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_findings WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .expect("finding count");
        let work_items: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM work_items WHERE project_id = ?1 AND resolved_at IS NULL",
                [project_id],
                |row| row.get(0),
            )
            .expect("work item count");
        assert_eq!((findings, work_items), (2, 2));
    })
    .expect("query");
}

#[test]
fn a_check_that_timed_out_does_not_resolve_the_finding_it_stopped_reporting() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/coverage-skipped", None)
        .expect("project");
    let url = "https://example.com";
    let site_id = db.get_or_create_site(url).expect("site");

    persist(
        &db,
        project_id,
        site_id,
        "seed",
        &results(
            url,
            &[
                ("security.headers.csp", CheckStatus::Fail),
                ("security.headers.hsts", CheckStatus::Fail),
            ],
        ),
    );
    persist(
        &db,
        project_id,
        site_id,
        "timed-out",
        &results(
            url,
            &[
                ("security.headers.csp", CheckStatus::Skipped),
                ("security.headers.hsts", CheckStatus::Pass),
            ],
        ),
    );

    assert_eq!(
        open_checks(&db),
        vec!["security.csp"],
        "the skipped check keeps its finding; the one that passed resolves it"
    );
}

#[test]
fn a_check_that_never_ran_does_not_resolve_its_finding() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/coverage-absent", None)
        .expect("project");
    let url = "https://example.com";
    let site_id = db.get_or_create_site(url).expect("site");

    persist(
        &db,
        project_id,
        site_id,
        "seed",
        &result(url, "security.headers.csp", CheckStatus::Fail),
    );
    persist(
        &db,
        project_id,
        site_id,
        "other-check",
        &result(url, "security.headers.hsts", CheckStatus::Pass),
    );

    assert_eq!(open_checks(&db), vec!["security.csp"]);
}

// Persist one cross-page parent run over `pages` of which `succeeded`
// answered.
fn persist_parent(
    db: &Database,
    project_id: i64,
    site_id: i64,
    key: &str,
    checks: &[(&str, CheckStatus)],
    selected: usize,
    succeeded: usize,
) {
    let env = "https://example.com";
    let all: Vec<String> = (0..selected).map(|i| format!("{env}/page{i}")).collect();
    let execution_id = execution(db, project_id, env, key);
    let batch = crate::core::normalized_scan::normalize_multi_page_parent(
        &checks
            .iter()
            .map(|(check_id, status)| check(check_id, *status))
            .collect::<Vec<_>>(),
        execution_id,
        Some(project_id),
        site_id,
        env.into(),
        all.clone(),
        all[..succeeded].to_vec(),
        selected,
        Some(80),
        10,
        100,
        200,
        ScanType::Health,
        false,
        true,
    )
    .expect("normalize parent");
    db.persist_normalized_scan_run(batch).expect("persist");
}

#[test]
fn a_partial_route_set_does_not_resolve_a_cross_page_finding() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/coverage-session", None)
        .expect("project");
    let site_id = db.get_or_create_site("https://example.com").expect("site");

    persist_parent(
        &db,
        project_id,
        site_id,
        "session-seed",
        &[("seo.duplicate_h1", CheckStatus::Warn)],
        3,
        3,
    );
    persist_parent(
        &db,
        project_id,
        site_id,
        "session-partial",
        &[("seo.duplicate_h1", CheckStatus::Pass)],
        3,
        2,
    );

    assert_eq!(open_checks(&db), vec!["seo.duplicate_h1"]);

    persist_parent(
        &db,
        project_id,
        site_id,
        "session-complete",
        &[("seo.duplicate_h1", CheckStatus::Pass)],
        3,
        3,
    );

    assert!(
        open_checks(&db).is_empty(),
        "the complete set proves what the partial one could not"
    );
}

#[test]
fn page_coverage_does_not_resolve_a_sibling_page() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/canonical-page-coverage", None)
        .expect("project");
    let env = "https://example.com";
    let site_id = db.get_or_create_site(env).expect("site");

    for (index, page) in ["https://example.com/a", "https://example.com/b"]
        .into_iter()
        .enumerate()
    {
        let execution_id = execution(&db, project_id, env, &format!("seed-{index}"));
        let batch = normalize_web_scan(
            &result(page, "security.headers.csp", CheckStatus::Fail),
            execution_id,
            None,
            Some(project_id),
            site_id,
            ScanRunKind::Page,
            100 + index as i64,
        )
        .expect("normalize");
        db.persist_normalized_scan_run(batch).expect("persist seed");
    }

    let execution_id = execution(&db, project_id, env, "clean-a");
    let clean = normalize_web_scan(
        &result(
            "https://example.com/a",
            "security.headers.csp",
            CheckStatus::Pass,
        ),
        execution_id,
        None,
        Some(project_id),
        site_id,
        ScanRunKind::Page,
        200,
    )
    .expect("normalize clean");
    db.persist_normalized_scan_run(clean)
        .expect("persist clean");

    let active_pages = db
        .execute(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT page_url FROM work_items WHERE resolved_at IS NULL ORDER BY page_url",
                )
                .expect("prepare");
            stmt.query_map([], |row| row.get::<_, String>(0))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect")
        })
        .expect("active pages");
    assert_eq!(active_pages, vec!["https://example.com/b"]);
}

#[test]
fn page_coverage_does_not_resolve_the_other_trailing_slash_identity() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/canonical-trailing-slash-coverage", None)
        .expect("project");
    let env = "https://example.com";
    let site_id = db.get_or_create_site(env).expect("site");

    let seed_execution = execution(&db, project_id, env, "seed-checkout-slash");
    let seed = normalize_web_scan(
        &result(
            "https://example.com/checkout/",
            "security.headers.csp",
            CheckStatus::Fail,
        ),
        seed_execution,
        None,
        Some(project_id),
        site_id,
        ScanRunKind::Page,
        100,
    )
    .expect("normalize seed");
    db.persist_normalized_scan_run(seed).expect("persist seed");

    let clean_execution = execution(&db, project_id, env, "clean-checkout-no-slash");
    let clean = normalize_web_scan(
        &result(
            "https://example.com/checkout",
            "security.headers.csp",
            CheckStatus::Pass,
        ),
        clean_execution,
        None,
        Some(project_id),
        site_id,
        ScanRunKind::Page,
        200,
    )
    .expect("normalize clean");
    db.persist_normalized_scan_run(clean)
        .expect("persist clean");

    assert_eq!(
        open_checks(&db),
        vec!["security.csp"],
        "a clean /checkout observation cannot verify /checkout/"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_async_persist_writes_the_same_run_without_blocking_the_worker() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/canonical-async-persistence", None)
        .expect("project");
    let url = "https://example.com";
    let site_id = db.get_or_create_site(url).expect("site");
    let execution_id = execution(&db, project_id, url, "persist-async");
    let batch = normalize_web_scan(
        &result(url, "security.headers.csp", CheckStatus::Fail),
        execution_id,
        None,
        Some(project_id),
        site_id,
        ScanRunKind::Single,
        100,
    )
    .expect("normalize");

    // A timer on the same single-threaded runtime only fires if the async
    // persist yields instead of parking the worker on the database thread.
    let ticked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ticker = {
        let ticked = ticked.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            ticked.store(true, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let run_id = db
        .persist_normalized_scan_run_async(batch)
        .await
        .expect("async persist");
    assert!(
        ticked.load(std::sync::atomic::Ordering::SeqCst),
        "the async persist must yield the runtime worker to other tasks"
    );
    ticker.await.expect("ticker task");

    let (run_count, finding_count) = db
        .execute(move |conn| {
            let run_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
                    [run_id],
                    |row| row.get(0),
                )
                .expect("run count");
            let finding_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM scan_findings WHERE run_id = ?1",
                    [run_id],
                    |row| row.get(0),
                )
                .expect("finding count");
            (run_count, finding_count)
        })
        .expect("read back");
    assert_eq!(run_count, 1, "the async path must commit the run row");
    assert_eq!(finding_count, 1, "the async path must commit its findings");
    assert_eq!(open_checks(&db), vec!["security.csp".to_string()]);
}
