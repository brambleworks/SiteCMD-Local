use super::*;
use crate::core::audit::{CodeIssue, CodeScanReport};
use crate::core::normalized_scan::{normalize_code_scan_with_provenance, ScanRunKind};
use crate::core::scan_types::{IssueConfidence, Severity};
use crate::db::test_helpers::{code_batch, code_execution, temp_db};

const SCOPE: &str = "https://example.com";
const FIRST: &str = "code_scan.hardcoded-secret";
const SECOND: &str = "code_scan.n-plus-one-query";

fn persist(db: &Database, project_id: i64, key: &str, checks: &[(&str, CheckStatus)]) -> i64 {
    let execution_id = code_execution(db, project_id, SCOPE, key);
    db.persist_normalized_scan_run(code_batch(project_id, execution_id, SCOPE, checks))
        .expect("persist")
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
    let run_id = persist(
        &db,
        project_id,
        "persist-one",
        &[(FIRST, CheckStatus::Fail)],
    );

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
        assert_eq!(projection, (run_id, run_id, "hardcoded-secret".into()));
    })
    .expect("query");
}

#[test]
fn code_persistence_keeps_distinct_findings_at_the_same_location() {
    // The database can conflate two finding identities at the same source location.
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/code-occurrence-identity", None)
        .expect("project");
    let issue = |dependency: &str| CodeIssue {
        id: format!("standin.rule:package.json:{dependency}"),
        check_id: String::new(),
        category: "supply-chain".into(),
        severity: Severity::Low,
        title: "Fixture finding".into(),
        description: "detail".into(),
        relative_path: "package.json".into(),
        absolute_path: "/tmp/code-occurrence-identity/package.json".into(),
        line: Some(90),
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
    let scope = format!("project:{project_id}");
    let execution_id = code_execution(&db, project_id, &scope, "same-location-code-findings");
    let batch = normalize_code_scan_with_provenance(
        &report,
        execution_id,
        project_id,
        None,
        format!("project:{project_id}"),
        "/tmp/code-occurrence-identity".into(),
        10,
        100,
        Some(crate::core::code_provenance::CodeCheckoutProvenance::default()),
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
fn not_applicable_resolves_a_work_item() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/removed-condition", None)
        .unwrap();
    persist(&db, project_id, "before", &[(FIRST, CheckStatus::Fail)]);
    assert_eq!(open_checks(&db), [FIRST]);
    persist(
        &db,
        project_id,
        "after",
        &[(FIRST, CheckStatus::NotApplicable)],
    );

    assert!(open_checks(&db).is_empty());
}

#[test]
fn not_applicable_counts_as_passed_when_persisting_a_scan_run() {
    let db = temp_db();
    let project_id = db.upsert_project("p", "/tmp/scan-outcomes", None).unwrap();
    let run_id = persist(
        &db,
        project_id,
        "scan-outcomes",
        &[
            (FIRST, CheckStatus::Pass),
            (SECOND, CheckStatus::NotApplicable),
            ("code_scan.unused-dependency", CheckStatus::Skipped),
        ],
    );

    let passed: i64 = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT issues_passed FROM scan_runs WHERE id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap()
        })
        .unwrap();
    assert_eq!(passed, 2);
}

#[test]
fn a_check_that_timed_out_does_not_resolve_the_finding_it_stopped_reporting() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/coverage-skipped", None)
        .expect("project");
    persist(
        &db,
        project_id,
        "seed",
        &[(FIRST, CheckStatus::Fail), (SECOND, CheckStatus::Fail)],
    );
    persist(
        &db,
        project_id,
        "timed-out",
        &[(FIRST, CheckStatus::Skipped), (SECOND, CheckStatus::Pass)],
    );

    assert_eq!(
        open_checks(&db),
        [FIRST],
        "the skipped check keeps its finding; the one that passed resolves it"
    );
}

#[test]
fn a_check_that_never_ran_does_not_resolve_its_finding() {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/coverage-absent", None)
        .expect("project");
    persist(&db, project_id, "seed", &[(FIRST, CheckStatus::Fail)]);
    persist(
        &db,
        project_id,
        "other-check",
        &[(SECOND, CheckStatus::Pass)],
    );

    assert_eq!(open_checks(&db), [FIRST]);
}

#[test]
fn a_web_batch_is_refused_before_anything_is_stored() {
    // A legacy web producer can write local scan evidence through the code-run boundary.
    let db = temp_db();
    let project_id = db
        .upsert_project("p", "/tmp/refuse-web-batch", None)
        .unwrap();
    let execution_id = code_execution(&db, project_id, SCOPE, "refuse-web");
    let mut batch = code_batch(project_id, execution_id, SCOPE, &[]);
    batch.source = ScanEvidenceSource::WebScan;
    batch.run_kind = ScanRunKind::Code;

    let outcome = db.persist_normalized_scan_run(batch);
    let count: i64 = db
        .execute(|conn| {
            conn.query_row("SELECT COUNT(*) FROM scan_runs", [], |row| row.get(0))
                .unwrap()
        })
        .unwrap();
    assert!(
        matches!(&outcome, Err(DbError::Other(message)) if message == "only code scan runs can be stored locally"),
        "{outcome:?}"
    );
    assert_eq!(count, 0);
}
