//! Tests for the watermark captured on scan admission.

use crate::constants::SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS;
use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionClass, ScanComponentStatus, ScanExecutionMode, ScanTrigger,
};
use crate::core::scan_types::ScanType;
use crate::db::test_helpers::{temp_db, TestDb};

const NOW_MS: i64 = 1_800_000_000_000;
const SITE: &str = "https://example.com";

fn web_execution(key: &str, project_id: Option<i64>, scope_key: &str) -> NewScanExecution {
    NewScanExecution {
        project_id,
        environment_id: None,
        environment_url: Some(SITE.into()),
        environment_scope_key: scope_key.into(),
        requested_mode: ScanExecutionMode::Web,
        web_focus: Some(ScanType::Health),
        trigger: ScanTrigger::Manual,
        admission_class: ScanAdmissionClass::GeneralScan,
        idempotency_key: key.into(),
        request_fingerprint: "v1:fixed-fingerprint".into(),
        now_ms: NOW_MS,
        web_status: Some(ScanComponentStatus::Planned),
        web_detail: None,
        code_status: None,
        code_detail: None,
    }
}

fn admit(db: &TestDb, key: &str, project_id: Option<i64>, scope_key: &str) -> i64 {
    db.admit_scan_execution(
        web_execution(key, project_id, scope_key),
        SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
    )
    .expect("admit execution")
    .execution
    .id
}

fn seeded_project(db: &TestDb) -> i64 {
    db.upsert_project("watermark-fixture", "", None)
        .expect("seed project")
}

#[test]
fn an_installation_that_never_submits_never_mints_an_identifier() {
    let db = temp_db();
    assert_eq!(db.get_producer_identity().expect("identity"), None);
}

#[test]
fn a_site_with_no_pull_reads_as_the_genesis_watermark() {
    let db = temp_db();
    let project_id = seeded_project(&db);
    let execution_id = admit(&db, "genesis-1", Some(project_id), SITE);

    assert_eq!(
        event_basis(&db, execution_id).expect("basis"),
        Some(0),
        "before the first pull there is no site event for the shield to engage against"
    );
}

#[test]
fn a_scan_declares_the_watermark_that_was_in_force_when_it_started() {
    let db = temp_db();
    let project_id = seeded_project(&db);
    seed_watermark(&db, project_id, SITE, 41, NOW_MS);

    let execution_id = admit(&db, "basis-1", Some(project_id), SITE);
    assert_eq!(event_basis(&db, execution_id).expect("basis"), Some(41));
}

#[test]
fn a_pull_during_a_scan_does_not_raise_the_basis_of_evidence_gathered_before_it() {
    let db = temp_db();
    let project_id = seeded_project(&db);
    seed_watermark(&db, project_id, SITE, 7, NOW_MS);

    let execution_id = admit(&db, "mid-scan-1", Some(project_id), SITE);
    seed_watermark(&db, project_id, SITE, 99, NOW_MS + 5_000);

    assert_eq!(
        event_basis(&db, execution_id).expect("basis"),
        Some(7),
        "the basis is what the producer knew when it started looking"
    );
    assert_eq!(
        event_basis(&db, admit(&db, "mid-scan-2", Some(project_id), SITE)).expect("basis"),
        Some(99),
        "the next scan starts from what it now knows"
    );
}

#[test]
fn watermarks_are_per_site_and_keyed_the_way_lifecycle_rows_are() {
    let db = temp_db();
    let project_id = seeded_project(&db);
    seed_watermark(&db, project_id, "HTTPS://Example.com/", 30, NOW_MS);

    assert_eq!(
        event_basis(&db, admit(&db, "key-1", Some(project_id), SITE)).expect("basis"),
        Some(30),
        "the same site under a differently written URL is the same site"
    );
    assert_eq!(
        event_basis(
            &db,
            admit(
                &db,
                "key-2",
                Some(project_id),
                "https://staging.example.com"
            )
        )
        .expect("basis"),
        Some(0),
        "another environment has its own basis"
    );
}

#[test]
fn a_code_only_projects_scope_key_is_not_run_through_url_normalization() {
    let db = temp_db();
    let project_id = seeded_project(&db);
    let scope_key = format!("project:{project_id}");
    seed_watermark(&db, project_id, &scope_key, 5, NOW_MS);

    assert_eq!(
        event_basis(&db, admit(&db, "code-1", Some(project_id), &scope_key)).expect("basis"),
        Some(5)
    );
}

#[test]
fn an_unattached_scan_has_no_site_and_therefore_no_basis_to_declare() {
    let db = temp_db();
    let execution_id = admit(&db, "adhoc-1", None, SITE);
    assert_eq!(event_basis(&db, execution_id).expect("basis"), Some(0));
}

fn event_basis(db: &TestDb, execution_id: i64) -> Result<Option<i64>, crate::db::DbError> {
    use rusqlite::OptionalExtension;

    db.execute(move |conn| {
        conn.query_row(
            "SELECT based_on_event_sequence FROM scan_executions WHERE id = ?1",
            [execution_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    })?
}

fn seed_watermark(db: &TestDb, project_id: i64, url: &str, sequence: i64, pulled_at: i64) {
    let url = super::super::helpers::lifecycle_env_url(url);
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO connected_site_watermarks (project_id, env_url, event_sequence, pulled_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(project_id, env_url) DO UPDATE SET
                 event_sequence = excluded.event_sequence, pulled_at = excluded.pulled_at",
            rusqlite::params![project_id, url, sequence, pulled_at],
        )
    })
    .unwrap()
    .unwrap();
}
