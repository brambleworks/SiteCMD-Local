use std::sync::{Arc, Barrier};

use crate::constants::SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS;
use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionClass, ScanAdmissionError, ScanComponentStatus,
    ScanExecutionMode, ScanExecutionStatus, ScanTrigger,
};
use crate::core::scan_types::ScanType;
use crate::db::test_helpers::{temp_db, temp_db_arc};

const NOW_MS: i64 = 1_800_000_000_000;

fn request(key: &str, mode: ScanExecutionMode, trigger: ScanTrigger) -> NewScanExecution {
    let (web_status, code_status) = match mode {
        ScanExecutionMode::Full => (
            Some(ScanComponentStatus::Planned),
            Some(ScanComponentStatus::Planned),
        ),
        ScanExecutionMode::Web => (Some(ScanComponentStatus::Planned), None),
        ScanExecutionMode::Code => (None, Some(ScanComponentStatus::Planned)),
    };
    NewScanExecution {
        project_id: None,
        environment_id: None,
        environment_url: Some("https://example.com".into()),
        environment_scope_key: "https://example.com".into(),
        requested_mode: mode,
        web_focus: (mode != ScanExecutionMode::Code).then_some(ScanType::Health),
        trigger,
        admission_class: ScanAdmissionClass::GeneralScan,
        idempotency_key: key.into(),
        request_fingerprint: "v1:fixed-fingerprint".into(),
        now_ms: NOW_MS,
        web_status,
        web_detail: None,
        code_status,
        code_detail: None,
    }
}

#[test]
fn completing_code_after_web_finishes_a_full_execution() {
    let db = temp_db();
    let admitted = db
        .admit_scan_execution(
            request("full-1", ScanExecutionMode::Full, ScanTrigger::Manual),
            SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
        )
        .expect("admit Full execution");

    assert_eq!(admitted.execution.status, ScanExecutionStatus::Planned);
    let id = admitted.execution.id;
    db.execute(move |conn| {
        conn.execute(
            "UPDATE scan_executions SET web_status = 'complete', status = 'running' WHERE id = ?1",
            [id],
        )
        .unwrap();
    })
    .unwrap();

    db.start_scan_execution_component(admitted.execution.id)
        .expect("start Code child");
    let finished = db
        .finish_scan_execution_component(
            admitted.execution.id,
            ScanComponentStatus::Complete,
            None,
            NOW_MS + 2_000,
        )
        .expect("finish Code child");
    assert_eq!(finished.status, ScanExecutionStatus::Complete);

    assert_eq!(finished.requested_mode, ScanExecutionMode::Full);
    assert_eq!(finished.web_status, Some(ScanComponentStatus::Complete));
    assert_eq!(finished.code_status, Some(ScanComponentStatus::Complete));
}

#[test]
fn completed_component_with_incomplete_coverage_makes_the_execution_partial() {
    let db = temp_db();
    let admitted = db
        .admit_scan_execution(
            request("partial-code", ScanExecutionMode::Code, ScanTrigger::Manual),
            SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
        )
        .expect("admit Code execution");

    db.start_scan_execution_component(admitted.execution.id)
        .expect("start Code child");
    let finished = db
        .finish_scan_execution_component(
            admitted.execution.id,
            ScanComponentStatus::Complete,
            Some("Some selected files failed to scan.".into()),
            NOW_MS + 1_000,
        )
        .expect("finish partial Code child");

    assert_eq!(finished.status, ScanExecutionStatus::Partial);
    assert_eq!(
        finished.code_detail.as_deref(),
        Some("Some selected files failed to scan.")
    );
}

#[test]
fn no_action_is_blocked_by_a_daily_allowance() {
    let db = temp_db();
    for (index, mode, trigger) in [
        (1, ScanExecutionMode::Web, ScanTrigger::Manual),
        (2, ScanExecutionMode::Code, ScanTrigger::Manual),
        (3, ScanExecutionMode::Full, ScanTrigger::Scheduled),
        (4, ScanExecutionMode::Code, ScanTrigger::Scheduled),
    ] {
        db.admit_scan_execution(
            request(&format!("action-{index}"), mode, trigger),
            SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
        )
        .expect("every action admits");
    }
}

#[test]
fn admission_class_not_trigger_controls_verification_exemption() {
    let db = temp_db();
    let mut bounded = request("bounded", ScanExecutionMode::Web, ScanTrigger::Verification);
    bounded.admission_class = ScanAdmissionClass::BoundedVerification;
    let bounded = db
        .admit_scan_execution(bounded, SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS)
        .expect("bounded verification");
    assert_eq!(
        bounded.execution.admission_class,
        ScanAdmissionClass::BoundedVerification
    );

    db.admit_scan_execution(
        request(
            "full-project-verify",
            ScanExecutionMode::Code,
            ScanTrigger::Verification,
        ),
        SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
    )
    .expect("full project verification");
    // The admission-class distinction survives for verification semantics,
    // not for a meter: no usage ledger exists to consult at all.
}

#[test]
fn idempotency_is_bound_to_fingerprint_and_terminal_retry_window() {
    let db = temp_db();
    let original_request = request("retry-key", ScanExecutionMode::Code, ScanTrigger::Manual);
    let admitted = db
        .admit_scan_execution(original_request.clone(), SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS)
        .expect("initial admission");
    let planned_retry = db
        .admit_scan_execution(original_request.clone(), SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS)
        .expect("planned retry");
    assert_eq!(planned_retry.execution.id, admitted.execution.id);

    let mut conflicting = original_request.clone();
    conflicting.request_fingerprint = "v1:different".into();
    assert_eq!(
        db.admit_scan_execution(conflicting, SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,)
            .expect_err("fingerprint mismatch"),
        ScanAdmissionError::IdempotencyConflict
    );

    db.start_scan_execution_component(admitted.execution.id)
        .expect("start");
    let completed_at = NOW_MS + 5_000;
    db.finish_scan_execution_component(
        admitted.execution.id,
        ScanComponentStatus::Complete,
        None,
        completed_at,
    )
    .expect("finish");

    let mut boundary = original_request.clone();
    boundary.now_ms = completed_at + SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS * 1_000;
    assert_eq!(
        db.admit_scan_execution(boundary, SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS)
            .expect("boundary retry")
            .execution
            .id,
        admitted.execution.id,
    );

    let mut stale = original_request;
    stale.now_ms = completed_at + SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS * 1_000 + 1;
    assert_eq!(
        db.admit_scan_execution(stale, SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,)
            .expect_err("stale retry"),
        ScanAdmissionError::IdempotencyStale
    );
}

#[test]
fn fresh_key_for_identical_request_admits() {
    let db = temp_db();
    for key in ["fresh-a", "fresh-b"] {
        db.admit_scan_execution(
            request(key, ScanExecutionMode::Web, ScanTrigger::Manual),
            SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
        )
        .expect("fresh action");
    }
}

#[test]
fn concurrent_admissions_all_succeed_with_no_slot_to_race_for() {
    // The retired daily limit made this a race for the last slot; with no
    // meter there is nothing to claim and both racers admit.
    let harness = temp_db_arc();
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["racer-a", "racer-b"].map(|key| {
        let db = harness.db.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.admit_scan_execution(
                request(key, ScanExecutionMode::Code, ScanTrigger::Manual),
                SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
            )
        })
    });
    barrier.wait();
    let outcomes = handles.map(|handle| handle.join().expect("admission thread"));
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 2);
}
