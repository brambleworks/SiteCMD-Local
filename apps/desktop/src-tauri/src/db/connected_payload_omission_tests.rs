use super::*;
use sitecmd_protocol::coverage::CoverageExceptionReason;

#[test]
fn n3_submission_omits_bad_occurrences_with_valid_manifests() {
    // An unencodable occurrence leaves otherwise valid coverage marked complete.
    let (db, project_id) = seeded();
    code_scan(
        &db,
        project_id,
        "omission-code",
        SITE,
        vec![code_issue("standin.rule", "src/db.ts", 1, Severity::High)],
    );
    let request = || ConnectedSubmissionRequest {
        site_id: "site_omission".into(),
        submission_sequence: 1,
        include_groups: false,
        fingerprint_key: Some(ProjectFingerprintKey::from_bytes([7; 32])),
        fingerprint_key_version: 1,
        deployed_commit: Some("abc1234".into()),
    };
    let baseline = db
        .build_connected_submission(project_id, SITE, request())
        .unwrap();
    let baseline_coverage = baseline.snapshots.code.unwrap().coverage;
    assert!(baseline_coverage.complete);
    assert!(baseline_coverage.exceptions.is_empty());
    let before = db.latest_submission_evidence(project_id, SITE).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].occurrences.len(), 1);
    db.execute(move |conn| {
        conn.execute(
            "UPDATE scan_findings SET canonical_check_id = ?1
             WHERE run_id IN (SELECT id FROM scan_runs WHERE project_id = ?2)",
            rusqlite::params!["code_scan.bad id", project_id],
        )
        .unwrap();
    })
    .unwrap();
    let submission = db
        .build_connected_submission(project_id, SITE, request())
        .expect("one bad occurrence must not refuse a submission");
    let snapshot = submission.snapshots.code.unwrap();
    assert!(snapshot.occurrences.is_empty());
    let coverage = snapshot.coverage;
    assert!(!coverage.complete);
    assert!(coverage
        .exceptions
        .iter()
        .any(|exception| exception.reason == CoverageExceptionReason::SessionIncomplete));
}
