use crate::core::audit::{CodeIssue, CodeScanReport};
use crate::db::test_helpers::temp_db;

fn rich_code_issue() -> CodeIssue {
    CodeIssue {
        check_id: String::new(),
        id: "security.persisted-check".to_string(),
        category: "security".to_string(),
        severity: crate::core::scan_types::Severity::High,
        title: "t".to_string(),
        description: "d".to_string(),
        relative_path: "a.ts".to_string(),
        absolute_path: "/tmp/a.ts".to_string(),
        line: Some(3),
        evidence: Some("evidence".to_string()),
        why_now: Some("why".to_string()),
        likely_fix: Some("fix".to_string()),
        confidence: crate::core::scan_types::IssueConfidence::High,
        confidence_reason: None,
        verify_hint: Some("verify".to_string()),
    }
}

fn one_issue_report() -> CodeScanReport {
    CodeScanReport {
        skipped_scopes: Default::default(),
        checked_at: "2026-07-14T12:00:00Z".into(),
        framework: Some("test".into()),
        issue_count: 1,
        critical_count: 0,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        issues: vec![CodeIssue {
            id: "hardcoded-secret".into(),
            ..rich_code_issue()
        }],
    }
}

#[test]
fn save_code_scan_rejects_inconsistent_report_counts() {
    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/code-scan-counts", None)
        .unwrap();
    let mut report = one_issue_report();
    report.issue_count = 2;

    assert!(db
        .save_code_scan_with_provenance(
            project_id,
            None,
            "/tmp/code-scan-counts".into(),
            &report,
            10,
            Default::default(),
        )
        .is_err());
}

#[test]
fn save_code_scan_refuses_an_unregistered_import_rule() {
    // Accepting an unregistered rule on import puts invalid findings in scan history.
    let db = temp_db();
    let path = "/tmp/code-scan-import";
    let project_id = db.upsert_project("test", path, None).unwrap();
    let mut report = one_issue_report();
    report.issues[0].id = "unregistered-fixture-rule:a.ts:3".into();

    let error = db
        .save_code_scan_with_provenance(
            project_id,
            None,
            path.into(),
            &report,
            10,
            Default::default(),
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The engine reported an unknown Code Scan rule."
    );
    let count: i64 = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT count(*) FROM scan_runs WHERE project_id = ?1",
                [project_id],
                |row| row.get(0),
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn save_code_scan_snapshots_canonical_id_inside_payload() {
    // A stored finding can keep different canonical IDs in its column and embedded payload.
    let db = temp_db();
    let project_id = db
        .upsert_project("test", "/tmp/code-scan-identity", None)
        .unwrap();
    let mut report = one_issue_report();
    report.issues[0].id = "standin.rule:a.ts:3".into();
    let scan_id = db
        .save_code_scan_with_provenance(
            project_id,
            None,
            "/tmp/code-scan-identity".into(),
            &report,
            10,
            Default::default(),
        )
        .unwrap();
    let (column_id, payload_id) = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT canonical_check_id, detail_json FROM scan_findings WHERE run_id = ?1",
                rusqlite::params![scan_id],
                |row| {
                    let column_id: String = row.get(0)?;
                    let payload: CodeIssue = serde_json::from_str(&row.get::<_, String>(1)?)
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    Ok((column_id, payload.check_id))
                },
            )
        })
        .unwrap()
        .unwrap();
    assert!(!column_id.is_empty());
    assert_eq!(payload_id, column_id);
}
