//! Behavior-focused tests for the post-scan persistence helpers.
//!
//! Full end-to-end persistence is exercised via integration tests against
//! a real `Database`.

use super::*;

fn scan_result_fixture(url: &str) -> scanner::ScanResult {
    scanner::ScanResult {
        page_signals: None,
        site_facts: None,
        url: url.to_string(),
        mode: "live".to_string(),
        scan_type: crate::core::scanner::ScanType::Health,
        overall_score: 85,
        categories: vec![],
        issues: vec![],
        detected_stack: None,
        duration_ms: 1234,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn execution_fixture(db: &Database, key: &str) -> i64 {
    let key = key.to_string();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO scan_executions (
                environment_url, environment_scope_key, requested_mode,
                web_focus, trigger, admission_class, status,
                idempotency_key, request_fingerprint, started_at, web_status
             ) VALUES (
                'https://example.com', 'https://example.com', 'web',
                'health', 'manual', 'general_scan', 'running',
                ?1, ?2, 1, 'running'
             )",
            rusqlite::params![key, format!("v1:{key}")],
        )
        .expect("insert execution");
        conn.last_insert_rowid()
    })
    .expect("execution dispatch")
}

fn project_execution_fixture(db: &Database, key: &str, project_id: i64, url: &str) -> i64 {
    let key = key.to_string();
    let url = url.to_string();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO scan_executions (
                project_id, environment_url, environment_scope_key, requested_mode,
                web_focus, trigger, admission_class, status,
                idempotency_key, request_fingerprint, started_at, web_status
             ) VALUES (
                ?1, ?2, ?2, 'web', 'health', 'manual', 'general_scan', 'running',
                ?3, ?4, 1, 'running'
             )",
            rusqlite::params![project_id, url, key, format!("v1:{key}")],
        )
        .expect("insert execution");
        conn.last_insert_rowid()
    })
    .expect("execution dispatch")
}

#[test]
fn persist_scan_blocking_returns_scan_id_when_save_succeeds() {
    let db = crate::db::test_helpers::temp_db_arc();
    let result = scan_result_fixture("https://example.com");
    let execution_id = execution_fixture(&db.db, "web-persist-success");

    let (outcome, notice) = persist_scan_blocking(
        &db.db,
        "https://example.com",
        "https://example.com",
        ScanType::Health,
        None,
        execution_id,
        true,
        true,
        true,
        Some("test-browser"),
        None,
        &result,
    );

    let scan_id = outcome.scan_id.expect("scan persistence should succeed");
    let diagnostics_json: String = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT diagnostics_json FROM scan_runs WHERE id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .expect("stored diagnostics")
        })
        .expect("database worker");
    let diagnostics: crate::core::normalized_scan::NormalizedRunDiagnostics =
        serde_json::from_str(&diagnostics_json).expect("run diagnostics");
    assert!(scan_id > 0);
    assert_eq!(diagnostics.axe_enabled, Some(true));
    assert_eq!(diagnostics.browser_ran, Some(true));
    assert_eq!(diagnostics.axe_ran, Some(true));
    assert_eq!(diagnostics.browser_build.as_deref(), Some("test-browser"));
    assert!(!outcome.blame_notified);
    assert!(notice.is_none());
}

#[test]
fn persist_scan_blocking_marks_browser_failure_as_incomplete() {
    let db = crate::db::test_helpers::temp_db_arc();
    let result = scan_result_fixture("https://example.com");
    let execution_id = execution_fixture(&db.db, "web-browser-failure");

    let (outcome, notice) = persist_scan_blocking(
        &db.db,
        "https://example.com",
        "https://example.com",
        ScanType::Health,
        None,
        execution_id,
        true,
        false,
        false,
        None,
        Some("Failed to create webview: unavailable"),
        &result,
    );

    let scan_id = outcome
        .scan_id
        .expect("partial scan persistence should succeed");
    let stored: (String, Option<i64>, String, Option<String>) = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT status, raw_score, coverage_json, status_detail
                 FROM scan_runs WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("stored partial run")
        })
        .expect("database worker");
    let coverage: crate::core::normalized_scan::ScanCoverageManifest =
        serde_json::from_str(&stored.2).expect("stored coverage");

    assert_eq!(stored.0, "failed");
    assert_eq!(stored.1, None);
    assert!(!coverage.successful);
    assert_eq!(
        stored.3.as_deref(),
        Some("Browser analysis failed: Failed to create webview: unavailable")
    );
    assert!(!outcome.blame_notified);
    assert!(notice.is_none());
}

#[test]
fn persist_scan_blocking_uses_the_selected_project_site_for_a_shared_url() {
    const URL: &str = "https://shared-persist.example";
    let db = crate::db::test_helpers::temp_db_arc();
    let first = db
        .upsert_project("First", "/tmp/shared-persist-a", None)
        .expect("project a");
    let second = db
        .upsert_project("Second", "/tmp/shared-persist-b", None)
        .expect("project b");
    for project_id in [first, second] {
        db.add_environment(project_id, URL, "Production", "production", "manual")
            .expect("environment");
    }
    db.get_or_create_site_for_project(first, URL)
        .expect("first site");
    let selected_site = db
        .get_or_create_site_for_project(second, URL)
        .expect("selected site");
    let execution_id = project_execution_fixture(&db.db, "web-persist-shared", second, URL);

    let (outcome, _) = persist_scan_blocking(
        &db.db,
        URL,
        URL,
        ScanType::Health,
        Some(second),
        execution_id,
        false,
        false,
        false,
        None,
        None,
        &scan_result_fixture(URL),
    );
    let scan_id = outcome.scan_id.expect("scan persistence");
    let stored: (Option<i64>, Option<i64>) = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT project_id, site_id FROM scan_runs WHERE id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("stored run")
        })
        .expect("database worker");

    assert_eq!(stored, (Some(second), Some(selected_site)));
}

#[test]
fn persist_scan_blocking_surfaces_save_failure_and_command_error_mentions_it() {
    let db = crate::db::test_helpers::temp_db_arc();
    // Break canonical run persistence while leaving site creation intact.
    db.execute(|conn| {
        conn.execute("DROP TABLE scan_findings", [])
            .map_err(|e| e.to_string())
    })
    .expect("db dispatch")
    .expect("drop scan_findings table");

    let result = scan_result_fixture("https://example.com");
    let execution_id = execution_fixture(&db.db, "web-persist-failure");
    let (outcome, notice) = persist_scan_blocking(
        &db.db,
        "https://example.com",
        "https://example.com",
        ScanType::Health,
        None,
        execution_id,
        false,
        false,
        false,
        None,
        None,
        &result,
    );

    let error = outcome
        .scan_id
        .expect_err("saving into a dropped scan_findings table must fail");
    assert!(
        error.contains("Failed to save canonical Web Scan run"),
        "got: {error}"
    );
    assert!(!outcome.blame_notified);
    assert!(notice.is_none());

    // The manual-command wrapper (run_and_persist_scan) returns this to
    // the frontend; it must say the scan ran but persistence failed.
    let command_error = persist_failure_error(&error).to_string();
    assert!(
        command_error.contains("scan completed but could not be fully persisted"),
        "got: {command_error}"
    );
    assert!(
        command_error.contains("Failed to save canonical Web Scan run"),
        "got: {command_error}"
    );
}

#[test]
fn browser_failure_disables_regression_comparison() {
    assert!(should_capture_regression_snapshot(ScanType::Health, None));
    assert!(!should_capture_regression_snapshot(
        ScanType::Health,
        Some("unavailable")
    ));
    assert!(!should_capture_regression_snapshot(
        ScanType::Security,
        None
    ));
}
