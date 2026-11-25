//! Smoke tests for the database layer.

#[cfg(test)]
#[allow(clippy::module_inception)] // file is named tests.rs; inner mod wraps 1600+ lines, not worth reindenting
mod tests {
    use crate::db::test_helpers::temp_db;
    use crate::db::Database;
    use crate::time::now_utc;
    use rusqlite::Connection;
    use sitecmd_protocol::time::{days, UtcTimestamp};
    use std::path::Path;

    #[test]
    fn execute_times_out_instead_of_blocking_forever_on_a_stalled_op() {
        use std::time::{Duration, Instant};
        let db = temp_db();
        let started = Instant::now();
        let result = db.execute_with_timeout(
            |_conn| {
                std::thread::sleep(Duration::from_secs(2));
                7
            },
            Duration::from_millis(100),
        );
        assert!(
            result.is_err(),
            "a stalled op must time out, got {:?}",
            result
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "caller must return at the ~100ms timeout, not wait out the op"
        );
    }

    #[test]
    fn execute_with_timeout_returns_the_value_when_the_op_is_fast() {
        use std::time::Duration;
        let db = temp_db();
        let value = db
            .execute_with_timeout(|_conn| 42, Duration::from_secs(5))
            .expect("a fast op must return its value within the timeout");
        assert_eq!(value, 42);
    }

    #[test]
    fn open_sets_wal_and_normal_synchronous_pragmas() {
        let db = temp_db();
        let journal_mode: String = db
            .execute(|conn| {
                conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                    .expect("read journal_mode")
            })
            .expect("db worker");
        let synchronous: i64 = db
            .execute(|conn| {
                conn.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                    .expect("read synchronous")
            })
            .expect("db worker");
        assert_eq!(
            journal_mode.to_lowercase(),
            "wal",
            "journal_mode must be WAL"
        );
        assert_eq!(
            synchronous, 1,
            "synchronous must be NORMAL (1), not FULL (2) - WAL makes NORMAL crash-safe"
        );
        let busy_timeout: i64 = db
            .execute(|conn| {
                conn.query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                    .expect("read busy_timeout")
            })
            .expect("db worker");
        assert_eq!(busy_timeout, 5000, "busy_timeout must be 5000ms");
    }

    fn seed_incompatible_db(path: &Path) {
        let conn = Connection::open(path).expect("open legacy db");
        conn.execute_batch(
            "CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL DEFAULT '' UNIQUE,
                framework TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE environments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                label TEXT NOT NULL,
                environment TEXT NOT NULL DEFAULT 'production',
                source TEXT,
                last_scanned_at TEXT,
                UNIQUE(project_id, url)
            );
            CREATE TABLE sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                label TEXT,
                project_path TEXT,
                framework TEXT,
                sitemap_url TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_scanned_at TEXT,
                UNIQUE(url)
            );
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL REFERENCES sites(id),
                timestamp TEXT NOT NULL,
                mode TEXT NOT NULL,
                scan_type TEXT NOT NULL DEFAULT 'health',
                overall_score INTEGER NOT NULL,
                security_score INTEGER,
                performance_score INTEGER,
                seo_score INTEGER,
                accessibility_score INTEGER,
                compliance_score INTEGER,
                config_score INTEGER,
                polish_score INTEGER,
                issues_total INTEGER NOT NULL DEFAULT 0,
                issues_critical INTEGER NOT NULL DEFAULT 0,
                issues_high INTEGER NOT NULL DEFAULT 0,
                issues_medium INTEGER NOT NULL DEFAULT 0,
                issues_low INTEGER NOT NULL DEFAULT 0,
                issues_passed INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL,
                detected_stack TEXT,
                session_id INTEGER,
                page_url TEXT
            );
            CREATE TABLE integration_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                integration_type TEXT NOT NULL,
                api_key TEXT,
                site_id TEXT,
                extra TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(project_id, integration_type)
            );
            CREATE TABLE issue_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                check_id TEXT NOT NULL,
                scan_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                external_id TEXT NOT NULL,
                external_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE project_work_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stable_key TEXT NOT NULL UNIQUE,
                project_id INTEGER NOT NULL,
                environment_url TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                category TEXT,
                domain TEXT,
                package_name TEXT,
                target_json TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                last_verified_at TEXT,
                last_status_changed_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            CREATE TABLE _schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO projects (name, path, framework, created_at)
            VALUES ('Legacy Import', '__url__https://legacy.example', 'nextjs', '2026-01-01T00:00:00Z');",
        )
        .expect("seed legacy schema");
        conn.execute(
            "INSERT INTO _schema_version (version) VALUES (?1)",
            [crate::db::migrations::latest_version() + 1],
        )
        .expect("mark schema as incompatible");
    }

    #[test]
    fn migration_018_adds_page_url_column() {
        let db = temp_db();
        db.execute(|conn| {
            conn.query_row("SELECT page_url FROM work_items LIMIT 1", [], |_row| Ok(()))
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(()),
                    other => Err(format!("unexpected error: {other}")),
                })
        })
        .unwrap()
        .unwrap();
    }

    #[test]
    fn migration_018_creates_dismissed_hints_table() {
        let db = temp_db();
        db.execute(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM dismissed_integration_hints",
                [],
                |row| row.get::<_, i64>(0),
            )
        })
        .unwrap()
        .unwrap();
    }

    fn environment_values(db: &Database, project_id: i64, field: &'static str) -> Vec<String> {
        db.execute(move |conn| {
            let sql = match field {
                "url" => "SELECT url FROM environments WHERE project_id = ?1",
                "label" => "SELECT label FROM environments WHERE project_id = ?1",
                _ => unreachable!(),
            };
            let mut query = conn.prepare(sql).unwrap();
            query
                .query_map([project_id], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        })
        .unwrap()
    }

    #[test]
    fn insert_and_get_project() {
        let db = temp_db();
        let id = db
            .upsert_project("Test Site", "/tmp/test", Some("react"))
            .expect("upsert");
        assert!(id > 0);

        db.execute(move |conn| {
            let (name, framework, namespace): (String, Option<String>, String) = conn
                .query_row(
                    "SELECT name, framework, secret_namespace FROM projects WHERE id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            let projects: i64 = conn
                .query_row("SELECT count(*) FROM projects", [], |row| row.get(0))
                .unwrap();
            assert_eq!(projects, 1);
            assert_eq!(name, "Test Site");
            assert_eq!(framework.as_deref(), Some("react"));
            assert!(!namespace.is_empty());
        })
        .unwrap();
    }

    #[test]
    fn add_environment_stores_normalized_url_and_resolves_project() {
        let db = temp_db();
        let project_id = db
            .upsert_project("Mixed Case", "/tmp/mixed-case", None)
            .expect("upsert");
        db.add_environment(
            project_id,
            "https://MySite.com/",
            "Production",
            "production",
            "manual",
        )
        .expect("add env");

        assert_eq!(
            environment_values(&db, project_id, "url"),
            ["https://mysite.com"]
        );

        // The whole point of write-boundary normalization: a scan of the
        // canonical URL resolves back to the project.
        assert_eq!(
            db.find_project_for_url_result("https://mysite.com")
                .unwrap(),
            Some(project_id)
        );
        // The lookup normalizes its input too, so the verbatim spelling also
        // resolves.
        assert_eq!(
            db.find_project_for_url_result("https://MySite.com/")
                .unwrap(),
            Some(project_id)
        );
    }

    #[test]
    fn add_environment_upserts_existing_row_across_url_spellings() {
        // Re-registering the same URL with different host case or a trailing
        // slash must update the existing row, not insert a duplicate.
        let db = temp_db();
        let project_id = db
            .upsert_project("Same Site", "/tmp/same-site", None)
            .expect("upsert");
        let first = db
            .add_environment(
                project_id,
                "https://example.com",
                "Production",
                "production",
                "manual",
            )
            .expect("add env");
        let second = db
            .add_environment(
                project_id,
                "https://Example.com/",
                "Prod",
                "production",
                "detected",
            )
            .expect("re-add env");
        assert_eq!(first, second);

        assert_eq!(environment_values(&db, project_id, "label"), ["Prod"]);
    }

    #[test]
    fn find_project_for_url_shared_url_resolves_to_oldest_registration() {
        let db = temp_db();
        let first = db
            .upsert_project("First", "/tmp/first", None)
            .expect("upsert first");
        let second = db
            .upsert_project("Second", "/tmp/second", None)
            .expect("upsert second");
        db.add_environment(
            first,
            "https://shared.example.com",
            "Production",
            "production",
            "manual",
        )
        .expect("env on first");
        db.add_environment(
            second,
            "https://shared.example.com",
            "Production",
            "production",
            "manual",
        )
        .expect("env on second");

        // Deterministic pick: the oldest environment row (lowest id) wins,
        // not whichever row SQLite visits first.
        assert_eq!(
            db.find_project_for_url_result("https://shared.example.com")
                .unwrap(),
            Some(first)
        );
    }

    #[test]
    fn strict_project_url_lookup_distinguishes_storage_failure_from_no_project() {
        let db = temp_db();
        assert_eq!(
            db.find_project_for_url_result("https://unlinked.example.com")
                .expect("healthy lookup"),
            None
        );
        db.execute(|conn| conn.execute("DROP TABLE environments", []).map(|_| ()))
            .expect("database worker")
            .expect("drop environments");

        let error = db
            .find_project_for_url_result("https://unlinked.example.com")
            .expect_err("storage failure must not look like an unlinked scan");
        assert!(error.to_string().contains("environments"));
    }

    #[test]
    fn open_moves_pre_squash_db_aside_and_starts_fresh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("legacy-incompatible.db");
        seed_incompatible_db(&path);

        let db = Database::open(path.clone()).expect("open must recover by starting fresh");
        let projects: i64 = db
            .execute(|conn| {
                conn.query_row("SELECT count(*) FROM projects", [], |row| row.get(0))
                    .unwrap()
            })
            .unwrap();
        assert_eq!(projects, 0, "fresh database must not carry legacy rows");

        let schema_version: u32 = db
            .execute(|conn| {
                conn.query_row(
                    "SELECT COALESCE(MAX(version), 0) FROM _schema_version",
                    [],
                    |row| row.get(0),
                )
                .expect("schema version")
            })
            .expect("db worker");
        assert_eq!(schema_version, crate::db::migrations::latest_version());

        let backup = path.with_extension("db.pre-squash.bak");
        assert!(
            backup.exists(),
            "incompatible database must be preserved as {}",
            backup.display()
        );
    }

    #[test]
    fn scan_admission_has_no_usage_ledger() {
        let admit_at = |db: &Database, instant: UtcTimestamp, key: &str| {
            db.admit_scan_execution(
                crate::core::scan_execution::NewScanExecution {
                    project_id: None,
                    environment_id: None,
                    environment_url: Some("https://count.example.com".to_string()),
                    environment_scope_key: "https://count.example.com".to_string(),
                    requested_mode: crate::core::scan_execution::ScanExecutionMode::Web,
                    web_focus: Some(crate::core::scan_types::ScanType::Health),
                    trigger: crate::core::scan_execution::ScanTrigger::Manual,
                    admission_class: crate::core::scan_execution::ScanAdmissionClass::GeneralScan,
                    idempotency_key: key.to_string(),
                    request_fingerprint: format!("v1:fixture:{key}"),
                    now_ms: instant.timestamp_millis(),
                    web_status: Some(crate::core::scan_execution::ScanComponentStatus::Planned),
                    web_detail: None,
                    code_status: None,
                    code_detail: None,
                },
                crate::constants::SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
            )
            .expect("admit fixture execution");
        };

        let db = temp_db();
        for (offset_days, key) in [(1, "yesterday"), (0, "now"), (0, "again")] {
            admit_at(&db, now_utc() - days(offset_days), key);
        }
        // No quota columns survive in the schema for a meter to read.
        let quota_columns: i64 = db
            .execute(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('scan_executions')
                     WHERE name IN ('quota_date', 'quota_state', 'counts_toward_quota')",
                    [],
                    |row| row.get(0),
                )
            })
            .expect("database worker")
            .expect("pragma");
        assert_eq!(quota_columns, 0, "migration 023 dropped the quota ledger");
    }

    #[test]
    fn execute_returns_result_with_correct_shape() {
        let db = temp_db();
        let res: Result<i64, String> = db
            .execute(|conn| {
                conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                    .map_err(|e| e.to_string())
            })
            .map_err(String::from)
            .and_then(|v| v);
        assert_eq!(res.unwrap(), 1);
    }
}
