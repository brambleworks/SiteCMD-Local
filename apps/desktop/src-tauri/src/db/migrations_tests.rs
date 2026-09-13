//! Versioned migration and baseline-schema tests.

use rusqlite::Connection;

const SCHEMA_SNAPSHOT_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/db/schema_snapshot.sql");

fn migrated_conn() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::run_all(&conn).expect("run migrations");
    crate::licensing::store::create_table(&conn).expect("licensing table");
    conn
}

#[test]
fn fresh_db_migrates_to_latest_and_creates_core_tables() {
    let conn = migrated_conn();
    let version: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM _schema_version",
            [],
            |row| row.get(0),
        )
        .expect("read version");
    assert_eq!(version, super::latest_version());

    for table in [
        "projects",
        "environments",
        "sites",
        "scan_executions",
        "scan_runs",
        "scan_findings",
        "events",
        "work_items",
        "alerts",
        "project_issue_states",
        "fix_attempts",
        "regressions",
        "license_state",
    ] {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .expect("table check");
        assert!(exists, "baseline must create table {table}");
    }

    for removed in [
        "scans",
        "scan_sessions",
        "code_scans",
        "scan_issues",
        "session_issues",
        "code_scan_issues",
    ] {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [removed],
                |row| row.get(0),
            )
            .expect("removed table check");
        assert!(!exists, "cutover must remove legacy table {removed}");
    }
}

#[test]
fn run_all_is_idempotent() {
    let conn = migrated_conn();
    super::run_all(&conn).expect("second run is a no-op");
}

#[test]
fn migration_028_removes_only_inferred_update_activity() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    super::apply_pending(&conn, &super::MIGRATIONS[..27], 0).expect("upgrade through v27");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace) VALUES ('p', 'migration-028')",
        [],
    )
    .expect("seed project");
    conn.execute_batch(
        "INSERT INTO events
             (project_id, event_type, severity, occurred_at_ms, title, source, source_id)
         VALUES
             (1, 'update', 'info', 1, '8 Updates Applied', 'internal',
              'updates-refresh:1:0:0:npm:astro:5->6'),
             (1, 'update', 'info', 2, '1 Update Applied', 'internal',
              'updates-verify:1:npm:astro:verified:2');",
    )
    .expect("seed update events");

    super::apply_pending(&conn, &super::MIGRATIONS[27..], 27).expect("apply v28");

    let remaining: Vec<String> = conn
        .prepare("SELECT source_id FROM events ORDER BY id")
        .expect("prepare event query")
        .query_map([], |row| row.get(0))
        .expect("query events")
        .collect::<Result<_, _>>()
        .expect("collect events");
    assert_eq!(remaining, vec!["updates-verify:1:npm:astro:verified:2"]);
}

#[test]
fn migration_030_preserves_queued_requests_and_checks_location_shape() {
    let conn = Connection::open_in_memory().unwrap();
    super::ensure_version_table(&conn).unwrap();
    super::apply_pending(&conn, &super::MIGRATIONS[..29], 0).unwrap();
    conn.execute_batch(
        "INSERT INTO projects (name, secret_namespace) VALUES ('p', 'migration-030');
         INSERT INTO agent_requests
             (kind, project_id, env_url, check_id, agent_tool, created_at, updated_at)
         VALUES ('start_fix', 1, 'https://example.com', 'code_scan.unsafe-html', 'codex', 1, 2);",
    )
    .unwrap();
    super::apply_pending(&conn, &super::MIGRATIONS[29..], 29).unwrap();
    let row = conn
        .query_row(
            "SELECT status, created_at, updated_at, target_relative_path, target_line
         FROM agent_requests WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(row, ("requested".into(), 1, 2, None, None));
    assert!(conn
        .execute("UPDATE agent_requests SET target_line = 346", [])
        .is_err());
    conn.execute(
        "UPDATE agent_requests SET target_relative_path = 'web/logic.js', target_line = 346",
        [],
    )
    .unwrap();
    for invalid in [0_i64, -1, 4_294_967_296] {
        assert!(conn
            .execute("UPDATE agent_requests SET target_line = ?1", [invalid])
            .is_err());
    }
    assert!(conn
        .execute("UPDATE agent_requests SET target_line = 1.5", [])
        .is_err());
    assert!(conn
        .execute("UPDATE agent_requests SET target_relative_path = ''", [])
        .is_err());
    assert!(conn
        .execute("UPDATE agent_requests SET kind = 'run_scan'", [])
        .is_err());
}

#[test]
fn failed_migration_rolls_back_ddl_and_version_together() {
    let conn = migrated_conn();
    let current = super::latest_version();

    let failing: &[(u32, &str)] = &[(
        current + 1,
        "CREATE TABLE crash_probe (id INTEGER PRIMARY KEY);\n\
         INSERT INTO no_such_table (id) VALUES (1);",
    )];
    let err =
        super::apply_pending(&conn, failing, current).expect_err("mid-batch failure must error");
    assert!(
        err.contains(&format!("Migration {} failed", current + 1)),
        "error must name the failing migration, got: {err}"
    );

    let table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='crash_probe')",
            [],
            |row| row.get(0),
        )
        .expect("table check");
    assert!(!table_exists, "partial DDL must roll back with the failure");

    let recorded: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM _schema_version",
            [],
            |row| row.get(0),
        )
        .expect("read version");
    assert_eq!(recorded, current, "a failed migration must not be recorded");

    // The rollback leaves the database retryable: a corrected migration with
    // the same version applies cleanly instead of colliding with leftovers.
    let corrected: &[(u32, &str)] = &[(
        current + 1,
        "CREATE TABLE crash_probe (id INTEGER PRIMARY KEY);",
    )];
    super::apply_pending(&conn, corrected, current).expect("retry after rollback must succeed");
}

#[test]
fn run_all_rejects_pre_squash_or_newer_databases() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(
        "CREATE TABLE _schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .expect("create version table");
    let incompatible = super::latest_version() + 1;
    conn.execute(
        "INSERT INTO _schema_version (version) VALUES (?1)",
        [incompatible],
    )
    .expect("seed incompatible version");

    let err = super::run_all(&conn).expect_err("must reject a newer schema version");
    assert!(
        err.starts_with(super::INCOMPATIBLE_SCHEMA),
        "error must carry the incompatible-schema marker, got: {err}"
    );
}

#[test]
fn project_issue_states_status_check_rejects_unknown_values() {
    // The lifecycle vocabulary is pinned at the schema level; a typo'd status
    // write fails loudly instead of creating an invisible lifecycle fork.
    let conn = migrated_conn();
    conn.execute(
        "INSERT INTO projects (name, secret_namespace) VALUES ('p', 'ns-check')",
        [],
    )
    .expect("seed project");
    let result = conn.execute(
        "INSERT INTO project_issue_states
             (project_id, env_url, check_id, status, last_status_changed_at)
         VALUES (1, 'https://example.com', 'seo.title', 'dismisssed', 0)",
        [],
    );
    assert!(result.is_err(), "unknown status must violate the CHECK");

    // `verified` needs a prover: migration 020 made provenance and status
    // inseparable, so the allowed-value walk supplies one for that status only.
    for status in [
        "new",
        "snoozed",
        "ignored",
        "blocked",
        "verified",
        "regressed",
    ] {
        let verified_by = if status == "verified" {
            "'local_scan'"
        } else {
            "NULL"
        };
        conn.execute(
            &format!(
                "INSERT INTO project_issue_states
                     (project_id, env_url, check_id, status, verified_by,
                      last_status_changed_at)
                 VALUES (1, 'https://example.com', 'check-{status}', '{status}',
                         {verified_by}, 0)"
            ),
            [],
        )
        .unwrap_or_else(|e| panic!("status '{status}' must be allowed: {e}"));
    }
}

#[test]
fn migration_020_attributes_existing_verifications_to_the_scan_that_proved_them() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    super::apply_pending(&conn, &super::MIGRATIONS[..19], 0).expect("upgrade through v19");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace)
         VALUES ('p', 'verification-provenance')",
        [],
    )
    .expect("seed project");
    for (check_id, status) in [("seo.title", "verified"), ("security.csp", "ignored")] {
        conn.execute(
            "INSERT INTO project_issue_states
                 (project_id, env_url, check_id, status, last_status_changed_at)
             VALUES (1, 'https://example.com', ?1, ?2, 1000)",
            rusqlite::params![check_id, status],
        )
        .expect("seed pre-migration lifecycle row");
    }

    super::apply_pending(&conn, &super::MIGRATIONS[19..], 19).expect("apply v20");

    let rows: Vec<(String, String, Option<String>)> = conn
        .prepare("SELECT check_id, status, verified_by FROM project_issue_states ORDER BY check_id")
        .expect("prepare")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect");
    assert_eq!(
        rows,
        vec![
            (
                "security.csp".to_string(),
                "ignored".to_string(),
                None
            ),
            (
                "seo.title".to_string(),
                "verified".to_string(),
                Some("local_scan".to_string())
            ),
        ],
        "the rebuild must preserve every row and attribute the verified one to the only path that could have written it"
    );

    let unprovenanced = conn.execute(
        "INSERT INTO project_issue_states
             (project_id, env_url, check_id, status, last_status_changed_at)
         VALUES (1, 'https://example.com', 'seo.canonical', 'verified', 2000)",
        [],
    );
    assert!(
        unprovenanced.is_err(),
        "after the rebuild a verified row must name who verified it"
    );
}

#[test]
fn migration_021_gives_existing_scans_the_genesis_basis_and_keeps_one_producer_row() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    super::apply_pending(&conn, &super::MIGRATIONS[..20], 0).expect("upgrade through v20");
    conn.execute(
        "INSERT INTO scan_executions
             (environment_scope_key, requested_mode, trigger, admission_class, status,
              idempotency_key, request_fingerprint, started_at, quota_date, quota_state,
              counts_toward_quota)
         VALUES ('https://example.com', 'web', 'manual', 'general_scan', 'complete',
                 'k1', 'v1:f', 1000, '2026-08-06', 'exempt', 0)",
        [],
    )
    .expect("seed pre-migration execution");

    super::apply_pending(&conn, &super::MIGRATIONS[20..], 20).expect("apply v21");

    let basis: i64 = conn
        .query_row(
            "SELECT based_on_event_sequence FROM scan_executions WHERE idempotency_key = 'k1'",
            [],
            |row| row.get(0),
        )
        .expect("read basis");
    assert_eq!(
        basis, 0,
        "a scan from a build that could not pull anything declares the genesis basis, \
         which is its true one rather than a filler"
    );

    conn.execute(
        "INSERT INTO connected_producer (id, installation_id, submission_sequence, minted_at)
         VALUES (1, 'inst_a', 0, 1000)",
        [],
    )
    .expect("first producer row");
    assert!(
        conn.execute(
            "INSERT INTO connected_producer (id, installation_id, submission_sequence, minted_at)
             VALUES (2, 'inst_b', 0, 1000)",
            [],
        )
        .is_err(),
        "one installation has one identity; a second row would be a second namespace \
         for the same counter"
    );
}

#[test]
fn every_migration_sql_file_is_registered() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/db/migrations");
    let registered: std::collections::HashSet<u32> = super::MIGRATIONS
        .iter()
        .map(|&(version, _)| version)
        .collect();

    let mut file_count = 0;
    for entry in std::fs::read_dir(dir).expect("read migrations dir") {
        let name = entry
            .expect("dir entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        if !name.ends_with(".sql") {
            continue;
        }
        file_count += 1;
        let version: u32 = name
            .split('_')
            .next()
            .and_then(|prefix| prefix.parse().ok())
            .unwrap_or_else(|| panic!("migration file {name} must start with a numeric version"));
        assert!(
            registered.contains(&version),
            "migration file {name} is not registered in the MIGRATIONS list (it would never run)"
        );
    }

    assert_eq!(
        file_count,
        super::MIGRATIONS.len(),
        "every MIGRATIONS entry must map to exactly one migrations/*.sql file"
    );
}

#[test]
fn no_new_migration_uses_datetime_now_defaults() {
    for &(version, sql) in super::MIGRATIONS {
        if version == 1 {
            continue;
        }
        assert!(
            !sql.contains("datetime('now')") && !sql.contains("date('now')"),
            "migration {version} uses a datetime('now') default; supply epoch ms from Rust instead"
        );
    }
}

#[test]
fn migration_022_makes_an_unbound_or_contradictory_recorded_decision_unwritable() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .expect("enforce foreign keys");
    super::ensure_version_table(&conn).expect("version table");
    super::apply_pending(&conn, super::MIGRATIONS, 0).expect("upgrade to latest");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace) VALUES ('p', 'connected-outbox')",
        [],
    )
    .expect("seed project");

    let entry = |decision: &str, extra_column: &str, extra_value: &str| {
        conn.execute(
            &format!(
                "INSERT INTO connected_mutation_outbox
                     (project_id, env_url, check_id, decision, {extra_column},
                      based_on_revision, idempotency_key, decided_at)
                 VALUES (1, 'https://example.com', 'security.csp', '{decision}',
                         {extra_value}, 0, 'mut_{decision}_{extra_column}', 1000)"
            ),
            [],
        )
    };

    assert!(
        entry("ignore", "snooze_until", "NULL").is_err(),
        "a decision about an environment with no site binding has no revision \
         namespace to be guarded in"
    );

    conn.execute(
        "INSERT INTO connected_sites (project_id, env_url, site_id, connected_at)
         VALUES (1, 'https://example.com', 'site_a', 1000)",
        [],
    )
    .expect("bind the environment");

    entry("ignore", "snooze_until", "NULL").expect("a bound environment can record intent");
    assert!(
        entry("ignore", "snooze_until", "5000").is_err(),
        "only a snooze has a deadline"
    );
    assert!(
        entry("snooze", "snooze_until", "NULL").is_err(),
        "a snooze with no deadline is a dismissal that never expires"
    );
    assert!(
        entry("wontfix", "snooze_until", "NULL").is_err(),
        "the recorded decision must be one the user can actually make"
    );
    assert!(
        entry("ignore", "block_reason", "'because'").is_err(),
        "only a block carries a reason"
    );

    conn.execute("DELETE FROM connected_sites", [])
        .expect("disconnect");
    let remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM connected_mutation_outbox",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(
        remaining, 0,
        "undelivered intent is scoped to the binding it was recorded under"
    );
}

#[test]
fn migration_029_restores_independent_lines_after_the_v15_path_identity() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    super::apply_pending(&conn, &super::MIGRATIONS[..14], 0).expect("upgrade through v14");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace)
         VALUES ('p', 'fix-target-migration')",
        [],
    )
    .expect("seed project");
    for (line, updated_at) in [(10, 1_000), (18, 2_000)] {
        conn.execute(
            "INSERT INTO fix_attempts (
                project_id, env_url, check_id, target_kind,
                target_relative_path, target_line, agent_tool, status,
                created_at, updated_at
             ) VALUES (
                1, 'https://example.com', 'code_scan.hardcoded-secret',
                'occurrence', 'src/a.ts', ?1, 'codex', 'briefed', ?2, ?2
             )",
            rusqlite::params![line, updated_at],
        )
        .expect("v14 index permits distinct line snapshots");
    }

    super::apply_pending(&conn, &super::MIGRATIONS[14..15], 14).expect("apply v15");

    let statuses = conn
        .prepare("SELECT status FROM fix_attempts ORDER BY updated_at")
        .expect("prepare statuses")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query statuses")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect statuses");
    assert_eq!(statuses, vec!["canceled", "briefed"]);

    let duplicate = conn.execute(
        "INSERT INTO fix_attempts (
            project_id, env_url, check_id, target_kind,
            target_relative_path, target_line, agent_tool, status,
            created_at, updated_at
         ) VALUES (
            1, 'https://example.com', 'code_scan.hardcoded-secret',
            'occurrence', 'src/a.ts', 99, 'codex', 'briefed', 3000, 3000
         )",
        [],
    );
    assert!(
        duplicate.is_err(),
        "v15 treated line movement as one file-scoped attempt"
    );

    super::apply_pending(&conn, &super::MIGRATIONS[15..], 15).expect("upgrade through v29");
    conn.execute(
        "INSERT INTO fix_attempts (
            project_id, env_url, check_id, target_kind,
            target_relative_path, target_line, agent_tool, status,
            created_at, updated_at
         ) VALUES (
            1, 'https://example.com', 'code_scan.hardcoded-secret',
            'occurrence', 'src/a.ts', 99, 'codex', 'briefed', 3000, 3000
         )",
        [],
    )
    .expect("v29 permits a separate active line occurrence");
}

#[test]
fn migration_002_preserves_future_verdict_fields_and_backfills_legacy_web_status() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    conn.execute_batch(super::MIGRATIONS[0].1)
        .expect("apply baseline only");
    conn.execute("INSERT INTO _schema_version (version) VALUES (1)", [])
        .expect("record baseline");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace) VALUES ('p', 'verdict-migration')",
        [],
    )
    .expect("seed project");
    conn.execute(
        "INSERT INTO work_items
            (project_id, env_url, source, signal_id, check_id, category, severity,
             title, description, first_seen_at, last_seen_at)
         VALUES (1, 'https://example.com', 'web_scan', 'web_scan:x', 'x',
                 'security', 'low', 't', 'd', 1, 1)",
        [],
    )
    .expect("seed pre-002 web row");

    super::run_all(&conn).expect("upgrade through current migrations");

    let legacy_status: Option<String> = conn
        .query_row(
            "SELECT check_status FROM work_items WHERE signal_id = 'web_scan:x'",
            [],
            |row| row.get(0),
        )
        .expect("read backfilled status");
    assert_eq!(legacy_status.as_deref(), Some("fail"));

    conn.execute(
        "UPDATE work_items
         SET check_status = 'warn', confidence_reason = 'Static evidence is incomplete.'
         WHERE signal_id = 'web_scan:x'",
        [],
    )
    .expect("new verdict fields accept valid values");
    let invalid = conn.execute(
        "UPDATE work_items SET check_status = 'warning' WHERE signal_id = 'web_scan:x'",
        [],
    );
    assert!(
        invalid.is_err(),
        "unknown scanner status must violate the CHECK"
    );
}

#[test]
fn migration_003_preserves_producer_fields_without_guessing_legacy_values() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    conn.execute_batch(super::MIGRATIONS[0].1)
        .expect("apply baseline only");
    conn.execute("INSERT INTO _schema_version (version) VALUES (1)", [])
        .expect("record baseline");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace) VALUES ('p', 'producer-migration')",
        [],
    )
    .expect("seed project");
    conn.execute(
        "INSERT INTO work_items
            (project_id, env_url, source, signal_id, check_id, category, severity,
             title, description, fix_prompt, first_seen_at, last_seen_at)
         VALUES (1, 'https://example.com', 'web_scan', 'web_scan:security.headers.csp:x',
                 'security.csp', 'security', 'low', 't', 'd', 'generated prompt', 1, 1)",
        [],
    )
    .expect("seed legacy row");

    super::run_all(&conn).expect("upgrade through migration 003");

    let legacy: (Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT producer_check_id, producer_fix_prompt, producer_category
             FROM work_items WHERE signal_id = 'web_scan:security.headers.csp:x'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read legacy producer fields");
    assert_eq!(legacy, (None, None, None));

    conn.execute(
        "UPDATE work_items
         SET producer_check_id = 'security.headers.csp',
             producer_fix_prompt = 'producer prompt',
             producer_category = 'config'
         WHERE signal_id = 'web_scan:security.headers.csp:x'",
        [],
    )
    .expect("new producer fields accept valid values");
    let invalid = conn.execute(
        "UPDATE work_items SET producer_category = 'configuration'
         WHERE signal_id = 'web_scan:security.headers.csp:x'",
        [],
    );
    assert!(
        invalid.is_err(),
        "unknown producer category must violate the CHECK"
    );
}

#[test]
fn migration_004_marks_legacy_scans_and_constrains_immutable_issue_snapshots() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    conn.execute_batch(super::MIGRATIONS[0].1)
        .expect("apply baseline only");
    conn.execute("INSERT INTO _schema_version (version) VALUES (1)", [])
        .expect("record baseline");
    conn.execute("INSERT INTO sites (url) VALUES ('https://example.com')", [])
        .expect("seed site");
    conn.execute(
        "INSERT INTO scans
            (site_id, timestamp, mode, scan_type, overall_score, duration_ms)
         VALUES (1, '2026-01-01T00:00:00Z', 'live', 'health', 80, 1)",
        [],
    )
    .expect("seed legacy scan");

    super::apply_pending(&conn, &super::MIGRATIONS[..4], 1).expect("upgrade through migration 004");

    let version: i64 = conn
        .query_row(
            "SELECT issue_snapshot_version FROM scans WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read legacy snapshot marker");
    assert_eq!(
        version, 0,
        "legacy scans must use the explicit fallback path"
    );

    conn.execute(
        "INSERT INTO scan_issues
            (scan_id, ordinal, check_id, category, title, description,
             check_status, severity, confidence)
         VALUES (1, 0, 'seo.title', 'seo', 'Title', 'Present', 'pass', 'low', 'high')",
        [],
    )
    .expect("valid immutable issue row");
    let invalid = conn.execute(
        "INSERT INTO scan_issues
            (scan_id, ordinal, check_id, category, title, description,
             check_status, severity, confidence)
         VALUES (1, 1, 'x', 'seo', 'x', 'x', 'warning', 'low', 'high')",
        [],
    );
    assert!(invalid.is_err(), "unknown snapshot status must be rejected");
}

#[test]
fn migration_005_marks_legacy_sessions_and_constrains_immutable_issue_snapshots() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    conn.execute_batch(super::MIGRATIONS[0].1)
        .expect("apply baseline only");
    conn.execute("INSERT INTO _schema_version (version) VALUES (1)", [])
        .expect("record baseline");
    conn.execute("INSERT INTO sites (url) VALUES ('https://example.com')", [])
        .expect("seed site");
    conn.execute(
        "INSERT INTO scan_sessions (site_id, total_pages, axe_enabled)
         VALUES (1, 2, 0)",
        [],
    )
    .expect("seed legacy session");

    super::apply_pending(&conn, &super::MIGRATIONS[..5], 1).expect("upgrade through migration 005");

    let version: i64 = conn
        .query_row(
            "SELECT issue_snapshot_version FROM scan_sessions WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read legacy session snapshot marker");
    assert_eq!(
        version, 0,
        "legacy sessions must use the explicit fallback path"
    );

    conn.execute(
        "INSERT INTO session_issues
            (session_id, ordinal, check_id, category, title, description,
             check_status, severity, confidence)
         VALUES (1, 0, 'seo.duplicate_title_across_pages', 'seo', 'Duplicate titles',
                 'Two pages use one title', 'fail', 'high', 'confirmed')",
        [],
    )
    .expect("valid immutable session issue row");
    let invalid_status = conn.execute(
        "INSERT INTO session_issues
            (session_id, ordinal, check_id, category, title, description,
             check_status, severity, confidence)
         VALUES (1, 1, 'x', 'seo', 'x', 'x', 'warning', 'low', 'high')",
        [],
    );
    assert!(
        invalid_status.is_err(),
        "unknown session issue status must be rejected"
    );
    let invalid_category = conn.execute(
        "INSERT INTO session_issues
            (session_id, ordinal, check_id, category, title, description,
             check_status, severity, confidence)
         VALUES (1, 2, 'x', 'configuration', 'x', 'x', 'fail', 'low', 'high')",
        [],
    );
    assert!(
        invalid_category.is_err(),
        "unknown session issue category must be rejected"
    );
}

#[test]
fn migration_006_marks_legacy_code_scans_and_constrains_issue_snapshots() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    conn.execute_batch(super::MIGRATIONS[0].1)
        .expect("apply baseline only");
    conn.execute("INSERT INTO _schema_version (version) VALUES (1)", [])
        .expect("record baseline");
    conn.execute(
        "INSERT INTO projects (name, path, secret_namespace)
         VALUES ('Test', '/tmp/test', 'test-namespace')",
        [],
    )
    .expect("seed project");
    conn.execute(
        "INSERT INTO code_scans
            (project_id, project_path, checked_at, overall_score, duration_ms)
         VALUES (1, '/tmp/test', '2026-01-01T00:00:00Z', 80, 1)",
        [],
    )
    .expect("seed legacy code scan");

    super::apply_pending(&conn, &super::MIGRATIONS[..6], 1).expect("upgrade through migration 006");

    let version: i64 = conn
        .query_row(
            "SELECT issue_snapshot_version FROM code_scans WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read legacy Code Scan snapshot marker");
    assert_eq!(
        version, 0,
        "legacy Code Scans must use the explicit fallback path"
    );

    conn.execute(
        "INSERT INTO code_scan_issues
            (scan_id, ordinal, canonical_check_id, domain, severity, title, issue_json)
         VALUES (1, 0, 'code.ai-safety.ai-timeout', 'ai-safety', 'high',
                 'Missing timeout', '{}')",
        [],
    )
    .expect("valid immutable Code Scan issue row");
    let invalid_domain = conn.execute(
        "INSERT INTO code_scan_issues
            (scan_id, ordinal, canonical_check_id, domain, severity, title, issue_json)
         VALUES (1, 1, 'x', 'quality', 'low', 'x', '{}')",
        [],
    );
    assert!(
        invalid_domain.is_err(),
        "unknown Code Scan domain must be rejected"
    );
    let invalid_severity = conn.execute(
        "INSERT INTO code_scan_issues
            (scan_id, ordinal, canonical_check_id, domain, severity, title, issue_json)
         VALUES (1, 2, 'x', 'security', 'warning', 'x', '{}')",
        [],
    );
    assert!(
        invalid_severity.is_err(),
        "unknown Code Scan severity must be rejected"
    );
}

#[test]
fn migration_007_preserves_unknown_legacy_scan_provenance() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    super::ensure_version_table(&conn).expect("version table");
    conn.execute_batch(super::MIGRATIONS[0].1)
        .expect("apply baseline only");
    conn.execute("INSERT INTO _schema_version (version) VALUES (1)", [])
        .expect("record baseline");
    conn.execute(
        "INSERT INTO projects (name, secret_namespace)
         VALUES ('Test', 'scan-provenance')",
        [],
    )
    .expect("seed project");
    conn.execute(
        "INSERT INTO work_items
            (project_id, env_url, source, signal_id, check_id, category,
             severity, title, description, scan_ref, first_seen_at,
             last_seen_at, resolved_at)
         VALUES (1, 'https://example.com', 'web_scan', 'web_scan:x', 'x',
                 'security', 'high', 'x', 'x', 41, 1000, 2000, 3000)",
        [],
    )
    .expect("seed legacy resolved row");

    super::apply_pending(&conn, &super::MIGRATIONS[..7], 1).expect("upgrade through migration 007");

    let provenance: (Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT first_seen_scan_ref, resolved_scan_ref
             FROM work_items WHERE signal_id = 'web_scan:x'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read scan provenance");
    assert_eq!(
        provenance,
        (None, None),
        "legacy scan_ref is the last observation, not proof of either lifecycle boundary"
    );
}

#[test]
fn schema_snapshot_is_current() {
    let conn = migrated_conn();
    let mut stmt = conn
        .prepare(
            "SELECT sql FROM sqlite_master
             WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
             ORDER BY
                CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END,
                tbl_name, name",
        )
        .expect("prepare schema dump");
    let statements: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("dump schema")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect schema");

    let mut snapshot = String::from(
        "-- GENERATED by db::migrations::tests::schema_snapshot_is_current.\n\
         -- Do not edit by hand: change db/migrations/, run cargo test, commit the diff.\n\
         -- Consumers: apps/mcp-server test fixtures seed their SQLite from this file.\n\n",
    );
    for statement in &statements {
        snapshot.push_str(statement);
        snapshot.push_str(";\n\n");
    }

    let existing = std::fs::read_to_string(SCHEMA_SNAPSHOT_PATH).unwrap_or_default();
    if existing != snapshot {
        std::fs::write(SCHEMA_SNAPSHOT_PATH, &snapshot).expect("write schema snapshot");
        panic!(
            "schema_snapshot.sql was stale and has been regenerated; \
             re-run tests and commit the updated snapshot"
        );
    }
}
