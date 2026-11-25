use rusqlite::{types::Value, Connection};

fn snapshot(conn: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = conn.prepare(sql).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn migration_keeps_rows_and_allows_not_applicable() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    super::ensure_version_table(&conn).unwrap();
    super::apply_pending(&conn, &super::MIGRATIONS[..30], 0).unwrap();
    assert_eq!(super::current_version(&conn).unwrap(), 30);

    conn.execute_batch(
        "INSERT INTO projects (id, name, secret_namespace) VALUES (1, 'p', 'verdicts');
         INSERT INTO scan_executions
             (id, project_id, environment_scope_key, requested_mode, trigger, admission_class,
              status, idempotency_key, request_fingerprint, started_at)
         VALUES (1, 1, 'https://example.com', 'web', 'manual', 'general_scan',
                 'complete', 'verdicts', 'verdicts', 1);
         INSERT INTO scan_runs
             (id, execution_id, project_id, environment_scope_key, source, run_kind, status,
              started_at, timestamp_text, coverage_kind)
         VALUES (1, 1, 1, 'https://example.com', 'web_scan', 'single', 'complete',
                 1, '2026-01-01T00:00:00Z', 'page');
         WITH verdicts(id, status) AS (VALUES (1, 'pass'), (2, 'fail'), (3, 'warn'),
                                            (4, 'skipped'), (5, NULL), (60, 'pass'))
         INSERT INTO work_items
             (id, project_id, env_url, source, signal_id, check_id, category, severity,
              title, description, detail_json, scan_ref, first_seen_at, last_seen_at,
              resolved_at, page_url, fix_prompt, manual_fix, why_it_matters, confidence,
              domain, relative_path, line, check_status, confidence_reason, producer_check_id,
              producer_fix_prompt, producer_category, first_seen_scan_ref, resolved_scan_ref)
         SELECT id, 1, 'https://example.com', 'web_scan', 'signal-' || id, 'seo.title',
                'seo', 'low', 'title', 'description', '{}', 1, 2, 3,
                4, 'https://example.com/docs', 'fix', 'manual', 'impact', 'confirmed',
                'example.com', 'docs.html', 5, status, 'confidence reason', 'producer',
                'producer prompt', 'seo', 1, 1
         FROM verdicts;
         WITH verdicts(id, status) AS (VALUES (1, 'pass'), (2, 'fail'), (3, 'warn'),
                                            (4, 'skipped'), (60, 'pass'))
         INSERT INTO scan_findings
             (id, run_id, ordinal, occurrence_id, source, canonical_check_id,
              producer_check_id, category, producer_category, domain, verdict, severity,
              confidence, confidence_reason, title, description, fix_prompt, producer_fix_prompt,
              manual_fix, why_it_matters, verification_hint, raw_data, detail_json, location_kind,
              page_url, relative_path, line)
         SELECT id, 1, id, 'occurrence-' || id, 'web_scan', 'seo.title',
                'producer', 'seo', 'seo', 'example.com', status, 'low', 'confirmed',
                'confidence reason', 'title', 'description', 'fix', 'producer prompt',
                'manual', 'impact', 'hint', '{}', '{}', 'page',
                'https://example.com/docs', 'docs.html', 5
         FROM verdicts;
         DELETE FROM work_items WHERE id = 60;
         DELETE FROM scan_findings WHERE id = 60;
         INSERT INTO historical_enrichments (work_item_id, integration, payload, created_at)
         VALUES (2, 'github', '{}', 11);",
    )
    .unwrap();

    let queries = [
        "SELECT * FROM work_items ORDER BY id",
        "SELECT * FROM scan_findings ORDER BY id",
        "SELECT * FROM historical_enrichments ORDER BY work_item_id, integration",
        "SELECT name, sql FROM sqlite_schema
         WHERE type = 'index' AND tbl_name IN ('work_items', 'scan_findings')
         ORDER BY name",
        "SELECT * FROM sqlite_sequence
         WHERE name IN ('work_items', 'scan_findings') ORDER BY name",
    ];
    let before = queries.map(|sql| snapshot(&conn, sql));
    super::run_all(&conn).unwrap();

    assert_eq!(super::current_version(&conn).unwrap(), 31);
    for (sql, expected) in queries.into_iter().zip(before) {
        assert_eq!(snapshot(&conn, sql), expected, "{sql}");
    }
    assert!(snapshot(&conn, "PRAGMA foreign_key_check").is_empty());
    assert_eq!(
        snapshot(&conn, "PRAGMA foreign_keys"),
        [[Value::Integer(1)]]
    );

    let work_item_id: i64 = conn
        .query_row(
            "INSERT INTO work_items
             (project_id, env_url, source, signal_id, check_id, category, severity,
              title, description, first_seen_at, last_seen_at, check_status)
         VALUES (1, 'https://example.com', 'web_scan', 'new-signal', 'seo.title', 'seo',
                 'low', 'title', 'description', 10, 10, 'not_applicable')
         RETURNING id",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let finding_id: i64 = conn
        .query_row(
            "INSERT INTO scan_findings
             (run_id, ordinal, occurrence_id, source, canonical_check_id, producer_check_id,
              category, producer_category, verdict, severity, confidence, title, description,
              location_kind)
         VALUES (1, 5, 'new-occurrence', 'web_scan', 'seo.title', 'seo.title', 'seo', 'seo',
                 'not_applicable', 'low', 'confirmed', 'title', 'description', 'page')
         RETURNING id",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((work_item_id, finding_id), (61, 61));
}
