//! Open candidate loading and resolution tests for the scan-run projection.

use super::*;
use crate::core::normalized_scan::{ScanCoverageKind, ScanCoverageManifest};
use crate::db::test_helpers::temp_db;
use crate::db::Database;

const ENV: &str = "https://example.com";

fn page_url(page: usize) -> String {
    format!("{ENV}/page-{page}")
}

fn seed_rows(db: &Database, project_id: i64, source: &str, rows: Vec<(String, Option<String>)>) {
    let source = source.to_string();
    db.execute_mut(move |conn| {
        let tx = conn.transaction().expect("transaction");
        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO work_items
                        (project_id, env_url, source, signal_id, check_id, category,
                         severity, title, description, first_seen_at, last_seen_at,
                         resolved_at, page_url)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'security', 'high', ?5, ?5,
                             100, 100, NULL, ?6)",
                )
                .expect("prepare");
            for (check_id, page_url) in &rows {
                let signal_id = format!(
                    "{source}:{check_id}:{}",
                    page_url.as_deref().unwrap_or_default()
                );
                insert
                    .execute(params![
                        project_id, ENV, source, signal_id, check_id, page_url,
                    ])
                    .expect("insert work item");
            }
        }
        tx.commit().expect("commit");
    })
    .expect("seed");
}

fn seeded_project(name: &str) -> (crate::db::test_helpers::TestDb, i64) {
    let db = temp_db();
    let project_id = db
        .upsert_project("p", &format!("/tmp/{name}"), None)
        .expect("project");
    (db, project_id)
}

#[test]
fn a_code_run_loads_open_rows_with_or_without_a_route() {
    // A route filter can hide open rows from a project-wide code run.
    let (db, project_id) = seeded_project("projection-no-route-bound");
    seed_rows(
        &db,
        project_id,
        "code_scan",
        vec![
            ("code_scan.security".into(), None),
            ("code_scan.quality".into(), Some(page_url(1))),
        ],
    );

    let open_count = db
        .execute_mut(move |conn| {
            let tx = conn.transaction().unwrap();
            let scope = ResolveScope {
                run_id: 1,
                observed_at: 1_000,
                project_id,
                source: "code_scan",
                environment_url: ENV,
            };
            load_open_candidates(&tx, &scope).unwrap().len()
        })
        .unwrap();
    assert_eq!(open_count, 2);
}

#[test]
fn a_code_run_resolves_only_checks_it_claims() {
    // A code absence can resolve a check that only shares a registry family prefix.
    let (db, project_id) = seeded_project("exact-code-coverage");
    let claimed = "code_scan.claimed";
    let excepted = "code_scan.excepted";
    let unclaimed = "accessibility.axe.label";
    seed_rows(
        &db,
        project_id,
        "code_scan",
        vec![
            (claimed.into(), None),
            (excepted.into(), None),
            (unclaimed.into(), None),
        ],
    );
    let mut coverage = ScanCoverageManifest::declared(
        ScanCoverageKind::Project,
        Vec::new(),
        vec![claimed.into(), excepted.into(), "accessibility.axe.".into()],
    );
    coverage
        .exceptions
        .push(sitecmd_protocol::coverage::CoverageException {
            route: None,
            checks_not_run: vec![excepted.into()],
            reason: sitecmd_protocol::coverage::CoverageExceptionReason::CheckSkipped,
        });
    let mut batch = crate::db::test_helpers::code_batch(project_id, 1, ENV, &[]);
    batch.coverage = coverage;
    db.execute_mut(move |conn| {
        let tx = conn.transaction().unwrap();
        resolve_covered_absences(
            &tx,
            ResolveScope {
                run_id: 1,
                observed_at: 110,
                project_id,
                source: "code_scan",
                environment_url: ENV,
            },
            &batch,
            &[],
        )
        .unwrap();
        let resolved = |check| -> Option<i64> {
            tx.query_row(
                "SELECT resolved_at FROM work_items WHERE check_id = ?1",
                [check],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(resolved(claimed), Some(110));
        assert_eq!(resolved(excepted), None);
        assert_eq!(resolved(unclaimed), None);
    })
    .unwrap();
}
