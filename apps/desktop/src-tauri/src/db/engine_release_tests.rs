//! Engine-release persistence tests.

use crate::db::test_helpers::{code_batch, code_execution, temp_db, TestDb};

fn stamped_run(db: &TestDb, project_id: i64, key: &str, site_id: Option<i64>) -> i64 {
    let scope = "https://example.com";
    let execution_id = code_execution(db, project_id, scope, key);
    let mut batch = code_batch(project_id, execution_id, scope, &[]);
    batch.site_id = site_id;
    db.persist_normalized_scan_run(batch).expect("persist")
}

#[test]
fn the_run_records_the_scope_revision_it_was_scoped_by() {
    let db = temp_db();
    let url = "https://example.com";
    let project_id = db
        .upsert_project("p", "/tmp/engine-release-stamp-scope", None)
        .unwrap();
    let site_id = crate::db::test_helpers::seed_site(&db, project_id, url).expect("site");
    db.execute(move |conn| {
        conn.execute(
            "UPDATE sites SET scope_revision = 1 WHERE id = ?1",
            [site_id],
        )
    })
    .unwrap()
    .unwrap();
    let run_id = stamped_run(&db, project_id, "stamp-scope", Some(site_id));

    let stored: Option<i64> = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT scope_revision FROM scan_runs WHERE id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .expect("scope revision column")
        })
        .expect("query");

    assert_eq!(
        stored,
        Some(1),
        "a run must record which scope it covered, or two runs of different scopes compare as if they covered the same routes"
    );
}

#[test]
fn an_unstamped_run_reads_back_as_no_basis_at_all() {
    let db = temp_db();
    let project_id = db.upsert_project("p", "/tmp/unstamped", None).unwrap();
    let run_id = stamped_run(&db, project_id, "unstamped", None);
    db.execute(move |conn| {
        conn.execute(
            "UPDATE scan_runs SET engine_release = NULL, manifest_digest = NULL WHERE id = ?1",
            [run_id],
        )
        .expect("clear stamp");
    })
    .expect("update");

    assert!(
        stored_stamp(&db, run_id).expect("read").is_none(),
        "a run with no stamp must not borrow the current build's identity"
    );
}

fn stored_stamp(
    db: &TestDb,
    run_id: i64,
) -> Result<Option<sitecmd_protocol::release::ReleaseStamp>, crate::db::DbError> {
    db.execute(move |conn| super::read_stamp(conn, run_id))?
}

#[test]
fn a_code_run_is_stamped_with_the_modules_manifest_digest() {
    // A code run names the host's compiled manifest instead of the module that produced it.
    let db = temp_db();
    let project_id = db.upsert_project("p", "/tmp/module-stamp", None).unwrap();
    let run_id = stamped_run(&db, project_id, "code-stamp", None);
    let stamp = stored_stamp(&db, run_id).unwrap().unwrap();
    let engine = sitecmd_engine_host::load().unwrap();
    assert_eq!(
        stamp.manifest_digest,
        engine.info().manifest_digest.as_str()
    );
    assert_eq!(stamp.engine_release, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        stamp.canonicalizer,
        sitecmd_protocol::release::CANONICALIZER_VERSION
    );
    assert_eq!(
        stamp.crawl_profile,
        sitecmd_protocol::release::CRAWL_PROFILE
    );
    assert_eq!(stamp.execution.layers_run, ["code"]);

    let (score, checks): (Option<i64>, i64) = db
        .execute(move |conn| {
            conn.query_row(
                "SELECT raw_score, (SELECT COUNT(*) FROM engine_release_checks)
             FROM scan_runs WHERE id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        })
        .unwrap();
    assert_eq!(score, None);
    assert_eq!(checks, 0);
}
