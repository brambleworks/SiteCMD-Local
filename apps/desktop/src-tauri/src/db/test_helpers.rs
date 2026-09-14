//! Temporary-file database fixtures for unit tests.
#![cfg(any(test, feature = "test-support"))]

use crate::db::Database;
use std::sync::Arc;

// Owns a `Database` plus the `TempDir` that backs it, so the directory is
// cleaned up when the wrapper drops. Deref to `Database` so callers can use
// it like a plain handle.
pub struct TestDb {
    pub db: Database,
    _dir: tempfile::TempDir, // dropped when TestDb drops, cleaning the dir
}

impl std::ops::Deref for TestDb {
    type Target = Database;
    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

// Open a fresh database in a new temporary directory.
pub fn temp_db() -> TestDb {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.db");
    let db = Database::open(path).expect("open");
    TestDb { db, _dir: dir }
}

// `temp_db` with project id 1 for foreign-key-constrained fixtures.
pub fn temp_db_with_project() -> TestDb {
    let db = temp_db();
    db.upsert_project("fk-seed", "", None)
        .expect("seed project"); // allow-expect: test fixture, panic at call site
    db
}

// Owns an `Arc<Database>` plus the backing `TempDir`. Used by adapters that
// take `Arc<Database>` by value (e.g. `UpdatesAdapter::new`); callers clone
// the inner Arc via `db.db.clone`.
pub struct TestDbArc {
    pub db: Arc<Database>,
    _dir: tempfile::TempDir, // dropped when TestDbArc drops, cleaning the dir
}

impl std::ops::Deref for TestDbArc {
    type Target = Arc<Database>;
    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

// Open a fresh database wrapped in `Arc` in a new temporary directory.
pub fn temp_db_arc() -> TestDbArc {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.db");
    let db = Arc::new(Database::open(path).expect("open"));
    TestDbArc { db, _dir: dir }
}

// Insert one unresolved work item without running diff resolution.
// Pass a normalized `env_url`.
pub fn insert_test_work_item(
    db: &Database,
    project_id: i64,
    env_url: &str,
    check_id: &str,
) -> Result<(), String> {
    insert_test_work_item_at(db, project_id, env_url, check_id, None, None)
}

pub fn insert_test_work_item_at(
    db: &Database,
    project_id: i64,
    env_url: &str,
    check_id: &str,
    relative_path: Option<&str>,
    line: Option<u32>,
) -> Result<(), String> {
    let source = if check_id.starts_with("code_scan.") {
        "code_scan"
    } else {
        "web_scan"
    };
    let env_url = env_url.to_string();
    let check_id = check_id.to_string();
    let relative_path = relative_path.map(str::to_string);
    let signal_id = format!(
        "{source}:{check_id}:{}",
        relative_path.as_deref().unwrap_or_default()
    );
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO work_items
                (project_id, env_url, source, signal_id, check_id, category, severity,
                 title, description, first_seen_at, last_seen_at, resolved_at,
                 relative_path, line)
             VALUES (?1, ?2, ?3, ?4, ?5, 'security', 'high', ?5, ?5, 1000, 1000, NULL,
                     ?6, ?7)",
            rusqlite::params![
                project_id,
                env_url,
                source,
                signal_id,
                check_id,
                relative_path,
                line,
            ],
        )
        .map_err(|e| e.to_string())
    })??;
    Ok(())
}
