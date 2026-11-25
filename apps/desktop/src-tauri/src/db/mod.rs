//! SQLite persistence on a dedicated connection-owning worker thread.
//!
//! Executions store intent, runs and findings store immutable evidence, and work
//! items plus issue states store the mutable projection.

mod code_scans;
mod connected_bootstrap;
pub(crate) use connected_bootstrap::collapse_code_observations;
pub use connected_bootstrap::{
    BootstrapGroup, BootstrapSet, BootstrapState, ObservedOccurrence, OccurrenceIdentity,
    OccurrenceLocation, SourceEvidence,
};
pub(crate) mod connected_payload;
pub use connected_payload::ConnectedSubmissionRequest;
mod connected_producer;
pub use connected_producer::ProducerIdentity;
mod connected_sites;
mod engine_release;
mod error;
mod helpers;
mod issue_states;
mod migrations;
mod projects;
mod scan_executions;
mod scan_run_projection;
mod scan_runs;
#[cfg(any(test, feature = "test-support"))]
pub mod test_helpers;
#[cfg(test)]
mod tests;
pub mod types;

pub use error::DbError;

pub use types::*;

use crate::constants::DB_OP_TIMEOUT;
use helpers::DbOp;
use rusqlite::{Connection, MAIN_DB};
use std::path::PathBuf;
use std::time::Duration;

/// Database handle serialized through a dedicated SQLite worker thread.
pub struct Database {
    sender: std::sync::mpsc::Sender<DbOp>,
}

impl Database {
    /// Run a shared-connection operation within [`DB_OP_TIMEOUT`].
    pub fn execute<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> T + Send + 'static,
    ) -> Result<T, DbError> {
        self.execute_with_timeout(f, DB_OP_TIMEOUT)
    }

    /// [`execute`](Self::execute) with an explicit timeout. Used by long,
    /// user-initiated ops (backup restore) and by tests exercising the timeout.
    pub fn execute_with_timeout<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> T + Send + 'static,
        timeout: Duration,
    ) -> Result<T, DbError> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<T>(1);
        let op: DbOp = Box::new(move |conn| {
            let _ = tx.send(f(&*conn));
        });
        self.dispatch(op, rx, timeout)
    }

    /// Send a mutable operation (e.g. a transaction) to the DB thread and block
    /// until it returns, up to [`DB_OP_TIMEOUT`].
    pub fn execute_mut<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> T + Send + 'static,
    ) -> Result<T, DbError> {
        self.execute_mut_with_timeout(f, DB_OP_TIMEOUT)
    }

    /// [`execute_mut`](Self::execute_mut) with an explicit timeout.
    pub fn execute_mut_with_timeout<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> T + Send + 'static,
        timeout: Duration,
    ) -> Result<T, DbError> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<T>(1);
        let op: DbOp = Box::new(move |conn| {
            let _ = tx.send(f(conn));
        });
        self.dispatch(op, rx, timeout)
    }

    /// Dispatch an operation and wait up to `timeout`.
    /// Timed-out operations remain queued, so writes must be idempotent or reconcilable.
    fn dispatch<T: Send + 'static>(
        &self,
        op: DbOp,
        rx: std::sync::mpsc::Receiver<T>,
        timeout: Duration,
    ) -> Result<T, DbError> {
        self.sender
            .send(op)
            .map_err(|_| DbError::WorkerUnavailable)?;
        match rx.recv_timeout(timeout) {
            Ok(value) => Ok(value),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(DbError::Timeout {
                secs: timeout.as_secs(),
            }),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(DbError::WorkerTerminated),
        }
    }

    /// Open or create the database at the given path.
    ///
    /// Runs schema migrations and data fixups on the connection directly,
    /// then hands the connection off to a dedicated worker thread.
    #[tracing::instrument(skip(path), fields(path_len = path.to_string_lossy().len()))]
    pub fn open(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create database directory: {}", e))?;
        }

        let mut conn = Self::open_connection(&path)?;

        let current_schema = migrations::current_version_if_present(&conn)?;
        if current_schema > 0 && current_schema < migrations::UNIFIED_SCAN_CUTOVER_VERSION {
            Self::create_unified_scan_cutover_backup(&conn, &path, current_schema)?;
        }

        // Run migrations before the worker starts; replace incompatible schemas.
        match migrations::run_all(&conn) {
            Ok(()) => {}
            Err(e) if e.starts_with(migrations::INCOMPATIBLE_SCHEMA) => {
                tracing::warn!("db: {} - moving the database aside and starting fresh", e);
                drop(conn);
                Self::move_incompatible_db_aside(&path)?;
                conn = Self::open_connection(&path)?;
                migrations::run_all(&conn)?;
            }
            Err(e) => return Err(e),
        }

        // License state table is managed by the licensing crate.

        // Enable foreign keys on the live connection so cascade constraints apply.
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("Failed to enable foreign keys: {}", e))?;

        let (sender, receiver) = std::sync::mpsc::channel::<DbOp>();

        std::thread::Builder::new()
            .name("db-worker".into())
            .spawn(move || {
                for op in receiver {
                    op(&mut conn);
                }
            })
            .map_err(|e| format!("Failed to spawn DB thread: {}", e))?;

        Ok(Database { sender })
    }

    fn open_connection(path: &std::path::Path) -> Result<Connection, String> {
        let conn = Connection::open(path).map_err(|e| format!("Failed to open database: {}", e))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| format!("Failed to set WAL/synchronous/busy_timeout pragmas: {}", e))?;
        Ok(conn)
    }

    fn create_unified_scan_cutover_backup(
        conn: &Connection,
        path: &std::path::Path,
        current_schema: u32,
    ) -> Result<(), String> {
        let backup_path = path.with_extension(format!(
            "db.pre-unified-scan-v{}.bak",
            migrations::UNIFIED_SCAN_CUTOVER_VERSION
        ));
        if backup_path.exists() {
            let backup = Connection::open_with_flags(
                &backup_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|error| {
                format!(
                    "Unified scan cutover backup exists but cannot be opened: {}",
                    error
                )
            })?;
            let backup_version = migrations::current_version_if_present(&backup)?;
            if backup_version == 0 || backup_version >= migrations::UNIFIED_SCAN_CUTOVER_VERSION {
                return Err(format!(
                    "Unified scan cutover backup is not a recoverable pre-cutover database (schema {})",
                    backup_version
                ));
            }
            tracing::info!(
                backup_schema = backup_version,
                "db: retaining existing unified scan cutover backup"
            );
            return Ok(());
        }
        conn.backup(
            MAIN_DB,
            &backup_path,
            None::<fn(rusqlite::backup::Progress)>,
        )
        .map_err(|error| format!("Failed to create unified scan cutover backup: {error}"))?;
        tracing::info!(
            schema = current_schema,
            "db: created pre-unified-scan cutover backup"
        );
        Ok(())
    }

    /// Moves an incompatible database and its sidecars to a recoverable
    /// `<name>.pre-squash.bak` backup before replacement.
    fn move_incompatible_db_aside(path: &std::path::Path) -> Result<(), String> {
        let base = path.to_string_lossy().to_string();
        for suffix in ["", "-wal", "-shm"] {
            let source = std::path::PathBuf::from(format!("{}{}", base, suffix));
            if !source.exists() {
                continue;
            }
            let mut target = std::path::PathBuf::from(format!("{}{}.pre-squash.bak", base, suffix));
            if target.exists() {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                target = std::path::PathBuf::from(format!(
                    "{}{}.pre-squash-{}.bak",
                    base, suffix, stamp
                ));
            }
            std::fs::rename(&source, &target).map_err(|e| {
                format!(
                    "Failed to move incompatible database file {} aside: {}",
                    source.display(),
                    e
                )
            })?;
        }
        Ok(())
    }
}
