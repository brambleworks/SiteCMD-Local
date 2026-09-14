//! SQLite persistence on a dedicated connection-owning worker thread.
//!
//! Executions store intent, runs and findings store immutable evidence, and work
//! items plus issue states store the mutable projection.

mod agent_requests;
pub mod alerts;
mod code_scan_summaries;
mod code_scans;
mod connected_bootstrap;
pub use connected_bootstrap::{
    BootstrapGroup, BootstrapSet, BootstrapState, LastKnownOccurrenceRecord, ObservedOccurrence,
    OccurrenceIdentity, OccurrenceLocation, SourceEvidence,
};
mod connected_payload;
pub use connected_payload::{ConnectedCodeBasis, ConnectedSubmissionRequest, PendingRotation};
mod connected_outbox;
pub use connected_outbox::{DecisionRecord, GroupDecision, MutationConflict, PendingMutation};
mod connected_producer;
pub use connected_producer::{ProducerIdentity, SubmissionTicket};
mod connected_sites;
pub use connected_sites::{ConnectedSite, ConnectedSiteBinding};
mod correlation;
mod engine_release;
pub use engine_release::StoredBasis;
mod error;
mod events;
mod fix_attempts;
pub mod from_row;
mod helpers;
pub mod insert;
mod integrations;
mod issue_links;
mod issue_states;
mod migrations;
mod pages;
mod project_signals;
mod projects;
mod regressions;
mod reports;
pub mod resolved_issues;
pub mod retention;
mod scan_execution_detail;
mod scan_executions;
mod scan_retention;
pub use scan_retention::ScanRetentionWindow;
mod scan_run_projection;
mod scan_runs;
mod scan_scope;
pub use scan_scope::{scan_scope_urls, scan_scope_urls_for_project, ConnectedScanScopeTarget};
mod scans;
mod scheduled_scan_baseline;
pub use scheduled_scan_baseline::{
    web_execution_matches_comparison_profile, WebRunComparisonProfile,
};
mod schedules;
mod score_snapshots;
mod sessions;
mod sites;
mod snapshot;
#[cfg(any(test, feature = "test-support"))]
pub mod test_helpers;
mod verified_good;
pub use verified_good::{BaselineDecision, BaselineDecisionOutcome};
#[cfg(test)]
mod tests;
pub mod types;
mod webhooks;
mod work_item_groups;
mod work_item_types;
pub mod work_items;

pub use agent_requests::AgentRequestRow;
pub use correlation::CausalLinkObservationInput;
pub use error::DbError;
pub use fix_attempts::FixAttemptRow;
// Consumed by the desktop watcher and by tests; unused in a plain CLI build.
pub use fix_attempts::FixAttemptTarget;
pub use fix_attempts::FIX_ATTEMPT_EXPIRY_MS;
pub use helpers::normalize_env_url;
pub use issue_links::IssueLink;
pub use issue_states::{IssueLifecycle, IssueStateRow};
pub use regressions::{RegressionInput, RegressionRow};
pub use scans::{normalize_scan_retention, MAX_SCAN_RETENTION};
pub use work_items::IssueCheckMemory;

pub use types::*;

use crate::constants::{DB_OP_TIMEOUT, DB_RESTORE_TIMEOUT};
use helpers::DbOp;
use rusqlite::{Connection, MAIN_DB};
use std::path::PathBuf;
use std::time::Duration;

/// Database handle serialized through a dedicated SQLite worker thread.
pub struct Database {
    sender: std::sync::mpsc::Sender<DbOp>,
    db_path: String,
    #[cfg(any(test, feature = "test-support"))]
    operation_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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
        #[cfg(any(test, feature = "test-support"))]
        self.operation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// Async-aware shared-connection operation. The calling task yields while
    /// the worker runs `f`, so a slow query never parks a runtime worker.
    ///
    /// The closure is sent to the worker before this future first awaits,
    /// so it runs exactly once even if the caller's future is dropped; only
    /// the reply is lost on cancellation.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> T + Send + 'static,
    ) -> Result<T, DbError> {
        let (tx, rx) = tokio::sync::oneshot::channel::<T>();
        let op: DbOp = Box::new(move |conn| {
            let _ = tx.send(f(&*conn));
        });
        self.dispatch_async(op, rx).await
    }

    /// Async-aware mutable operation (transactions), used by the scan-run
    /// persistence path in `persist_normalized_scan_run_async`.
    ///
    /// The closure is sent to the worker before this future first awaits,
    /// so it runs exactly once even if the caller's future is dropped; only
    /// the reply is lost on cancellation.
    pub async fn run_mut<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> T + Send + 'static,
    ) -> Result<T, DbError> {
        let (tx, rx) = tokio::sync::oneshot::channel::<T>();
        let op: DbOp = Box::new(move |conn| {
            let _ = tx.send(f(conn));
        });
        self.dispatch_async(op, rx).await
    }

    async fn dispatch_async<T: Send + 'static>(
        &self,
        op: DbOp,
        rx: tokio::sync::oneshot::Receiver<T>,
    ) -> Result<T, DbError> {
        #[cfg(any(test, feature = "test-support"))]
        self.operation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sender
            .send(op)
            .map_err(|_| DbError::WorkerUnavailable)?;
        match tokio::time::timeout(DB_OP_TIMEOUT, rx).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(DbError::WorkerTerminated),
            Err(_) => Err(DbError::Timeout {
                secs: DB_OP_TIMEOUT.as_secs(),
            }),
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

        let db_path = path.to_string_lossy().to_string();

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
        crate::licensing::store::create_table(&conn)?;

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

        Ok(Database {
            sender,
            db_path,
            #[cfg(any(test, feature = "test-support"))]
            operation_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_operation_count(&self) {
        self.operation_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn operation_count(&self) -> usize {
        self.operation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the filesystem path to the database file.
    #[tracing::instrument(skip(self))]
    pub fn path(&self) -> &str {
        &self.db_path
    }

    #[tracing::instrument(skip(self, source_path), fields(source_path_len = source_path.to_string_lossy().len()))]
    pub fn restore_from_backup(&self, source_path: PathBuf) -> Result<(), String> {
        self.execute_mut_with_timeout(
            move |conn| {
                // Reject an incompatible backup BEFORE overwriting live data:
                // conn.restore replaces the main database first, so checking
                // after the fact would leave the app on an unmigratable DB.
                {
                    let source = Connection::open_with_flags(
                        &source_path,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                    )
                    .map_err(|e| format!("Failed to open backup for inspection: {}", e))?;
                    // Reject backups whose schema version cannot be verified.
                    let version: u32 = source
                        .query_row(
                            "SELECT COALESCE(MAX(version), 0) FROM _schema_version",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(|e| {
                            format!(
                                "{} could not read the backup's schema version ({e}); refusing to restore an unverifiable file",
                                migrations::INCOMPATIBLE_SCHEMA
                            )
                        })?;
                    if version > migrations::latest_version() {
                        return Err(format!(
                            "{} backup schema version {} is newer than this build's {} \
                             (pre-squash or newer-build backup)",
                            migrations::INCOMPATIBLE_SCHEMA,
                            version,
                            migrations::latest_version()
                        ));
                    }
                }
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                    .map_err(|e| format!("Failed to checkpoint live database: {}", e))?;
                // Once restore starts, bump the license generation on every
                // exit because a timed-out worker operation may still change rows.
                let restore_result = (|| {
                    conn.restore(
                        MAIN_DB,
                        &source_path,
                        None::<fn(rusqlite::backup::Progress)>,
                    )
                    .map_err(|e| format!("Failed to restore database: {}", e))?;
                    conn.execute_batch("PRAGMA journal_mode=WAL;")
                        .map_err(|e| format!("Failed to restore WAL mode: {}", e))?;
                    // A pre-squash backup reports INCOMPATIBLE_SCHEMA here; unlike
                    // open, a restore target chosen by the user must not be
                    // silently discarded, so the error surfaces as-is.
                    migrations::run_all(conn)?;
                    crate::licensing::store::create_table(conn)?;
                    // Restore leaves foreign_keys at the connection default; re-enable.
                    conn.execute_batch("PRAGMA foreign_keys=ON;").map_err(|e| {
                        format!("Failed to re-enable foreign keys after restore: {}", e)
                    })?;
                    Ok(())
                })();
                crate::licensing::generation::note_license_rows_replaced();
                restore_result
            },
            DB_RESTORE_TIMEOUT,
        )?
    }

    /// Open a connection with WAL, NORMAL durability, and a busy timeout for
    /// concurrent checkpoint, backup, and licensing access.
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
