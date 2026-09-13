//! Transactional, ordered SQLite schema migrations.
//!
//! Versions newer than this build return `INCOMPATIBLE_SCHEMA` rather than
//! attempting a downgrade.

use rusqlite::Connection;

/// Embedded migration SQL files, ordered by version number.
static MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("migrations/001_baseline.sql")),
    (
        2,
        include_str!("migrations/002_work_item_issue_verdict.sql"),
    ),
    (
        3,
        include_str!("migrations/003_work_item_producer_fields.sql"),
    ),
    (4, include_str!("migrations/004_immutable_scan_issues.sql")),
    (
        5,
        include_str!("migrations/005_immutable_session_issues.sql"),
    ),
    (
        6,
        include_str!("migrations/006_immutable_code_scan_issues.sql"),
    ),
    (
        7,
        include_str!("migrations/007_work_item_scan_provenance.sql"),
    ),
    (8, include_str!("migrations/008_score_snapshots.sql")),
    (
        9,
        include_str!("migrations/009_scan_schedule_full_type.sql"),
    ),
    (10, include_str!("migrations/010_scan_executions.sql")),
    (
        11,
        include_str!("migrations/011_canonical_code_identity.sql"),
    ),
    (
        12,
        include_str!("migrations/012_scan_runs_and_findings.sql"),
    ),
    (13, include_str!("migrations/013_unified_scan_cutover.sql")),
    (
        14,
        include_str!("migrations/014_unified_scan_compatibility.sql"),
    ),
    (
        15,
        include_str!("migrations/015_fix_attempt_stable_targets.sql"),
    ),
    (
        16,
        include_str!("migrations/016_issue_link_attempt_identity.sql"),
    ),
    (17, include_str!("migrations/017_scan_scope.sql")),
    (18, include_str!("migrations/018_verified_good_profile.sql")),
    (19, include_str!("migrations/019_engine_release_stamp.sql")),
    (
        20,
        include_str!("migrations/020_verification_provenance.sql"),
    ),
    (21, include_str!("migrations/021_submission_ordering.sql")),
    (
        22,
        include_str!("migrations/022_connected_mutation_outbox.sql"),
    ),
    (23, include_str!("migrations/023_retire_scan_quota.sql")),
    (24, include_str!("migrations/024_fingerprint_key_epoch.sql")),
    (
        25,
        include_str!("migrations/025_connected_scope_delivery.sql"),
    ),
    (26, include_str!("migrations/026_code_scan_provenance.sql")),
    (27, include_str!("migrations/027_agent_requests.sql")),
    (
        28,
        include_str!("migrations/028_remove_inferred_update_events.sql"),
    ),
    (
        29,
        include_str!("migrations/029_fix_attempt_occurrence_targets.sql"),
    ),
    (
        30,
        include_str!("migrations/030_agent_request_occurrence_targets.sql"),
    ),
];

pub(crate) const UNIFIED_SCAN_CUTOVER_VERSION: u32 = 13;
const UNIFIED_SCAN_SCHEMA_VERSION: u32 = 12;

/// Error prefix identifying a database written by a newer (or pre-squash)
/// migration chain. Callers match on this to decide between reset and abort.
pub(crate) const INCOMPATIBLE_SCHEMA: &str = "incompatible-schema:";

/// Highest migration version this build knows about.
pub(crate) fn latest_version() -> u32 {
    MIGRATIONS.last().map(|&(version, _)| version).unwrap_or(0)
}

/// Ensure the version-tracking table exists.
fn ensure_version_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .map_err(|e| format!("Failed to create _schema_version table: {}", e))
}

/// Return the highest migration version that has been applied (0 if none).
pub(crate) fn current_version(conn: &Connection) -> Result<u32, String> {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM _schema_version",
        [],
        |row| row.get(0),
    )
    .map_err(|e| format!("Failed to read schema version: {}", e))
}

/// Read the schema version without mutating the database before a cutover backup.
pub(crate) fn current_version_if_present(conn: &Connection) -> Result<u32, String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = '_schema_version'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("Failed to inspect schema metadata: {error}"))?;
    if !exists {
        return Ok(0);
    }
    current_version(conn)
}

/// Run all pending migrations on the given connection.
/// Called during `Database::open` before the worker thread is spawned.
#[tracing::instrument(skip(conn))]
pub(crate) fn run_all(conn: &Connection) -> Result<(), String> {
    ensure_version_table(conn)?;
    let current = current_version(conn)?;
    let latest = latest_version();

    if current > latest {
        return Err(format!(
            "{} database schema version {} is newer than this build's {} \
             (pre-squash or newer-build database)",
            INCOMPATIBLE_SCHEMA, current, latest
        ));
    }

    apply_pending(conn, MIGRATIONS, current)
}

/// Apply pending migrations atomically with their version records.
fn apply_pending(
    conn: &Connection,
    migrations: &[(u32, &str)],
    current: u32,
) -> Result<(), String> {
    let atomic_unified_cutover = current < UNIFIED_SCAN_SCHEMA_VERSION
        && migrations
            .iter()
            .any(|(version, _)| *version == UNIFIED_SCAN_SCHEMA_VERSION)
        && migrations
            .iter()
            .any(|(version, _)| *version == UNIFIED_SCAN_CUTOVER_VERSION);
    let mut index = 0;
    while index < migrations.len() {
        let (version, sql) = migrations[index];
        if version <= current {
            index += 1;
            continue;
        }
        if atomic_unified_cutover && version == UNIFIED_SCAN_SCHEMA_VERSION {
            tracing::info!(
                "db: applying unified scan migrations {}-{} atomically",
                UNIFIED_SCAN_SCHEMA_VERSION,
                UNIFIED_SCAN_CUTOVER_VERSION
            );
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| format!("Failed to begin unified scan cutover transaction: {}", e))?;
            while index < migrations.len() {
                let (grouped_version, grouped_sql) = migrations[index];
                if grouped_version > UNIFIED_SCAN_CUTOVER_VERSION {
                    break;
                }
                if grouped_version >= UNIFIED_SCAN_SCHEMA_VERSION {
                    tx.execute_batch(grouped_sql)
                        .map_err(|e| format!("Migration {} failed: {}", grouped_version, e))?;
                    tx.execute(
                        "INSERT INTO _schema_version (version) VALUES (?1)",
                        [grouped_version],
                    )
                    .map_err(|e| {
                        format!("Failed to record migration {}: {}", grouped_version, e)
                    })?;
                }
                index += 1;
            }
            tx.commit()
                .map_err(|e| format!("Failed to commit unified scan cutover: {}", e))?;
            tracing::info!("db: unified scan cutover complete");
            continue;
        }
        tracing::info!("db: applying migration {}", version);
        // Commit migration DDL and its version record atomically before the worker starts.
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("Failed to begin migration {} transaction: {}", version, e))?;
        tx.execute_batch(sql)
            .map_err(|e| format!("Migration {} failed: {}", version, e))?;
        tx.execute(
            "INSERT INTO _schema_version (version) VALUES (?1)",
            [version],
        )
        .map_err(|e| format!("Failed to record migration {}: {}", version, e))?;
        tx.commit()
            .map_err(|e| format!("Failed to commit migration {}: {}", version, e))?;
        tracing::info!("db: migration {} complete", version);
        index += 1;
    }

    Ok(())
}

#[cfg(test)]
#[path = "migrations_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "migrations_011_tests.rs"]
mod canonical_code_identity_tests;

#[cfg(test)]
#[path = "migrations_012_tests.rs"]
mod canonical_scan_history_tests;

#[cfg(test)]
#[path = "migrations_013_tests.rs"]
mod unified_scan_cutover_tests;
