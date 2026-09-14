//! Execution-level retention for canonical scan history.

use rusqlite::named_params;

use super::{Database, DbError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRetentionWindow {
    All,
    BoundedVerification,
}

impl Database {
    /// Prune visible and bounded-verification history in separate windows.
    #[tracing::instrument(
        skip(self, environment_scope_key),
        fields(project_id, environment_scope_key, requested_keep_count = keep_count)
    )]
    pub fn prune_scan_executions_for_scope(
        &self,
        project_id: Option<i64>,
        environment_scope_key: &str,
        keep_count: u32,
        window: ScanRetentionWindow,
    ) -> Result<u64, DbError> {
        let keep_count = super::scans::normalize_scan_retention(Some(keep_count));
        let prune_visible = i64::from(window == ScanRetentionWindow::All);
        let environment_scope_key = environment_scope_key.to_string();
        self.execute_mut(move |conn| {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TEMP TABLE IF NOT EXISTS temp_pruned_scan_executions (
                     execution_id INTEGER PRIMARY KEY
                 ) WITHOUT ROWID;
                 DELETE FROM temp_pruned_scan_executions;",
            )?;
            tx.execute(
                "INSERT INTO temp_pruned_scan_executions(execution_id)
                 WITH classified AS (
                     SELECT execution.id,
                            execution.started_at,
                            CASE
                                WHEN execution.admission_class = 'bounded_verification'
                                    THEN 'bounded_verification'
                                ELSE 'visible_history'
                            END AS retention_class
                     FROM scan_executions execution
                     WHERE (
                         (:project_id IS NULL AND execution.project_id IS NULL)
                         OR execution.project_id = :project_id
                     )
                       AND execution.environment_scope_key = :environment_scope_key
                       AND execution.status IN ('complete', 'partial', 'failed', 'cancelled')
                 ),
                 ranked AS (
                     SELECT id,
                            retention_class,
                            ROW_NUMBER() OVER (
                                PARTITION BY retention_class
                                ORDER BY started_at DESC, id DESC
                            ) AS retention_rank
                     FROM classified
                 )
                 SELECT id FROM ranked
                 WHERE (
                     retention_class = 'visible_history'
                     AND :prune_visible = 1
                     AND retention_rank > :visible_keep_count
                 ) OR (
                     retention_class = 'bounded_verification'
                     AND retention_rank > :keep_count
                 )",
                named_params! {
                    ":project_id": project_id,
                    ":environment_scope_key": environment_scope_key,
                    ":prune_visible": prune_visible,
                    ":visible_keep_count": keep_count,
                    ":keep_count": keep_count,
                },
            )?;
            let deleted = tx.query_row(
                "SELECT COUNT(*) FROM temp_pruned_scan_executions",
                [],
                |row| row.get::<_, i64>(0),
            )? as u64;

            // Delete resolved projections; detach stale evidence from active rows.
            tx.execute(
                "DELETE FROM work_items
                 WHERE source IN ('web_scan', 'site_scan', 'code_scan')
                   AND resolved_at IS NOT NULL
                   AND scan_ref IN (
                       SELECT run.id FROM scan_runs run
                       JOIN temp_pruned_scan_executions expired
                         ON expired.execution_id = run.execution_id
                   )",
                [],
            )?;
            tx.execute(
                "UPDATE work_items
                 SET scan_ref = CASE
                         WHEN scan_ref IN (
                             SELECT run.id FROM scan_runs run
                             JOIN temp_pruned_scan_executions expired
                               ON expired.execution_id = run.execution_id
                         ) THEN NULL ELSE scan_ref END,
                     first_seen_scan_ref = CASE
                         WHEN first_seen_scan_ref IN (
                             SELECT run.id FROM scan_runs run
                             JOIN temp_pruned_scan_executions expired
                               ON expired.execution_id = run.execution_id
                         ) THEN NULL ELSE first_seen_scan_ref END,
                     resolved_scan_ref = CASE
                         WHEN resolved_scan_ref IN (
                             SELECT run.id FROM scan_runs run
                             JOIN temp_pruned_scan_executions expired
                               ON expired.execution_id = run.execution_id
                         ) THEN NULL ELSE resolved_scan_ref END
                 WHERE source IN ('web_scan', 'site_scan', 'code_scan')
                   AND (
                       scan_ref IN (
                           SELECT run.id FROM scan_runs run
                           JOIN temp_pruned_scan_executions expired
                             ON expired.execution_id = run.execution_id
                       )
                       OR first_seen_scan_ref IN (
                           SELECT run.id FROM scan_runs run
                           JOIN temp_pruned_scan_executions expired
                             ON expired.execution_id = run.execution_id
                       )
                       OR resolved_scan_ref IN (
                           SELECT run.id FROM scan_runs run
                           JOIN temp_pruned_scan_executions expired
                             ON expired.execution_id = run.execution_id
                       )
                   )",
                [],
            )?;
            tx.execute(
                "DELETE FROM scan_executions
                 WHERE id IN (
                     SELECT execution_id FROM temp_pruned_scan_executions
                 )",
                [],
            )?;
            tx.execute("DELETE FROM temp_pruned_scan_executions", [])?;
            tx.commit()?;
            Ok(deleted)
        })?
    }
}
