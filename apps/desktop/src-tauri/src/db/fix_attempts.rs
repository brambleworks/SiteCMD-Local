//! Agent fix-attempt lifecycle persistence.

use super::DbError;
use rusqlite::{params, OptionalExtension, Row};

use super::helpers::normalize_env_url;
use super::Database;

/// Statuses that mark an attempt as in flight. At most one active attempt may
/// exist per stable group/occurrence target; see `uq_fix_attempts_active`.
pub(crate) const ACTIVE_FIX_ATTEMPT_STATUSES: &[&str] =
    &["briefed", "verify_requested", "verifying"];

/// Every status the lifecycle knows about; `set_fix_attempt_status` rejects
/// anything outside this set so external callers (the MCP server) cannot
/// write arbitrary strings into the state machine.
pub(crate) const ALL_FIX_ATTEMPT_STATUSES: &[&str] = &[
    "briefed",
    "verify_requested",
    "verifying",
    "verified",
    "verify_failed",
    "canceled",
    "expired",
];

/// Active attempts untouched for this long are expired by the watcher.
pub const FIX_ATTEMPT_EXPIRY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, serde::Serialize)]
pub struct FixAttemptRow {
    pub id: i64,
    pub project_id: i64,
    pub env_url: String,
    pub check_id: String,
    pub producer_rule: Option<String>,
    pub target_kind: String,
    pub target_relative_path: Option<String>,
    pub target_line: Option<u32>,
    pub target_occurrence_count: Option<u32>,
    pub agent_tool: String,
    pub status: String,
    pub brief_md: String,
    pub agent_summary: Option<String>,
    pub failure_detail: Option<String>,
    pub verify_started_at: Option<i64>,
    /// Epoch milliseconds when MCP first served the brief to an agent.
    pub brief_fetched_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

const FIX_ATTEMPT_COLUMNS: &str = "id, project_id, env_url, check_id, producer_rule,
     target_kind, target_relative_path, target_line, target_occurrence_count, agent_tool, status,
     brief_md, agent_summary, failure_detail, verify_started_at, brief_fetched_at,
     created_at, updated_at";

fn row_to_attempt(row: &Row) -> rusqlite::Result<FixAttemptRow> {
    Ok(FixAttemptRow {
        id: row.get(0)?,
        project_id: row.get(1)?,
        env_url: row.get(2)?,
        check_id: row.get(3)?,
        producer_rule: row.get(4)?,
        target_kind: row.get(5)?,
        target_relative_path: row.get(6)?,
        target_line: row.get(7)?,
        target_occurrence_count: row.get(8)?,
        agent_tool: row.get(9)?,
        status: row.get(10)?,
        brief_md: row.get(11)?,
        agent_summary: row.get(12)?,
        failure_detail: row.get(13)?,
        verify_started_at: row.get(14)?,
        brief_fetched_at: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixAttemptTarget {
    pub relative_path: Option<String>,
    pub line: Option<u32>,
}

impl FixAttemptTarget {
    pub fn group() -> Self {
        Self {
            relative_path: None,
            line: None,
        }
    }

    pub fn occurrence(relative_path: String, line: Option<u32>) -> Self {
        Self {
            relative_path: Some(relative_path),
            line,
        }
    }

    fn kind(&self) -> &'static str {
        if self.relative_path.is_some() {
            "occurrence"
        } else {
            "group"
        }
    }
}

/// `'briefed', 'verify_requested', 'verifying'` for SQL `IN (...)` clauses,
/// derived from the const so the active set has one source of truth.
fn active_status_sql_list() -> String {
    ACTIVE_FIX_ATTEMPT_STATUSES
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ")
}

impl Database {
    /// Start a fresh attempt for one issue, canceling any attempt that is
    /// still in flight for the same stable target so the partial unique index
    /// never sees two active rows.
    #[tracing::instrument(skip(self, env_url), fields(project_id, check_id = %check_id, agent_tool = %agent_tool))]
    pub fn create_fix_attempt(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
        agent_tool: &str,
        now_ms: i64,
    ) -> Result<i64, DbError> {
        self.create_fix_attempt_with_target(
            project_id,
            env_url,
            check_id,
            agent_tool,
            FixAttemptTarget::group(),
            now_ms,
        )
    }

    /// Start a fresh attempt for one canonical group or explicit occurrence.
    /// Different file targets for the same Code rule remain independent.
    pub fn create_fix_attempt_with_target(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
        agent_tool: &str,
        target: FixAttemptTarget,
        now_ms: i64,
    ) -> Result<i64, DbError> {
        let env_key = normalize_env_url(Some(env_url));
        if env_key.is_empty() {
            return Err("env_url is required for fix attempts".into());
        }

        crate::core::code_scan::validate_canonical_check_id(check_id).map_err(DbError::Other)?;
        let check_id = check_id.to_string();
        let agent_tool = agent_tool.to_string();
        let target_kind = target.kind().to_string();
        let target_relative_path = target.relative_path;
        let target_line = target.line;
        self.execute(move |conn| {
            let tx = conn.unchecked_transaction()?;
            // Recover mapped Code producer ids from structured occurrences;
            // canonical ids may intentionally be shared with Web checks.
            let producer_rule = match crate::core::code_scan::code_rule_id(&check_id) {
                Some(rule) => Some(rule.to_string()),
                None if target_kind == "occurrence" => {
                    let producer: Option<String> = tx.query_row(
                        "SELECT COALESCE(
                             (SELECT wi.producer_check_id
                              FROM work_items wi
                              WHERE wi.project_id = ?1
                                AND wi.env_url = ?2
                                AND wi.source = 'code_scan'
                                AND wi.check_id = ?3
                                AND wi.relative_path = ?4
                                AND wi.line IS ?5
                                AND wi.producer_check_id IS NOT NULL
                                AND wi.producer_check_id != ''
                              ORDER BY (wi.resolved_at IS NULL) DESC,
                                       wi.last_seen_at DESC, wi.id DESC
                              LIMIT 1),
                             (SELECT finding.producer_check_id
                              FROM scan_findings finding
                              JOIN scan_runs run ON run.id = finding.run_id
                              WHERE run.project_id = ?1
                                AND run.environment_url = ?2
                                AND finding.source = 'code_scan'
                                AND finding.canonical_check_id = ?3
                                AND finding.relative_path = ?4
                                AND finding.line IS ?5
                              ORDER BY run.started_at DESC, finding.ordinal
                              LIMIT 1)
                         )",
                        params![
                            project_id,
                            env_key,
                            check_id,
                            target_relative_path,
                            target_line
                        ],
                        |row| row.get(0),
                    )?;
                    producer.map(|value| {
                        crate::core::code_scan::code_producer_rule_id(&value).to_string()
                    })
                }
                None => None,
            };
            let target_occurrence_count = if target_kind == "occurrence" {
                let count = tx.query_row(
                    "SELECT COUNT(*) FROM work_items
                     WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3
                       AND source = 'code_scan' AND relative_path = ?4 AND resolved_at IS NULL
                       AND (?5 IS NULL OR producer_check_id = ?5 OR producer_check_id IS NULL)",
                    params![
                        project_id,
                        env_key,
                        check_id,
                        target_relative_path,
                        producer_rule
                    ],
                    |row| row.get::<_, u32>(0),
                )?;
                (count > 0).then_some(count)
            } else {
                None
            };
            tx.execute(
                &format!(
                    "UPDATE fix_attempts
                     SET status = 'canceled', updated_at = ?7
                     WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3
                       AND target_kind = ?4
                       AND target_relative_path IS ?5
                       AND target_line IS ?6
                       AND status IN ({})",
                    active_status_sql_list()
                ),
                params![
                    project_id,
                    env_key,
                    check_id,
                    target_kind,
                    target_relative_path,
                    target_line,
                    now_ms
                ],
            )?;
            tx.execute(
                "INSERT INTO fix_attempts (
                    project_id, env_url, check_id, producer_rule, target_kind,
                    target_relative_path, target_line, target_occurrence_count,
                    agent_tool, status,
                    created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'briefed', ?10, ?10)",
                params![
                    project_id,
                    env_key,
                    check_id,
                    producer_rule,
                    target_kind,
                    target_relative_path,
                    target_line,
                    target_occurrence_count,
                    agent_tool,
                    now_ms
                ],
            )?;
            let id = tx.last_insert_rowid();
            tx.commit()?;
            Ok(id)
        })?
    }

    #[tracing::instrument(skip(self, brief_md), fields(id, brief_len = brief_md.len()))]
    pub fn update_fix_attempt_brief(
        &self,
        id: i64,
        brief_md: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        let brief_md = brief_md.to_string();
        self.execute(move |conn| {
            let changed = conn.execute(
                "UPDATE fix_attempts SET brief_md = ?2, updated_at = ?3 WHERE id = ?1",
                params![id, brief_md, now_ms],
            )?;
            if changed == 0 {
                return Err(format!("no fix attempt with id {id}").into());
            }
            Ok(())
        })?
    }

    /// Transition an attempt without clearing prior details or reviving terminal rows.
    /// Entering `verifying` stamps `verify_started_at` once.
    #[tracing::instrument(skip(self, agent_summary, failure_detail), fields(id, status = %status))]
    pub fn set_fix_attempt_status(
        &self,
        id: i64,
        status: &str,
        agent_summary: Option<&str>,
        failure_detail: Option<&str>,
        now_ms: i64,
    ) -> Result<(), DbError> {
        if !ALL_FIX_ATTEMPT_STATUSES.contains(&status) {
            return Err(format!("unknown fix attempt status: {status}").into());
        }
        let status = status.to_string();
        let agent_summary = agent_summary.map(|s| s.to_string());
        let failure_detail = failure_detail.map(|s| s.to_string());
        self.execute(move |conn| {
            let changed = conn.execute(
                &format!(
                    "UPDATE fix_attempts SET
                            status = ?2,
                            agent_summary = COALESCE(?3, agent_summary),
                            failure_detail = COALESCE(?4, failure_detail),
                            verify_started_at = CASE
                                WHEN ?2 = 'verifying' THEN COALESCE(verify_started_at, ?5)
                                ELSE verify_started_at
                            END,
                            updated_at = ?5
                         WHERE id = ?1 AND status IN ({})",
                    active_status_sql_list()
                ),
                params![id, status, agent_summary, failure_detail, now_ms],
            )?;
            if changed > 0 {
                return Ok(());
            }
            let current: Option<String> = conn
                .query_row(
                    "SELECT status FROM fix_attempts WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            match current {
                None => Err(format!("no fix attempt with id {id}").into()),
                Some(current) if current == status => Ok(()),
                Some(current) => Err(format!(
                    "fix attempt {id} is '{current}'; cannot transition to '{status}'"
                )
                .into()),
            }
        })?
    }

    /// Atomically cancel an active attempt; terminal states are no-ops.
    #[tracing::instrument(skip(self), fields(id))]
    pub fn cancel_fix_attempt_if_active(&self, id: i64, now_ms: i64) -> Result<(), DbError> {
        self.execute(move |conn| {
            let changed = conn.execute(
                &format!(
                    "UPDATE fix_attempts
                         SET status = 'canceled', updated_at = ?2
                         WHERE id = ?1 AND status IN ({})",
                    active_status_sql_list()
                ),
                params![id, now_ms],
            )?;
            if changed > 0 {
                return Ok(());
            }
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM fix_attempts WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            match exists {
                None => Err(format!("no fix attempt with id {id}").into()),
                Some(_) => Ok(()),
            }
        })?
    }

    #[tracing::instrument(skip(self), fields(id))]
    pub fn get_fix_attempt(&self, id: i64) -> Result<Option<FixAttemptRow>, DbError> {
        self.execute(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {} FROM fix_attempts WHERE id = ?1",
                    FIX_ATTEMPT_COLUMNS
                ),
                params![id],
                row_to_attempt,
            )
            .optional()
            .map_err(DbError::from)
        })?
    }

    /// Most recent attempt for one canonical issue regardless of target or status.
    #[tracing::instrument(skip(self, env_url), fields(project_id, check_id = %check_id))]
    pub fn get_latest_fix_attempt(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
    ) -> Result<Option<FixAttemptRow>, DbError> {
        self.get_latest_fix_attempt_matching(project_id, env_url, check_id, None)
    }

    /// Most recent attempt for one exact group or code occurrence target.
    pub fn get_latest_fix_attempt_for_target(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
        target: FixAttemptTarget,
    ) -> Result<Option<FixAttemptRow>, DbError> {
        self.get_latest_fix_attempt_matching(project_id, env_url, check_id, Some(target))
    }

    fn get_latest_fix_attempt_matching(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
        target: Option<FixAttemptTarget>,
    ) -> Result<Option<FixAttemptRow>, DbError> {
        let env_key = normalize_env_url(Some(env_url));
        if env_key.is_empty() {
            return Ok(None);
        }
        let check_id = check_id.to_string();
        let target =
            target.map(|target| (target.kind().to_string(), target.relative_path, target.line));
        self.execute(move |conn| {
            match target {
                Some((target_kind, target_relative_path, target_line)) => conn
                    .query_row(
                        &format!(
                            "SELECT {} FROM fix_attempts
                             WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3
                               AND target_kind = ?4
                               AND target_relative_path IS ?5
                               AND target_line IS ?6
                             ORDER BY id DESC LIMIT 1",
                            FIX_ATTEMPT_COLUMNS
                        ),
                        params![
                            project_id,
                            env_key,
                            check_id,
                            target_kind,
                            target_relative_path,
                            target_line
                        ],
                        row_to_attempt,
                    )
                    .optional(),
                None => conn
                    .query_row(
                        &format!(
                            "SELECT {} FROM fix_attempts
                             WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3
                             ORDER BY id DESC LIMIT 1",
                            FIX_ATTEMPT_COLUMNS
                        ),
                        params![project_id, env_key, check_id],
                        row_to_attempt,
                    )
                    .optional(),
            }
            .map_err(DbError::from)
        })?
    }

    #[tracing::instrument(skip(self), fields(statuses = ?statuses))]
    pub fn list_fix_attempts_in_status(
        &self,
        statuses: &[&str],
    ) -> Result<Vec<FixAttemptRow>, DbError> {
        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        let statuses: Vec<String> = statuses.iter().map(|s| s.to_string()).collect();
        self.execute(move |conn| {
            let placeholders = (1..=statuses.len())
                .map(|i| format!("?{}", i))
                .collect::<Vec<_>>()
                .join(", ");
            let mut stmt = conn.prepare(&format!(
                "SELECT {} FROM fix_attempts WHERE status IN ({}) ORDER BY id",
                FIX_ATTEMPT_COLUMNS, placeholders
            ))?;
            let rows =
                stmt.query_map(rusqlite::params_from_iter(statuses.iter()), row_to_attempt)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })?
    }

    /// Return check IDs with active fix attempts for one environment.
    /// An empty environment includes the entire project.
    #[tracing::instrument(skip(self, env_url), fields(project_id))]
    pub fn active_fix_attempt_check_ids(
        &self,
        project_id: i64,
        env_url: Option<&str>,
    ) -> Result<std::collections::HashSet<String>, DbError> {
        let env_key = normalize_env_url(env_url);
        self.execute(move |conn| {
            let statuses = ACTIVE_FIX_ATTEMPT_STATUSES
                .iter()
                .map(|status| format!("'{}'", status))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = if env_key.is_empty() {
                format!(
                    "SELECT DISTINCT check_id FROM fix_attempts
                     WHERE project_id = ?1 AND status IN ({statuses})"
                )
            } else {
                format!(
                    "SELECT DISTINCT check_id FROM fix_attempts
                     WHERE project_id = ?1 AND env_url = ?2 AND status IN ({statuses})"
                )
            };
            let mut stmt = conn.prepare(&sql)?;
            fn first_column(row: &rusqlite::Row<'_>) -> rusqlite::Result<String> {
                row.get(0)
            }
            let rows = if env_key.is_empty() {
                stmt.query_map(params![project_id], first_column)
            } else {
                stmt.query_map(params![project_id, env_key], first_column)
            }?;
            rows.collect::<Result<std::collections::HashSet<_>, _>>()
                .map_err(DbError::from)
        })?
    }

    /// Whether an exact canonical group or reported path and line remains active.
    #[tracing::instrument(skip(self, env_url, target_relative_path), fields(project_id, check_id = %check_id, target_kind = %target_kind))]
    pub fn is_fix_attempt_target_active(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
        target_kind: &str,
        target_relative_path: Option<&str>,
        target_line: Option<u32>,
    ) -> Result<bool, DbError> {
        self.fix_attempt_target_active(
            project_id,
            env_url,
            check_id,
            target_kind,
            target_relative_path,
            target_line,
            None,
            None,
        )
    }

    /// Whether the stored target remains active after accounting for line movement.
    pub fn is_fix_attempt_active(&self, attempt: &FixAttemptRow) -> Result<bool, DbError> {
        self.fix_attempt_target_active(
            attempt.project_id,
            &attempt.env_url,
            &attempt.check_id,
            &attempt.target_kind,
            attempt.target_relative_path.as_deref(),
            attempt.target_line,
            attempt.producer_rule.as_deref(),
            attempt.target_occurrence_count,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn fix_attempt_target_active(
        &self,
        project_id: i64,
        env_url: &str,
        check_id: &str,
        target_kind: &str,
        target_relative_path: Option<&str>,
        target_line: Option<u32>,
        producer_rule: Option<&str>,
        target_occurrence_count: Option<u32>,
    ) -> Result<bool, DbError> {
        let env_key = normalize_env_url(Some(env_url));
        crate::core::code_scan::validate_canonical_check_id(check_id).map_err(DbError::Other)?;
        let check_id = check_id.to_string();
        let target_kind = target_kind.to_string();
        let target_relative_path = target_relative_path.map(str::to_string);
        let producer_rule = producer_rule.map(str::to_string);
        self.execute(move |conn| {
            if target_kind == "group" {
                return conn
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM work_items
                            WHERE project_id = ?1 AND env_url = ?2
                              AND check_id = ?3 AND resolved_at IS NULL
                         )",
                        params![project_id, env_key, check_id],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(DbError::from);
            }
            let (exact_line_active, active_count) = conn.query_row(
                "SELECT
                    EXISTS(
                        SELECT 1 FROM work_items
                        WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3
                          AND source = 'code_scan' AND relative_path = ?4
                          AND line IS ?6 AND resolved_at IS NULL
                          AND (?5 IS NULL OR producer_check_id = ?5 OR producer_check_id IS NULL)
                    ),
                    COUNT(*)
                 FROM work_items
                 WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3
                   AND source = 'code_scan' AND relative_path = ?4 AND resolved_at IS NULL
                   AND (?5 IS NULL OR producer_check_id = ?5 OR producer_check_id IS NULL)",
                params![
                    project_id,
                    env_key,
                    check_id,
                    target_relative_path,
                    producer_rule,
                    target_line
                ],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, u32>(1)?)),
            )?;
            Ok(exact_line_active
                || target_occurrence_count
                    .is_some_and(|initial_count| active_count >= initial_count))
        })?
    }

    /// Expire active attempts that have not been touched since `cutoff_ms`.
    /// Returns how many rows were expired.
    #[tracing::instrument(skip(self), fields(cutoff_ms, now_ms))]
    pub fn expire_stale_fix_attempts(&self, cutoff_ms: i64, now_ms: i64) -> Result<usize, DbError> {
        self.execute(move |conn| {
            conn.execute(
                &format!(
                    "UPDATE fix_attempts
                     SET status = 'expired', updated_at = ?2
                     WHERE updated_at < ?1 AND status IN ({})",
                    active_status_sql_list()
                ),
                params![cutoff_ms, now_ms],
            )
            .map_err(DbError::from)
        })?
    }

    /// Refresh updated_at only - the awaiting-deploy recheck heartbeat. Keeps
    /// a waiting attempt ahead of expire_stale_fix_attempts without a status
    /// transition.
    #[tracing::instrument(skip(self))]
    pub fn touch_fix_attempt(&self, id: i64, now_ms: i64) -> Result<(), DbError> {
        self.execute(move |conn| {
            conn.execute(
                "UPDATE fix_attempts SET updated_at = ?2 WHERE id = ?1",
                params![id, now_ms],
            )
            .map(|_| ())
            .map_err(DbError::from)
        })?
    }

    /// Count attempts since `since_ms`, excluding verification failures.
    #[tracing::instrument(skip(self))]
    pub fn count_metered_fix_attempts(&self, since_ms: i64) -> Result<u32, DbError> {
        self.execute(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM fix_attempts
                 WHERE created_at >= ?1 AND status != 'verify_failed'",
                params![since_ms],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as u32)
            .map_err(DbError::from)
        })?
    }
}

#[cfg(test)]
#[path = "fix_attempts_tests.rs"]
mod tests;
