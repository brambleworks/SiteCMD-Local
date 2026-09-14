//! Scan storage, retrieval, and data management.

use super::DbError;
use rusqlite::{named_params, params, Connection, OptionalExtension};

use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};
use crate::core::normalized_scan::{normalize_web_scan, ScanRunKind};
use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionClass, ScanComponent, ScanComponentStatus, ScanExecutionMode,
    ScanTrigger,
};
use crate::core::scanner::ScanResult;
use crate::scoring::calculator::CategoryScore;

use super::from_row::{self, row_u64};
use super::helpers::{normalize_url, parse_required_enum};
use super::types::ScanSummary;
use super::Database;

pub const DEFAULT_SCAN_RETENTION: u32 = 50;
pub const MIN_SCAN_RETENTION: u32 = 1;
pub const MAX_SCAN_RETENTION: u32 = 100;

pub fn normalize_scan_retention(keep_count: Option<u32>) -> u32 {
    keep_count
        .unwrap_or(DEFAULT_SCAN_RETENTION)
        .clamp(MIN_SCAN_RETENTION, MAX_SCAN_RETENTION)
}

impl Database {
    /// Import detached Web results for CLI imports and database fixtures.
    #[tracing::instrument(skip(self, result), fields(site_id))]
    pub fn save_scan(&self, site_id: i64, result: &ScanResult) -> Result<i64, DbError> {
        let (project_id, site_url): (Option<i64>, String) = self.execute(move |conn| {
            conn.query_row(
                "SELECT project_id, url FROM sites WHERE id = ?1",
                [site_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(DbError::from)
        })??;
        let started_at = super::timestamp_text_to_ms(&result.timestamp)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        let environment_scope_key = normalize_url(&site_url).0;
        let action_key = canonical_import_action_key("web")?;
        let execution = self
            .admit_scan_execution(
                NewScanExecution {
                    project_id,
                    environment_id: None,
                    environment_url: Some(site_url.clone()),
                    environment_scope_key: environment_scope_key.clone(),
                    requested_mode: ScanExecutionMode::Web,
                    web_focus: Some(result.scan_type),
                    trigger: ScanTrigger::Migration,
                    admission_class: ScanAdmissionClass::SystemExempt,
                    idempotency_key: action_key.clone(),
                    request_fingerprint: format!("v1:{action_key}"),
                    now_ms: started_at,
                    web_status: Some(ScanComponentStatus::Planned),
                    web_detail: None,
                    code_status: None,
                    code_detail: None,
                },
                crate::constants::SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
            )
            .map_err(|error| DbError::Other(error.to_string()))?
            .execution;
        self.start_scan_execution_component(execution.id, ScanComponent::Web)?;
        let mut batch = normalize_web_scan(
            result,
            execution.id,
            None,
            project_id,
            site_id,
            ScanRunKind::Single,
            started_at,
        )?;
        batch.environment_url = Some(site_url);
        batch.environment_scope_key = environment_scope_key;
        let run_id = match self.persist_normalized_scan_run(batch) {
            Ok(run_id) => run_id,
            Err(error) => {
                let _ = self.finish_scan_execution_component(
                    execution.id,
                    ScanComponent::Web,
                    ScanComponentStatus::Failed,
                    Some(error.to_string()),
                    chrono::Utc::now().timestamp_millis(),
                );
                return Err(error);
            }
        };
        self.finish_scan_execution_component(
            execution.id,
            ScanComponent::Web,
            ScanComponentStatus::Complete,
            None,
            started_at.saturating_add(result.duration_ms as i64),
        )?;
        let timestamp = result.timestamp.clone();
        self.execute(move |conn| {
            conn.execute(
                "UPDATE sites SET last_scanned_at = :ts WHERE id = :site_id",
                named_params! { ":ts": timestamp, ":site_id": site_id },
            )?;
            Ok::<_, DbError>(())
        })??;
        Ok(run_id)
    }

    /// Clear all canonical scan history and scan-derived work items. Keeps
    /// projects, sites, integrations, and non-scan signals.
    #[tracing::instrument(skip(self))]
    pub fn clear_scan_history(&self) -> Result<u64, DbError> {
        self.execute_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "DELETE FROM work_items
                 WHERE source IN ('web_scan', 'site_scan', 'code_scan')",
                [],
            )?;
            let deleted = tx.execute("DELETE FROM scan_executions", [])?;
            tx.commit()?;
            Ok(deleted as u64)
        })?
    }

    /// Delete the execution owning a canonical run and its scan-derived work
    /// items. History deletion is execution-atomic, including Full and
    /// multi-page children.
    #[tracing::instrument(skip(self), fields(scan_id))]
    pub fn delete_scan(&self, scan_id: i64) -> Result<(), DbError> {
        self.execute_mut(move |conn| {
            let tx = conn.transaction()?;
            let execution_id: Option<i64> = tx
                .query_row(
                    "SELECT execution_id FROM scan_runs WHERE id = ?1",
                    params![scan_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(execution_id) = execution_id {
                tx.execute(
                    "DELETE FROM work_items
                     WHERE source IN ('web_scan', 'site_scan', 'code_scan')
                       AND scan_ref IN (
                           SELECT id FROM scan_runs WHERE execution_id = ?1
                       )",
                    params![execution_id],
                )?;
                tx.execute(
                    "DELETE FROM scan_executions WHERE id = ?1",
                    params![execution_id],
                )?;
            }
            tx.commit()?;
            Ok(())
        })?
    }

    /// Delete all executions containing a Web run for a specific site.
    #[tracing::instrument(skip(self), fields(site_id))]
    pub fn delete_site_scans(&self, site_id: i64) -> Result<u64, DbError> {
        self.execute_mut(move |conn| {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TEMP TABLE IF NOT EXISTS temp_deleted_executions (
                     execution_id INTEGER PRIMARY KEY
                 ) WITHOUT ROWID;
                 DELETE FROM temp_deleted_executions;",
            )?;
            tx.execute(
                "INSERT INTO temp_deleted_executions(execution_id)
                 SELECT DISTINCT execution_id FROM scan_runs WHERE site_id = ?1",
                params![site_id],
            )?;
            tx.execute(
                "DELETE FROM work_items
                 WHERE source IN ('web_scan', 'site_scan', 'code_scan')
                   AND scan_ref IN (
                       SELECT run.id FROM scan_runs run
                       JOIN temp_deleted_executions doomed
                         ON doomed.execution_id = run.execution_id
                   )",
                [],
            )?;
            let deleted = tx.execute(
                "DELETE FROM scan_executions
                 WHERE id IN (SELECT execution_id FROM temp_deleted_executions)",
                [],
            )?;
            tx.execute("DELETE FROM temp_deleted_executions", [])?;
            tx.commit()?;
            Ok(deleted as u64)
        })?
    }

    /// Find open issue links for a project whose checks are now passing.
    /// Returns (link_id, check_id, provider, external_id) tuples that need external resolution.
    #[tracing::instrument(skip(self), fields(project_id, passing_check_ids = ?passing_check_ids))]
    pub fn find_resolvable_issue_links(
        &self,
        project_id: i64,
        passing_check_ids: Vec<String>,
    ) -> Result<Vec<(i64, String, String, String)>, DbError> {
        self.execute(move |conn| {
            if passing_check_ids.is_empty() {
                return Ok(Vec::new());
            }
            let placeholders: String = (0..passing_check_ids.len())
                .map(|i| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT id, check_id, provider, external_id
                 FROM issue_links
                 WHERE project_id = ?1 AND status = 'open' AND check_id IN ({})",
                placeholders
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(project_id)];
            for id in &passing_check_ids {
                params_vec.push(Box::new(id.clone()));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|b| b.as_ref()).collect();

            let rows = stmt
                .query_map(param_refs.as_slice(), |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(rows)
        })?
    }

    /// Count scans for a site
    #[tracing::instrument(skip(self), fields(site_id))]
    pub fn get_scan_count(&self, site_id: i64) -> Result<u64, DbError> {
        self.execute(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(DISTINCT execution_id)
                 FROM scan_runs
                 WHERE site_id = ?1 AND source = 'web_scan'",
                params![site_id],
                |row| row.get(0),
            )?;
            Ok(count as u64)
        })?
    }

    /// Get scan history for a URL
    #[tracing::instrument(skip(self, url), fields(limit))]
    pub fn get_scan_history(&self, url: &str, limit: u32) -> Result<Vec<ScanSummary>, DbError> {
        self.get_scan_history_for_scope(None, url, limit)
    }

    /// Get scan history for one explicitly selected project environment.
    #[tracing::instrument(skip(self, url), fields(project_id, limit))]
    pub fn get_scan_history_for_project(
        &self,
        project_id: i64,
        url: &str,
        limit: u32,
    ) -> Result<Vec<ScanSummary>, DbError> {
        self.get_scan_history_for_scope(Some(project_id), url, limit)
    }

    fn get_scan_history_for_scope(
        &self,
        project_id: Option<i64>,
        url: &str,
        limit: u32,
    ) -> Result<Vec<ScanSummary>, DbError> {
        let url = url.to_string();
        self.execute(move |conn| {
            let normalized = normalize_url(&url).0;
            let mut stmt = conn.prepare(
                "SELECT run.id AS id,
                        COALESCE(run.page_url, run.environment_url, run.environment_scope_key) AS url,
                        COALESCE(run.mode, 'live') AS mode,
                        run.raw_score AS overall_score,
                        run.issues_total AS issues_total,
                        run.issues_critical AS issues_critical,
                        run.issues_high AS issues_high,
                        run.issues_medium AS issues_medium,
                        run.issues_low AS issues_low,
                        run.duration_ms AS duration_ms,
                        run.timestamp_text AS timestamp,
                        run.parent_run_id AS session_id,
                        run.page_url AS page_url,
                        COALESCE(run.focus, 'health') AS scan_type
                 FROM scan_runs run
                 WHERE run.source = 'web_scan'
                   AND run.run_kind IN ('single', 'page')
                   AND run.status = 'complete'
                   AND run.environment_scope_key = :environment_scope_key
                   AND (:project_id IS NULL OR run.project_id = :project_id)
                 ORDER BY run.started_at DESC, run.id DESC
                 LIMIT :limit",
            )?;
            let rows = stmt.query_map(
                named_params! {
                    ":environment_scope_key": normalized,
                    ":project_id": project_id,
                    ":limit": limit,
                },
                <ScanSummary as from_row::FromRow>::from_row,
            )?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?
    }

    /// Get full scan details by scan ID
    #[tracing::instrument(skip(self), fields(scan_id))]
    pub fn get_scan_detail(&self, scan_id: i64) -> Result<Option<ScanResult>, DbError> {
        self.execute(move |conn| {
            let scan_row = conn.query_row(
                "SELECT COALESCE(run.page_url, run.environment_url, run.environment_scope_key),
                        COALESCE(run.mode, 'live'), run.raw_score,
                        run.duration_ms, run.timestamp_text, run.detected_stack,
                        run.security_score, run.performance_score, run.seo_score,
                        run.accessibility_score, run.compliance_score, run.config_score,
                        run.polish_score, COALESCE(run.focus, 'health')
                 FROM scan_runs run
                 WHERE run.id = ?1 AND run.source = 'web_scan'",
                params![scan_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row_u64(row, 3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<u32>>(6)?,
                        row.get::<_, Option<u32>>(7)?,
                        row.get::<_, Option<u32>>(8)?,
                        row.get::<_, Option<u32>>(9)?,
                        row.get::<_, Option<u32>>(10)?,
                        row.get::<_, Option<u32>>(11)?,
                        row.get::<_, Option<u32>>(12)?,
                        row.get::<_, String>(13)?,
                    ))
                },
            );

            let (
                url,
                mode,
                overall_score,
                duration_ms,
                timestamp,
                detected_stack_json,
                sec_score,
                perf_score,
                seo_score,
                accessibility_score,
                comp_score,
                cfg_score,
                polish_score,
                scan_type,
            ) = match scan_row {
                Ok(r) => r,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(e.into()),
            };

            let issues = load_scan_issue_snapshot(conn, scan_id)?;

            // Tally every category in one pass over the issue vec instead of
            // re-scanning it once per category and severity (~5 x 7 passes).
            let counts = count_issues_by_category(&issues);
            let mut categories = Vec::new();
            let cat_scores = [
                (ScanCategory::Security, sec_score),
                (ScanCategory::Performance, perf_score),
                (ScanCategory::Seo, seo_score),
                (ScanCategory::Accessibility, accessibility_score),
                (ScanCategory::Compliance, comp_score),
                (ScanCategory::Config, cfg_score),
                (ScanCategory::Polish, polish_score),
            ];
            for (cat, score_opt) in cat_scores {
                if let Some(score) = score_opt {
                    let c = counts.get(&cat).copied().unwrap_or_default();
                    categories.push(CategoryScore {
                        category: cat,
                        score,
                        issues_total: c.total,
                        issues_critical: c.critical,
                        issues_high: c.high,
                        issues_medium: c.medium,
                        issues_low: c.low,
                        issues_passed: c.passed,
                    });
                }
            }

            let detected_stack = detected_stack_json
                .map(|value| {
                    serde_json::from_str(&value).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })
                .transpose()?;

            Ok(Some(ScanResult {
                page_signals: None,
                site_facts: None,
                url,
                mode,
                scan_type: parse_required_enum(13, "scan_type", &scan_type)?,
                overall_score,
                categories,
                issues,
                detected_stack,
                duration_ms,
                timestamp,
            }))
        })?
    }

    /// Returns the prior scan's canonical check-to-severity map for an
    /// environment, excluding `current_scan_id`. Version-zero scans fall back
    /// to work items, and duplicate canonical groups keep the highest severity.
    pub fn get_prior_scan_check_severities(
        &self,
        env_url: &str,
        current_scan_id: i64,
        source: &str,
    ) -> Result<std::collections::HashMap<String, String>, DbError> {
        let env_url = super::helpers::normalize_url(env_url).0;
        let source = source.to_string();
        self.execute(move |conn| {
            let mut out: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            let mut record = |check_id: String, severity: String| -> Result<(), DbError> {
                let parsed: Severity = severity.parse().map_err(|error: String| {
                    DbError::Other(format!("invalid prior-scan severity: {error}"))
                })?;
                let replace = out
                    .get(&check_id)
                    .and_then(|existing| existing.parse::<Severity>().ok())
                    .is_none_or(|existing| parsed.impact_rank() > existing.impact_rank());
                if replace {
                    out.insert(check_id, parsed.as_str().to_string());
                }
                Ok(())
            };

            match source.as_str() {
                "web_scan" | "site_scan" => {
                    let run_kind = if source == "site_scan" {
                        "multi_parent"
                    } else {
                        "page"
                    };
                    let prior_scan_id: Option<i64> = conn
                        .query_row(
                            "SELECT prior.id
                             FROM scan_runs prior
                             JOIN scan_runs current ON current.id = ?2
                             WHERE prior.source = 'web_scan'
                               AND prior.id != current.id
                               AND prior.status = 'complete'
                               AND prior.environment_scope_key = ?1
                               AND (
                                   (?3 = 'multi_parent' AND prior.run_kind = 'multi_parent')
                                   OR (?3 = 'page'
                                       AND prior.run_kind IN ('single', 'page')
                                       AND COALESCE(prior.page_url, prior.environment_scope_key) =
                                           COALESCE(current.page_url, current.environment_scope_key))
                               )
                             ORDER BY prior.started_at DESC, prior.id DESC
                             LIMIT 1",
                            params![env_url, current_scan_id, run_kind],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let Some(prior_scan_id) = prior_scan_id else {
                        return Ok(out);
                    };
                    let mut stmt = conn.prepare(
                        "SELECT canonical_check_id, severity
                         FROM scan_findings
                         WHERE run_id = ?1 AND verdict IN ('fail', 'warn')
                         ORDER BY ordinal",
                    )?;
                    let rows = stmt.query_map(params![prior_scan_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?;
                    for row in rows {
                        let (check_id, severity) = row?;
                        record(check_id, severity)?;
                    }
                }
                "code_scan" => {
                    let prior_scan_id: Option<i64> = conn
                        .query_row(
                            "SELECT prior.id
                             FROM scan_runs current
                             JOIN scan_runs prior
                               ON prior.project_id = current.project_id
                              AND prior.environment_scope_key = current.environment_scope_key
                             WHERE current.id = ?1
                               AND current.source = 'code_scan'
                               AND prior.source = 'code_scan'
                               AND prior.run_kind = 'code'
                               AND prior.status = 'complete'
                               AND prior.id != current.id
                             ORDER BY prior.started_at DESC, prior.id DESC
                             LIMIT 1",
                            params![current_scan_id],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let Some(prior_scan_id) = prior_scan_id else {
                        return Ok(out);
                    };
                    let mut stmt = conn.prepare(
                        "SELECT canonical_check_id, severity
                         FROM scan_findings
                         WHERE run_id = ?1 AND verdict IN ('fail', 'warn')
                         ORDER BY ordinal",
                    )?;
                    let rows = stmt.query_map(params![prior_scan_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?;
                    for row in rows {
                        let (check_id, severity) = row?;
                        record(check_id, severity)?;
                    }
                }
                other => {
                    return Err(DbError::Other(format!(
                        "unsupported regression source: {other}"
                    )));
                }
            }
            Ok(out)
        })?
    }
}

pub(super) fn canonical_import_action_key(prefix: &str) -> Result<String, DbError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| DbError::Other(format!("could not create import action key: {error}")))?;
    Ok(format!("migration:{prefix}:{}", hex::encode(random)))
}

fn load_scan_issue_snapshot(conn: &Connection, scan_id: i64) -> Result<Vec<CheckResult>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT producer_category, producer_check_id, severity, verdict,
                title, description, producer_fix_prompt, manual_fix, raw_data, why_it_matters,
                confidence, confidence_reason
         FROM scan_findings
         WHERE run_id = ?1 AND source = 'web_scan'
         ORDER BY ordinal",
    )?;
    let issues = stmt
        .query_map(params![scan_id], check_result_from_snapshot_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(issues)
}

fn check_result_from_snapshot_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CheckResult> {
    let category: String = row.get(0)?;
    let severity: String = row.get(2)?;
    let status: Option<String> = row.get(3)?;
    let raw_data: Option<String> = row.get(8)?;
    let confidence: Option<String> = row.get(10)?;
    let raw_data = raw_data
        .map(|value| {
            serde_json::from_str(&value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    let status = match status.as_deref() {
        Some(value) => parse_required_enum(3, "verdict", value)?,
        None => {
            return Err(rusqlite::Error::InvalidColumnType(
                3,
                "check_status".into(),
                rusqlite::types::Type::Null,
            ))
        }
    };
    let confidence = match confidence.as_deref() {
        Some(value) => parse_required_enum(10, "confidence", value)?,
        None => {
            return Err(rusqlite::Error::InvalidColumnType(
                10,
                "confidence".into(),
                rusqlite::types::Type::Null,
            ))
        }
    };

    Ok(CheckResult {
        category: parse_required_enum(0, "category", &category)?,
        check_id: row.get(1)?,
        severity: parse_required_enum(2, "severity", &severity)?,
        status,
        title: row.get(4)?,
        description: row.get(5)?,
        fix_prompt: row.get(6)?,
        manual_fix: row.get(7)?,
        raw_data,
        confidence,
        confidence_reason: row.get(11)?,
        why_it_matters: row.get(9)?,
    })
}

/// Per-category issue tallies accumulated in one pass.
#[derive(Clone, Copy, Default)]
struct CategoryIssueCounts {
    total: u32,
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    passed: u32,
}

/// Tally issues by category in one pass, matching
/// `scoring::calculator::calculate_scores`: Fail/Warn populate issue and
/// severity counts, Pass populates `passed`, and Skipped populates neither.
fn count_issues_by_category(
    issues: &[CheckResult],
) -> std::collections::HashMap<ScanCategory, CategoryIssueCounts> {
    let mut counts: std::collections::HashMap<ScanCategory, CategoryIssueCounts> =
        std::collections::HashMap::new();
    for issue in issues {
        let entry = counts.entry(issue.category).or_default();
        match issue.status {
            CheckStatus::Pass => entry.passed += 1,
            CheckStatus::Skipped => {}
            CheckStatus::Fail | CheckStatus::Warn => {
                entry.total += 1;
                match issue.severity {
                    Severity::Critical => entry.critical += 1,
                    Severity::High => entry.high += 1,
                    Severity::Medium => entry.medium += 1,
                    Severity::Low => entry.low += 1,
                }
            }
        }
    }
    counts
}

#[cfg(test)]
#[path = "scans_tests.rs"]
mod tests;
