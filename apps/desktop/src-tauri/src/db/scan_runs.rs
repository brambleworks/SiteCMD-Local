//! Canonical persistence for immutable scan runs and findings.

use std::collections::HashSet;

use rusqlite::{named_params, params, Connection, OptionalExtension, Transaction};

use crate::core::normalized_scan::{
    actionable_findings, NormalizedFinding, NormalizedRunBatch, ScanEvidenceSource, ScanRunKind,
};
use crate::core::scan_types::CheckStatus;

use super::scan_run_projection::reconcile_scan_projection;
use super::{Database, DbError};

/// The scope revision the run was scoped by, when the site has one. Part of
/// the captured basis: two runs taken under different scopes covered different
/// routes, so an absence in one says nothing about the other.
fn scope_revision(conn: &Connection, site_id: Option<i64>) -> Option<i64> {
    let site_id = site_id?;
    conn.query_row(
        "SELECT scope_revision FROM sites WHERE id = ?1",
        params![site_id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .ok()
    .flatten()
}

fn validate_batch(batch: &NormalizedRunBatch) -> Result<(), DbError> {
    batch.coverage.validate().map_err(DbError::Other)?;
    if batch.completed_at < batch.started_at {
        return Err(DbError::Other(
            "scan run completion precedes its start".to_string(),
        ));
    }
    if batch.run_kind != ScanRunKind::Code {
        return Err(DbError::Other(
            "scan run source and kind are inconsistent".into(),
        ));
    }
    let mut occurrences = HashSet::with_capacity(batch.findings.len());
    for finding in &batch.findings {
        if finding.source != batch.source {
            return Err(DbError::Other(
                "scan finding source differs from its run source".to_string(),
            ));
        }
        if finding.canonical_check_id.trim().is_empty()
            || finding.producer_check_id.trim().is_empty()
            || finding.occurrence_id.trim().is_empty()
        {
            return Err(DbError::Other(
                "scan finding identities must be non-empty".to_string(),
            ));
        }
        if !occurrences.insert(finding.occurrence_id.as_str()) {
            return Err(DbError::Other(format!(
                "duplicate occurrence in normalized scan batch: {}",
                finding.occurrence_id
            )));
        }
    }
    Ok(())
}

fn passed_count(findings: &[NormalizedFinding]) -> i64 {
    findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.verdict,
                CheckStatus::Pass | CheckStatus::NotApplicable
            )
        })
        .count() as i64
}

fn insert_findings(
    tx: &Transaction<'_>,
    run_id: i64,
    batch: &NormalizedRunBatch,
) -> Result<(), DbError> {
    let mut statement = tx.prepare(
        "INSERT INTO scan_findings (
            run_id, ordinal, occurrence_id, source,
            canonical_check_id, producer_check_id, category,
            producer_category, domain, verdict, severity, confidence,
            confidence_reason, title, description, fix_prompt,
            producer_fix_prompt, manual_fix, why_it_matters,
            verification_hint, raw_data, detail_json, location_kind,
            page_url, relative_path, line
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
            ?24, ?25, ?26
         )",
    )?;
    for (ordinal, finding) in batch.findings.iter().enumerate() {
        statement.execute(params![
            run_id,
            i64::try_from(ordinal)
                .map_err(|_| DbError::Other("scan finding ordinal exceeds SQLite range".into()))?,
            finding.occurrence_id,
            finding.source.as_str(),
            finding.canonical_check_id,
            finding.producer_check_id,
            finding.category,
            finding.producer_category,
            finding.domain,
            finding.verdict.as_str(),
            finding.severity.as_str(),
            finding.confidence.as_str(),
            finding.confidence_reason,
            finding.title,
            finding.description,
            finding.fix_prompt,
            finding.producer_fix_prompt,
            finding.manual_fix,
            finding.why_it_matters,
            finding.verification_hint,
            finding.raw_data,
            finding.detail_json,
            finding.location_kind.as_str(),
            finding.page_url,
            finding.relative_path,
            finding.line.map(i64::from),
        ])?;
    }
    Ok(())
}

impl Database {
    /// Persist one completed (or explicitly failed/skipped) collector run and
    /// reconcile only the lifecycle scope its coverage proves.
    #[tracing::instrument(skip(self, batch), fields(execution_id = batch.execution_id, source = batch.source.as_str(), run_kind = batch.run_kind.as_str()))]
    pub fn persist_normalized_scan_run(&self, batch: NormalizedRunBatch) -> Result<i64, DbError> {
        if batch.source != ScanEvidenceSource::CodeScan {
            return Err(DbError::Other(
                "only code scan runs can be stored locally".into(),
            ));
        }
        validate_batch(&batch)?;
        self.execute_mut(move |conn| persist_run_batch(conn, batch))?
    }
}

/// Insert one normalized run with its findings and reconcile the lifecycle
/// projection, all inside a single transaction.
fn persist_run_batch(conn: &mut Connection, batch: NormalizedRunBatch) -> Result<i64, DbError> {
    let tx = conn.transaction()?;
    let coverage_json = serde_json::to_string(&batch.coverage)?;
    let diagnostics_json = serde_json::to_string(&batch.diagnostics)?;
    let actionable = actionable_findings(&batch.findings).collect::<Vec<_>>();
    let count = |severity: crate::core::scan_types::Severity| -> i64 {
        actionable
            .iter()
            .filter(|finding| finding.severity == severity)
            .count() as i64
    };
    let passed = passed_count(&batch.findings);
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    let stamp = crate::core::engine_release::code_stamp(
        engine.info(),
        batch
            .diagnostics
            .focus
            .as_deref()
            .or(batch.diagnostics.mode.as_deref()),
    );
    let run_scope_revision = scope_revision(&tx, batch.site_id);

    tx.execute(
                "INSERT INTO scan_runs (
                    execution_id, parent_run_id, project_id, site_id,
                    environment_url, environment_scope_key, source, run_kind,
                    status, focus,
                    started_at, completed_at, timestamp_text,
                    duration_ms, coverage_kind, coverage_json,
                    diagnostics_json, status_detail, detail_state, mode,
                    security_score, performance_score, seo_score,
                    accessibility_score, compliance_score, config_score,
                    polish_score, issues_total, issues_critical, issues_high,
                    issues_medium, issues_low, issues_passed, detected_stack,
                    page_url, total_pages, completed_pages, axe_enabled,
                    project_path, framework, engine_release, manifest_digest,
                    canonicalizer, crawl_profile, execution_profile_json,
                    scope_revision, code_commit_sha, code_tree_clean
                 ) VALUES (
                    :execution_id, :parent_run_id, :project_id, :site_id,
                    :environment_url, :environment_scope_key, :source,
                    :run_kind, :status, :focus,
                    :started_at, :completed_at, :timestamp_text,
                    :duration_ms, :coverage_kind, :coverage_json,
                    :diagnostics_json, :status_detail, 'exact', :mode,
                    :security_score, :performance_score, :seo_score,
                    :accessibility_score, :compliance_score, :config_score,
                    :polish_score, :issues_total, :issues_critical, :issues_high,
                    :issues_medium, :issues_low, :issues_passed, :detected_stack,
                    :page_url, :total_pages, :completed_pages, :axe_enabled,
                    :project_path, :framework, :engine_release,
                    :manifest_digest, :canonicalizer, :crawl_profile,
                    :execution_profile_json, :scope_revision,
                    :code_commit_sha, :code_tree_clean
                 )",
                named_params! {
                    ":execution_id": batch.execution_id,
                    ":parent_run_id": batch.parent_run_id,
                    ":project_id": batch.project_id,
                    ":site_id": batch.site_id,
                    ":environment_url": batch.environment_url,
                    ":environment_scope_key": batch.environment_scope_key,
                    ":source": batch.source.as_str(),
                    ":run_kind": batch.run_kind.as_str(),
                    ":status": batch.status.as_str(),
                    ":focus": batch.diagnostics.focus,
                    ":started_at": batch.started_at,
                    ":completed_at": batch.completed_at,
                    ":timestamp_text": batch.timestamp_text,
                    ":duration_ms": i64::try_from(batch.duration_ms).map_err(|_| DbError::Other("scan duration exceeds SQLite range".into()))?,
                    ":coverage_kind": batch.coverage.kind.as_str(),
                    ":coverage_json": coverage_json,
                    ":diagnostics_json": diagnostics_json,
                    ":status_detail": batch.status_detail,
                    ":mode": batch.diagnostics.mode,
                    ":security_score": batch.diagnostics.security_score.map(i64::from),
                    ":performance_score": batch.diagnostics.performance_score.map(i64::from),
                    ":seo_score": batch.diagnostics.seo_score.map(i64::from),
                    ":accessibility_score": batch.diagnostics.accessibility_score.map(i64::from),
                    ":compliance_score": batch.diagnostics.compliance_score.map(i64::from),
                    ":config_score": batch.diagnostics.config_score.map(i64::from),
                    ":polish_score": batch.diagnostics.polish_score.map(i64::from),
                    ":issues_total": actionable.len() as i64,
                    ":issues_critical": count(crate::core::scan_types::Severity::Critical),
                    ":issues_high": count(crate::core::scan_types::Severity::High),
                    ":issues_medium": count(crate::core::scan_types::Severity::Medium),
                    ":issues_low": count(crate::core::scan_types::Severity::Low),
                    ":issues_passed": passed,
                    ":detected_stack": batch.diagnostics.detected_stack,
                    ":page_url": batch.diagnostics.page_url,
                    ":project_path": batch.diagnostics.project_path,
                    ":framework": batch.diagnostics.framework,
                    ":code_commit_sha": batch.diagnostics.code_commit_sha,
                    ":code_tree_clean": batch.diagnostics.code_tree_clean.map(i64::from),
                    ":total_pages": batch.diagnostics.total_pages.map(i64::from),
                    ":completed_pages": batch.diagnostics.completed_pages.map(i64::from),
                    ":axe_enabled": batch.diagnostics.axe_enabled.map(i64::from),
                    ":engine_release": stamp.engine_release,
                    ":manifest_digest": stamp.manifest_digest,
                    ":canonicalizer": i64::from(stamp.canonicalizer),
                    ":crawl_profile": i64::from(stamp.crawl_profile),
                    ":execution_profile_json": serde_json::to_string(&stamp.execution)?,
                    ":scope_revision": run_scope_revision,
                },
            )?;
    let run_id = tx.last_insert_rowid();
    insert_findings(&tx, run_id, &batch)?;
    reconcile_scan_projection(&tx, run_id, &batch)?;
    tx.commit()?;
    Ok(run_id)
}

#[cfg(test)]
#[path = "scan_runs_tests.rs"]
mod tests;
