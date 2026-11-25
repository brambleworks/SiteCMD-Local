//! Transactional reconciliation of canonical scan runs and work-item projections.

use std::collections::BTreeSet;

use rusqlite::{params, Transaction};
use sitecmd_protocol::coverage::exact_claim_key;

use super::helpers::lifecycle_env_url;
use super::issue_states::reconcile_reobserved_lifecycle;
use super::DbError;
use crate::core::normalized_scan::{
    actionable_findings, NormalizedFinding, NormalizedRunBatch, ScanEvidenceSource,
};

pub(crate) fn reconcile_scan_projection(
    tx: &Transaction<'_>,
    run_id: i64,
    batch: &NormalizedRunBatch,
) -> Result<(), DbError> {
    let Some(project_id) = batch.project_id else {
        return Ok(());
    };
    let environment_url = lifecycle_env_url(&batch.environment_scope_key);
    let source = ScanEvidenceSource::CodeScan.as_str();
    let observed_at = batch.completed_at;
    let observed: Vec<&NormalizedFinding> = actionable_findings(&batch.findings).collect();

    for finding in &observed {
        let detail_json = finding.detail_json.as_ref().or(finding.raw_data.as_ref());
        tx.execute(
            "INSERT INTO work_items
                (project_id, env_url, source, signal_id, check_id, category,
                 severity, title, description, detail_json, scan_ref, page_url,
                 fix_prompt, manual_fix, why_it_matters, first_seen_at,
                 last_seen_at, resolved_at, confidence, domain, relative_path,
                 line, check_status, confidence_reason, producer_check_id,
                 producer_fix_prompt, producer_category, first_seen_scan_ref,
                 resolved_scan_ref)
             VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?16, NULL, ?17, ?18, ?19, ?20, ?21, ?22,
                 ?23, ?24, ?25, ?11, NULL
             )
             ON CONFLICT(project_id, env_url, source, signal_id)
                 WHERE resolved_at IS NULL
             DO UPDATE SET
                 last_seen_at = excluded.last_seen_at,
                 category = excluded.category,
                 severity = excluded.severity,
                 title = excluded.title,
                 description = excluded.description,
                 detail_json = excluded.detail_json,
                 scan_ref = excluded.scan_ref,
                 page_url = excluded.page_url,
                 fix_prompt = excluded.fix_prompt,
                 manual_fix = excluded.manual_fix,
                 why_it_matters = excluded.why_it_matters,
                 confidence = excluded.confidence,
                 domain = excluded.domain,
                 relative_path = excluded.relative_path,
                 line = excluded.line,
                 check_status = excluded.check_status,
                 confidence_reason = excluded.confidence_reason,
                 producer_check_id = excluded.producer_check_id,
                 producer_fix_prompt = excluded.producer_fix_prompt,
                 producer_category = excluded.producer_category",
            params![
                project_id,
                environment_url,
                source,
                finding.occurrence_id,
                finding.canonical_check_id,
                finding.category,
                finding.severity.as_str(),
                finding.title,
                finding.description,
                detail_json,
                run_id,
                finding.page_url,
                finding.fix_prompt,
                finding.manual_fix,
                finding.why_it_matters,
                observed_at,
                finding.confidence.as_str(),
                finding.domain,
                finding.relative_path,
                finding.line.map(i64::from),
                finding.verdict.as_str(),
                finding.confidence_reason,
                finding.producer_check_id,
                finding.producer_fix_prompt,
                Option::<&str>::None,
            ],
        )?;
    }

    reconcile_reobserved_lifecycle(
        tx,
        project_id,
        &environment_url,
        observed_at,
        observed
            .iter()
            .map(|finding| finding.canonical_check_id.as_str()),
    )?;

    resolve_covered_absences(
        tx,
        ResolveScope {
            run_id,
            observed_at,
            project_id,
            source,
            environment_url: &environment_url,
        },
        batch,
        &observed,
    )
}

/// The lifecycle rows one run may speak for.
struct ResolveScope<'a> {
    run_id: i64,
    observed_at: i64,
    project_id: i64,
    source: &'a str,
    environment_url: &'a str,
}

/// Resolve absent open rows only for checks the code run covered.
fn resolve_covered_absences(
    tx: &Transaction<'_>,
    scope: ResolveScope<'_>,
    batch: &NormalizedRunBatch,
    observed: &[&NormalizedFinding],
) -> Result<(), DbError> {
    if !batch.coverage.successful {
        return Ok(());
    }
    let seen: BTreeSet<&str> = observed
        .iter()
        .map(|finding| finding.occurrence_id.as_str())
        .collect();

    let resolved: Vec<i64> = load_open_candidates(tx, &scope)?
        .into_iter()
        .filter(|candidate| {
            !seen.contains(candidate.signal_id.as_str())
                && sitecmd_protocol::coverage::covers(
                    &batch.coverage,
                    None,
                    &candidate.check_id,
                    exact_claim_key,
                )
        })
        .map(|candidate| candidate.id)
        .collect();

    for id in resolved {
        tx.execute(
            "UPDATE work_items
             SET resolved_at = ?1, resolved_scan_ref = ?2
             WHERE id = ?3",
            params![scope.observed_at, scope.run_id, id],
        )?;
    }
    Ok(())
}

/// One open lifecycle row a run may speak for.
struct OpenCandidate {
    id: i64,
    signal_id: String,
    check_id: String,
}

/// Load open rows in the code run's lifecycle scope.
fn load_open_candidates(
    tx: &Transaction<'_>,
    scope: &ResolveScope<'_>,
) -> Result<Vec<OpenCandidate>, DbError> {
    let mut statement = tx.prepare(
        "SELECT id, signal_id, check_id FROM work_items
         WHERE source = ?1 AND project_id = ?2 AND env_url = ?3
           AND resolved_at IS NULL",
    )?;
    let candidates = statement
        .query_map(
            params![scope.source, scope.project_id, scope.environment_url],
            |row| {
                Ok(OpenCandidate {
                    id: row.get(0)?,
                    signal_id: row.get(1)?,
                    check_id: row.get(2)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(candidates)
}

#[cfg(test)]
#[path = "scan_run_projection_tests.rs"]
mod tests;
