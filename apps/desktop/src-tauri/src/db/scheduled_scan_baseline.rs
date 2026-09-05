//! Comparable Web Scan baselines for scheduled regression notifications.

use crate::core::normalized_scan::{ScanEvidenceSource, ScanRunKind, ScanRunStatus};
use crate::core::scan_execution::{
    ScanExecutionMode, ScanExecutionSummary, ScanRunSummary, ScanTrigger,
};
use crate::core::scanner::ScanType;

use super::helpers::{normalize_occurrence_url, normalize_url};
use super::scans::MAX_SCAN_RETENTION;
use super::{Database, DbError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebRunComparisonProfile {
    pub axe_enabled: bool,
    pub browser_ran: bool,
    pub axe_ran: bool,
}

impl WebRunComparisonProfile {
    fn matches(self, diagnostics: &crate::core::normalized_scan::NormalizedRunDiagnostics) -> bool {
        diagnostics.axe_enabled == Some(self.axe_enabled)
            && diagnostics.browser_ran == Some(self.browser_ran)
            && diagnostics.axe_ran == Some(self.axe_ran)
    }
}

fn normalized_scope<'a>(urls: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut normalized = urls
        .into_iter()
        .map(normalize_occurrence_url)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

struct ComparableWebRunBaseline {
    run_id: i64,
    score: u32,
    critical: u32,
    multi_parent_run_id: Option<i64>,
}

fn comparable_web_run_baseline(
    execution: &ScanExecutionSummary,
    run_kind: ScanRunKind,
    profile: WebRunComparisonProfile,
    expected_scope: &[String],
) -> Option<ComparableWebRunBaseline> {
    let run = execution.runs.iter().find(|run| {
        run.source == ScanEvidenceSource::WebScan
            && run.run_kind == run_kind
            && run.status == ScanRunStatus::Complete
    })?;
    if !profile.matches(&run.diagnostics) {
        return None;
    }
    let score = run.raw_score?;
    let expected_scope = normalized_scope(expected_scope.iter().map(String::as_str));
    if expected_scope.is_empty() {
        return None;
    }

    match run_kind {
        ScanRunKind::Single => {
            let selected_url = run
                .diagnostics
                .page_url
                .as_deref()
                .or(execution.environment_url.as_deref())?;
            (normalized_scope([selected_url]) == expected_scope).then_some(
                ComparableWebRunBaseline {
                    run_id: run.id,
                    score,
                    critical: run.issues_critical,
                    multi_parent_run_id: None,
                },
            )
        }
        ScanRunKind::MultiParent => {
            if run.diagnostics.total_pages == Some(0)
                || run.diagnostics.completed_pages != run.diagnostics.total_pages
            {
                return None;
            }
            let page_runs = execution
                .runs
                .iter()
                .filter(|page| {
                    page.source == ScanEvidenceSource::WebScan
                        && page.run_kind == ScanRunKind::Page
                        && page.parent_run_id == Some(run.id)
                })
                .collect::<Vec<&ScanRunSummary>>();
            if page_runs.is_empty()
                || page_runs
                    .iter()
                    .any(|page| page.status != ScanRunStatus::Complete)
            {
                return None;
            }
            let observed_scope = page_runs
                .iter()
                .map(|page| page.diagnostics.page_url.as_deref())
                .collect::<Option<Vec<_>>>()?;
            if normalized_scope(observed_scope) != expected_scope {
                return None;
            }
            Some(ComparableWebRunBaseline {
                run_id: run.id,
                score,
                critical: run.issues_critical,
                multi_parent_run_id: Some(run.id),
            })
        }
        ScanRunKind::Page | ScanRunKind::Code => None,
    }
}

pub fn web_execution_matches_comparison_profile(
    execution: &ScanExecutionSummary,
    run_kind: ScanRunKind,
    profile: WebRunComparisonProfile,
    expected_scope: &[String],
) -> bool {
    comparable_web_run_baseline(execution, run_kind, profile, expected_scope).is_some()
}

impl Database {
    /// Score alerts compare only runs produced by the same scanner and runtime.
    pub fn scan_runs_have_matching_score_provenance(
        &self,
        before_run_id: i64,
        after_run_id: i64,
    ) -> Result<bool, DbError> {
        let before = self.run_release_basis(before_run_id)?;
        let after = self.run_release_basis(after_run_id)?;
        Ok(matches!((before, after), (Some(before), Some(after)) if before.stamp == after.stamp))
    }

    /// Load the comparable score and critical count for scheduler notifications.
    pub fn get_latest_web_run_baseline_for_project(
        &self,
        project_id: i64,
        url: &str,
        run_kind: ScanRunKind,
        web_focus: ScanType,
        requested_mode: ScanExecutionMode,
        profile: WebRunComparisonProfile,
        scope_urls: &[String],
    ) -> Result<Option<(i64, u32, u32)>, DbError> {
        let environment_scope_key = normalize_url(url).0;
        let history = self.get_scan_execution_history(
            Some(project_id),
            Some(environment_scope_key),
            Some(run_kind),
            MAX_SCAN_RETENTION,
        )?;
        let candidate = history.into_iter().find_map(|execution| {
            (execution.trigger == ScanTrigger::Scheduled
                && execution.web_focus == Some(web_focus)
                && execution.requested_mode == requested_mode)
                .then(|| {
                    comparable_web_run_baseline(&execution, run_kind, profile, scope_urls)
                        .map(|baseline| (execution.id, baseline))
                })
                .flatten()
        });
        let Some((execution_id, mut baseline)) = candidate else {
            return Ok(None);
        };
        if let Some(parent_run_id) = baseline.multi_parent_run_id {
            let Some(detail) = self.get_scan_execution_detail(execution_id)? else {
                return Ok(None);
            };
            let page_critical = detail
                .runs
                .iter()
                .filter(|run| {
                    run.source == ScanEvidenceSource::WebScan
                        && run.run_kind == ScanRunKind::Page
                        && run.parent_run_id == Some(parent_run_id)
                })
                .fold(0_u32, |total, run| {
                    total.saturating_add(
                        super::insert::grouped_normalized_finding_counts(&run.findings).critical,
                    )
                });
            baseline.critical = baseline.critical.saturating_add(page_critical);
        }
        Ok(Some((baseline.run_id, baseline.score, baseline.critical)))
    }

    /// Load the most recent comparable scheduler-owned Code Scan result.
    pub fn get_latest_scheduled_code_run_baseline_for_project(
        &self,
        project_id: i64,
        url: &str,
        requested_mode: ScanExecutionMode,
    ) -> Result<Option<super::CodeScanResult>, DbError> {
        let environment_scope_key = normalize_url(url).0;
        let history = self.get_scan_execution_history(
            Some(project_id),
            Some(environment_scope_key),
            Some(ScanRunKind::Code),
            MAX_SCAN_RETENTION,
        )?;
        let run_id = history.into_iter().find_map(|execution| {
            (execution.trigger == ScanTrigger::Scheduled
                && execution.requested_mode == requested_mode)
                .then(|| {
                    execution
                        .runs
                        .iter()
                        .find(|run| {
                            run.source == ScanEvidenceSource::CodeScan
                                && run.run_kind == ScanRunKind::Code
                                && run.status == ScanRunStatus::Complete
                        })
                        .map(|run| run.id)
                })
                .flatten()
        });
        match run_id {
            Some(run_id) => self.get_code_scan_detail(run_id),
            None => Ok(None),
        }
    }
}
