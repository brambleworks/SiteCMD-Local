//! Normalize module-backed Code Scan reports and coverage.

use std::collections::HashSet;

use sitecmd_protocol::engine_abi::{EngineInfo, FixTextTarget};

use crate::core::audit::{code_producer_rule_id, CodeScanReport, UNKNOWN_CODE_RULE};
use crate::core::code_provenance::CodeCheckoutProvenance;

use super::{
    CheckStatus, NormalizedFinding, NormalizedRunBatch, NormalizedRunDiagnostics, ScanCoverageKind,
    ScanCoverageManifest, ScanEvidenceSource, ScanFindingLocationKind, ScanRunKind, ScanRunStatus,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn normalize_code_scan_with_inventory(
    report: &CodeScanReport,
    execution_id: i64,
    project_id: i64,
    environment_url: Option<String>,
    environment_scope_key: String,
    project_path: String,
    duration_ms: u64,
    started_at: i64,
    info: &EngineInfo,
) -> Result<NormalizedRunBatch, String> {
    let positions = crate::core::audit::fingerprints::ordinals(&report.issues);
    let mut seen = HashSet::new();
    let mut issues = Vec::new();
    for (issue, ordinal) in report.issues.iter().zip(positions) {
        if seen.insert((issue.id.as_str(), issue.relative_path.as_str(), issue.line)) {
            let rule = info
                .code_rule(code_producer_rule_id(&issue.id))
                .ok_or(UNKNOWN_CODE_RULE)?;
            issues.push((issue, ordinal, rule));
        }
    }
    let framework = report.framework.as_deref().unwrap_or("not detected");
    let prompts = crate::core::fixes::fix_text(
        issues
            .iter()
            .map(|(issue, _, _)| {
                let mut issue = (*issue).clone();
                issue.evidence = None;
                issue.absolute_path.clear();
                FixTextTarget::Code {
                    issue: Box::new(issue),
                    framework: framework.into(),
                }
            })
            .collect(),
    )?;
    let findings = issues
        .into_iter()
        .zip(prompts)
        .map(|((issue, ordinal, rule), fix_prompt)| {
            let canonical_check_id = rule.check_id.clone();
            let mut persisted_issue = issue.clone();
            persisted_issue.check_id = canonical_check_id.clone();
            let mut detail = serde_json::to_value(&persisted_issue)?;
            detail["suppressionOrdinal"] = serde_json::json!(ordinal);
            Ok(NormalizedFinding {
                occurrence_id: code_scan_occurrence_id(issue),
                source: ScanEvidenceSource::CodeScan,
                canonical_check_id,
                producer_check_id: rule.id.clone(),
                producer_category: issue.category.clone(),
                category: rule.category.key().into(),
                domain: Some(rule.domain.as_str().to_string()),
                verdict: CheckStatus::Fail,
                severity: issue.severity,
                confidence: issue.confidence,
                confidence_reason: issue.confidence_reason.clone(),
                title: issue.title.clone(),
                description: issue.description.clone(),
                fix_prompt: Some(fix_prompt),
                producer_fix_prompt: issue.likely_fix.clone(),
                manual_fix: None,
                why_it_matters: issue.why_now.clone(),
                verification_hint: issue.verify_hint.clone(),
                raw_data: issue.evidence.clone(),
                detail_json: Some(serde_json::to_string(&detail)?),
                location_kind: ScanFindingLocationKind::File,
                page_url: None,
                relative_path: Some(issue.relative_path.clone()),
                line: issue.line,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()
        .map_err(|error| error.to_string())?;

    Ok(NormalizedRunBatch {
        execution_id,
        parent_run_id: None,
        project_id: Some(project_id),
        site_id: None,
        environment_url,
        environment_scope_key,
        source: ScanEvidenceSource::CodeScan,
        run_kind: ScanRunKind::Code,
        status: ScanRunStatus::Complete,
        timestamp_text: report.checked_at.clone(),
        started_at,
        completed_at: started_at.saturating_add(duration_ms as i64),
        duration_ms,
        // Code-scan coverage comes from the active registry because reports only
        // contain findings. Retired rules stay outside the claim until retirement.
        coverage: ScanCoverageManifest::declared(
            ScanCoverageKind::Project,
            Vec::new(),
            info.code_rules
                .iter()
                .map(|rule| rule.check_id.clone())
                .collect(),
        ),
        diagnostics: NormalizedRunDiagnostics {
            project_path: Some(project_path),
            framework: report.framework.clone(),
            ..Default::default()
        },
        status_detail: None,
        findings,
    })
}

pub(super) fn code_scan_occurrence_id(issue: &crate::core::audit::CodeIssue) -> String {
    format!(
        "code_scan:{}:{}",
        issue.id,
        issue.line.map(|line| line.to_string()).unwrap_or_default()
    )
}

/// Live runs supply checkout provenance even when Git metadata is unavailable.
#[allow(clippy::too_many_arguments)]
pub fn normalize_code_scan_with_provenance(
    report: &CodeScanReport,
    execution_id: i64,
    project_id: i64,
    environment_url: Option<String>,
    environment_scope_key: String,
    project_path: String,
    duration_ms: u64,
    started_at: i64,
    provenance: Option<CodeCheckoutProvenance>,
) -> Result<NormalizedRunBatch, String> {
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    let mut batch = normalize_code_scan_with_inventory(
        report,
        execution_id,
        project_id,
        environment_url,
        environment_scope_key,
        project_path,
        duration_ms,
        started_at,
        engine.info(),
    )?;
    if let Some(provenance) = provenance {
        batch.diagnostics.code_commit_sha = provenance.commit_sha;
        batch.diagnostics.code_tree_clean = provenance.tree_clean;
    }
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standin_code_coverage_uses_only_the_loaded_module_inventory() {
        // A covert channel from module to network
        let engine = sitecmd_engine_host::load().unwrap();
        let mut info = engine.info().clone();
        let mut rule = info.code_rules[0].clone();
        rule.id = "fixture-inventory-rule".into();
        rule.check_id = "code_scan.fixture-inventory-rule".into();
        info.code_rules = vec![rule];
        let report = CodeScanReport {
            checked_at: "2026-01-01T00:00:00Z".into(),
            framework: None,
            issue_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            issues: vec![],
            skipped_scopes: Default::default(),
        };
        let batch = normalize_code_scan_with_inventory(
            &report,
            1,
            1,
            None,
            "project:1".into(),
            "/project".into(),
            0,
            0,
            &info,
        )
        .unwrap();
        assert_eq!(batch.coverage.checks, ["code_scan.fixture-inventory-rule"]);
    }
}
