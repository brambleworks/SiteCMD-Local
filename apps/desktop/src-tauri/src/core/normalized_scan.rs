//! Normalizes source-native scan output for shared persistence.

use crate::checks::{CheckStatus, IssueConfidence, ScanCategory, Severity};
use crate::core::code_provenance::CodeCheckoutProvenance;
use crate::core::code_scan::{
    canonical_code_check_id, code_issue_domain, code_producer_rule_id, CodeScanReport,
};
use crate::core::scanner::ScanResult;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum ScanEvidenceSource {
    WebScan,
    CodeScan,
}

impl ScanEvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebScan => "web_scan",
            Self::CodeScan => "code_scan",
        }
    }
}

impl FromStr for ScanEvidenceSource {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "web_scan" => Ok(Self::WebScan),
            "code_scan" => Ok(Self::CodeScan),
            other => Err(format!("unknown scan evidence source: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum ScanRunKind {
    Single,
    MultiParent,
    Page,
    Code,
}

impl FromStr for ScanRunKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "single" => Ok(Self::Single),
            "multi_parent" => Ok(Self::MultiParent),
            "page" => Ok(Self::Page),
            "code" => Ok(Self::Code),
            other => Err(format!("unknown scan run kind: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum ScanRunStatus {
    Planned,
    Running,
    Complete,
    Failed,
    Cancelled,
    Skipped,
}

impl FromStr for ScanRunStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "planned" => Ok(Self::Planned),
            "running" => Ok(Self::Running),
            "complete" => Ok(Self::Complete),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "skipped" => Ok(Self::Skipped),
            other => Err(format!("unknown scan run status: {other}")),
        }
    }
}

impl ScanRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
        }
    }
}

impl ScanRunKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::MultiParent => "multi_parent",
            Self::Page => "page",
            Self::Code => "code",
        }
    }
}

/// Re-export the engine's pair-precise coverage vocabulary.
pub use sitecmd_engine::coverage::{
    CheckOutcome, ClaimBasis, CoverageException, CoverageExceptionReason, ScanCoverageKind,
    ScanCoverageManifest,
};

/// Derive coverage solely from persisted result rows.
/// `route` is absent for scan-set observations.
pub fn batch_outcomes(batch: &NormalizedRunBatch) -> Vec<CheckOutcome<'_>> {
    outcomes(&batch.findings, true)
}

/// Return both authored and effective route identities for redirected pages.
/// Findings use the effective URL while scan scope uses the authored URL, so
/// lifecycle coverage must recognize both.
pub fn covered_routes<'a>(authored: &'a str, effective: &'a str) -> Vec<&'a str> {
    if authored == effective {
        vec![authored]
    } else {
        vec![authored, effective]
    }
}

/// Attribute normalized outcomes to every authored and effective route identity.
pub fn batch_outcomes_on_routes<'a>(
    batch: &'a NormalizedRunBatch,
    routes: &'a [&'a str],
) -> Vec<CheckOutcome<'a>> {
    batch
        .findings
        .iter()
        .flat_map(|finding| {
            routes.iter().map(move |route| CheckOutcome {
                route: Some(*route),
                check_id: &finding.canonical_check_id,
                status: finding.verdict,
            })
        })
        .collect()
}

fn outcomes(findings: &[NormalizedFinding], per_route: bool) -> Vec<CheckOutcome<'_>> {
    findings
        .iter()
        .map(|finding| CheckOutcome {
            route: per_route.then_some(finding.page_url.as_deref()).flatten(),
            check_id: &finding.canonical_check_id,
            status: finding.verdict,
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum ScanFindingLocationKind {
    Page,
    File,
    Project,
    Site,
    None,
}

impl FromStr for ScanFindingLocationKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "page" => Ok(Self::Page),
            "file" => Ok(Self::File),
            "project" => Ok(Self::Project),
            "site" => Ok(Self::Site),
            "none" => Ok(Self::None),
            other => Err(format!("unknown scan finding location kind: {other}")),
        }
    }
}

impl ScanFindingLocationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::File => "file",
            Self::Project => "project",
            Self::Site => "site",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct NormalizedFinding {
    pub occurrence_id: String,
    pub source: ScanEvidenceSource,
    pub canonical_check_id: String,
    pub producer_check_id: String,
    /// Exact category vocabulary emitted by the collector. `category` is the
    /// canonical product category used for grouping and filtering.
    pub producer_category: String,
    pub category: String,
    pub domain: Option<String>,
    pub verdict: CheckStatus,
    pub severity: Severity,
    pub confidence: IssueConfidence,
    pub confidence_reason: Option<String>,
    pub title: String,
    pub description: String,
    pub fix_prompt: Option<String>,
    pub producer_fix_prompt: Option<String>,
    pub manual_fix: Option<String>,
    pub why_it_matters: Option<String>,
    pub verification_hint: Option<String>,
    /// Source-native evidence serialized exactly once at the adapter boundary.
    pub raw_data: Option<String>,
    /// Full source-native finding payload when columns do not carry every field.
    pub detail_json: Option<String>,
    pub location_kind: ScanFindingLocationKind,
    pub page_url: Option<String>,
    pub relative_path: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
#[ts(export_to = "ipc-bindings.ts")]
pub struct NormalizedRunDiagnostics {
    pub mode: Option<String>,
    pub focus: Option<String>,
    pub security_score: Option<u32>,
    pub performance_score: Option<u32>,
    pub seo_score: Option<u32>,
    pub accessibility_score: Option<u32>,
    pub compliance_score: Option<u32>,
    pub config_score: Option<u32>,
    pub polish_score: Option<u32>,
    pub detected_stack: Option<String>,
    pub page_url: Option<String>,
    pub project_path: Option<String>,
    pub framework: Option<String>,
    /// Git provenance captured immediately before a code audit begins.
    pub code_commit_sha: Option<String>,
    pub code_tree_clean: Option<bool>,
    pub total_pages: Option<u32>,
    pub completed_pages: Option<u32>,
    pub axe_enabled: Option<bool>,
    pub browser_ran: Option<bool>,
    pub axe_ran: Option<bool>,
    pub browser_build: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn normalize_multi_page_parent(
    issues: &[crate::checks::CheckResult],
    execution_id: i64,
    project_id: Option<i64>,
    site_id: i64,
    environment_url: String,
    selected_page_urls: Vec<String>,
    successful_page_urls: Vec<String>,
    selected_page_count: usize,
    raw_score: Option<u32>,
    duration_ms: u64,
    started_at: i64,
    completed_at: i64,
    focus: crate::core::scanner::ScanType,
    axe_enabled: bool,
    cross_page_coverage_successful: bool,
) -> Result<NormalizedRunBatch, serde_json::Error> {
    let synthetic = ScanResult {
        url: environment_url.clone(),
        mode: "multi_page".into(),
        scan_type: focus,
        overall_score: raw_score.unwrap_or(0),
        categories: Vec::new(),
        issues: issues.to_vec(),
        detected_stack: None,
        duration_ms,
        timestamp: chrono::DateTime::from_timestamp_millis(completed_at)
            .unwrap_or_default()
            .to_rfc3339(),
        page_signals: None,
        site_facts: None,
    };
    let mut batch = normalize_web_scan(
        &synthetic,
        execution_id,
        None,
        project_id,
        site_id,
        ScanRunKind::MultiParent,
        started_at,
    )?;
    batch.completed_at = completed_at;
    batch.raw_score = raw_score;
    // Failed parents retain intended coverage without resolving findings.
    let covered_page_urls = if cross_page_coverage_successful {
        successful_page_urls.clone()
    } else {
        selected_page_urls
    };
    // Cross-page checks require a complete route set for resolution.
    batch.coverage = ScanCoverageManifest::derive(
        ScanCoverageKind::PageSet,
        covered_page_urls,
        &outcomes(&batch.findings, false),
        ClaimBasis::RouteSet {
            complete: successful_page_urls.len() == selected_page_count,
        },
    );
    batch.coverage.successful = cross_page_coverage_successful;
    batch.diagnostics.page_url = None;
    batch.diagnostics.total_pages = Some(selected_page_count as u32);
    batch.diagnostics.completed_pages = Some(successful_page_urls.len() as u32);
    batch.diagnostics.axe_enabled = Some(axe_enabled);
    batch.status_detail =
        (!cross_page_coverage_successful).then(|| "cross_page_analysis_not_run".to_string());
    for finding in &mut batch.findings {
        finding.occurrence_id = format!(
            "site_scan:{}:{}",
            finding.producer_check_id, environment_url
        );
        finding.location_kind = ScanFindingLocationKind::Site;
        finding.page_url = None;
    }
    Ok(batch)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedRunBatch {
    pub execution_id: i64,
    pub parent_run_id: Option<i64>,
    pub project_id: Option<i64>,
    pub site_id: Option<i64>,
    pub environment_url: Option<String>,
    /// Normalized lifecycle/score scope. Code-only projects use the execution's
    /// stable project scope key even when there is no URL snapshot.
    pub environment_scope_key: String,
    pub source: ScanEvidenceSource,
    pub run_kind: ScanRunKind,
    pub status: ScanRunStatus,
    pub timestamp_text: String,
    pub started_at: i64,
    pub completed_at: i64,
    pub raw_score: Option<u32>,
    pub duration_ms: u64,
    pub coverage: ScanCoverageManifest,
    pub diagnostics: NormalizedRunDiagnostics,
    pub status_detail: Option<String>,
    pub findings: Vec<NormalizedFinding>,
}

fn category_score(result: &ScanResult, category: ScanCategory) -> Option<u32> {
    result
        .categories
        .iter()
        .find(|entry| entry.category == category)
        .map(|entry| entry.score)
}

pub fn normalize_web_scan(
    result: &ScanResult,
    execution_id: i64,
    parent_run_id: Option<i64>,
    project_id: Option<i64>,
    site_id: i64,
    run_kind: ScanRunKind,
    started_at: i64,
) -> Result<NormalizedRunBatch, serde_json::Error> {
    let findings = result
        .issues
        .iter()
        .map(|issue| {
            let canonical_check_id =
                crate::core::correlation::resolve_check_id("web_scan", &issue.check_id);
            let canonical_category = match issue.category {
                // The product issue taxonomy intentionally folds low-level
                // configuration findings into Compliance. Preserve the exact
                // producer category separately below.
                ScanCategory::Config => ScanCategory::Compliance,
                category => category,
            };
            let raw_data = issue
                .raw_data
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            Ok(NormalizedFinding {
                occurrence_id: format!("web_scan:{}:{}", issue.check_id, result.url),
                source: ScanEvidenceSource::WebScan,
                canonical_check_id,
                producer_check_id: issue.check_id.clone(),
                producer_category: issue.category.as_str().to_string(),
                category: canonical_category.as_str().to_string(),
                domain: None,
                verdict: issue.status,
                severity: issue.severity,
                confidence: issue.confidence,
                confidence_reason: issue.confidence_reason.clone(),
                title: issue.title.clone(),
                description: issue.description.clone(),
                fix_prompt: matches!(issue.status, CheckStatus::Fail | CheckStatus::Warn).then(
                    || {
                        crate::ai::build_fix_prompt(
                            issue,
                            &result.url,
                            result.detected_stack.as_ref(),
                        )
                    },
                ),
                producer_fix_prompt: issue.fix_prompt.clone(),
                manual_fix: issue.manual_fix.clone(),
                why_it_matters: issue.why_it_matters.clone(),
                verification_hint: None,
                raw_data,
                detail_json: None,
                location_kind: ScanFindingLocationKind::Page,
                page_url: Some(result.url.clone()),
                relative_path: None,
                line: None,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    let detected_stack = result
        .detected_stack
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    // A single-page collector proves coverage only for its observed route.
    let coverage = ScanCoverageManifest::derive(
        ScanCoverageKind::Page,
        vec![result.url.clone()],
        &outcomes(&findings, true),
        ClaimBasis::PerRoute,
    );
    Ok(NormalizedRunBatch {
        execution_id,
        parent_run_id,
        project_id,
        site_id: Some(site_id),
        environment_url: Some(result.url.clone()),
        environment_scope_key: result.url.clone(),
        source: ScanEvidenceSource::WebScan,
        run_kind,
        status: ScanRunStatus::Complete,
        timestamp_text: result.timestamp.clone(),
        started_at,
        completed_at: started_at.saturating_add(result.duration_ms as i64),
        raw_score: Some(result.overall_score),
        duration_ms: result.duration_ms,
        coverage,
        diagnostics: NormalizedRunDiagnostics {
            mode: Some(result.mode.clone()),
            focus: Some(result.scan_type.as_str().to_string()),
            security_score: category_score(result, ScanCategory::Security),
            performance_score: category_score(result, ScanCategory::Performance),
            seo_score: category_score(result, ScanCategory::Seo),
            accessibility_score: category_score(result, ScanCategory::Accessibility),
            compliance_score: category_score(result, ScanCategory::Compliance),
            config_score: category_score(result, ScanCategory::Config),
            polish_score: category_score(result, ScanCategory::Polish),
            detected_stack,
            page_url: (run_kind == ScanRunKind::Page).then(|| result.url.clone()),
            ..Default::default()
        },
        status_detail: None,
        findings,
    })
}

pub fn normalize_code_scan(
    report: &CodeScanReport,
    execution_id: i64,
    project_id: i64,
    environment_url: Option<String>,
    environment_scope_key: String,
    project_path: String,
    raw_score: u32,
    duration_ms: u64,
    started_at: i64,
) -> Result<NormalizedRunBatch, serde_json::Error> {
    let findings = report
        .issues
        .iter()
        .map(|issue| {
            let producer_rule = code_producer_rule_id(&issue.id);
            let canonical_check_id = canonical_code_check_id(&issue.id);
            let mut persisted_issue = issue.clone();
            persisted_issue.check_id = canonical_check_id.clone();
            Ok(NormalizedFinding {
                occurrence_id: code_scan_occurrence_id(issue),
                source: ScanEvidenceSource::CodeScan,
                canonical_check_id,
                producer_check_id: producer_rule.to_string(),
                producer_category: issue.category.clone(),
                category: issue.category.clone(),
                domain: Some(code_issue_domain(issue).as_str().to_string()),
                verdict: CheckStatus::Fail,
                severity: issue.severity,
                confidence: issue.confidence,
                confidence_reason: issue.confidence_reason.clone(),
                title: issue.title.clone(),
                description: issue.description.clone(),
                fix_prompt: Some(crate::ai::build_code_fix_prompt_with_framework(
                    issue,
                    report.framework.as_deref().unwrap_or("not detected"),
                )),
                producer_fix_prompt: issue.likely_fix.clone(),
                manual_fix: None,
                why_it_matters: issue.why_now.clone(),
                verification_hint: issue.verify_hint.clone(),
                raw_data: issue.evidence.clone(),
                detail_json: Some(serde_json::to_string(&persisted_issue)?),
                location_kind: ScanFindingLocationKind::File,
                page_url: None,
                relative_path: Some(issue.relative_path.clone()),
                line: issue.line,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

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
        raw_score: Some(raw_score),
        duration_ms,
        // Code-scan coverage comes from the active registry because reports only
        // contain findings. Retired rules stay outside the claim until retirement.
        coverage: ScanCoverageManifest::declared(
            ScanCoverageKind::Project,
            Vec::new(),
            crate::core::code_scan::registry::registered_code_check_ids().collect(),
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

pub(crate) fn code_scan_occurrence_id(issue: &crate::core::code_scan::CodeIssue) -> String {
    format!(
        "code_scan:{}:{}",
        issue.id,
        issue.line.map(|line| line.to_string()).unwrap_or_default()
    )
}

#[allow(clippy::too_many_arguments)]
pub fn normalize_code_scan_with_provenance(
    report: &CodeScanReport,
    execution_id: i64,
    project_id: i64,
    environment_url: Option<String>,
    environment_scope_key: String,
    project_path: String,
    raw_score: u32,
    duration_ms: u64,
    started_at: i64,
    provenance: CodeCheckoutProvenance,
) -> Result<NormalizedRunBatch, serde_json::Error> {
    let mut batch = normalize_code_scan(
        report,
        execution_id,
        project_id,
        environment_url,
        environment_scope_key,
        project_path,
        raw_score,
        duration_ms,
        started_at,
    )?;
    batch.diagnostics.code_commit_sha = provenance.commit_sha;
    batch.diagnostics.code_tree_clean = provenance.tree_clean;
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, Severity};
    use crate::core::code_scan::{CodeIssue, CodeScanSkippedScopes};

    #[test]
    fn web_adapter_preserves_every_verdict_and_raw_evidence() {
        let issue = |id: &str, status: CheckStatus| CheckResult {
            check_id: id.into(),
            category: ScanCategory::Security,
            title: id.into(),
            description: "detail".into(),
            status,
            severity: Severity::High,
            fix_prompt: Some("fix".into()),
            manual_fix: None,
            raw_data: Some(serde_json::json!({"header": "value"})),
            confidence: IssueConfidence::Confirmed,
            confidence_reason: Some("observed".into()),
            why_it_matters: Some("impact".into()),
        };
        let result = ScanResult {
            page_signals: None,
            site_facts: None,
            url: "https://example.com".into(),
            mode: "live".into(),
            scan_type: crate::core::scanner::ScanType::Health,
            overall_score: 80,
            categories: Vec::new(),
            issues: vec![
                issue("pass", CheckStatus::Pass),
                issue("fail", CheckStatus::Fail),
                issue("warn", CheckStatus::Warn),
                issue("skip", CheckStatus::Skipped),
            ],
            detected_stack: None,
            duration_ms: 10,
            timestamp: "2026-07-21T00:00:00Z".into(),
        };

        let batch = normalize_web_scan(&result, 1, None, Some(1), 1, ScanRunKind::Single, 100)
            .expect("normalize");
        assert_eq!(batch.findings.len(), 4);
        assert_eq!(batch.findings[0].verdict, CheckStatus::Pass);
        assert_eq!(batch.findings[1].verdict, CheckStatus::Fail);
        assert_eq!(batch.findings[2].verdict, CheckStatus::Warn);
        assert_eq!(batch.findings[3].verdict, CheckStatus::Skipped);
        assert_eq!(
            batch.findings[0].raw_data.as_deref(),
            Some(r#"{"header":"value"}"#)
        );
    }

    #[test]
    fn a_redirect_makes_one_request_cover_two_route_identities() {
        assert_eq!(
            covered_routes("https://example.com/pricing", "https://example.com/pricing"),
            vec!["https://example.com/pricing"]
        );
        assert_eq!(
            covered_routes(
                "https://example.com/pricing",
                "https://example.com/pricing/"
            ),
            vec![
                "https://example.com/pricing",
                "https://example.com/pricing/"
            ]
        );
    }

    #[test]
    fn code_adapter_separates_group_identity_from_occurrence_location() {
        let issue = |path: &str, line: u32| CodeIssue {
            id: format!("hardcoded-secret:{path}"),
            check_id: String::new(),
            category: "security".into(),
            severity: Severity::High,
            title: "Secret".into(),
            description: "detail".into(),
            relative_path: path.into(),
            absolute_path: format!("/tmp/{path}"),
            line: Some(line),
            source_excerpt: None,
            evidence: Some("evidence".into()),
            why_now: Some("impact".into()),
            likely_fix: Some("fix".into()),
            confidence: IssueConfidence::High,
            confidence_reason: None,
            verify_hint: None,
        };
        let report = CodeScanReport {
            checked_at: "2026-07-21T00:00:00Z".into(),
            framework: Some("nextjs".into()),
            issue_count: 2,
            critical_count: 0,
            high_count: 2,
            medium_count: 0,
            low_count: 0,
            issues: vec![issue("src/a.ts", 10), issue("src/b.ts", 20)],
            skipped_scopes: CodeScanSkippedScopes::default(),
        };

        let batch = normalize_code_scan(
            &report,
            1,
            1,
            Some("https://example.com".into()),
            "https://example.com".into(),
            "/tmp/project".into(),
            80,
            10,
            100,
        )
        .expect("normalize");
        assert_eq!(
            batch.findings[0].canonical_check_id,
            "code_scan.hardcoded-secret"
        );
        assert_eq!(
            batch.findings[0].canonical_check_id,
            batch.findings[1].canonical_check_id
        );
        assert_ne!(
            batch.findings[0].occurrence_id,
            batch.findings[1].occurrence_id
        );
        assert_eq!(batch.findings[0].relative_path.as_deref(), Some("src/a.ts"));
    }

    #[test]
    fn code_occurrence_identity_preserves_producer_disambiguators() {
        let issue = |id: &str| CodeIssue {
            id: id.into(),
            check_id: String::new(),
            category: "supply-chain".into(),
            severity: Severity::Low,
            title: "Unused dependency".into(),
            description: "detail".into(),
            relative_path: "package.json".into(),
            absolute_path: "/tmp/package.json".into(),
            line: Some(90),
            source_excerpt: None,
            evidence: None,
            why_now: None,
            likely_fix: None,
            confidence: IssueConfidence::NeedsReview,
            confidence_reason: None,
            verify_hint: None,
        };

        let first = issue("unused-dependency:package.json:first-package");
        let second = issue("unused-dependency:package.json:second-package");
        assert_ne!(
            code_scan_occurrence_id(&first),
            code_scan_occurrence_id(&second)
        );
        assert_eq!(
            code_scan_occurrence_id(&first),
            "code_scan:unused-dependency:package.json:first-package:90"
        );
    }
}
