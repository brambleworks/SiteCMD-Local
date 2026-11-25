//! Normalizes source-native scan output for shared persistence.

use crate::core::scan_types::{CheckStatus, IssueConfidence, Severity};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

pub use sitecmd_protocol::coverage::{ScanCoverageKind, ScanCoverageManifest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
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
    pub duration_ms: u64,
    pub coverage: ScanCoverageManifest,
    pub diagnostics: NormalizedRunDiagnostics,
    pub status_detail: Option<String>,
    pub findings: Vec<NormalizedFinding>,
}

pub(crate) fn actionable_findings(
    findings: &[NormalizedFinding],
) -> impl Iterator<Item = &NormalizedFinding> {
    findings
        .iter()
        .filter(|row| matches!(row.verdict, CheckStatus::Fail | CheckStatus::Warn))
}

mod code;
pub use code::normalize_code_scan_with_provenance;

#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn normalize_code_scan_with_inventory_for_test(
    report: &crate::core::audit::CodeScanReport,
    execution_id: i64,
    project_id: i64,
    environment_url: Option<String>,
    environment_scope_key: String,
    project_path: String,
    duration_ms: u64,
    started_at: i64,
    info: &sitecmd_protocol::engine_abi::EngineInfo,
) -> Result<NormalizedRunBatch, String> {
    code::normalize_code_scan_with_inventory(
        report,
        execution_id,
        project_id,
        environment_url,
        environment_scope_key,
        project_path,
        duration_ms,
        started_at,
        info,
    )
}

#[cfg(test)]
mod tests {
    use super::normalize_code_scan_with_provenance;
    use crate::core::audit::CodeScanReport;
    use sitecmd_protocol::skipped_scopes::CodeScanSkippedScopes;

    #[test]
    fn standin_code_adapter_separates_group_identity_from_occurrence_location() {
        // Occurrence locations can be lost when findings share a canonical check ID.
        let issue = |path: &str, line: u32| CodeIssue {
            id: format!("standin.rule:{path}"),
            check_id: String::new(),
            category: "security".into(),
            severity: Severity::High,
            title: "Secret".into(),
            description: "detail".into(),
            relative_path: path.into(),
            absolute_path: format!("/tmp/{path}"),
            line: Some(line),
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

        let batch = normalize_code_scan_with_provenance(
            &report,
            1,
            1,
            Some("https://example.com".into()),
            "https://example.com".into(),
            "/tmp/project".into(),
            10,
            100,
            Some(crate::core::code_provenance::CodeCheckoutProvenance::default()),
        )
        .expect("normalize");
        assert_eq!(
            batch.findings[0].canonical_check_id,
            "code_scan.standin.rule"
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

    use super::code::code_scan_occurrence_id;
    use crate::core::audit::CodeIssue;
    use crate::core::scan_types::{IssueConfidence, Severity};

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
