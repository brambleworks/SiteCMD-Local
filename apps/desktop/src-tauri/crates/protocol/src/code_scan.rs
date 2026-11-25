//! Code Scan report and cancellation types shared by the module and host.

use crate::skipped_scopes::CodeScanSkippedScopes;
use crate::vocab::{IssueConfidence, Severity};
use serde::{Deserialize, Serialize};

mod abi;
pub use self::abi::audit_issue_at;

/// Internal finding. The CLI resolves its display category from the rule metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeIssue {
    pub id: String,
    /// Canonical check ID shared by findings from the same rule.
    #[serde(default)]
    pub check_id: String,
    /// The category recorded by the detector.
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub relative_path: String,
    pub absolute_path: String,
    pub line: Option<u32>,
    pub evidence: Option<String>,
    pub why_now: Option<String>,
    pub likely_fix: Option<String>,
    #[serde(default)]
    pub confidence: IssueConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_reason: Option<String>,
    pub verify_hint: Option<String>,
}

/// Internal report carrying findings before the CLI formats them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeScanReport {
    pub checked_at: String,
    pub framework: Option<String>,
    pub issue_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub issues: Vec<CodeIssue>,
    #[serde(default)]
    pub skipped_scopes: CodeScanSkippedScopes,
}

/// Error surfaced by `run_code_scan_internal` and its callers.
#[derive(Debug)]
pub enum CodeScanError {
    /// The text is matched by `scan-error.ts`.
    Cancelled,
    /// Engine or infrastructure failure, sanitized before wrapping.
    Failed(String),
}

impl std::fmt::Display for CodeScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Code scan cancelled."),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CodeScanError {}

/// Engine helpers report plain messages; `?` lifts them into the failure arm
/// so cancellation stays the only other outcome.
impl From<String> for CodeScanError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

#[derive(Debug, Clone)]
pub struct CodeScanAuditProgress {
    pub check_id: &'static str,
    pub status: &'static str,
    pub results_count: usize,
    pub checks_done: usize,
    pub checks_total: usize,
}

impl From<CodeScanError> for crate::engine_abi::AuditFailure {
    fn from(error: CodeScanError) -> Self {
        match error {
            CodeScanError::Cancelled => Self::Cancelled,
            CodeScanError::Failed(message) => Self::AnalysisFailed(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_display_matches_frontend_contract() {
        let rendered = CodeScanError::Cancelled.to_string();
        assert_eq!(
            rendered, "Code scan cancelled.",
            "wire text must stay byte-identical to the legacy literal"
        );
        assert!(
            rendered.to_lowercase().contains("cancelled"),
            "scan-error.ts keys on this substring: {rendered}"
        );
    }

    #[test]
    fn failed_display_is_message_passthrough() {
        let rendered = CodeScanError::Failed("Code scan task failed: boom".to_string()).to_string();
        assert_eq!(rendered, "Code scan task failed: boom");
    }
}
