//! Source-free projections for output that can leave the local terminal.

use sitecmd_protocol::engine_abi::EngineInfo;

use super::{code_producer_rule_id, rule_for_issue, CodeIssue, CodeScanReport};

/// Retain occurrence metadata and binary-owned wording only; analyzer prose
/// can interpolate customer identifiers even without an excerpt field.
pub(crate) fn published_issue(
    issue: &CodeIssue,
    rules: &EngineInfo,
) -> Result<CodeIssue, &'static str> {
    let rule = code_producer_rule_id(&issue.id);
    let metadata = rule_for_issue(issue, rules)?;
    Ok(CodeIssue {
        id: format!("{rule}:{}:{}", issue.relative_path, issue.line.unwrap_or(0)),
        check_id: metadata.check_id.clone(),
        category: metadata.category.key().into(),
        severity: issue.severity,
        title: format!("Code Scan: {rule}"),
        description: metadata
            .rationale
            .as_deref()
            .unwrap_or("Review the reported rule at this file and line.")
            .to_string(),
        relative_path: issue.relative_path.clone(),
        absolute_path: String::new(),
        line: issue.line,
        evidence: None,
        why_now: None,
        likely_fix: Some("Review and fix the reported rule in this repository.".into()),
        confidence: issue.confidence,
        confidence_reason: None,
        verify_hint: Some("Run Code Scan again after reviewing the change.".into()),
    })
}

pub(crate) fn published_report(
    report: &CodeScanReport,
    rules: &EngineInfo,
) -> Result<CodeScanReport, &'static str> {
    let mut published = report.clone();
    published.issues = report
        .issues
        .iter()
        .map(|issue| published_issue(issue, rules))
        .collect::<Result<_, _>>()?;
    Ok(published)
}
