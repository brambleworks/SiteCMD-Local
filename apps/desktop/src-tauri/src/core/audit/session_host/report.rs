use std::borrow::Cow;

use super::SessionReport;
use crate::core::project_listing::ProjectListing;
use sitecmd_engine_host::redact_evidence;
use sitecmd_protocol::code_scan::{CodeIssue, CodeScanReport};
use sitecmd_protocol::engine_abi::{AuditFailure, AuditIssue, EngineInfo, FileLocation};
use sitecmd_protocol::identity::code_producer_rule_id;
use sitecmd_protocol::skipped_scopes::CodeScanSkippedScopes;
use sitecmd_protocol::time::UtcTimestamp;

pub(crate) const UNKNOWN_CODE_RULE: &str = "The engine reported an unknown Code Scan rule.";
pub(crate) const INCONSISTENT_CODE_RULE: &str =
    "The engine reported an inconsistent Code Scan rule.";

pub(in crate::core) fn native_report(
    result: SessionReport,
    listing: &ProjectListing,
    now_ms: i64,
    rules: &EngineInfo,
) -> Result<CodeScanReport, AuditFailure> {
    let SessionReport { report, files } = result;
    let root = listing.root();
    let relative_path = |location: &FileLocation| {
        Ok(match location {
            FileLocation::Listed(path) if listing.wire().is_file(path) => path.as_str(),
            FileLocation::Listed(_) => return Err(AuditFailure::InvalidInput),
            FileLocation::Offer { id } => files
                .get(*id as usize)
                .filter(|file| file.id == *id)
                .ok_or(AuditFailure::InvalidInput)?
                .path
                .as_str(),
        }
        .to_owned())
    };
    Ok(CodeScanReport {
        checked_at: UtcTimestamp::from_timestamp_millis(now_ms)
            .ok_or(AuditFailure::InvalidInput)?
            .to_rfc3339(),
        framework: report.framework,
        issue_count: report.issue_count,
        critical_count: report.critical_count,
        high_count: report.high_count,
        medium_count: report.medium_count,
        low_count: report.low_count,
        issues: report
            .issues
            .into_iter()
            .map(|issue| {
                let relative = relative_path(&issue.path)?;
                let mut base = root;
                let mut suffix = relative.as_str();
                while let Some(rest) = suffix.strip_prefix("../") {
                    base = base.parent().ok_or(AuditFailure::InvalidInput)?;
                    suffix = rest;
                }
                let absolute = base.join(suffix).to_string_lossy().into_owned();
                let rule = rules
                    .code_rule(&issue.rule_id)
                    .ok_or_else(|| AuditFailure::AnalysisFailed(UNKNOWN_CODE_RULE.into()))?;
                if issue.check_id != rule.check_id {
                    return Err(AuditFailure::AnalysisFailed(INCONSISTENT_CODE_RULE.into()));
                }
                native_issue(issue, relative.replace('\\', "/"), absolute)
            })
            .collect::<Result<_, AuditFailure>>()?,
        skipped_scopes: CodeScanSkippedScopes::from_module(report.skipped_scopes, |location| {
            relative_path(location).map(|path| path.replace('\\', "/"))
        })?,
    })
}

pub(crate) fn resolved_issue_id<'a>(
    issue: &'a AuditIssue,
    relative_path: &str,
) -> Result<Cow<'a, str>, AuditFailure> {
    let id = match issue.id_path_offset {
        Some(offset) => {
            let offset = offset as usize;
            if !matches!(issue.path, FileLocation::Offer { .. })
                || !issue.id.is_char_boundary(offset)
            {
                return Err(AuditFailure::InvalidInput);
            }
            let mut id = issue.id.clone();
            id.insert_str(offset, relative_path);
            Cow::Owned(id)
        }
        None => Cow::Borrowed(issue.id.as_str()),
    };
    if code_producer_rule_id(&id) != issue.rule_id {
        return Err(AuditFailure::InvalidInput);
    }
    Ok(id)
}

fn native_issue(
    issue: AuditIssue,
    relative_path: String,
    absolute_path: String,
) -> Result<CodeIssue, AuditFailure> {
    let id = resolved_issue_id(&issue, &relative_path)?.into_owned();
    let AuditIssue {
        check_id,
        category,
        severity,
        title,
        description,
        line,
        evidence,
        why_now,
        likely_fix,
        confidence,
        confidence_reason,
        verify_hint,
        ..
    } = issue;
    Ok(CodeIssue {
        id,
        check_id,
        category,
        severity,
        title,
        description,
        relative_path,
        absolute_path,
        line,
        // The module masks provider keys before it answers; the host can link only the public log redactor.
        evidence: evidence.map(redact_evidence),
        why_now,
        likely_fix,
        confidence,
        confidence_reason,
        verify_hint,
    })
}

#[cfg(test)]
mod tests {
    use super::native_issue;
    use sitecmd_protocol::code_scan::CodeIssue;
    use sitecmd_protocol::engine_abi::{AuditIssue, FileLocation, RelPath};
    use sitecmd_protocol::vocab::{IssueConfidence, Severity};

    fn populated_issue() -> CodeIssue {
        CodeIssue {
            id: "example-rule:src/lib.rs:23".into(),
            check_id: "code_scan.example-rule".into(),
            category: "security".into(),
            severity: Severity::High,
            title: "Finding title".into(),
            description: "Finding description".into(),
            relative_path: "src/lib.rs".into(),
            absolute_path: "/workspace/src/lib.rs".into(),
            line: Some(23),
            evidence: Some("Observed value".into()),
            why_now: Some("Finding impact".into()),
            likely_fix: Some("Suggested change".into()),
            confidence: IssueConfidence::Confirmed,
            confidence_reason: Some("Observed directly".into()),
            verify_hint: Some("Run the check again".into()),
        }
    }

    #[test]
    fn populated_code_issue_round_trips_through_audit_wire() {
        // Combining native finding fields can discard content used by the CLI's output formats.
        let issue = populated_issue();
        let audit = AuditIssue::try_from(issue.clone()).unwrap();
        assert_eq!(audit.rule_id, "example-rule");
        assert_eq!(
            audit.path,
            FileLocation::Listed(RelPath::parse("src/lib.rs").unwrap())
        );
        assert_eq!(audit.fix_prompt, None);
        let encoded = serde_json::to_vec(&audit).unwrap();
        let decoded: AuditIssue = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, audit);
        assert_eq!(
            native_issue(decoded, "src/lib.rs".into(), "/workspace/src/lib.rs".into()).unwrap(),
            issue
        );
    }

    #[test]
    fn offered_issue_id_uses_the_host_display_path() {
        for path in ["src/sign-in.ts", "src/sign:in.ts"] {
            let mut wire = AuditIssue::try_from(populated_issue()).unwrap();
            wire.path = FileLocation::Offer { id: 0 };
            wire.id = "example-rule:kind:[]:23".into();
            wire.id_path_offset = Some("example-rule:kind:[".len() as u32);
            let issue = native_issue(wire, path.into(), format!("/workspace/{path}")).unwrap();
            assert_eq!(issue.id, format!("example-rule:kind:[{path}]:23"));
        }
    }

    #[test]
    fn audit_wire_evidence_is_redacted_on_conversion() {
        // Evidence from a module can carry a credential into a native finding.
        let mut audit = AuditIssue::try_from(populated_issue()).unwrap();
        audit.evidence = Some("https://account:fixture-value@example.com/".into());
        let evidence = native_issue(audit, "src/lib.rs".into(), "/workspace/src/lib.rs".into())
            .unwrap()
            .evidence
            .unwrap();
        assert!(evidence.contains("example.com"));
        assert!(!evidence.contains("fixture-value"));
    }

    #[test]
    fn invalid_issue_path_cannot_convert_from_native_wire() {
        // Bug: A finding with a refused native name can bypass the opaque offer ID.
        let mut issue = populated_issue();
        issue.relative_path = "sign:in.ts".into();
        assert!(AuditIssue::try_from(issue).is_err());
    }
}
