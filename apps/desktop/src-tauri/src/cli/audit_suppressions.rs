use crate::checks::Severity;
use crate::core::code_scan::{CodeIssue, CodeScanReport};
use chrono::NaiveDate;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeScanConfig {
    #[serde(default)]
    pub suppressions: Vec<CodeScanSuppression>,
}

impl CodeScanConfig {
    pub fn is_empty(&self) -> bool {
        self.suppressions.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeScanSuppression {
    #[serde(rename = "match")]
    pub matcher: CodeScanSuppressionMatch,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeScanSuppressionMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuppressionState {
    Active,
    Stale,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuppressionStatus {
    #[serde(rename = "match")]
    pub matcher: CodeScanSuppressionMatch,
    pub reason: String,
    pub expires: Option<String>,
    pub state: SuppressionState,
    pub matched_findings: usize,
}

#[derive(Debug, Clone)]
pub struct IgnoredFinding {
    pub issue: CodeIssue,
    pub fingerprint: String,
    pub reason: String,
    pub expires: Option<String>,
    pub suppression_index: usize,
}

#[derive(Debug)]
pub struct SuppressedAudit {
    pub report: CodeScanReport,
    pub ignored_findings: Vec<IgnoredFinding>,
    pub suppressions: Vec<SuppressionStatus>,
}

#[derive(Debug, Clone)]
pub struct ActiveSuppression {
    pub reason: String,
    pub expires: Option<String>,
}

impl SuppressedAudit {
    pub fn stale_suppression_count(&self) -> usize {
        self.suppressions
            .iter()
            .filter(|entry| entry.state != SuppressionState::Active)
            .count()
    }
}

struct PreparedSuppression {
    config: CodeScanSuppression,
    path_matcher: Option<Gitignore>,
    expired: bool,
    matched_findings: usize,
}

pub fn apply_project_suppressions(
    project_root: &Path,
    mut report: CodeScanReport,
    today: NaiveDate,
) -> Result<SuppressedAudit, String> {
    let mut prepared = prepare_project_suppressions(project_root, today)?;

    let mut active_issues = Vec::with_capacity(report.issues.len());
    let mut ignored_findings = Vec::new();
    for issue in report.issues.drain(..) {
        let fingerprint = issue_fingerprint(&issue);
        let mut first_active_match = None;
        for (index, suppression) in prepared.iter_mut().enumerate() {
            if suppression_matches(suppression, project_root, &issue, &fingerprint) {
                suppression.matched_findings += 1;
                if !suppression.expired && first_active_match.is_none() {
                    first_active_match = Some(index);
                }
            }
        }

        if let Some(index) = first_active_match {
            let suppression = &prepared[index].config;
            ignored_findings.push(IgnoredFinding {
                issue,
                fingerprint,
                reason: suppression.reason.clone(),
                expires: suppression.expires.clone(),
                suppression_index: index,
            });
        } else {
            active_issues.push(issue);
        }
    }

    report.issues = active_issues;
    recount_report(&mut report);
    let suppressions = prepared
        .into_iter()
        .map(|entry| SuppressionStatus {
            matcher: entry.config.matcher,
            reason: entry.config.reason,
            expires: entry.config.expires,
            state: if entry.expired {
                SuppressionState::Expired
            } else if entry.matched_findings == 0 {
                SuppressionState::Stale
            } else {
                SuppressionState::Active
            },
            matched_findings: entry.matched_findings,
        })
        .collect();

    Ok(SuppressedAudit {
        report,
        ignored_findings,
        suppressions,
    })
}

pub fn active_project_suppression(
    project_root: &Path,
    check_id: &str,
    relative_path: &str,
    fingerprint: Option<&str>,
    today: NaiveDate,
) -> Result<Option<ActiveSuppression>, String> {
    let prepared = prepare_project_suppressions(project_root, today)?;
    Ok(prepared
        .into_iter()
        .find(|suppression| {
            !suppression.expired
                && suppression_matches_target(
                    suppression,
                    project_root,
                    check_id,
                    relative_path,
                    fingerprint,
                )
        })
        .map(|suppression| ActiveSuppression {
            reason: suppression.config.reason,
            expires: suppression.config.expires,
        }))
}

fn prepare_project_suppressions(
    project_root: &Path,
    today: NaiveDate,
) -> Result<Vec<PreparedSuppression>, String> {
    if !project_root.join(".sitecmd/config.json").is_file() {
        return Ok(Vec::new());
    }
    crate::cli::read_config(&project_root.join(".sitecmd"))?
        .code_scan
        .suppressions
        .into_iter()
        .enumerate()
        .map(|(index, suppression)| prepare_suppression(project_root, index, suppression, today))
        .collect()
}

pub fn issue_fingerprint(issue: &CodeIssue) -> String {
    let relative_path = issue.relative_path.replace('\\', "/");
    let occurrence = issue
        .source_excerpt
        .as_deref()
        .or(issue.evidence.as_deref())
        .unwrap_or(&issue.id)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let material = format!(
        "sitecmd-code-finding-v1\0{}\0{}\0{}",
        issue.check_id, relative_path, occurrence
    );
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

fn prepare_suppression(
    project_root: &Path,
    index: usize,
    mut suppression: CodeScanSuppression,
    today: NaiveDate,
) -> Result<PreparedSuppression, String> {
    suppression.reason = suppression.reason.trim().to_string();
    if suppression.reason.is_empty() {
        return Err(format!(
            "Code Scan suppression {} requires a non-empty reason",
            index + 1
        ));
    }
    validate_matcher(index, &mut suppression.matcher)?;

    let expiry = suppression
        .expires
        .as_deref()
        .map(|value| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| {
                format!(
                    "Code Scan suppression {} has invalid expires date '{}'; use YYYY-MM-DD",
                    index + 1,
                    value
                )
            })
        })
        .transpose()?;
    let path_matcher = suppression
        .matcher
        .path
        .as_deref()
        .map(|pattern| compile_path_matcher(project_root, index, pattern))
        .transpose()?;

    Ok(PreparedSuppression {
        config: suppression,
        path_matcher,
        expired: expiry.is_some_and(|date| date < today),
        matched_findings: 0,
    })
}

fn validate_matcher(index: usize, matcher: &mut CodeScanSuppressionMatch) -> Result<(), String> {
    matcher.path = trimmed_option(matcher.path.take());
    matcher.rule = trimmed_option(matcher.rule.take());
    matcher.fingerprint = trimmed_option(matcher.fingerprint.take());
    if matcher.path.is_none() && matcher.rule.is_none() && matcher.fingerprint.is_none() {
        return Err(format!(
            "Code Scan suppression {} must match a path, rule, or fingerprint",
            index + 1
        ));
    }
    if let Some(pattern) = matcher.path.as_deref() {
        let path = Path::new(pattern);
        if path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
            return Err(format!(
                "Code Scan suppression {} path must be project-relative and cannot contain '..'",
                index + 1
            ));
        }
    }
    if let Some(rule) = matcher.rule.as_deref() {
        if !rule.starts_with("code_scan.")
            || crate::core::code_scan::validate_canonical_check_id(rule).is_err()
        {
            return Err(format!(
                "Code Scan suppression {} rule must be an exact canonical code_scan.* check ID",
                index + 1
            ));
        }
    }
    if let Some(fingerprint) = matcher.fingerprint.as_deref() {
        let digest = fingerprint.strip_prefix("sha256:").unwrap_or_default();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "Code Scan suppression {} fingerprint must be sha256 followed by 64 lowercase hexadecimal characters",
                index + 1
            ));
        }
    }
    Ok(())
}

fn trimmed_option(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn compile_path_matcher(
    project_root: &Path,
    index: usize,
    pattern: &str,
) -> Result<Gitignore, String> {
    let mut builder = GitignoreBuilder::new(project_root);
    builder.add_line(None, pattern).map_err(|error| {
        format!(
            "Code Scan suppression {} has invalid path pattern '{}': {}",
            index + 1,
            pattern,
            error
        )
    })?;
    builder.build().map_err(|error| {
        format!(
            "Code Scan suppression {} path pattern could not be compiled: {}",
            index + 1,
            error
        )
    })
}

fn suppression_matches(
    suppression: &PreparedSuppression,
    project_root: &Path,
    issue: &CodeIssue,
    fingerprint: &str,
) -> bool {
    suppression_matches_target(
        suppression,
        project_root,
        &issue.check_id,
        &issue.relative_path,
        Some(fingerprint),
    )
}

fn suppression_matches_target(
    suppression: &PreparedSuppression,
    project_root: &Path,
    check_id: &str,
    relative_path: &str,
    fingerprint: Option<&str>,
) -> bool {
    let matcher = &suppression.config.matcher;
    matcher.rule.as_deref().is_none_or(|rule| rule == check_id)
        && matcher
            .fingerprint
            .as_deref()
            .is_none_or(|expected| fingerprint == Some(expected))
        && suppression.path_matcher.as_ref().is_none_or(|paths| {
            paths
                .matched_path_or_any_parents(project_root.join(relative_path), false)
                .is_ignore()
        })
}

fn recount_report(report: &mut CodeScanReport) {
    report.issue_count = report.issues.len();
    report.critical_count = 0;
    report.high_count = 0;
    report.medium_count = 0;
    report.low_count = 0;
    for issue in &report.issues {
        match issue.severity {
            Severity::Critical => report.critical_count += 1,
            Severity::High => report.high_count += 1,
            Severity::Medium => report.medium_count += 1,
            Severity::Low => report.low_count += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::IssueConfidence;
    use crate::core::code_scan::CodeScanSkippedScopes;

    fn issue(path: &str, line: u32, excerpt: &str) -> CodeIssue {
        CodeIssue {
            id: format!("hardcoded-secret:{path}"),
            check_id: "code_scan.hardcoded-secret".into(),
            category: "security".into(),
            severity: Severity::High,
            title: "Credential-shaped value".into(),
            description: "Fixture finding".into(),
            relative_path: path.into(),
            absolute_path: format!("/tmp/project/{path}"),
            line: Some(line),
            source_excerpt: Some(excerpt.into()),
            evidence: None,
            why_now: None,
            likely_fix: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            verify_hint: None,
        }
    }

    fn report(issues: Vec<CodeIssue>) -> CodeScanReport {
        CodeScanReport {
            checked_at: "2026-08-19T00:00:00Z".into(),
            framework: None,
            issue_count: issues.len(),
            critical_count: 0,
            high_count: issues.len(),
            medium_count: 0,
            low_count: 0,
            issues,
            skipped_scopes: CodeScanSkippedScopes::default(),
        }
    }

    fn write_config(root: &Path, suppressions: &str) {
        let sitecmd_dir = root.join(".sitecmd");
        std::fs::create_dir_all(&sitecmd_dir).expect("sitecmd directory");
        std::fs::write(
            sitecmd_dir.join("config.json"),
            format!(
                r#"{{
  "version": 1,
  "url": "https://example.com",
  "name": "suppression test",
  "code_scan": {{ "suppressions": {suppressions} }}
}}"#
            ),
        )
        .expect("suppression config");
    }

    #[test]
    fn fingerprints_survive_line_movement_but_change_with_the_occurrence() {
        let first = issue("src/config.ts", 10, "const secret = 'fixture';");
        let moved = issue("src/config.ts", 80, "  const   secret = 'fixture'; ");
        let changed = issue("src/config.ts", 10, "const secret = 'different';");

        assert_eq!(issue_fingerprint(&first), issue_fingerprint(&moved));
        assert_ne!(issue_fingerprint(&first), issue_fingerprint(&changed));
    }

    #[test]
    fn fingerprint_vector_is_pinned_for_mcp_parity() {
        // apps/mcp-server/test/suppressions.test.mjs asserts the same digest.
        let finding = issue("src/config.ts", 10, "const secret = 'fixture';");
        assert_eq!(
            issue_fingerprint(&finding),
            "sha256:4522c6c0147aa43bbd24ea42bb759ad735e2dcddea6d2b83ed75de0fa5bfb1a6"
        );
    }

    #[test]
    fn path_globs_and_rules_are_combined() {
        let project = tempfile::tempdir().expect("project");
        write_config(
            project.path(),
            r#"[{
  "match": { "path": "examples/**", "rule": "code_scan.hardcoded-secret" },
  "reason": "The examples contain inert security fixtures."
}]"#,
        );
        let audit = apply_project_suppressions(
            project.path(),
            report(vec![
                issue("examples/insecure.ts", 1, "const secret = 'fixture';"),
                issue("src/config.ts", 1, "const secret = 'real';"),
            ]),
            NaiveDate::from_ymd_opt(2026, 8, 19).expect("date"),
        )
        .expect("valid suppressions");

        assert_eq!(audit.ignored_findings.len(), 1);
        assert_eq!(audit.report.issues.len(), 1);
        assert_eq!(audit.report.issues[0].relative_path, "src/config.ts");
    }

    #[test]
    fn fingerprint_suppression_acknowledges_only_the_exact_occurrence() {
        let project = tempfile::tempdir().expect("project");
        let acknowledged = issue("src/config.ts", 10, "const secret = 'fixture';");
        let fingerprint = issue_fingerprint(&acknowledged);
        write_config(
            project.path(),
            &format!(
                r#"[{{
  "match": {{ "fingerprint": "{fingerprint}" }},
  "reason": "This exact occurrence is an inert test fixture."
}}]"#
            ),
        );
        let audit = apply_project_suppressions(
            project.path(),
            report(vec![
                acknowledged,
                issue("src/config.ts", 20, "const secret = 'different';"),
            ]),
            NaiveDate::from_ymd_opt(2026, 8, 19).expect("date"),
        )
        .expect("valid suppressions");

        assert_eq!(audit.ignored_findings.len(), 1);
        assert_eq!(audit.report.issues.len(), 1);
    }

    #[test]
    fn expired_and_unmatched_suppressions_are_reported_without_hiding_findings() {
        let project = tempfile::tempdir().expect("project");
        write_config(
            project.path(),
            r#"[
  {
    "match": { "path": "src/config.ts", "rule": "code_scan.hardcoded-secret" },
    "reason": "Temporary fixture acknowledgement.",
    "expires": "2026-08-18"
  },
  {
    "match": { "path": "removed/**", "rule": "code_scan.hardcoded-secret" },
    "reason": "The old fixture was expected here."
  }
]"#,
        );
        let audit = apply_project_suppressions(
            project.path(),
            report(vec![issue("src/config.ts", 1, "const secret = 'fixture';")]),
            NaiveDate::from_ymd_opt(2026, 8, 19).expect("date"),
        )
        .expect("valid suppressions");

        assert_eq!(audit.report.issues.len(), 1);
        assert!(audit.ignored_findings.is_empty());
        assert_eq!(audit.stale_suppression_count(), 2);
        assert_eq!(audit.suppressions[0].state, SuppressionState::Expired);
        assert_eq!(audit.suppressions[1].state, SuppressionState::Stale);
    }

    #[test]
    fn suppression_reason_is_required() {
        let project = tempfile::tempdir().expect("project");
        write_config(
            project.path(),
            r#"[{
  "match": { "rule": "code_scan.hardcoded-secret" },
  "reason": "  "
}]"#,
        );

        let error = apply_project_suppressions(
            project.path(),
            report(vec![issue("src/config.ts", 1, "const secret = 'fixture';")]),
            NaiveDate::from_ymd_opt(2026, 8, 19).expect("date"),
        )
        .expect_err("empty reason must fail closed");

        assert!(error.contains("requires a non-empty reason"));
    }
}
