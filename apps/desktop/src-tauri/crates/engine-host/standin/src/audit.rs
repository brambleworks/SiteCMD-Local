use sitecmd_protocol::code_scan::{audit_issue_at, CodeIssue};
use sitecmd_protocol::engine_abi::{
    AnalyzeFilesRequest, AuditFileKind, AuditFileRefusal, AuditIssue, AuditReport, Done, EntryKind,
    ErrorCode, FileAnalysisResult, FileLocation, SessionBegin, SkippedScopes, Want, WantAnswer,
};
use sitecmd_protocol::time::UtcTimestamp;
use sitecmd_protocol::vocab::{IssueConfidence, Severity};

use super::{CHECK_ID, RULE, RULE_CATEGORY, TITLE};

pub(super) struct PendingAudit {
    files: Vec<(String, FileLocation)>,
    database_issues: Vec<AuditIssue>,
    now_ms: i64,
    skipped: SkippedScopes,
}

impl PendingAudit {
    pub(super) fn new(input: SessionBegin) -> Self {
        let mut files: Vec<_> = input
            .listing
            .entries
            .into_iter()
            .filter(|entry| {
                entry.kind == EntryKind::File && entry.path.as_str() != ".sitecmd/config.json"
            })
            .map(|entry| (entry.path.as_str().into(), FileLocation::Listed(entry.path)))
            .collect();
        let mut database_issues = Vec::new();
        for file in input.host.files {
            let path = file.path.as_str();
            let location = FileLocation::Offer { id: file.id };
            match file.kind {
                AuditFileKind::Inventory { .. } => files.push((path.into(), location)),
                AuditFileKind::DatabaseLocation {} => {
                    let mut finding = issue(path, 0);
                    finding.id.push_str(":database");
                    finding.evidence = None;
                    database_issues.push(audit_issue_at(finding, location));
                }
                _ => {}
            }
        }
        Self {
            files,
            database_issues,
            now_ms: input.now_ms,
            skipped: input.host.skipped_scopes,
        }
    }

    pub(super) fn has(&self, name: &str) -> bool {
        self.files
            .iter()
            .any(|(path, _)| path.rsplit('/').next() == Some(name))
    }

    pub(super) fn wants(&self) -> Vec<Want> {
        self.files
            .iter()
            .map(|(_, location)| match location {
                FileLocation::Listed(path) => Want::File { path: path.clone() },
                FileLocation::Offer { id } => Want::OfferedFile { id: *id },
            })
            .collect()
    }

    pub(super) fn finish(self, answers: Vec<WantAnswer>, region: &[u8]) -> Result<Done, ErrorCode> {
        if self.files.len() != answers.len() {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut issues = Vec::new();
        let mut coverage = Vec::new();
        for ((path, location), response) in self.files.into_iter().zip(answers) {
            match response {
                WantAnswer::File { body } => {
                    let bytes = body
                        .slice(region)
                        .map_err(|_| ErrorCode::InvalidBodyReference)?;
                    let name = path.rsplit('/').next();
                    if matches!(name, Some("fixture-findings.txt" | "fixture-evidence.txt")) {
                        let text =
                            std::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
                        for (index, line) in text
                            .lines()
                            .enumerate()
                            .filter(|(_, line)| !line.is_empty())
                        {
                            let line_number = (index + 1) as u32;
                            let mut finding = issue(&path, bytes.len());
                            finding.line = Some(line_number);
                            finding.id.push_str(&format!(":{line_number}"));
                            if name == Some("fixture-evidence.txt") {
                                finding.title = line.into();
                                finding.description = line.into();
                                finding.evidence = Some(line.into());
                                finding.why_now = Some(line.into());
                                finding.likely_fix = Some(line.into());
                                finding.verify_hint = Some(line.into());
                                finding.confidence_reason = Some(line.into());
                            }
                            issues.push(audit_issue_at(finding, location.clone()));
                        }
                    } else {
                        let finding = issue(&path, bytes.len());
                        issues.push(audit_issue_at(finding, location));
                    }
                }
                WantAnswer::Refused { reason } => coverage.push(AuditFileRefusal {
                    path: location,
                    reason,
                }),
                _ => return Err(ErrorCode::InvalidRequest),
            }
        }
        issues.extend(self.database_issues);
        let checked_at = UtcTimestamp::from_timestamp_millis(self.now_ms)
            .ok_or(ErrorCode::InvalidRequest)?
            .to_rfc3339();
        Ok(Done::Audit(AuditReport {
            checked_at,
            framework: None,
            issue_count: issues.len(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: issues.len(),
            issues,
            skipped_scopes: self.skipped,
            coverage,
        }))
    }
}

pub(super) fn analyze(
    input: AnalyzeFilesRequest,
    region: &[u8],
) -> Result<Vec<FileAnalysisResult>, ErrorCode> {
    input
        .files
        .into_iter()
        .map(|file| {
            let bytes = file
                .body
                .slice(region)
                .map_err(|_| ErrorCode::InvalidBodyReference)?;
            Ok(FileAnalysisResult {
                issues: vec![issue(&file.path, bytes.len())],
                path: file.path,
                summary: Default::default(),
            })
        })
        .collect()
}

fn issue(path: &str, length: usize) -> CodeIssue {
    CodeIssue {
        id: format!("{RULE}:{path}"),
        check_id: CHECK_ID.into(),
        category: RULE_CATEGORY.key().into(),
        severity: Severity::Low,
        title: TITLE.into(),
        description: String::new(),
        relative_path: path.into(),
        absolute_path: String::new(),
        line: None,
        evidence: Some(length.to_string()),
        why_now: None,
        likely_fix: None,
        confidence: IssueConfidence::Confirmed,
        confidence_reason: None,
        verify_hint: None,
    }
}
