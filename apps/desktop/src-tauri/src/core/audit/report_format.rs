use super::{
    code_issue_category, CodeIssue, CodeScanReport, CodeScanReportFormat, CodeScanReportView,
};
use sitecmd_protocol::engine_abi::EngineInfo;
use sitecmd_protocol::vocab::Severity;
use std::fmt::Write as _;
use std::path::Path;
pub fn format_report(
    report: &CodeScanReport,
    rules: &EngineInfo,
    project_path: &Path,
    format: CodeScanReportFormat,
) -> Result<String, String> {
    let published = super::published_report(report, rules)?;
    let report = &published;
    let output = match format {
        CodeScanReportFormat::Summary => {
            format_report_summary(report, rules, project_path).map_err(str::to_owned)
        }
        CodeScanReportFormat::Json => {
            serde_json::to_string_pretty(&CodeScanReportView::new(report, rules)?)
                .map_err(|error| format!("Could not serialize code scan report: {}", error))
        }
        CodeScanReportFormat::Markdown => {
            format_report_markdown(report, rules, project_path).map_err(str::to_owned)
        }
        CodeScanReportFormat::Review => {
            format_report_review(report, rules, project_path).map_err(str::to_owned)
        }
        CodeScanReportFormat::Github => format_report_github(report, rules).map_err(str::to_owned),
        CodeScanReportFormat::Sarif => {
            format_report_sarif(report, rules, env!("CARGO_PKG_VERSION"))
        }
    }?;
    if report.skipped_scopes.rule_blocks_skipped.unwrap_or(0) == 0 {
        return Ok(output);
    }
    let note = format!(
        "Rules analysis incomplete. Skipped rules constructs: {}.\n{}",
        report.skipped_scopes.rule_blocks_skipped.unwrap_or(0),
        report
            .skipped_scopes
            .rule_samples
            .as_deref()
            .unwrap_or_default()
            .join("\n")
    );
    match format {
        CodeScanReportFormat::Json => Ok(output),
        CodeScanReportFormat::Sarif => {
            let mut sarif: serde_json::Value = serde_json::from_str(&output)
                .map_err(|error| format!("Couldn't parse SARIF report: {error}"))?;
            sarif["runs"][0]["invocations"] = serde_json::json!([{
                "executionSuccessful": true,
                "toolExecutionNotifications": [{ "level": "warning", "message": { "text": note } }]
            }]);
            serde_json::to_string_pretty(&sarif)
                .map_err(|error| format!("Couldn't serialize SARIF report: {error}"))
        }
        CodeScanReportFormat::Github => Ok(format!(
            "::warning::{}\n{output}",
            escape_github_data(&note)
        )),
        _ => Ok(format!("{output}\n{note}\n")),
    }
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// SARIF 2.1.0 with one rule per check id and one result per occurrence.
/// The CLI adds fingerprints, baseline state, and suppressions on top.
fn format_report_sarif(
    report: &CodeScanReport,
    info: &EngineInfo,
    version: &str,
) -> Result<String, String> {
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut results: Vec<serde_json::Value> = Vec::new();
    for issue in &report.issues {
        let index = match rule_index.get(&issue.check_id) {
            Some(index) => *index,
            None => {
                rules.push(serde_json::json!({
                    "id": issue.check_id,
                    "name": issue.title,
                    "shortDescription": { "text": issue.title },
                    "fullDescription": { "text": issue.description },
                    "defaultConfiguration": { "level": sarif_level(issue.severity) },
                    "properties": {
                        "category": code_issue_category(issue, info)?.key(),
                    },
                }));
                rule_index.insert(issue.check_id.clone(), rules.len() - 1);
                rules.len() - 1
            }
        };
        let mut message = issue.description.clone();
        if let Some(likely_fix) = &issue.likely_fix {
            message.push_str(" Best first fix: ");
            message.push_str(likely_fix);
        }
        results.push(serde_json::json!({
            "ruleId": issue.check_id,
            "ruleIndex": index,
            "level": sarif_level(issue.severity),
            "message": { "text": message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": issue.relative_path.replace('\\', "/"), "uriBaseId": "%SRCROOT%" },
                    "region": { "startLine": issue.line.unwrap_or(1) }
                }
            }],
            "properties": {
                "severity": issue.severity.as_str(),
                "confidence": serde_json::to_value(issue.confidence).unwrap_or(serde_json::Value::Null),
            },
        }));
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "SiteCMD Code Scan",
                "version": version,
                "informationUri": "https://sitecmd.com",
                "rules": rules,
            } },
            "results": results,
        }],
    }))
    .map_err(|error| format!("Couldn't serialize SARIF report: {error}"))
}

fn scan_report_labels() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        "SiteCMD Code Scan",
        "code issues",
        "SiteCMD Code Scan Report",
        "SiteCMD Code Scan Review",
    )
}

pub(crate) fn escape_terminal_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn format_report_summary(
    report: &CodeScanReport,
    rules: &EngineInfo,
    project_path: &Path,
) -> Result<String, &'static str> {
    let (summary_title, empty_label, _, _) = scan_report_labels();
    let mut output = String::new();
    let _ = writeln!(
        output,
        "{} - {}",
        summary_title,
        escape_terminal_text(&project_path.to_string_lossy())
    );
    let _ = writeln!(
        output,
        "Checked: {}",
        escape_terminal_text(&report.checked_at)
    );
    if let Some(framework) = &report.framework {
        let _ = writeln!(output, "Framework: {}", escape_terminal_text(framework));
    }
    let _ = writeln!(
        output,
        "Issues: {} total | critical {} | high {} | medium {} | low {}",
        report.issue_count,
        report.critical_count,
        report.high_count,
        report.medium_count,
        report.low_count
    );

    if report.issues.is_empty() {
        let _ = writeln!(output, "\nNo {} detected.", empty_label);
        return Ok(output);
    }

    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let issues = issues_for_severity(report, &severity);
        if issues.is_empty() {
            continue;
        }
        let _ = writeln!(output, "\n{} ({})", severity.label(), issues.len());
        for issue in issues {
            let _ = writeln!(
                output,
                "- [{}] {} - {}{}",
                code_issue_category(issue, rules)?.label(),
                escape_terminal_text(&issue.title),
                escape_terminal_text(&issue.relative_path),
                issue
                    .line
                    .map(|line| format!(":{}", line))
                    .unwrap_or_default()
            );
        }
    }

    Ok(output)
}

fn format_report_markdown(
    report: &CodeScanReport,
    rules: &EngineInfo,
    project_path: &Path,
) -> Result<String, &'static str> {
    let (_, empty_label, markdown_title, _) = scan_report_labels();
    let mut output = String::new();
    let _ = writeln!(output, "# {}", markdown_title);
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "- Project: `{}`",
        escape_terminal_text(&project_path.to_string_lossy())
    );
    let _ = writeln!(
        output,
        "- Checked: `{}`",
        escape_terminal_text(&report.checked_at)
    );
    if let Some(framework) = &report.framework {
        let _ = writeln!(output, "- Framework: `{}`", escape_terminal_text(framework));
    }
    let _ = writeln!(output, "- Total issues: `{}`", report.issue_count);
    let _ = writeln!(output);
    let _ = writeln!(output, "| Severity | Count |");
    let _ = writeln!(output, "| --- | ---: |");
    let _ = writeln!(output, "| Critical | {} |", report.critical_count);
    let _ = writeln!(output, "| High | {} |", report.high_count);
    let _ = writeln!(output, "| Medium | {} |", report.medium_count);
    let _ = writeln!(output, "| Low | {} |", report.low_count);

    if report.issues.is_empty() {
        let _ = writeln!(output, "\nNo {} detected.", empty_label);
        return Ok(output);
    }

    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let issues = issues_for_severity(report, &severity);
        if issues.is_empty() {
            continue;
        }
        let _ = writeln!(output, "\n## {} ({})", severity.label(), issues.len());
        for issue in issues {
            let _ = writeln!(output, "\n### {}", escape_terminal_text(&issue.title));
            let _ = writeln!(
                output,
                "- Category: {}",
                code_issue_category(issue, rules)?.label()
            );
            let _ = writeln!(
                output,
                "- File: `{}`{}",
                escape_terminal_text(&issue.relative_path),
                issue
                    .line
                    .map(|line| format!(" (line {})", line))
                    .unwrap_or_default()
            );
            let _ = writeln!(
                output,
                "- Why this matters: {}",
                escape_terminal_text(&issue.description)
            );
            if let Some(evidence) = &issue.evidence {
                let _ = writeln!(output, "- Evidence: {}", escape_terminal_text(evidence));
            }
            if let Some(why_now) = &issue.why_now {
                let _ = writeln!(output, "- Why now: {}", escape_terminal_text(why_now));
            }
            if let Some(likely_fix) = &issue.likely_fix {
                let _ = writeln!(
                    output,
                    "- Suggested fix: {}",
                    escape_terminal_text(likely_fix)
                );
            }
            if let Some(verify_hint) = &issue.verify_hint {
                let _ = writeln!(output, "- Verify: {}", escape_terminal_text(verify_hint));
            }
        }
    }

    Ok(output)
}

fn format_report_review(
    report: &CodeScanReport,
    rules: &EngineInfo,
    project_path: &Path,
) -> Result<String, &'static str> {
    let (_, empty_label, _, review_title) = scan_report_labels();
    let mut output = String::new();
    let _ = writeln!(output, "# {}", review_title);
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "- Project: `{}`",
        escape_terminal_text(&project_path.to_string_lossy())
    );
    let _ = writeln!(
        output,
        "- Checked: `{}`",
        escape_terminal_text(&report.checked_at)
    );
    if let Some(framework) = &report.framework {
        let _ = writeln!(output, "- Framework: `{}`", escape_terminal_text(framework));
    }
    let _ = writeln!(output, "- Findings: `{}` total", report.issue_count);
    let _ = writeln!(output);
    let _ = writeln!(output, "| Severity | Count |");
    let _ = writeln!(output, "| --- | ---: |");
    let _ = writeln!(output, "| Critical | {} |", report.critical_count);
    let _ = writeln!(output, "| High | {} |", report.high_count);
    let _ = writeln!(output, "| Medium | {} |", report.medium_count);
    let _ = writeln!(output, "| Low | {} |", report.low_count);

    if report.issues.is_empty() {
        let _ = writeln!(output, "\nNo {} detected.", empty_label);
        return Ok(output);
    }

    let _ = writeln!(output, "\n## Findings");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let issues = issues_for_severity(report, &severity);
        if issues.is_empty() {
            continue;
        }
        let _ = writeln!(output, "\n### {} ({})", severity.label(), issues.len());
        for issue in issues {
            let _ = writeln!(output, "\n#### {}", escape_terminal_text(&issue.title));
            let _ = writeln!(
                output,
                "- Category: {}",
                code_issue_category(issue, rules)?.label()
            );
            let _ = writeln!(
                output,
                "- Location: `{}`",
                escape_terminal_text(&file_location(issue))
            );
            let _ = writeln!(
                output,
                "- Why it matters: {}",
                escape_terminal_text(&issue.description)
            );
            if let Some(evidence) = &issue.evidence {
                let _ = writeln!(output, "- Evidence: {}", escape_terminal_text(evidence));
            }
            if let Some(why_now) = &issue.why_now {
                let _ = writeln!(output, "- Why now: {}", escape_terminal_text(why_now));
            }
            if let Some(likely_fix) = &issue.likely_fix {
                let _ = writeln!(
                    output,
                    "- Best first fix: {}",
                    escape_terminal_text(likely_fix)
                );
            }
            if let Some(verify_hint) = &issue.verify_hint {
                let _ = writeln!(output, "- Verify: {}", escape_terminal_text(verify_hint));
            }
        }
    }

    Ok(output)
}

fn format_report_github(
    report: &CodeScanReport,
    rules: &EngineInfo,
) -> Result<String, &'static str> {
    if report.issues.is_empty() {
        return Ok(String::new());
    }

    let mut output = String::new();
    for issue in &report.issues {
        let level = match issue.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "notice",
        };
        let location = file_location(issue);
        let category = code_issue_category(issue, rules)?.label();
        let mut message_parts = vec![
            format!("[{category}] {}", issue.title),
            issue.description.clone(),
        ];
        if let Some(evidence) = &issue.evidence {
            message_parts.push(format!("Evidence: {}", evidence));
        }
        if let Some(likely_fix) = &issue.likely_fix {
            message_parts.push(format!("Best first fix: {}", likely_fix));
        }
        if let Some(verify_hint) = &issue.verify_hint {
            message_parts.push(format!("Verify: {}", verify_hint));
        }
        let message = escape_github_data(&message_parts.join(" "));
        let title =
            escape_github_property(&format!("SiteCMD {} [{category}]", issue.severity.label()));
        let file = escape_github_property(&issue.relative_path);
        let line = issue.line.unwrap_or(1);
        let _ = writeln!(
            output,
            "::{} file={},line={},title={}::{}",
            level, file, line, title, message
        );
        let _ = writeln!(
            output,
            "::notice file={},line={},title={}::{}",
            file,
            line,
            escape_github_property("SiteCMD location"),
            escape_github_data(location.as_str())
        );
    }
    Ok(output)
}

fn issues_for_severity<'a>(report: &'a CodeScanReport, severity: &Severity) -> Vec<&'a CodeIssue> {
    report
        .issues
        .iter()
        .filter(|issue| &issue.severity == severity)
        .collect()
}

fn file_location(issue: &CodeIssue) -> String {
    match issue.line {
        Some(line) => format!("{}:{}", issue.relative_path, line),
        None => issue.relative_path.clone(),
    }
}

fn escape_github_property(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn escape_github_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use sitecmd_protocol::engine_abi::ENGINE_ABI_VERSION;
    use sitecmd_protocol::skipped_scopes::CodeScanSkippedScopes;

    const SAMPLE: &str = "firestore.rules:3:7: unsupported match";
    const NOTE: &str =
        "Rules analysis incomplete. Skipped rules constructs: 2.\nfirestore.rules:3:7: unsupported match";

    fn render(format: CodeScanReportFormat, skipped: Option<usize>) -> String {
        let report = CodeScanReport {
            checked_at: "2026-11-23T00:00:00Z".into(),
            framework: None,
            issue_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            issues: Vec::new(),
            skipped_scopes: CodeScanSkippedScopes {
                rule_blocks_skipped: skipped,
                rule_samples: skipped.map(|_| vec![SAMPLE.into()]),
                ..CodeScanSkippedScopes::default()
            },
        };
        let rules = EngineInfo {
            module_version: "fixture".into(),
            abi_version: ENGINE_ABI_VERSION,
            manifest_digest: "0000000000000000".try_into().unwrap(),
            code_rules: Vec::new(),
            local_checks: Vec::new(),
        };
        format_report(&report, &rules, Path::new("project"), format).unwrap()
    }

    #[test]
    fn each_report_format_publishes_incomplete_rules_analysis() {
        use CodeScanReportFormat::*;
        for &(format, name) in CodeScanReportFormat::ALL {
            let report = render(format, Some(2));
            match format {
                Json => {
                    let json: Value = serde_json::from_str(&report).unwrap();
                    assert_eq!(json["skippedScopes"]["ruleBlocksSkipped"], 2);
                    assert_eq!(json["skippedScopes"]["ruleSamples"], json!([SAMPLE]));
                    assert!(!report.contains("Rules analysis incomplete"), "{name}");
                }
                Sarif => {
                    let sarif: Value = serde_json::from_str(&report).unwrap();
                    assert_eq!(
                        sarif["runs"][0]["invocations"],
                        json!([{
                            "executionSuccessful": true,
                            "toolExecutionNotifications": [
                                { "level": "warning", "message": { "text": NOTE } }
                            ]
                        }])
                    );
                }
                Github => {
                    assert_eq!(
                        report,
                        "::warning::Rules analysis incomplete. Skipped rules constructs: 2.%0Afirestore.rules:3:7: unsupported match\n"
                    );
                }
                Summary | Markdown | Review => {
                    assert!(report.ends_with(&format!("\n{NOTE}\n")), "{name}");
                }
            }
        }
    }

    #[test]
    fn no_report_format_warns_when_zero_rules_blocks_were_skipped() {
        for &(format, name) in CodeScanReportFormat::ALL {
            let report = render(format, Some(0));
            assert!(!report.contains("Rules analysis incomplete"), "{name}");
            if format != CodeScanReportFormat::Json {
                assert_eq!(report, render(format, None), "{name}");
            }
        }
    }
}
