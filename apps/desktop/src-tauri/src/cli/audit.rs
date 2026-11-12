use crate::checks::Severity;
use crate::cli::audit_suppressions::{
    apply_project_suppressions, issue_fingerprint, IgnoredFinding, SuppressedAudit,
    SuppressionState,
};
use crate::core::code_scan::{
    audit_project_with_options, format_report, CodeIssueView, CodeScanOptions,
    CodeScanReportFormat, CodeScanReportView,
};
use std::fmt::Write as _;
use std::path::PathBuf;

pub const HELP: &str = concat!(
    "SiteCMD audit - Run Code Scan against a source checkout\n\n",
    "Usage:\n  sitecmd audit <path> [options]\n\n",
    "Reviewed findings can be suppressed through .sitecmd/config.json. JSON reports include occurrence fingerprints and suppression status.\n\n",
    "Options:\n",
    "  --format <FORMAT>      summary, json, markdown, review, github, or sarif (default: summary)\n",
    "  --fail-on <SEVERITY>   Exit 1 when a critical, high, medium, or low finding meets the threshold\n",
    "  --output <PATH>        Write the report to a file instead of stdout\n",
    "  --baseline <PATH>      A previous --format json report; findings whose fingerprint it lists never trip --fail-on\n",
    "  --inspect-local-databases\n",
    "                         Opt in to local dotenv target discovery and read-only inspection of project SQLite and loopback PostgreSQL schemas\n",
    "  --help, -h             Show this help\n\n",
    "Exit codes:\n",
    "  0  Audit completed and no configured threshold was met\n",
    "  1  A finding met or exceeded --fail-on\n",
    "  2  Usage, scan, or output error\n\n",
    "Examples:\n",
    "  sitecmd audit .\n",
    "  sitecmd audit . --format review --output sitecmd-review.md\n",
    "  sitecmd audit . --inspect-local-databases\n",
    "  sitecmd audit . --format github --fail-on high\n",
    "  sitecmd audit . --format sarif --output sitecmd.sarif\n",
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditArgs {
    pub project_path: PathBuf,
    pub format: CodeScanReportFormat,
    pub fail_on: Option<Severity>,
    pub output: Option<PathBuf>,
    pub inspect_local_databases: bool,
    pub baseline: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOutcome {
    pub rendered: String,
    pub threshold_failed: bool,
}

pub fn help_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
}

pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<AuditArgs, String> {
    let mut args = args.into_iter();
    let mut project_path = None;
    let mut format = CodeScanReportFormat::Summary;
    let mut fail_on = None;
    let mut output = None;
    let mut inspect_local_databases = false;
    let mut baseline = None;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--format" => {
                let value = next_value(&mut args, "--format")?;
                format = match value.as_str() {
                    "summary" => CodeScanReportFormat::Summary,
                    "json" => CodeScanReportFormat::Json,
                    "markdown" | "md" => CodeScanReportFormat::Markdown,
                    "review" => CodeScanReportFormat::Review,
                    "github" | "gh" => CodeScanReportFormat::Github,
                    "sarif" => CodeScanReportFormat::Sarif,
                    _ => {
                        return Err(format!(
                            "Unknown format: {value}. Use: summary, json, markdown, review, github, sarif"
                        ))
                    }
                };
            }
            "--fail-on" => {
                let value = next_value(&mut args, "--fail-on")?;
                fail_on = Some(value.parse::<Severity>()?);
            }
            "--output" => {
                output = Some(PathBuf::from(next_value(&mut args, "--output")?));
            }
            "--baseline" => {
                baseline = Some(PathBuf::from(next_value(&mut args, "--baseline")?));
            }
            "--inspect-local-databases" => {
                inspect_local_databases = true;
            }
            "--help" | "-h" => return Err("help requested".into()),
            option if option.starts_with('-') => {
                return Err(format!("Unknown option: {option}"));
            }
            value => {
                if project_path.is_some() {
                    return Err(format!("Unexpected extra path argument: {value}"));
                }
                project_path = Some(PathBuf::from(value));
            }
        }
    }

    Ok(AuditArgs {
        project_path: project_path.ok_or_else(|| "Missing project path".to_string())?,
        format,
        fail_on,
        output,
        inspect_local_databases,
        baseline,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("Missing value for {option}"))
}

pub fn run(args: &AuditArgs) -> Result<AuditOutcome, String> {
    let report = audit_project_with_options(
        &args.project_path,
        CodeScanOptions {
            inspect_local_databases: args.inspect_local_databases,
        },
    )
    .map_err(|error| format!("Code Scan audit failed: {error}"))?;
    let project_root = std::fs::canonicalize(&args.project_path).map_err(|error| {
        format!(
            "Could not resolve Code Scan project path {}: {error}",
            args.project_path.display()
        )
    })?;
    let audit = apply_project_suppressions(&project_root, report, chrono::Utc::now().date_naive())?;
    let baseline = match &args.baseline {
        Some(path) => read_baseline_fingerprints(path)?,
        None => std::collections::HashSet::new(),
    };
    let display_path = if args.project_path.is_absolute() {
        std::path::Path::new(".")
    } else {
        &args.project_path
    };
    let rendered = format_audit_report(&audit, display_path, args.format, &baseline)
        .map_err(|error| format!("Could not render Code Scan report: {error}"))?;

    if let Some(output_path) = &args.output {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "Could not create output directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
        }
        std::fs::write(output_path, rendered.as_bytes()).map_err(|error| {
            format!(
                "Could not write report to {}: {error}",
                output_path.display()
            )
        })?;
    }

    Ok(AuditOutcome {
        threshold_failed: args.fail_on.is_some_and(|severity| {
            audit.report.issues.iter().any(|issue| {
                issue.severity.sort_rank() <= severity.sort_rank()
                    && !baseline.contains(&issue_fingerprint(issue))
            })
        }),
        rendered,
    })
}

/// Fingerprints from a previous `--format json` report, open or ignored.
fn read_baseline_fingerprints(
    path: &std::path::Path,
) -> Result<std::collections::HashSet<String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("Could not read baseline {}: {error}", path.display()))?;
    let report: serde_json::Value = serde_json::from_str(&contents).map_err(|error| {
        format!(
            "Baseline {} is not a sitecmd audit JSON report: {error}",
            path.display()
        )
    })?;
    let mut fingerprints = std::collections::HashSet::new();
    for key in ["issues", "ignoredFindings"] {
        for finding in report[key].as_array().into_iter().flatten() {
            if let Some(fingerprint) = finding["fingerprint"].as_str() {
                fingerprints.insert(fingerprint.to_string());
            }
        }
    }
    if fingerprints.is_empty() {
        return Err(format!(
            "Baseline {} lists no fingerprints; generate it with sitecmd audit --format json",
            path.display()
        ));
    }
    Ok(fingerprints)
}

fn format_audit_report(
    audit: &SuppressedAudit,
    project_path: &std::path::Path,
    format: CodeScanReportFormat,
    baseline: &std::collections::HashSet<String>,
) -> Result<String, String> {
    if format == CodeScanReportFormat::Json {
        return format_audit_json(audit, baseline);
    }
    if format == CodeScanReportFormat::Sarif {
        return format_audit_sarif(audit, baseline);
    }

    let mut rendered = format_report(&audit.report, project_path, format)?;
    if audit.suppressions.is_empty() && baseline.is_empty() {
        return Ok(rendered);
    }

    match format {
        CodeScanReportFormat::Summary => {
            if !audit.suppressions.is_empty() {
                let _ = writeln!(
                    rendered,
                    "\nSuppressions: {} ignored | {} stale or expired",
                    audit.ignored_findings.len(),
                    audit.stale_suppression_count()
                );
                append_text_suppression_details(&mut rendered, audit);
            }
            if !baseline.is_empty() {
                let baseline_count = audit
                    .report
                    .issues
                    .iter()
                    .filter(|issue| baseline.contains(&issue_fingerprint(issue)))
                    .count();
                let _ = writeln!(
                    rendered,
                    "\nBaseline: {baseline_count} known finding(s) excluded from --fail-on"
                );
            }
        }
        CodeScanReportFormat::Markdown | CodeScanReportFormat::Review => {
            if !audit.suppressions.is_empty() {
                let _ = writeln!(rendered, "\n## Suppressions");
                let _ = writeln!(
                    rendered,
                    "\n- Ignored findings: `{}`",
                    audit.ignored_findings.len()
                );
                let _ = writeln!(
                    rendered,
                    "- Stale or expired entries: `{}`",
                    audit.stale_suppression_count()
                );
                append_text_suppression_details(&mut rendered, audit);
            }
        }
        CodeScanReportFormat::Github => {
            if !audit.suppressions.is_empty() {
                let _ = writeln!(
                    rendered,
                    "::notice title=SiteCMD suppressions::{} finding(s) ignored; {} stale or expired suppression(s)",
                    audit.ignored_findings.len(),
                    audit.stale_suppression_count()
                );
            }
        }
        CodeScanReportFormat::Json => unreachable!("JSON returned above"),
        CodeScanReportFormat::Sarif => unreachable!("SARIF returned above"),
    }
    Ok(rendered)
}

fn format_audit_sarif(
    audit: &SuppressedAudit,
    baseline: &std::collections::HashSet<String>,
) -> Result<String, String> {
    let mut sarif: serde_json::Value = serde_json::from_str(&format_report(
        &audit.report,
        std::path::Path::new("."),
        CodeScanReportFormat::Sarif,
    )?)
    .map_err(|error| format!("Could not parse SARIF report: {error}"))?;
    let results = sarif["runs"][0]["results"]
        .as_array_mut()
        .ok_or_else(|| "SARIF report has no results array".to_string())?;
    for (result, issue) in results.iter_mut().zip(&audit.report.issues) {
        let fingerprint = issue_fingerprint(issue);
        result["baselineState"] = serde_json::Value::String(if baseline.contains(&fingerprint) {
            "unchanged".into()
        } else {
            "new".into()
        });
        result["partialFingerprints"] = serde_json::json!({ "sitecmd/v1": fingerprint });
    }
    for finding in &audit.ignored_findings {
        results.push(serde_json::json!({
            "ruleId": finding.issue.check_id,
            "level": "note",
            "message": { "text": finding.issue.description },
            "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": finding.issue.relative_path.replace('\\', "/"), "uriBaseId": "%SRCROOT%" },
                "region": { "startLine": finding.issue.line.unwrap_or(1) }
            } }],
            "partialFingerprints": { "sitecmd/v1": finding.fingerprint },
            "suppressions": [{ "kind": "external", "justification": finding.reason }],
        }));
    }
    serde_json::to_string_pretty(&sarif)
        .map_err(|error| format!("Could not serialize SARIF report: {error}"))
}

/// The JSON report is a CI artifact a project can commit, so the generating machine's checkout path never ships in it.
const LOCAL_CHECKOUT_PATH_FIELD: &str = "absolutePath";

fn format_audit_json(
    audit: &SuppressedAudit,
    baseline: &std::collections::HashSet<String>,
) -> Result<String, String> {
    let mut value = serde_json::to_value(CodeScanReportView::from(&audit.report))
        .map_err(|error| format!("Could not serialize code scan report: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Could not serialize Code Scan report as an object".to_string())?;

    let mut baseline_count = 0usize;
    if let Some(issues) = object
        .get_mut("issues")
        .and_then(serde_json::Value::as_array_mut)
    {
        for (value, issue) in issues.iter_mut().zip(&audit.report.issues) {
            if let Some(issue_object) = value.as_object_mut() {
                issue_object.remove(LOCAL_CHECKOUT_PATH_FIELD);
                let fingerprint = issue_fingerprint(issue);
                let in_baseline = baseline.contains(&fingerprint);
                if in_baseline {
                    baseline_count += 1;
                }
                issue_object.insert("fingerprint".into(), serde_json::Value::String(fingerprint));
                issue_object.insert("inBaseline".into(), serde_json::Value::Bool(in_baseline));
            }
        }
    }

    object.insert("baselineCount".into(), serde_json::json!(baseline_count));
    object.insert(
        "ignoredCount".into(),
        serde_json::json!(audit.ignored_findings.len()),
    );
    object.insert(
        "staleSuppressionCount".into(),
        serde_json::json!(audit.stale_suppression_count()),
    );
    object.insert(
        "ignoredFindings".into(),
        serde_json::Value::Array(
            audit
                .ignored_findings
                .iter()
                .map(ignored_finding_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    object.insert(
        "suppressions".into(),
        serde_json::to_value(&audit.suppressions)
            .map_err(|error| format!("Could not serialize Code Scan suppressions: {error}"))?,
    );
    serde_json::to_string_pretty(&value)
        .map_err(|error| format!("Could not serialize code scan report: {error}"))
}

fn ignored_finding_json(finding: &IgnoredFinding) -> Result<serde_json::Value, String> {
    let mut value = serde_json::to_value(CodeIssueView::from(&finding.issue))
        .map_err(|error| format!("Could not serialize ignored Code Scan finding: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Could not serialize ignored Code Scan finding as an object".to_string())?;
    object.remove(LOCAL_CHECKOUT_PATH_FIELD);
    object.insert(
        "fingerprint".into(),
        serde_json::Value::String(finding.fingerprint.clone()),
    );
    object.insert(
        "reason".into(),
        serde_json::Value::String(finding.reason.clone()),
    );
    object.insert(
        "expires".into(),
        finding
            .expires
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    object.insert(
        "suppressionIndex".into(),
        serde_json::json!(finding.suppression_index + 1),
    );
    Ok(value)
}

fn append_text_suppression_details(rendered: &mut String, audit: &SuppressedAudit) {
    for finding in &audit.ignored_findings {
        let _ = writeln!(
            rendered,
            "- Ignored `{}` in `{}` ({}) - {}",
            finding.issue.check_id,
            finding.issue.relative_path,
            finding.fingerprint,
            finding.reason
        );
    }
    for (index, suppression) in audit.suppressions.iter().enumerate() {
        if suppression.state == SuppressionState::Active {
            continue;
        }
        let _ = writeln!(
            rendered,
            "- Suppression {} is {:?}: {}",
            index + 1,
            suppression.state,
            suppression.reason
        );
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "audit_database_tests.rs"]
mod database_tests;
