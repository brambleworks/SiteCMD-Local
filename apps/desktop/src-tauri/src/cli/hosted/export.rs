//! Workspace guidance from hosted findings.

use std::fmt::Write;
use std::path::Path;

use serde_json::json;

use super::report::{clean, Report};
use crate::cli::export::{render_rules_md, verify_hint, write_file};
use crate::core::scan_types::Category;

pub(super) fn write(dir: &Path, report: &Report) -> Result<(), String> {
    let url = clean(report.url.as_str());
    let score = report.score();
    let timestamp = &report.timestamp;
    let mut findings: Vec<_> = report
        .issues
        .iter()
        .map(|issue| (issue, clean(&issue.title)))
        .collect();
    findings.sort_by_key(|(issue, _)| issue.severity.sort_rank());

    let mut markdown = format!(
        "# SiteCMD - {url}\nScore: {score}/100 | Scanned: {timestamp}\nRescan: `sitecmd scan --diff`\n\n"
    );
    let _ = writeln!(markdown, "## Fixes\n");
    if findings.is_empty() {
        let _ = writeln!(markdown, "No issues found.");
    }
    for (issue, title) in &findings {
        let _ = writeln!(
            markdown,
            "### {title}\nID: {} | {:?}\n",
            issue.check_id, issue.severity
        );
        let _ = writeln!(markdown, "Occurrences: {}\n", issue.occurrences);
        let _ = writeln!(markdown, "Verify: {}\n", verify_hint(&issue.check_id, &url));
    }

    let issues: Vec<_> = findings
        .iter()
        .map(|(issue, title)| {
            json!({
                "id": issue.check_id,
                "title": title,
                "severity": issue.severity,
                "category": issue.category,
                "occurrences": issue.occurrences,
                "verify": verify_hint(&issue.check_id, &url),
            })
        })
        .collect();
    let categories: Vec<_> = Category::ALL
        .into_iter()
        .filter_map(|category| {
            let score = report.category_scores.get(category.key());
            let count = findings
                .iter()
                .filter(|(issue, _)| issue.category == Some(category))
                .count();
            (score.is_some() || count > 0).then(|| {
                json!({
                    "key": category.key(),
                    "name": category.label(),
                    "score": score,
                    "issues": count,
                })
            })
        })
        .collect();
    let json = serde_json::to_string_pretty(&json!({
        "url": url,
        "score": score,
        "scanned_at": timestamp,
        "issues": issues,
        "categories": categories,
    }))
    .map_err(|error| error.to_string())?;
    let rules = render_rules_md(
        &url,
        findings.iter().filter_map(|(issue, title)| {
            Some((issue.category?, issue.check_id.as_str(), title.as_str()))
        }),
    );
    write_file(dir, "issues.md", &markdown)?;
    write_file(dir, "issues.json", &json)?;
    write_file(dir, "rules.md", &rules)
}
