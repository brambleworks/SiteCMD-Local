//! Hosted score and findings, plus the local artifact used by fix and diff.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sitecmd_protocol::sync::wire::{CheckId, Identifier, Timestamp};
use url::Url;

use super::{client, HostedError, HostedError::RequestFailed};
use crate::cli::scan::{self, ScanArgs};
use crate::connected_service::ConnectedServiceClient;
use crate::core::scan_types::{Category, ScanType, Severity};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct Finding {
    pub(in crate::cli) check_id: CheckId,
    pub(in crate::cli) title: String,
    #[serde(default, deserialize_with = "read_category")]
    pub(in crate::cli) category: Option<Category>,
    pub(in crate::cli) severity: Severity,
    pub(super) occurrences: u32,
    /// `None` when the file predates fix guides, `Some(None)` when Connect has no guide.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(in crate::cli) fix_guide: Option<Option<FixGuide>>,
}

fn read_category<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Category>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.and_then(|key| key.parse().ok()))
}

fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<FixGuide>>, D::Error> {
    Option::deserialize(deserializer).map(Some)
}

/// Connect's fix text for a check, in the shape Connect sends it.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct FixGuide {
    #[serde(default)]
    pub(in crate::cli) plain_only: bool,
    pub(in crate::cli) lead: Option<String>,
    #[serde(default)]
    pub(in crate::cli) plain: Vec<String>,
    pub(in crate::cli) steps: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct Report {
    connect_origin: String,
    site_id: Identifier,
    pub(super) scan_id: Identifier,
    pub(in crate::cli) url: Url,
    overall_score: u32,
    pub(super) timestamp: Timestamp,
    pub(super) category_scores: BTreeMap<String, u32>,
    pub(in crate::cli) issues: Vec<Finding>,
}

impl Report {
    pub(super) async fn read(
        client: &ConnectedServiceClient,
        site: &Identifier,
        url: &Url,
        scan: &client::Scan,
    ) -> Result<Self, HostedError> {
        let before = client::score(client, site).await?;
        let timestamp = before.last_scan_at.ok_or(RequestFailed)?;
        if scan.finished_at.as_ref() != Some(&timestamp) || before.score.overall > 100 {
            return Err(RequestFailed);
        }
        let issues = client::groups(client, site)
            .await?
            .into_iter()
            .map(|group| {
                Ok(Finding {
                    check_id: group.check,
                    title: group.title,
                    category: group.category.parse().ok(),
                    severity: group.severity.ok_or(RequestFailed)?,
                    occurrences: group.occurrences,
                    fix_guide: Some(group.fix_guide),
                })
            })
            .collect::<Result<_, HostedError>>()?;
        let after = client::score(client, site).await?;
        if after.last_scan_at.as_ref() != Some(&timestamp) || after.score != before.score {
            return Err(RequestFailed);
        }
        Ok(Self {
            connect_origin: client.origin(),
            site_id: site.clone(),
            scan_id: scan.id.clone(),
            url: url.clone(),
            overall_score: after.score.overall,
            timestamp,
            category_scores: after.score.per_category,
            issues,
        })
    }

    fn same_site(&self, other: &Self) -> bool {
        self.connect_origin == other.connect_origin
            && self.site_id == other.site_id
            && client::same_origin(&self.url, &other.url)
    }

    pub(in crate::cli) fn score(&self) -> u32 {
        self.overall_score
    }
}

#[derive(Deserialize, Serialize)]
pub(in crate::cli) struct Artifact {
    pub(in crate::cli) hosted: Report,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) previous: Option<Report>,
}

impl Artifact {
    pub(super) fn baseline_for(&self, current: &Report, expected: &Identifier) -> Option<&Report> {
        std::iter::once(&self.hosted)
            .chain(self.previous.as_ref())
            .find(|old| old.scan_id == *expected && old.same_site(current))
    }

    pub(super) fn older_than(&self, current: &Report) -> Option<&Report> {
        let current_time = current.timestamp.parse::<jiff::Timestamp>().ok()?;
        std::iter::once(&self.hosted)
            .chain(self.previous.as_ref())
            .find(|old| {
                old.same_site(current)
                    && old
                        .timestamp
                        .parse::<jiff::Timestamp>()
                        .is_ok_and(|at| at < current_time)
            })
    }
}

pub(in crate::cli) fn read_artifact(dir: &Path) -> Result<Artifact, String> {
    let text = super::super::read_cli_artifact(
        dir,
        &dir.join("last-scan.json"),
        crate::constants::MAX_CLI_SCAN_BYTES,
    )?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

fn write_artifact(dir: &Path, artifact: &Artifact) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, artifact).map_err(|error| error.to_string())?;
    file.flush().map_err(|error| error.to_string())?;
    file.persist(dir.join("last-scan.json"))
        .map_err(|error| error.to_string())?;
    super::export::write(dir, &artifact.hosted)
}

pub(super) fn export_artifact(dir: &Path, artifact: &Artifact) -> bool {
    match write_artifact(dir, artifact) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("Warning: failed to export scan results: {error}");
            false
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryRow {
    category: Category,
    score: Option<u32>,
    issues_total: usize,
    issues_critical: usize,
    issues_high: usize,
    issues_medium: usize,
    issues_low: usize,
}

impl CategoryRow {
    fn record(&mut self, issue: &Finding) {
        self.issues_total += 1;
        match issue.severity {
            Severity::Critical => self.issues_critical += 1,
            Severity::High => self.issues_high += 1,
            Severity::Medium => self.issues_medium += 1,
            Severity::Low => self.issues_low += 1,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct View<'a> {
    url: &'a Url,
    mode: &'static str,
    scan_type: ScanType,
    overall_score: Option<u32>,
    timestamp: &'a Timestamp,
    categories: Vec<CategoryRow>,
    issues: Vec<&'a Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<Diff<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Diff<'a> {
    previous_score: Option<u32>,
    fixed: Vec<&'a Finding>,
    introduced: Vec<&'a Finding>,
    remaining: Vec<&'a Finding>,
}

fn category_in_view(category: Option<Category>, args: &ScanArgs) -> bool {
    args.categories
        .as_ref()
        .is_none_or(|categories| category.is_some_and(|key| categories.contains(&key)))
}

fn selected_score(report: &Report, args: &ScanArgs) -> Option<u32> {
    let Some(categories) = &args.categories else {
        return Some(report.overall_score);
    };
    let score = |category: &Category| report.category_scores.get(category.key()).copied();
    let (first, rest) = categories.split_first()?;
    rest.iter().try_fold(score(first)?, |lowest, category| {
        Some(lowest.min(score(category)?))
    })
}

fn diff<'a>(
    current: &'a Report,
    previous: &'a Report,
    args: &ScanArgs,
    show: impl Fn(&Finding) -> bool,
) -> Diff<'a> {
    let visible = |rows: &'a [Finding]| rows.iter().filter(|issue| show(issue)).collect::<Vec<_>>();
    let previous_rows = visible(&previous.issues);
    let current_rows = visible(&current.issues);
    let old_ids: std::collections::HashSet<_> =
        previous_rows.iter().map(|row| &row.check_id).collect();
    let new_ids: std::collections::HashSet<_> =
        current_rows.iter().map(|row| &row.check_id).collect();
    Diff {
        previous_score: selected_score(previous, args),
        fixed: previous_rows
            .into_iter()
            .filter(|row| !new_ids.contains(&row.check_id))
            .collect(),
        introduced: current_rows
            .iter()
            .copied()
            .filter(|row| !old_ids.contains(&row.check_id))
            .collect(),
        remaining: current_rows
            .into_iter()
            .filter(|row| old_ids.contains(&row.check_id))
            .collect(),
    }
}

fn view<'a>(current: &'a Report, previous: Option<&'a Report>, args: &ScanArgs) -> View<'a> {
    let show = |issue: &Finding| category_in_view(issue.category, args);
    let issues: Vec<_> = current.issues.iter().filter(|issue| show(issue)).collect();
    let categories = Category::ALL
        .into_iter()
        .filter(|category| category_in_view(Some(*category), args))
        .filter_map(|category| {
            let mut row = category_row(
                category,
                current.category_scores.get(category.key()).copied(),
            );
            for issue in issues
                .iter()
                .filter(|issue| issue.category == Some(category))
            {
                row.record(issue);
            }
            (row.score.is_some() || row.issues_total > 0).then_some(row)
        })
        .collect();
    View {
        url: &current.url,
        mode: "live",
        scan_type: ScanType::Health,
        overall_score: selected_score(current, args),
        timestamp: &current.timestamp,
        categories,
        issues,
        diff: previous.map(|old| diff(current, old, args, show)),
    }
}

fn category_row(category: Category, score: Option<u32>) -> CategoryRow {
    CategoryRow {
        category,
        score,
        issues_total: 0,
        issues_critical: 0,
        issues_high: 0,
        issues_medium: 0,
        issues_low: 0,
    }
}

fn print_text(view: &View<'_>) {
    if let Some(diff) = &view.diff {
        println!("SiteCMD diff - {}", view.url);
        if let (Some(previous), Some(current)) = (diff.previous_score, view.overall_score) {
            let delta = i64::from(current) - i64::from(previous);
            println!("Score: {previous} \u{2192} {current} ({delta:+})\n");
        } else if let Some(current) = view.overall_score {
            print_score(current, view.scan_type);
        }
        if !diff.fixed.is_empty() {
            println!("Fixed ({}):", diff.fixed.len());
            for issue in &diff.fixed {
                println!("  \u{2714} {} - {}", issue.check_id, clean(&issue.title));
            }
            println!();
        }
        for (label, issues) in [
            ("New issues", &diff.introduced),
            ("Remaining", &diff.remaining),
        ] {
            if !issues.is_empty() {
                println!("{label} ({}):", issues.len());
                print_issues(issues);
                println!();
            }
        }
        if diff.fixed.is_empty() && diff.introduced.is_empty() && diff.remaining.is_empty() {
            println!("No issues in either scan.");
        }
        return;
    }

    println!("SiteCMD - {}", view.url);
    if let Some(score) = view.overall_score {
        print_score(score, view.scan_type);
    }
    println!("{:<20} {:>5}  Issues", "Category", "Score");
    println!("{}", "\u{2500}".repeat(50));
    for category in &view.categories {
        scan::print_category(
            category.category.label(),
            category.score,
            [
                category.issues_critical,
                category.issues_high,
                category.issues_medium,
                category.issues_low,
            ],
        );
    }
    if view.issues.is_empty() {
        println!("\nNo issues found.");
    } else {
        println!("\nIssues ({} total):", view.issues.len());
        print_issues(&view.issues);
    }
}

fn print_score(score: u32, scan_type: ScanType) {
    println!("Score: {score}/100 ({scan_type} scan)\n");
}

fn print_issues(issues: &[&Finding]) {
    for issue in issues {
        scan::print_issue(&issue.severity, &issue.check_id, &clean(&issue.title));
    }
}

pub(in crate::cli) fn clean(input: &str) -> String {
    input.chars().filter(|ch| !ch.is_control()).collect()
}

pub(super) fn finish(
    current: Report,
    previous: Option<Report>,
    args: &ScanArgs,
    dir: Option<&Path>,
) -> Result<u8, HostedError> {
    let artifact = Artifact {
        hosted: current,
        previous,
    };
    let baseline = artifact.previous.as_ref().filter(|_| args.diff);
    let view = view(&artifact.hosted, baseline, args);
    let json = args
        .json
        .then(|| serde_json::to_string_pretty(&view))
        .transpose()
        .map_err(|_| RequestFailed)?;
    if args.diff && baseline.is_none() {
        eprintln!("{}", scan::NO_EARLIER_SCAN);
    }
    let exported =
        args.categories.is_none() && dir.is_some_and(|dir| export_artifact(dir, &artifact));
    if let Some(json) = json {
        println!("{json}");
    } else {
        print_text(&view);
        if let Some(dir) = dir.filter(|_| exported) {
            scan::print_claude_snippet(dir);
        }
    }
    Ok(exit_code(&view, args))
}

fn exit_code(view: &View<'_>, args: &ScanArgs) -> u8 {
    if args.fail_under.is_some() && view.overall_score.is_none() {
        eprintln!("\nFailed: a selected category has no score.");
        return 1;
    }
    let gate = scan::threshold_exit_code(
        view.overall_score,
        view.issues.iter().map(|issue| &issue.severity),
        args,
    );
    if gate != 0 {
        return gate;
    }
    view.diff.as_ref().map_or(0, |diff| {
        scan::regression_exit_code(
            diff.introduced
                .iter()
                .filter(|issue| issue.severity == Severity::Critical)
                .count(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_filter_keeps_matching_rows_and_full_scan_keeps_unknown_rows() {
        let args = ScanArgs {
            categories: Some(vec![Category::Email]),
            ..super::super::tests::args()
        };
        assert!(category_in_view(Some(Category::Email), &args));
        assert!(!category_in_view(Some(Category::Security), &args));
        let all = super::super::tests::args();
        assert!(category_in_view(Some(Category::DomainHttps), &all));
        assert!(!category_in_view(None, &args));
        assert!(category_in_view(None, &all));
    }

    #[test]
    fn hosted_comparison_uses_the_selected_scores_in_both_reports() {
        // Bug: A filtered comparison can show the previous overall score beside a category score.
        let report = |overall, security, performance| {
            serde_json::from_value::<Report>(serde_json::json!({
                "connectOrigin": "https://connect.example.com",
                "siteId": "site_a",
                "scanId": "hs_a",
                "url": "https://example.com",
                "overallScore": overall,
                "timestamp": "2026-11-21T16:00:00.000Z",
                "categoryScores": { "security": security, "performance": performance },
                "issues": [],
            }))
            .unwrap()
        };
        let previous = report(80, 70, 60);
        let current = report(85, 75, 90);
        use Category::{Accessibility, Performance, Security};
        for (categories, old, new) in [
            (None, Some(80), Some(85)),
            (Some(vec![Security]), Some(70), Some(75)),
            (Some(vec![Security, Performance]), Some(60), Some(75)),
            (Some(vec![Security, Accessibility]), None, None),
        ] {
            let args = ScanArgs {
                categories,
                fail_under: Some(75),
                ..super::super::tests::args()
            };
            let view = view(&current, Some(&previous), &args);
            assert_eq!(view.overall_score, new);
            if new.is_none() {
                assert_eq!(exit_code(&view, &args), 1);
            }
            assert_eq!(view.diff.unwrap().previous_score, old);
        }
    }
}
