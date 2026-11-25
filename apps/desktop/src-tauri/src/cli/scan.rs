//! Web Scan CLI command.

use crate::core::scan_types::{actionable, Category, ScanResult, ScanType, Severity};

use super::hosted::{self, HostedError};
use super::lane::{self, Lane, LOCAL_CHECKS_NOTICE};

pub(super) const NO_EARLIER_SCAN: &str = "There was no earlier finished scan to compare with.";

pub struct ScanArgs {
    pub url: Option<String>,
    pub fail_under: Option<u32>,
    pub fail_on: Option<Severity>,
    pub json: bool,
    pub timeout: Option<u64>,
    pub categories: Option<Vec<Category>>,
    pub diff: bool,
    pub env_name: Option<String>,
    pub latest: bool,
    pub connect_origin: Option<String>,
}

#[derive(Debug)]
pub enum ScanFailure {
    Local(String),
    Hosted(HostedError),
}

/// Run a scan and return its process exit code.
pub async fn run(args: ScanArgs) -> Result<u8, ScanFailure> {
    if args.diff && args.categories.is_some() {
        return Err(ScanFailure::Local("--diff cannot be combined with --categories. Run an unfiltered scan --diff to compare the same scope.".into()));
    }
    let url = resolve_url(&args).map_err(ScanFailure::Local)?;
    let target = lane::Target::resolve(&url, args.timeout)
        .await
        .map_err(|error| ScanFailure::Local(error.to_string()))?;
    if target.lane() == Lane::Hosted {
        return hosted::run(&target.url, &args)
            .await
            .map_err(ScanFailure::Hosted);
    }

    if args.latest {
        const LOCAL_LATEST: &str = "--latest requires a public site.";
        return Err(ScanFailure::Local(LOCAL_LATEST.into()));
    }
    if args.diff {
        run_diff(target, args).await.map_err(ScanFailure::Local)
    } else {
        run_standard(target, args).await.map_err(ScanFailure::Local)
    }
}

async fn run_standard(target: lane::Target, args: ScanArgs) -> Result<u8, String> {
    let scan = local_scan(target, args.categories.clone()).await?;

    if args.json {
        print_json(&scan);
        eprintln!("{LOCAL_CHECKS_NOTICE}");
    } else {
        print_text(&scan);
        println!("{LOCAL_CHECKS_NOTICE}");
    }

    // Only full scans outside JSON mode replace the shared artifacts.
    if let Some(sitecmd_dir) = export_scan_files(
        &scan,
        args.json,
        args.categories.as_deref(),
        crate::cli::find_config_dir(),
    ) {
        eprintln!("\r\x1b[KExported to {}/", sitecmd_dir.display());
        print_claude_snippet(&sitecmd_dir);
    }

    Ok(check_threshold(&scan, &args))
}

/// Write `.sitecmd/` artifacts for a full scan outside JSON mode.
/// Returns None when skipped or when a failed write warns on stderr.
fn export_scan_files(
    scan: &ScanResult,
    json_mode: bool,
    categories: Option<&[Category]>,
    sitecmd_dir: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if json_mode || categories.is_some() {
        return None;
    }
    let dir = sitecmd_dir?;
    match crate::cli::export::export_scan(&dir, scan) {
        Ok(()) => Some(dir),
        Err(e) => {
            eprintln!("Warning: failed to export scan results: {}", e);
            None
        }
    }
}

async fn run_diff(target: lane::Target, args: ScanArgs) -> Result<u8, String> {
    let sitecmd_dir = crate::cli::find_config_dir()
        .ok_or_else(|| "No .sitecmd/ directory found. Run `sitecmd init` first or use `sitecmd scan` without --diff.".to_string())?;

    let Some(old_scan) = load_diff_baseline(&sitecmd_dir)? else {
        eprintln!("{NO_EARLIER_SCAN}");
        return run_standard(target, args).await;
    };

    let new_scan = local_scan(target, None).await?;
    print_diff(&old_scan, &new_scan);
    println!("{LOCAL_CHECKS_NOTICE}");

    // Overwrite `.sitecmd/` files.
    if let Err(e) = crate::cli::export::export_scan(&sitecmd_dir, &new_scan) {
        eprintln!("Warning: failed to export scan results: {}", e);
    }

    Ok(diff_exit_code(&old_scan, &new_scan, &args))
}

/// The local baseline, or None when the last scan was hosted.
fn load_diff_baseline(sitecmd_dir: &std::path::Path) -> Result<Option<ScanResult>, String> {
    let last_scan_path = sitecmd_dir.join("last-scan.json");
    let contents = std::fs::read_to_string(&last_scan_path).map_err(|_| {
        format!(
            "No previous scan found at {}. Run `sitecmd scan` first.",
            last_scan_path.display()
        )
    })?;
    if serde_json::from_str::<hosted::report::Artifact>(&contents).is_ok() {
        return Ok(None);
    }
    serde_json::from_str(&contents).map(Some).map_err(|e| {
        format!(
            "Failed to parse last-scan.json: {e}. {}",
            super::fix::REFRESH_CACHE
        )
    })
}

/// Exit code for --diff mode: the --fail-under gate first, then the
/// regression gate the docs promise - a new critical fails the diff even
/// without --fail-under.
fn diff_exit_code(old: &ScanResult, new: &ScanResult, args: &ScanArgs) -> u8 {
    let exit_code = check_threshold(new, args);
    if exit_code != 0 {
        return exit_code;
    }
    regression_exit_code(introduced_critical_count(old, new))
}

pub(super) fn regression_exit_code(introduced: usize) -> u8 {
    if introduced > 0 {
        eprintln!(
            "\nFailed: {} new critical issue{} since the last scan",
            introduced,
            if introduced == 1 { "" } else { "s" }
        );
        return 1;
    }
    0
}

/// Criticals failing in `new` whose check_id was not failing in `old`.
fn introduced_critical_count(old: &ScanResult, new: &ScanResult) -> usize {
    let old_failing = failing_check_ids(old);
    actionable(&new.issues)
        .filter(|i| i.severity == Severity::Critical && !old_failing.contains(i.check_id.as_str()))
        .count()
}

fn failing_check_ids(scan: &ScanResult) -> std::collections::HashSet<&str> {
    actionable(&scan.issues)
        .map(|i| i.check_id.as_str())
        .collect()
}

async fn local_scan(
    target: lane::Target,
    categories: Option<Vec<Category>>,
) -> Result<ScanResult, String> {
    target
        .scan_local(ScanType::Health, lane::ScanPurpose::OneShot, categories)
        .await
        .map_err(|error| error.to_string())
}

fn resolve_url(args: &ScanArgs) -> Result<String, String> {
    if let Some(ref url) = args.url {
        return Ok(url.clone());
    }

    if let Some(sitecmd_dir) = crate::cli::find_config_dir() {
        let config = crate::cli::read_config(&sitecmd_dir)?;

        if let Some(ref env_name) = args.env_name {
            if let Some(env_url) = config.environments.get(env_name) {
                return Ok(env_url.clone());
            }
            return Err(format!(
                "Environment '{}' not found in .sitecmd/config.json. Available: {}",
                env_name,
                config
                    .environments
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        return Ok(config.url);
    }

    Err("No URL provided. Use --url or run `sitecmd init` first.".into())
}

fn check_threshold(scan: &ScanResult, args: &ScanArgs) -> u8 {
    threshold_exit_code(
        Some(scan.overall_score),
        actionable(&scan.issues).map(|issue| &issue.severity),
        args,
    )
}

pub(super) fn threshold_exit_code<'a>(
    score: Option<u32>,
    severities: impl Iterator<Item = &'a Severity>,
    args: &ScanArgs,
) -> u8 {
    if let (Some(score), Some(threshold)) = (score, args.fail_under) {
        if score < threshold {
            eprintln!("\nFailed: score {} is below threshold {}", score, threshold,);
            return 1;
        }
    }
    if let Some(minimum) = args.fail_on {
        let hits = severities
            .filter(|severity| severity.sort_rank() <= minimum.sort_rank())
            .count();
        if hits > 0 {
            eprintln!(
                "\nFailed: {} failing issue{} at or above {}",
                hits,
                if hits == 1 { "" } else { "s" },
                minimum
            );
            return 1;
        }
    }
    0
}

fn print_json(scan: &ScanResult) {
    println!("{}", scan_json(scan));
}

fn scan_json(scan: &ScanResult) -> String {
    serde_json::to_value(scan)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_default()
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => " MED",
        Severity::Low => " LOW",
    }
}

pub fn print_text(result: &ScanResult) {
    eprintln!(); // clear progress line
    println!("SiteCMD - {}", result.url);
    println!(
        "Score: {}/100 ({} scan, {:.1}s)\n",
        result.overall_score,
        result.scan_type,
        result.duration_ms as f64 / 1000.0,
    );

    if let Some(ref stack) = result.detected_stack {
        if let Some(summary) = stack.get("summary").and_then(|s| s.as_str()) {
            println!("Stack: {}\n", summary);
        }
    }

    print!("{}", category_table(result));

    let failing: Vec<_> = actionable(&result.issues).collect();

    if failing.is_empty() {
        println!("\nNo issues found.");
    } else {
        println!("\nIssues ({} total):", failing.len());
        for issue in &failing {
            print_issue(&issue.severity, &issue.check_id, &issue.title);
        }
    }
}

/// The category bars in canonical order, each under its display label.
pub(crate) fn category_table(result: &ScanResult) -> String {
    let mut table = format!("{:<20} {:>5}  Issues\n", "Category", "Score");
    table.push_str(&format!("{}\n", "\u{2500}".repeat(50)));
    for category in Category::ALL {
        let Some(cat) = result
            .categories
            .iter()
            .find(|bar| bar.category == category)
        else {
            continue;
        };
        table.push_str(&category_line(
            category.label(),
            Some(cat.score),
            [
                cat.issues_critical as usize,
                cat.issues_high as usize,
                cat.issues_medium as usize,
                cat.issues_low as usize,
            ],
        ));
    }
    table
}

pub(super) fn print_category(name: &str, score: Option<u32>, counts: [usize; 4]) {
    print!("{}", category_line(name, score, counts));
}

fn category_line(name: &str, score: Option<u32>, counts: [usize; 4]) -> String {
    let counts = counts
        .into_iter()
        .zip(["critical", "high", "medium", "low"])
        .filter(|(count, _)| *count > 0)
        .map(|(count, severity)| format!("{count} {severity}"))
        .collect::<Vec<_>>();
    let score = score.map_or_else(|| "-".to_owned(), |score| score.to_string());
    let issues = if counts.is_empty() {
        "-".to_owned()
    } else {
        counts.join(", ")
    };
    format!("{name:<20} {score:>5}   {issues}\n")
}

pub(super) fn print_issue(severity: &Severity, check: &str, title: &str) {
    println!("  {} {check} - {title}", severity_label(severity));
}

/// The lines above a diff's issue lists: what the score did.
///
/// A comparison is only meaningful between two scans that ran the same checks.
fn diff_header(old: &ScanResult, new: &ScanResult, delta: &str) -> String {
    format!(
        "SiteCMD diff - {}\nScore: {} \u{2192} {} ({})\n\n",
        new.url, old.overall_score, new.overall_score, delta
    )
}

fn print_diff(old: &ScanResult, new: &ScanResult) {
    eprintln!(); // clear progress line

    let score_delta = new.overall_score as i32 - old.overall_score as i32;
    let delta_str = if score_delta >= 0 {
        format!("+{}", score_delta)
    } else {
        format!("{}", score_delta)
    };

    print!("{}", diff_header(old, new, &delta_str));

    // Build sets of check IDs from failing issues
    let old_failing = failing_check_ids(old);
    let new_failing = failing_check_ids(new);

    let fixed: Vec<_> = actionable(&old.issues)
        .filter(|i| !new_failing.contains(i.check_id.as_str()))
        .collect();

    let introduced: Vec<_> = actionable(&new.issues)
        .filter(|i| !old_failing.contains(i.check_id.as_str()))
        .collect();

    // Remaining: in both
    let remaining: Vec<_> = actionable(&new.issues)
        .filter(|i| old_failing.contains(i.check_id.as_str()))
        .collect();

    if !fixed.is_empty() {
        println!("Fixed ({}):", fixed.len());
        for issue in &fixed {
            println!("  \u{2714} {} - {}", issue.check_id, issue.title);
        }
        println!();
    }

    if !introduced.is_empty() {
        println!("New issues ({}):", introduced.len());
        for issue in &introduced {
            print_issue(&issue.severity, &issue.check_id, &issue.title);
        }
        println!();
    }

    if !remaining.is_empty() {
        println!("Remaining ({}):", remaining.len());
        for issue in &remaining {
            print_issue(&issue.severity, &issue.check_id, &issue.title);
        }
        println!();
    }

    if fixed.is_empty() && introduced.is_empty() && remaining.is_empty() {
        println!("No issues in either scan.");
    }
}

/// Print a one-line hint pointing to `.sitecmd/issues.md` for the first scan
/// or when significant issues exist.
pub(super) fn print_claude_snippet(sitecmd_dir: &std::path::Path) {
    let issues_md = sitecmd_dir.join("issues.md");
    let rules_md = sitecmd_dir.join("rules.md");
    println!(
        "\nTip: Add to CLAUDE.md:\n  See {issues} for fix instructions\n  See {rules} for coding rules",
        issues = issues_md.display(),
        rules = rules_md.display(),
    );
}

#[cfg(test)]
mod tests;
