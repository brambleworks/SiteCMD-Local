//! Regression check for Git hooks.
//! Default mode refreshes stale cached data and enforces the score threshold;
//! strict mode also rejects newly failing check IDs.

use std::collections::HashSet;

use crate::checks::{CheckStatus, Severity};
use crate::core::scanner::{self, ScanProgress, ScanResult, ScanType};

pub struct CheckArgs {
    pub install: bool,
    pub strict: bool,
    pub threshold: Option<u32>,
}

/// Run the check subcommand.
///
/// Returns exit code: 0 = pass, 1 = regression/threshold violation.
pub async fn run(args: CheckArgs) -> Result<u8, String> {
    if args.install {
        install_hook(args.strict)
    } else {
        run_check(args).await
    }
}

fn install_hook(strict: bool) -> Result<u8, String> {
    // Verify.git/ exists
    let cwd = std::env::current_dir()
        .map_err(|e| format!("failed to determine current directory: {}", e))?;

    let git_dir = cwd.join(".git");
    if !git_dir.is_dir() {
        return Err(
            "Not a git repository. Run `sitecmd check --install` from within a git repo."
                .to_string(),
        );
    }

    // Create.git/hooks/ if needed
    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .map_err(|e| format!("failed to create {}: {}", hooks_dir.display(), e))?;

    let check_cmd = if strict {
        "sitecmd check --strict"
    } else {
        "sitecmd check"
    };

    let script = format!(
        "#!/bin/sh\n# SiteCMD pre-push Web Scan check\nif command -v sitecmd >/dev/null 2>&1; then\n  {}\nfi\n",
        check_cmd
    );

    let hook_path = hooks_dir.join("pre-push");
    std::fs::write(&hook_path, &script)
        .map_err(|e| format!("failed to write {}: {}", hook_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755)).map_err(
            |e| {
                format!(
                    "failed to set permissions on {}: {}",
                    hook_path.display(),
                    e
                )
            },
        )?;
    }

    eprintln!("Installed pre-push hook at {}", hook_path.display());
    eprintln!("Hook will run `{}` before every push.", check_cmd);

    Ok(0)
}

async fn run_check(args: CheckArgs) -> Result<u8, String> {
    // Find.sitecmd/ directory
    let sitecmd_dir = crate::cli::find_config_dir()
        .ok_or_else(|| "No .sitecmd/ directory found. Run `sitecmd init` first.".to_string())?;

    let config = crate::cli::read_config(&sitecmd_dir)?;
    let url = config.url.clone();

    // Determine threshold: flag > config fail_under > 0
    let threshold: u32 = args.threshold.or(config.fail_under).unwrap_or(0);

    if args.strict {
        // Strict compares against the previous export, so it always scans
        // fresh; reusing the <24h cache would diff a scan against itself.
        let baseline = read_baseline_failing_ids(&sitecmd_dir);
        let scan = run_fresh_scan(&url, config.scan_type).await?;
        if let Err(e) = crate::cli::export::export_scan(&sitecmd_dir, &scan) {
            eprintln!("Warning: failed to export scan results: {}", e);
        }
        return Ok(strict_verdict(&scan, baseline.as_ref(), threshold));
    }

    if threshold == 0 {
        eprintln!(
            "sitecmd check: no threshold configured; passing. Set fail_under in \
             .sitecmd/config.json or pass --threshold to enforce a minimum score, \
             or use --strict to fail on new issues."
        );
        return Ok(0);
    }

    // Try to use cached scan; re-scan if missing or stale
    let scan = load_or_rescan(&sitecmd_dir, &url, config.scan_type).await?;
    Ok(threshold_verdict(&scan, threshold))
}

fn is_failing(issue: &crate::checks::CheckResult) -> bool {
    issue.status == CheckStatus::Fail || issue.status == CheckStatus::Warn
}

/// Exit code for the plain threshold gate: 1 when a positive threshold is set
/// and the score sits below it, 0 otherwise.
fn threshold_verdict(scan: &ScanResult, threshold: u32) -> u8 {
    if threshold > 0 && scan.overall_score < threshold {
        let critical_count = scan
            .issues
            .iter()
            .filter(|i| is_failing(i) && i.severity == Severity::Critical)
            .count();

        eprintln!(
            "Check failed: score {}/100 is below threshold {} ({} critical issues)",
            scan.overall_score, threshold, critical_count
        );
        return 1;
    }
    0
}

/// Apply the score threshold, then fail on checks absent from the baseline.
fn strict_verdict(scan: &ScanResult, baseline: Option<&HashSet<String>>, threshold: u32) -> u8 {
    if threshold > 0 && scan.overall_score < threshold {
        return threshold_verdict(scan, threshold);
    }

    let Some(baseline) = baseline else {
        eprintln!("No previous scan to compare against; this scan becomes the baseline.");
        return 0;
    };

    let new_issues: Vec<_> = scan
        .issues
        .iter()
        .filter(|i| is_failing(i) && !baseline.contains(&i.check_id))
        .collect();

    if new_issues.is_empty() {
        return 0;
    }

    eprintln!(
        "Check failed: {} new issue{} since the last scan:",
        new_issues.len(),
        if new_issues.len() == 1 { "" } else { "s" }
    );
    for issue in &new_issues {
        eprintln!(
            "  [{:?}] {} - {}",
            issue.severity, issue.check_id, issue.title
        );
    }
    1
}

/// Failing check ids from the previous `.sitecmd/last-scan.json` export, if
/// one exists and parses. None means "no baseline yet".
fn read_baseline_failing_ids(sitecmd_dir: &std::path::Path) -> Option<HashSet<String>> {
    let contents = std::fs::read_to_string(sitecmd_dir.join("last-scan.json")).ok()?;
    let baseline: ScanResult = serde_json::from_str(&contents).ok()?;
    Some(
        baseline
            .issues
            .iter()
            .filter(|i| is_failing(i))
            .map(|i| i.check_id.clone())
            .collect(),
    )
}

/// Load `last-scan.json` if it exists and is fresh (< 24 hours).
/// Otherwise run a fresh scan, export it, and return the new result.
async fn load_or_rescan(
    sitecmd_dir: &std::path::Path,
    url: &str,
    scan_type: ScanType,
) -> Result<ScanResult, String> {
    let last_scan_path = sitecmd_dir.join("last-scan.json");

    if let Ok(contents) = std::fs::read_to_string(&last_scan_path) {
        match serde_json::from_str::<ScanResult>(&contents) {
            Ok(cached) => {
                if is_fresh(&cached.timestamp) {
                    return Ok(cached);
                }
                eprintln!("Scan data is stale. Running fresh scan...");
            }
            Err(e) => {
                eprintln!(
                    "Warning: failed to parse last-scan.json ({}). Running fresh scan...",
                    e
                );
            }
        }
    } else {
        eprintln!("No scan data found. Running fresh scan...");
    }

    let scan = run_fresh_scan(url, scan_type).await?;

    if let Err(e) = crate::cli::export::export_scan(sitecmd_dir, &scan) {
        eprintln!("Warning: failed to export scan results: {}", e);
    }

    Ok(scan)
}

/// Return true if the RFC 3339 timestamp is less than 24 hours old.
fn is_fresh(timestamp: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(timestamp) {
        Ok(scanned_at) => {
            let age =
                chrono::Utc::now().signed_duration_since(scanned_at.with_timezone(&chrono::Utc));
            age < chrono::Duration::hours(24)
        }
        Err(_) => false,
    }
}

async fn run_fresh_scan(url: &str, scan_type: ScanType) -> Result<ScanResult, String> {
    let progress_fn: std::sync::Arc<scanner::ProgressFn> =
        std::sync::Arc::new(|p: &ScanProgress| {
            eprint!(
                "\r\x1b[K[{}/{}] {} - {}",
                p.checks_done, p.checks_total, p.check_id, p.status
            );
        });

    let result = crate::scan_runtime::run_scan_low_priority(
        url.to_string(),
        Some(progress_fn),
        None,
        None,
        scan_type,
        false,
        None,
    )
    .await
    .map_err(|e| format!("{}", e))?;

    eprint!("\r\x1b[K");

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};

    fn issue(check_id: &str, severity: Severity, status: CheckStatus) -> CheckResult {
        CheckResult {
            check_id: check_id.to_string(),
            category: ScanCategory::Security,
            title: format!("Title for {}", check_id),
            description: String::new(),
            status,
            severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    }

    fn scan(score: u32, issues: Vec<CheckResult>) -> ScanResult {
        ScanResult {
            page_signals: None,
            site_facts: None,
            url: "https://example.com".to_string(),
            mode: "live".to_string(),
            scan_type: ScanType::Health,
            overall_score: score,
            categories: vec![],
            issues,
            detected_stack: None,
            duration_ms: 100,
            timestamp: "2026-01-05T10:00:00Z".to_string(),
        }
    }

    fn ids(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn threshold_verdict_fails_below_and_passes_at_threshold() {
        let s = scan(79, vec![]);
        assert_eq!(threshold_verdict(&s, 80), 1);
        let s = scan(80, vec![]);
        assert_eq!(threshold_verdict(&s, 80), 0);
    }

    #[test]
    fn threshold_verdict_zero_threshold_always_passes() {
        let s = scan(1, vec![issue("a", Severity::Critical, CheckStatus::Fail)]);
        assert_eq!(threshold_verdict(&s, 0), 0);
    }

    #[test]
    fn strict_verdict_fails_on_a_new_failing_check_id() {
        let s = scan(
            95,
            vec![issue(
                "security.headers.hsts",
                Severity::High,
                CheckStatus::Fail,
            )],
        );
        assert_eq!(strict_verdict(&s, Some(&ids(&["seo.title"])), 0), 1);
    }

    #[test]
    fn strict_verdict_passes_when_all_failing_ids_were_already_in_the_baseline() {
        let s = scan(
            95,
            vec![issue("seo.title", Severity::High, CheckStatus::Warn)],
        );
        assert_eq!(strict_verdict(&s, Some(&ids(&["seo.title"])), 0), 0);
    }

    #[test]
    fn strict_verdict_ignores_passing_checks() {
        let s = scan(
            100,
            vec![issue("brand.new", Severity::High, CheckStatus::Pass)],
        );
        assert_eq!(strict_verdict(&s, Some(&ids(&[])), 0), 0);
    }

    #[test]
    fn strict_verdict_without_a_baseline_passes_as_the_first_run() {
        let s = scan(40, vec![issue("a", Severity::Critical, CheckStatus::Fail)]);
        assert_eq!(strict_verdict(&s, None, 0), 0);
    }

    #[test]
    fn strict_verdict_still_enforces_the_score_threshold() {
        let s = scan(50, vec![]);
        assert_eq!(strict_verdict(&s, Some(&ids(&[])), 80), 1);
    }

    #[test]
    fn baseline_ids_come_from_failing_issues_in_last_scan_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let baseline = scan(
            70,
            vec![
                issue("failing.one", Severity::High, CheckStatus::Fail),
                issue("warning.two", Severity::Low, CheckStatus::Warn),
                issue("passing.three", Severity::High, CheckStatus::Pass),
            ],
        );
        std::fs::write(
            dir.path().join("last-scan.json"),
            serde_json::to_string(&baseline).expect("serialize"),
        )
        .expect("write");

        let got = read_baseline_failing_ids(dir.path()).expect("baseline should parse");
        assert_eq!(got, ids(&["failing.one", "warning.two"]));
    }

    #[test]
    fn missing_or_unparseable_baseline_reads_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_baseline_failing_ids(dir.path()), None);
        std::fs::write(dir.path().join("last-scan.json"), "not json").expect("write");
        assert_eq!(read_baseline_failing_ids(dir.path()), None);
    }
}
