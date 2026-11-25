//! Regression check for Git hooks.
//! Default mode checks the latest hosted report or refreshes stale local data.
//! Strict mode also rejects newly failing check IDs.

use crate::time::now_utc;
use jiff::SignedDuration;
use sitecmd_protocol::time::UtcTimestamp;

use std::collections::HashSet;

use crate::core::scan_types::{actionable, CheckResult, ScanResult, ScanType, Severity};

use super::export::export_native_scan;
use super::hosted;
use super::lane::{self, Lane, LOCAL_CHECKS_NOTICE};

pub struct CheckArgs {
    pub install: bool,
    pub strict: bool,
    pub threshold: Option<u32>,
}

/// Run the check subcommand.
///
/// Returns 0 for a pass, 1 for a regression or threshold failure, and an error for scan failures.
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
    // Determine threshold: flag > config fail_under > 0
    let threshold: u32 = args.threshold.or(config.fail_under).unwrap_or(0);
    if !args.strict && threshold == 0 {
        eprintln!(
            "sitecmd check: no threshold configured; passing. Set fail_under in \
             .sitecmd/config.json or pass --threshold to enforce a minimum score, \
             or use --strict to fail on new issues."
        );
        return Ok(0);
    }

    let target = lane::Target::resolve(&config.url, None)
        .await
        .map_err(|error| error.to_string())?;
    if target.lane() == Lane::Hosted {
        return hosted::check::run(&target.url, &sitecmd_dir, args.strict, threshold)
            .await
            .map_err(|error| error.command_message());
    }

    if args.strict {
        // Strict compares against the previous export, so it always scans
        // fresh; reusing the <24h cache would diff a scan against itself.
        let baseline = read_baseline_failing_ids(&sitecmd_dir)?;
        let scan = run_fresh_scan(target).await?;
        export_native_scan(&sitecmd_dir, &scan);
        return Ok(strict_verdict(&scan, baseline.as_ref(), threshold));
    }

    // Try to use cached scan; re-scan if missing or stale
    let scan = load_or_rescan(&sitecmd_dir, target).await?;
    Ok(threshold_verdict(&scan, threshold))
}

fn threshold_failure(scan: &ScanResult, threshold: u32) -> Option<String> {
    threshold_failure_for_score(scan.overall_score, threshold, || {
        actionable(&scan.issues)
            .filter(|issue| issue.severity == Severity::Critical)
            .count()
    })
}

pub(super) fn threshold_failure_for_score(
    score: u32,
    threshold: u32,
    critical_count: impl FnOnce() -> usize,
) -> Option<String> {
    (score < threshold).then(|| {
        format!(
            "Check failed: score {score}/100 is below threshold {threshold} ({} critical issues)",
            critical_count()
        )
    })
}

fn threshold_verdict(scan: &ScanResult, threshold: u32) -> u8 {
    match threshold_failure(scan, threshold) {
        Some(message) => {
            eprintln!("{message}");
            1
        }
        None => 0,
    }
}

fn new_issues<'a>(scan: &'a ScanResult, baseline: &HashSet<String>) -> Vec<&'a CheckResult> {
    actionable(&scan.issues)
        .filter(|issue| !baseline.contains(&issue.check_id))
        .collect()
}

pub(super) const FIRST_BASELINE: &str =
    "No previous scan to compare against; this scan becomes the baseline.";

pub(super) fn regression_heading(count: usize) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("Check failed: {count} new issue{suffix} since the last scan:")
}

pub(super) fn regression_issue_line(
    severity: Severity,
    check_id: &impl std::fmt::Display,
    title: &str,
) -> String {
    format!("  [{severity:?}] {check_id} - {title}")
}

/// Apply the score threshold, then fail on checks absent from the baseline.
fn strict_verdict(scan: &ScanResult, baseline: Option<&HashSet<String>>, threshold: u32) -> u8 {
    if threshold > 0 && scan.overall_score < threshold {
        return threshold_verdict(scan, threshold);
    }

    let Some(baseline) = baseline else {
        eprintln!("{FIRST_BASELINE}");
        return 0;
    };

    let new_issues = new_issues(scan, baseline);

    if new_issues.is_empty() {
        return 0;
    }

    eprintln!("{}", regression_heading(new_issues.len()));
    for issue in &new_issues {
        eprintln!(
            "{}",
            regression_issue_line(issue.severity, &issue.check_id, &issue.title)
        );
    }
    1
}

/// Failing ids from the previous export; an incompatible baseline must be refreshed.
fn read_baseline_failing_ids(
    sitecmd_dir: &std::path::Path,
) -> Result<Option<HashSet<String>>, String> {
    let path = sitecmd_dir.join("last-scan.json");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot read {}: {e}", path.display())),
    };
    if let Ok(artifact) = serde_json::from_str::<super::hosted::report::Artifact>(&contents) {
        return Ok(Some(
            artifact
                .hosted
                .issues
                .into_iter()
                .map(|issue| issue.check_id.to_string())
                .collect(),
        ));
    }
    let baseline: ScanResult = serde_json::from_str(&contents).map_err(|e| {
        format!("Cannot read last-scan.json baseline: {e}. Run `sitecmd scan` to refresh it.")
    })?;
    Ok(Some(
        actionable(&baseline.issues)
            .map(|issue| issue.check_id.clone())
            .collect(),
    ))
}

/// Load `last-scan.json` if it exists and is fresh (< 24 hours).
/// Otherwise run a fresh scan, export it unless a hosted artifact exists, and return the new result.
async fn load_or_rescan(
    sitecmd_dir: &std::path::Path,
    target: lane::Target,
) -> Result<ScanResult, String> {
    let last_scan_path = sitecmd_dir.join("last-scan.json");

    if super::hosted::report::read_artifact(sitecmd_dir).is_ok() {
        return run_fresh_scan(target).await;
    }
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

    let scan = run_fresh_scan(target).await?;

    export_native_scan(sitecmd_dir, &scan);
    Ok(scan)
}

/// Return true if the RFC 3339 timestamp is less than 24 hours old.
fn is_fresh(timestamp: &str) -> bool {
    match UtcTimestamp::parse_from_rfc3339(timestamp) {
        Ok(scanned_at) => {
            let age = now_utc().duration_since(scanned_at);
            age < SignedDuration::from_hours(24)
        }
        Err(_) => false,
    }
}

async fn run_fresh_scan(target: lane::Target) -> Result<ScanResult, String> {
    let result = target
        .scan_local(ScanType::Health, lane::ScanPurpose::OneShot, None)
        .await
        .map_err(|error| error.to_string())?;
    eprintln!("{LOCAL_CHECKS_NOTICE}");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan_types::{CheckResult, CheckStatus, Severity};

    fn issue(check_id: &str, severity: Severity, status: CheckStatus) -> CheckResult {
        CheckResult {
            covered: false,
            check_id: check_id.to_string(),
            category: None,
            title: format!("Title for {}", check_id),
            description: String::new(),
            status,
            severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::core::scan_types::IssueConfidence::High,
            confidence_reason: None,
            skip_reason: None,
            why_it_matters: None,
        }
    }

    fn scan(score: u32, issues: Vec<CheckResult>) -> ScanResult {
        ScanResult {
            url: "https://example.com".to_string(),
            mode: "live".to_string(),
            scan_type: ScanType::Health,
            overall_score: score,
            categories: vec![],
            fix_points: vec![0; issues.len()],
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
    fn check_counts_only_actionable_critical_results() {
        // A passing critical check can inflate the cached score failure count.
        let scan = scan(55, local_results());
        assert_eq!(
            threshold_failure(&scan, 80).as_deref(),
            Some("Check failed: score 55/100 is below threshold 80 (1 critical issues)")
        );
        assert_eq!(threshold_verdict(&scan, 80), 1);
    }

    #[test]
    fn strict_check_reports_one_new_issue_and_stores_one_baseline_id() {
        let scan = scan(90, local_results());
        let detail = "security.env_leak";
        let empty = ids(&[]);
        let found = new_issues(&scan, &empty);
        assert_eq!(
            found
                .iter()
                .map(|row| row.check_id.as_str())
                .collect::<Vec<_>>(),
            [detail]
        );
        assert_eq!(strict_verdict(&scan, Some(&empty), 0), 1);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("last-scan.json"),
            serde_json::to_vec(&scan).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_baseline_failing_ids(dir.path()).unwrap(),
            Some(ids(&[detail]))
        );
        assert_eq!(strict_verdict(&scan, Some(&ids(&[detail])), 0), 0);
    }

    fn local_results() -> Vec<CheckResult> {
        vec![
            CheckResult {
                covered: true,
                ..issue("summary", Severity::Critical, CheckStatus::Fail)
            },
            issue("security.env_leak", Severity::Critical, CheckStatus::Fail),
            issue(
                "security.source_maps",
                Severity::Critical,
                CheckStatus::Pass,
            ),
        ]
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

        let got = read_baseline_failing_ids(dir.path())
            .expect("baseline should parse")
            .expect("baseline exists");
        assert_eq!(got, ids(&["failing.one", "warning.two"]));
    }

    #[test]
    fn only_a_missing_baseline_reads_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_baseline_failing_ids(dir.path()).unwrap(), None);
        std::fs::write(dir.path().join("last-scan.json"), "not json").expect("write");
        let error = read_baseline_failing_ids(dir.path()).unwrap_err();
        assert!(error.contains("Run `sitecmd scan`"));
    }
}
