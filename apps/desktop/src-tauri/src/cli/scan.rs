//! Web Scan CLI command.

use crate::checks::{CheckStatus, Severity};
use crate::core::scanner::{self, ScanProgress, ScanResult, ScanType};

pub struct ScanArgs {
    pub url: Option<String>,
    pub scan_type: ScanType,
    pub fail_under: Option<u32>,
    pub fail_on: Option<Severity>,
    pub json: bool,
    pub timeout: Option<u64>,
    pub categories: Option<Vec<String>>,
    pub diff: bool,
    pub env_name: Option<String>,
    pub no_browser: bool,
    pub cwv: bool,
}

/// Run a scan and return its process exit code and result.
pub async fn run(args: ScanArgs) -> Result<(u8, ScanResult), String> {
    let url = resolve_url(&args)?;

    let progress_fn: std::sync::Arc<scanner::ProgressFn> =
        std::sync::Arc::new(|p: &ScanProgress| {
            eprint!(
                "\r\x1b[K[{}/{}] {} - {}",
                p.checks_done, p.checks_total, p.check_id, p.status
            );
        });

    if args.diff {
        run_diff(url, args, progress_fn).await
    } else {
        run_standard(url, args, progress_fn).await
    }
}

async fn run_standard(
    url: String,
    args: ScanArgs,
    progress_fn: std::sync::Arc<scanner::ProgressFn>,
) -> Result<(u8, ScanResult), String> {
    let scan = run_scan_inner(&url, &args, progress_fn).await?;

    // Browser analysis (feature-gated)
    #[cfg(feature = "browser")]
    let mut scan = scan;

    #[cfg(feature = "browser")]
    let incomplete_reason = do_browser_analysis(&url, &args, &mut scan);

    #[cfg(not(feature = "browser"))]
    let incomplete_reason: Option<String> = None;

    if args.json {
        print_json(&scan, incomplete_reason.as_deref());
    } else {
        print_text(&scan, incomplete_reason.as_deref());
    }

    // Export to `.sitecmd/` if the directory exists. `--json` is machine-output
    // mode: stdout gets the JSON and `.sitecmd/` stays untouched, as the CLI
    // help promises.
    if let Some(sitecmd_dir) = export_scan_files(&scan, args.json, crate::cli::find_config_dir()) {
        eprintln!("\r\x1b[KExported to {}/", sitecmd_dir.display());
        print_claude_snippet(&sitecmd_dir);
    }

    let exit_code = check_threshold(&scan, &args);
    Ok((exit_code, scan))
}

/// Write the `.sitecmd/` artifacts unless in JSON mode. Returns the directory
/// written to, or None when skipped (JSON mode, no `.sitecmd/`, or a failed
/// write, which warns on stderr).
fn export_scan_files(
    scan: &ScanResult,
    json_mode: bool,
    sitecmd_dir: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if json_mode {
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

async fn run_diff(
    url: String,
    args: ScanArgs,
    progress_fn: std::sync::Arc<scanner::ProgressFn>,
) -> Result<(u8, ScanResult), String> {
    let sitecmd_dir = crate::cli::find_config_dir()
        .ok_or_else(|| "No .sitecmd/ directory found. Run `sitecmd init` first or use `sitecmd scan` without --diff.".to_string())?;

    let last_scan_path = sitecmd_dir.join("last-scan.json");
    let old_scan: ScanResult = {
        let contents = std::fs::read_to_string(&last_scan_path).map_err(|_| {
            format!(
                "No previous scan found at {}. Run `sitecmd scan` first.",
                last_scan_path.display()
            )
        })?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse last-scan.json: {}", e))?
    };

    let new_scan = run_scan_inner(&url, &args, progress_fn).await?;

    // Browser analysis (feature-gated)
    #[cfg(feature = "browser")]
    let mut new_scan = new_scan;

    #[cfg(feature = "browser")]
    let incomplete_reason = do_browser_analysis(&url, &args, &mut new_scan);

    #[cfg(not(feature = "browser"))]
    let incomplete_reason: Option<String> = None;

    print_diff(&old_scan, &new_scan, incomplete_reason.as_deref());

    // Overwrite `.sitecmd/` files.
    if let Err(e) = crate::cli::export::export_scan(&sitecmd_dir, &new_scan) {
        eprintln!("Warning: failed to export scan results: {}", e);
    }

    let exit_code = diff_exit_code(&old_scan, &new_scan, &args);
    Ok((exit_code, new_scan))
}

/// Exit code for --diff mode: the --fail-under gate first, then the
/// regression gate the docs promise - a new critical fails the diff even
/// without --fail-under.
fn diff_exit_code(old: &ScanResult, new: &ScanResult, args: &ScanArgs) -> u8 {
    let exit_code = check_threshold(new, args);
    if exit_code != 0 {
        return exit_code;
    }
    let introduced = introduced_critical_count(old, new);
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
    new.issues
        .iter()
        .filter(|i| {
            is_failing(i)
                && i.severity == Severity::Critical
                && !old_failing.contains(i.check_id.as_str())
        })
        .count()
}

fn is_failing(issue: &crate::checks::CheckResult) -> bool {
    issue.status == CheckStatus::Fail || issue.status == CheckStatus::Warn
}

fn failing_check_ids(scan: &ScanResult) -> std::collections::HashSet<&str> {
    scan.issues
        .iter()
        .filter(|i| is_failing(i))
        .map(|i| i.check_id.as_str())
        .collect()
}

async fn run_scan_inner(
    url: &str,
    args: &ScanArgs,
    progress_fn: std::sync::Arc<scanner::ProgressFn>,
) -> Result<ScanResult, String> {
    crate::scan_runtime::run_scan_low_priority(
        url.to_string(),
        Some(progress_fn),
        args.categories.clone(),
        args.timeout,
        args.scan_type,
        false,
        None,
        // Single-page CLI scan: no other page to share stylesheets with.
        None,
    )
    .await
    .map_err(|e| format!("{}", e))
}

#[cfg(feature = "browser")]
fn do_browser_analysis(url: &str, args: &ScanArgs, scan: &mut ScanResult) -> Option<String> {
    if !args.no_browser && matches!(args.scan_type, ScanType::Health | ScanType::Accessibility) {
        eprintln!("\r\x1b[KLaunching browser for accessibility scan...");
        let analysis = crate::browser::analyze_url(url, args.cwv);
        if analysis.skipped {
            analysis.skip_reason.clone()
        } else {
            // A report is present only when headless Chrome ran axe to
            // completion, so it is authoritative (no violations = clean page)
            // and its rule buckets say which first-party checks it displaces.
            scanner::append_webview_results(scan, analysis.axe.as_ref(), analysis.cwv.as_ref());
            None
        }
    } else {
        None
    }
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
    if let Some(threshold) = args.fail_under {
        if scan.overall_score < threshold {
            eprintln!(
                "\nFailed: score {} is below threshold {}",
                scan.overall_score, threshold,
            );
            return 1;
        }
    }
    if let Some(minimum) = args.fail_on {
        let hits = scan
            .issues
            .iter()
            .filter(|issue| is_failing(issue) && issue.severity.sort_rank() <= minimum.sort_rank())
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

fn print_json(scan: &ScanResult, incomplete_reason: Option<&str>) {
    // Check results are already merged into `scan` by append_webview_results;
    // what is not in there is why a layer produced none, which is exactly what
    // a CI gate reading this JSON needs to tell an incomplete run from a clean
    // one. Added at the edge rather than on ScanResult because it describes
    // this invocation, not the persisted scan.
    println!("{}", scan_json(scan, incomplete_reason));
}

/// The `--json` payload: the scan, plus the reason a layer of it did not run.
fn scan_json(scan: &ScanResult, incomplete_reason: Option<&str>) -> String {
    let mut payload = match serde_json::to_value(scan) {
        Ok(value) => value,
        Err(_) => return String::new(),
    };
    if let (Some(reason), Some(object)) = (incomplete_reason, payload.as_object_mut()) {
        object.insert(
            "incompleteReason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
    serde_json::to_string_pretty(&payload).unwrap_or_default()
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => " MED",
        Severity::Low => " LOW",
    }
}

pub fn print_text(result: &ScanResult, incomplete_accessibility: Option<&str>) {
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

    println!("{:<18} {:>5}  Issues", "Category", "Score");
    println!("{}", "\u{2500}".repeat(50));
    for cat in &result.categories {
        let issues_str = if cat.issues_total == 0 {
            "-".to_string()
        } else {
            let mut parts = Vec::new();
            if cat.issues_critical > 0 {
                parts.push(format!("{} critical", cat.issues_critical));
            }
            if cat.issues_high > 0 {
                parts.push(format!("{} high", cat.issues_high));
            }
            if cat.issues_medium > 0 {
                parts.push(format!("{} medium", cat.issues_medium));
            }
            if cat.issues_low > 0 {
                parts.push(format!("{} low", cat.issues_low));
            }
            parts.join(", ")
        };
        println!(
            "{:<18} {:>5}   {}",
            format!("{:?}", cat.category),
            cat.score,
            issues_str,
        );
    }

    if let Some(reason) = incomplete_accessibility {
        println!(
            "{:<18} {:>5}   (incomplete: {})",
            "Accessibility", "-", reason
        );
    }

    let failing: Vec<_> = result
        .issues
        .iter()
        .filter(|i| i.status == CheckStatus::Fail || i.status == CheckStatus::Warn)
        .collect();

    if failing.is_empty() {
        println!("\nNo issues found.");
    } else {
        println!("\nIssues ({} total):", failing.len());
        for issue in &failing {
            println!(
                "  {} {} - {}",
                severity_label(&issue.severity),
                issue.check_id,
                issue.title,
            );
        }
    }
}

/// The lines above a diff's issue lists: what the score did, and the reason a
/// layer of the new scan did not run.
///
/// A comparison is only meaningful between two scans that ran the same checks.
/// When a layer is skipped, every issue it would have found reads as "fixed"
/// against a complete previous scan, so the reason has to reach the reader of
/// the comparison, not only the reader of a single scan.
fn diff_header(
    old: &ScanResult,
    new: &ScanResult,
    delta: &str,
    incomplete_reason: Option<&str>,
) -> String {
    let mut header = format!(
        "SiteCMD diff - {}\nScore: {} \u{2192} {} ({})\n\n",
        new.url, old.overall_score, new.overall_score, delta
    );
    if let Some(reason) = incomplete_reason {
        header.push_str(&format!("Accessibility incomplete: {}\n\n", reason));
    }
    header
}

fn print_diff(old: &ScanResult, new: &ScanResult, incomplete_reason: Option<&str>) {
    eprintln!(); // clear progress line

    let score_delta = new.overall_score as i32 - old.overall_score as i32;
    let delta_str = if score_delta >= 0 {
        format!("+{}", score_delta)
    } else {
        format!("{}", score_delta)
    };

    print!("{}", diff_header(old, new, &delta_str, incomplete_reason));

    // Build sets of check IDs from failing issues
    let old_failing = failing_check_ids(old);
    let new_failing = failing_check_ids(new);

    let fixed: Vec<_> = old
        .issues
        .iter()
        .filter(|i| is_failing(i) && !new_failing.contains(i.check_id.as_str()))
        .collect();

    let introduced: Vec<_> = new
        .issues
        .iter()
        .filter(|i| is_failing(i) && !old_failing.contains(i.check_id.as_str()))
        .collect();

    // Remaining: in both
    let remaining: Vec<_> = new
        .issues
        .iter()
        .filter(|i| is_failing(i) && old_failing.contains(i.check_id.as_str()))
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
            println!(
                "  {} {} - {}",
                severity_label(&issue.severity),
                issue.check_id,
                issue.title,
            );
        }
        println!();
    }

    if !remaining.is_empty() {
        println!("Remaining ({}):", remaining.len());
        for issue in &remaining {
            println!(
                "  {} {} - {}",
                severity_label(&issue.severity),
                issue.check_id,
                issue.title,
            );
        }
        println!();
    }

    if fixed.is_empty() && introduced.is_empty() && remaining.is_empty() {
        println!("No issues in either scan.");
    }
}

/// Print a one-line hint pointing to `.sitecmd/issues.md` for the first scan
/// or when significant issues exist.
fn print_claude_snippet(sitecmd_dir: &std::path::Path) {
    let issues_md = sitecmd_dir.join("issues.md");
    let rules_md = sitecmd_dir.join("rules.md");
    println!(
        "\nTip: Add to CLAUDE.md:\n  See {issues} for fix instructions\n  See {rules} for coding rules",
        issues = issues_md.display(),
        rules = rules_md.display(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{CheckResult, ScanCategory};

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

    fn scan(issues: Vec<CheckResult>) -> ScanResult {
        ScanResult {
            page_signals: None,
            site_facts: None,
            url: "https://example.com".to_string(),
            mode: "live".to_string(),
            scan_type: ScanType::Health,
            overall_score: 80,
            categories: vec![],
            issues,
            detected_stack: None,
            duration_ms: 100,
            timestamp: "2026-01-05T10:00:00Z".to_string(),
        }
    }

    #[test]
    fn diff_gate_counts_only_new_failing_criticals() {
        let old = scan(vec![
            issue("already.failing", Severity::Critical, CheckStatus::Fail),
            issue("was.passing", Severity::Critical, CheckStatus::Pass),
        ]);
        let new = scan(vec![
            issue("already.failing", Severity::Critical, CheckStatus::Fail),
            issue("was.passing", Severity::Critical, CheckStatus::Fail),
            issue("new.but.high", Severity::High, CheckStatus::Fail),
        ]);
        // "was.passing" flipped to failing: one new critical. The pre-existing
        // critical and the new high do not count.
        assert_eq!(introduced_critical_count(&old, &new), 1);
    }

    #[test]
    fn diff_exit_code_fails_on_a_new_critical_without_fail_under() {
        let args = ScanArgs {
            url: None,
            scan_type: ScanType::Health,
            fail_under: None,
            fail_on: None,
            json: false,
            timeout: None,
            categories: None,
            diff: true,
            env_name: None,
            no_browser: false,
            cwv: false,
        };
        let old = scan(vec![]);
        let new = scan(vec![issue(
            "fresh.critical",
            Severity::Critical,
            CheckStatus::Fail,
        )]);
        assert_eq!(diff_exit_code(&old, &new, &args), 1);
        assert_eq!(diff_exit_code(&old, &old, &args), 0);
    }

    #[test]
    fn diff_gate_is_zero_when_nothing_new_fails() {
        let old = scan(vec![issue("a", Severity::Critical, CheckStatus::Fail)]);
        let new = scan(vec![issue("a", Severity::Critical, CheckStatus::Warn)]);
        assert_eq!(introduced_critical_count(&old, &new), 0);
    }

    #[test]
    fn json_mode_skips_the_file_export_entirely() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = scan(vec![]);
        let exported = export_scan_files(&result, true, Some(dir.path().to_path_buf()));
        assert!(exported.is_none(), "--json must not export");
        assert!(
            !dir.path().join("last-scan.json").exists(),
            "--json must leave .sitecmd/ untouched"
        );
    }

    #[test]
    fn non_json_mode_writes_the_sitecmd_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = scan(vec![]);
        let exported = export_scan_files(&result, false, Some(dir.path().to_path_buf()));
        assert!(exported.is_some(), "normal mode exports");
        for artifact in ["last-scan.json", "issues.md", "issues.json", "rules.md"] {
            assert!(
                dir.path().join(artifact).exists(),
                "{artifact} should be written"
            );
        }
    }

    #[test]
    fn a_skipped_browser_layer_states_its_reason_in_the_json_payload() {
        // The JSON is what a CI gate reads. A run whose browser layer refused
        // to grade must not look identical to one that graded a clean page.
        let reason = "could not confirm which document was graded";
        let payload: serde_json::Value =
            serde_json::from_str(&scan_json(&scan(vec![]), Some(reason))).expect("valid JSON");
        assert_eq!(
            payload.get("incompleteReason").and_then(|v| v.as_str()),
            Some(reason)
        );
        // Every field the payload already carried is still there.
        assert_eq!(
            payload.get("url").and_then(|v| v.as_str()),
            Some("https://example.com")
        );
    }

    #[test]
    fn a_skipped_browser_layer_states_its_reason_in_the_diff_too() {
        // `sitecmd scan --diff` is the other output a CI gate reads, and a skipped
        // layer distorts a comparison more than a single scan: its issues
        // vanish from the new side and read as fixed.
        let reason = "could not confirm which document was graded";
        let header = diff_header(&scan(vec![]), &scan(vec![]), "+0", Some(reason));
        assert!(
            header.contains(reason),
            "the diff must state why the run was incomplete, got {header:?}"
        );
        assert!(header.contains("Score: 80 \u{2192} 80 (+0)"));
    }

    #[test]
    fn a_complete_diff_claims_nothing_about_completeness() {
        let header = diff_header(&scan(vec![]), &scan(vec![]), "+0", None);
        assert!(
            !header.contains("incomplete"),
            "a complete run must not be labelled incomplete, got {header:?}"
        );
    }

    #[test]
    fn a_complete_run_carries_no_incomplete_reason() {
        let payload: serde_json::Value =
            serde_json::from_str(&scan_json(&scan(vec![]), None)).expect("valid JSON");
        assert!(
            payload.get("incompleteReason").is_none(),
            "a complete run must not claim to be incomplete"
        );
    }

    #[test]
    fn fail_on_exits_one_for_a_failing_issue_at_or_above_the_severity() {
        let mut args = ScanArgs {
            url: None,
            scan_type: ScanType::Health,
            fail_under: None,
            fail_on: Some(Severity::High),
            json: false,
            timeout: None,
            categories: None,
            diff: false,
            env_name: None,
            no_browser: false,
            cwv: false,
        };
        let failing_high = scan(vec![issue("a", Severity::High, CheckStatus::Fail)]);
        assert_eq!(check_threshold(&failing_high, &args), 1);
        let passing_high = scan(vec![issue("a", Severity::High, CheckStatus::Pass)]);
        assert_eq!(check_threshold(&passing_high, &args), 0);
        let failing_low = scan(vec![issue("b", Severity::Low, CheckStatus::Fail)]);
        assert_eq!(check_threshold(&failing_low, &args), 0);
        args.fail_on = None;
        assert_eq!(check_threshold(&failing_high, &args), 0);
    }
}
