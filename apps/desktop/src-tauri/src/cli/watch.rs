//! sitecmd watch command
//!
//! Continuously scans a URL at a fixed interval, printing score diffs to
//! stderr after each iteration. stdout stays clean so output can be piped.

use std::collections::HashSet;

use tokio::time::{sleep, Duration};

use crate::checks::CheckStatus;
use crate::core::scanner::{self, ScanProgress, ScanResult, ScanType};

pub struct WatchArgs {
    pub url: Option<String>,
    pub interval: u64,
    pub env_name: Option<String>,
}

/// Run the watch subcommand. Loops forever until Ctrl+C.
pub async fn run(args: WatchArgs) -> Result<(), String> {
    let url = resolve_url(&args)?;

    eprintln!(
        "Watching {} (interval: {}s, Ctrl+C to stop)",
        url, args.interval
    );

    let progress_fn: std::sync::Arc<scanner::ProgressFn> =
        std::sync::Arc::new(|p: &ScanProgress| {
            eprint!(
                "\r\x1b[K[{}/{}] {} - {}",
                p.checks_done, p.checks_total, p.check_id, p.status
            );
        });

    let mut previous: Option<ScanResult> = None;
    let mut iteration: u32 = 0;

    loop {
        iteration += 1;

        let scan_result = crate::scan_runtime::run_scan_low_priority(
            url.clone(),
            Some(progress_fn.clone()),
            None, // categories
            None, // timeout
            ScanType::Health,
            false,
            None, // cancel check
            None, // each watch iteration re-reads the site
        )
        .await;

        eprint!("\r\x1b[K");

        match scan_result {
            Err(e) => {
                eprintln!("[#{}] Scan error: {}", iteration, e);
            }
            Ok(scan) => {
                if let Some(sitecmd_dir) = crate::cli::find_config_dir() {
                    if let Err(e) = crate::cli::export::export_scan(&sitecmd_dir, &scan) {
                        eprintln!("Warning: failed to export scan results: {}", e);
                    }
                }

                print_iteration_summary(iteration, &previous, &scan);

                previous = Some(scan);
            }
        }

        sleep(Duration::from_secs(args.interval)).await;
    }
}

fn print_iteration_summary(iteration: u32, previous: &Option<ScanResult>, current: &ScanResult) {
    let issue_count = current
        .issues
        .iter()
        .filter(|i| i.status == CheckStatus::Fail || i.status == CheckStatus::Warn)
        .count();

    match previous {
        None => {
            eprintln!(
                "[#{}] Baseline - Score: {}/100, {} issues",
                iteration, current.overall_score, issue_count
            );
        }
        Some(prev) => {
            let old_score = prev.overall_score as i32;
            let new_score = current.overall_score as i32;
            let delta = new_score - old_score;

            if delta == 0 {
                eprintln!(
                    "[#{}] No change (score: {})",
                    iteration, current.overall_score
                );
            } else {
                let delta_str = if delta >= 0 {
                    format!("+{}", delta)
                } else {
                    format!("{}", delta)
                };
                eprintln!(
                    "[#{}] Score: {} \u{2192} {} ({})",
                    iteration, old_score, new_score, delta_str
                );

                let prev_failing: HashSet<&str> = prev
                    .issues
                    .iter()
                    .filter(|i| i.status == CheckStatus::Fail || i.status == CheckStatus::Warn)
                    .map(|i| i.check_id.as_str())
                    .collect();

                let curr_failing: HashSet<&str> = current
                    .issues
                    .iter()
                    .filter(|i| i.status == CheckStatus::Fail || i.status == CheckStatus::Warn)
                    .map(|i| i.check_id.as_str())
                    .collect();

                // Fixed issues: were failing before, not failing now
                let fixed: Vec<_> = prev
                    .issues
                    .iter()
                    .filter(|i| {
                        (i.status == CheckStatus::Fail || i.status == CheckStatus::Warn)
                            && !curr_failing.contains(i.check_id.as_str())
                    })
                    .collect();

                // New issues: failing now, were not failing before
                let introduced: Vec<_> = current
                    .issues
                    .iter()
                    .filter(|i| {
                        (i.status == CheckStatus::Fail || i.status == CheckStatus::Warn)
                            && !prev_failing.contains(i.check_id.as_str())
                    })
                    .collect();

                for issue in &fixed {
                    eprintln!("  \u{2713} {} - {}", issue.check_id, issue.title);
                }
                for issue in &introduced {
                    eprintln!("  \u{2717} {} - {}", issue.check_id, issue.title);
                }
            }
        }
    }
}

fn resolve_url(args: &WatchArgs) -> Result<String, String> {
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

        if let Some(local_url) = config.environments.get("local") {
            return Ok(local_url.clone());
        }

        return Ok(config.url);
    }

    Err("No URL provided. Use --url or run `sitecmd init` first.".into())
}
