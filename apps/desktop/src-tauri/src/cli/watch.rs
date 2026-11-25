//! sitecmd watch command
//!
//! Follows hosted completions or prints local score diffs at a fixed interval.

use std::collections::HashSet;
use std::io::{self, Write};

use tokio::time::{sleep, Duration};

use crate::core::scan_types::{actionable, ScanResult, ScanType};

use super::hosted;
use super::lane::{self, Lane, LOCAL_CHECKS_NOTICE};

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

    let mut previous: Option<ScanResult> = None;
    let mut local_notice_shown = false;
    let mut iteration: u32 = 0;

    loop {
        iteration += 1;

        let scan = match lane::Target::resolve(&url, None).await {
            Ok(target) if target.lane() == Lane::Hosted => {
                return hosted::watch::run(&target.url, Duration::from_secs(args.interval))
                    .await
                    .map_err(|error| error.command_message());
            }
            Ok(target) => {
                target
                    .scan_local(ScanType::Health, lane::ScanPurpose::Watch, None)
                    .await
            }
            Err(error) => Err(error),
        };
        let scan = match scan {
            Ok(scan) => scan,
            Err(lane::Error::Fetch(error)) => {
                eprint!("\r\x1b[K");
                eprintln!("[#{iteration}] Scan error: {error}");
                sleep(Duration::from_secs(args.interval)).await;
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };

        if let Some(sitecmd_dir) = crate::cli::find_config_dir() {
            super::export::export_native_scan(&sitecmd_dir, &scan);
        }
        write_iteration_summary(io::stderr().lock(), iteration, previous.as_ref(), &scan)
            .map_err(|error| error.to_string())?;
        if !local_notice_shown {
            eprintln!("{LOCAL_CHECKS_NOTICE}");
            local_notice_shown = true;
        }
        previous = Some(scan);

        sleep(Duration::from_secs(args.interval)).await;
    }
}

fn write_iteration_summary(
    mut output: impl Write,
    iteration: u32,
    previous: Option<&ScanResult>,
    current: &ScanResult,
) -> io::Result<()> {
    let Some(previous) = previous else {
        let count = actionable(&current.issues).count();
        return writeln!(
            output,
            "[#{iteration}] Baseline - Score: {}/100, {count} issues",
            current.overall_score
        );
    };

    let old_score = previous.overall_score;
    let new_score = current.overall_score;
    let delta = i64::from(new_score) - i64::from(old_score);
    if delta == 0 {
        return writeln!(output, "[#{iteration}] No change (score: {new_score})");
    }
    writeln!(
        output,
        "[#{iteration}] Score: {old_score} \u{2192} {new_score} ({delta:+})"
    )?;

    let previous: Vec<_> = actionable(&previous.issues).collect();
    let current: Vec<_> = actionable(&current.issues).collect();
    let previous_ids: HashSet<_> = previous.iter().map(|row| row.check_id.as_str()).collect();
    let current_ids: HashSet<_> = current.iter().map(|row| row.check_id.as_str()).collect();
    for row in previous
        .iter()
        .filter(|row| !current_ids.contains(row.check_id.as_str()))
    {
        writeln!(output, "  \u{2713} {} - {}", row.check_id, row.title)?;
    }
    for row in current
        .iter()
        .filter(|row| !previous_ids.contains(row.check_id.as_str()))
    {
        writeln!(output, "  \u{2717} {} - {}", row.check_id, row.title)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_counts_and_lists_only_actionable_results() {
        // A covered summary can inflate counts and appear in the watch diff.
        let detail = "security.env_leak";
        let issues = [
            ("summary", "fail", true),
            (detail, "fail", false),
            ("security.source_maps", "pass", false),
        ]
        .map(|(id, status, covered)| {
            serde_json::json!({
                "checkId": id,
                "category": "security",
                "title": "Environment leak",
                "description": "An environment value was exposed.",
                "status": status,
                "covered": covered,
                "severity": "critical"
            })
        });
        let scan: ScanResult = serde_json::from_value(serde_json::json!({
            "url": "https://example.com/",
            "mode": "live",
            "scanType": "health",
            "overallScore": 70,
            "categories": [],
            "issues": issues,
            "durationMs": 100,
            "timestamp": "2026-01-05T10:00:00Z"
        }))
        .unwrap();
        let mut baseline = scan.clone();
        baseline.issues.clear();
        baseline.overall_score = 90;

        let mut output = Vec::new();
        write_iteration_summary(&mut output, 1, None, &scan).unwrap();
        write_iteration_summary(&mut output, 2, Some(&baseline), &scan).unwrap();
        write_iteration_summary(&mut output, 3, Some(&scan), &baseline).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("[#1] Baseline - Score: 70/100, 1 issues\n[#2] Score: 90 \u{2192} 70 (-20)\n  \u{2717} {detail} - Environment leak\n[#3] Score: 70 \u{2192} 90 (+20)\n  \u{2713} {detail} - Environment leak\n")
        );
    }
}
