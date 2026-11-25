use std::collections::HashSet;
use std::io::{self, Write};
use std::path::Path;

use jiff::Timestamp;
use url::Url;

use super::report::{self, Artifact, Report};
use super::{
    client, connect_client, request_finished_scan, Clock, ConnectedServiceClient, HostedError,
    ScanRequestError, SystemClock,
};
use crate::cli::check::{
    regression_heading, regression_issue_line, threshold_failure_for_score, FIRST_BASELINE,
};
use crate::core::scan_types::Severity;

pub(in crate::cli) async fn run(
    target: &Url,
    dir: &Path,
    strict: bool,
    threshold: u32,
) -> Result<u8, HostedError> {
    let client = connect_client(None)?;
    run_with(
        &client,
        target,
        dir,
        strict,
        threshold,
        &SystemClock,
        io::stderr(),
    )
    .await
}

pub(super) async fn run_with(
    client: &ConnectedServiceClient,
    target: &Url,
    dir: &Path,
    strict: bool,
    threshold: u32,
    clock: &impl Clock,
    mut output: impl Write,
) -> Result<u8, HostedError> {
    let (site, site_url) = client::find_site(client, target).await?;
    let cached = report::read_artifact(dir).ok();
    let mut start_limit = None;
    let fresh = if strict {
        match request_finished_scan(client, &site, clock).await {
            Ok(scan) => Some(scan),
            Err(ScanRequestError::StartLimited(reason)) => {
                start_limit = Some(reason);
                None
            }
            Err(ScanRequestError::Failed(error)) => return Err(error),
        }
    } else {
        None
    };
    let scan = match fresh {
        Some(scan) => scan,
        None => client::scans(client, &site, None)
            .await?
            .ok_or(HostedError::NoFinishedScan)?,
    };
    let report = Report::read(client, &site, &site_url, &scan).await?;
    if let Some(reason) = start_limit {
        let finished_at = report
            .timestamp
            .parse::<Timestamp>()
            .map_err(|_| HostedError::RequestFailed)?;
        let seconds = clock
            .wall_time()
            .duration_since(finished_at)
            .as_secs()
            .max(0);
        write_fallback_notice(&mut output, &reason, seconds)
            .map_err(|_| HostedError::RequestFailed)?;
    }

    let previous = cached.as_ref().and_then(|cache| cache.older_than(&report));
    let baseline = cached
        .as_ref()
        .and_then(|cache| cache.baseline_for(&report, &report.scan_id))
        .or(previous);
    let code = verdict(&mut output, &report, baseline, strict, threshold)
        .map_err(|_| HostedError::RequestFailed)?;
    report::export_artifact(
        dir,
        &Artifact {
            hosted: report,
            previous: previous.cloned(),
        },
    );
    Ok(code)
}

fn write_fallback_notice(
    output: &mut impl Write,
    reason: &HostedError,
    seconds: i64,
) -> io::Result<()> {
    writeln!(
        output,
        "{reason} The latest finished hosted scan is {} old.",
        scan_age(seconds)
    )
}

fn scan_age(seconds: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    let (age, unit) = match seconds {
        DAY.. => (seconds / DAY, "day"),
        HOUR.. => (seconds / HOUR, "hour"),
        MINUTE.. => (seconds / MINUTE, "minute"),
        _ => (seconds, "second"),
    };
    let suffix = if age == 1 { "" } else { "s" };
    format!("{age} {unit}{suffix}")
}

fn verdict(
    mut output: impl Write,
    report: &Report,
    baseline: Option<&Report>,
    strict: bool,
    threshold: u32,
) -> io::Result<u8> {
    if let Some(message) = threshold_failure_for_score(report.score(), threshold, || {
        report
            .issues
            .iter()
            .filter(|issue| issue.severity == Severity::Critical)
            .count()
    }) {
        writeln!(output, "{message}")?;
        return Ok(1);
    }
    if !strict {
        return Ok(0);
    }
    let Some(baseline) = baseline else {
        writeln!(output, "{FIRST_BASELINE}")?;
        return Ok(0);
    };

    let baseline_ids: HashSet<_> = baseline
        .issues
        .iter()
        .map(|issue| &issue.check_id)
        .collect();
    let new: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| !baseline_ids.contains(&issue.check_id))
        .collect();
    if new.is_empty() {
        return Ok(0);
    }

    writeln!(output, "{}", regression_heading(new.len()))?;
    for issue in new {
        writeln!(
            output,
            "{}",
            regression_issue_line(
                issue.severity,
                &issue.check_id,
                &report::clean(&issue.title)
            )
        )?;
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::scan_age;

    #[test]
    fn age_uses_the_largest_whole_unit() {
        // Bug: The fallback prints raw seconds, rounds up, or mislabels a singular unit.
        for (seconds, age) in [
            (0, "0 seconds"),
            (1, "1 second"),
            (59, "59 seconds"),
            (60, "1 minute"),
            (119, "1 minute"),
            (120, "2 minutes"),
            (2_700, "45 minutes"),
            (3_599, "59 minutes"),
            (3_600, "1 hour"),
            (7_200, "2 hours"),
            (86_399, "23 hours"),
            (86_400, "1 day"),
            (172_799, "1 day"),
            (259_200, "3 days"),
        ] {
            assert_eq!(scan_age(seconds), age, "{seconds} seconds");
        }
    }
}
