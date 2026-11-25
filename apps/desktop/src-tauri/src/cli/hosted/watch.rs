use std::collections::HashSet;
use std::io::{self, Write};

use super::{
    client, connect_client, Clock, ConnectedServiceClient, Duration, HostedError, Identifier,
    SystemClock, Url,
};

pub(in crate::cli) async fn run(target: &Url, interval: Duration) -> Result<(), HostedError> {
    let client = connect_client(None)?;
    run_with(&client, target, interval, &SystemClock, io::stderr()).await
}

pub(super) async fn run_with(
    client: &ConnectedServiceClient,
    target: &Url,
    interval: Duration,
    clock: &impl Clock,
    mut output: impl Write,
) -> Result<(), HostedError> {
    let mut first_response_at = None;
    let mut site = None;
    let mut seen = HashSet::new();
    let mut initialized = false;
    let mut iteration = 0;
    loop {
        iteration += 1;
        let result = async {
            let mut observe_date = |date| {
                // A response without a date still counts as the first response.
                first_response_at.get_or_insert(date);
            };
            let site = match &site {
                Some(id) => id,
                None => {
                    let (id, _) = client::read_site(client, target, &mut observe_date).await?;
                    site.insert(id)
                }
            };
            client::finished_scans(client, site, &mut observe_date).await
        }
        .await;

        let delay = match result {
            Ok(mut scans) => {
                let started_at = first_response_at.flatten();
                if !initialized && started_at.is_none() {
                    write_undated_snapshot_notice(&mut output, iteration)
                        .map_err(|_| HostedError::RequestFailed)?;
                }
                scans.sort_unstable();
                for (finished_at, id) in scans {
                    if seen.insert(id.clone())
                        && (initialized || started_at.is_some_and(|start| finished_at > start))
                    {
                        write_finished(&mut output, iteration, &id, finished_at)
                            .map_err(|_| HostedError::RequestFailed)?;
                    }
                }
                initialized = true;
                interval
            }
            Err(refusal) => match refusal.error {
                HostedError::RateLimited | HostedError::ServiceUnavailable => {
                    writeln!(output, "[#{iteration}] Scan error: {}", refusal.error)
                        .map_err(|_| HostedError::RequestFailed)?;
                    interval.max(Duration::from_secs(refusal.retry_after.unwrap_or(0)))
                }
                error => return Err(error),
            },
        };
        clock.sleep(delay).await;
    }
}

fn write_undated_snapshot_notice(output: &mut impl Write, iteration: u64) -> io::Result<()> {
    writeln!(
        output,
        "[#{iteration}] Connect didn't provide a usable time. Skipping the scans in the first snapshot."
    )
}

fn write_finished(
    output: &mut impl Write,
    iteration: u64,
    id: &Identifier,
    finished_at: jiff::Timestamp,
) -> io::Result<()> {
    writeln!(
        output,
        "[#{iteration}] Hosted scan {id} finished at {finished_at}."
    )
}
