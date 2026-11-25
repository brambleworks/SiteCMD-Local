//! The account, request, and reporting flow for public site scans.

use std::path::Path;
use std::time::Duration;

use jiff::Timestamp;
use sitecmd_protocol::sync::wire::{Digest, Identifier};
use tokio::time::Instant;
use url::Url;

use crate::connected_service::{ConnectedServiceClient, ConnectedServiceError};
use crate::constants::{HOSTED_SCAN_POLL_INTERVAL, HOSTED_SCAN_WAIT_LIMIT};

use super::credential_store::CredentialStore;
use super::{login, scan::ScanArgs};

pub(super) mod check;
mod client;
mod export;
pub(super) mod report;
pub(super) mod watch;

use client::{Scan, ScanState};
use report::Report;

const SIGNED_OUT: &str = concat!(
    "Scanning a public site runs on SiteCMD's hosted scanner, so it needs a SiteCMD account.\n",
    "Sign in with `sitecmd login`, or set SITECMD_TOKEN in CI.\n",
    "To check a site without an account, use the free scan at https://sitecmd.com/scan.",
);
const NOT_IN_ACCOUNT: &str = "This site isn't in your SiteCMD account.";
const UNVERIFIED: &str = "Verify ownership of this site in SiteCMD before scanning it.";
const SUSPENDED: &str = "Your SiteCMD subscription can't run hosted scans.";
const EXHAUSTED: &str = "This site has used its hosted scan budget for today.";
const TIMEOUT: &str = "The hosted scan didn't finish within 20 minutes.";
const DASHBOARD: &str = "Follow it in SiteCMD:";
const INVALID_CONFIGURATION: &str =
    "Configure a valid SiteCMD Connect origin with --connect-origin or SITECMD_CONNECT_ORIGIN.";
const INVALID_READ_CONFIGURATION: &str =
    "Configure a valid SiteCMD Connect origin with SITECMD_CONNECT_ORIGIN.";
const NO_FINISHED_SCAN: &str = "There is no finished hosted scan for this site.";
const REQUEST_FAILED: &str = "SiteCMD couldn't complete the hosted scan request.";
const QUEUED: &str = "Hosted scan queued.";
const RUNNING: &str = "Hosted scan running.";
const FINISHED_NOTICE: &str = "Hosted scan finished.";
const STOPPED: &str = "Hosted scan stopped before the report was available.";
const RATE_LIMITED: &str = "SiteCMD is receiving scan requests too quickly. Try again later.";
const UNAVAILABLE: &str = "SiteCMD couldn't retrieve a hosted scan report. Try again later.";

#[derive(Debug, PartialEq, Eq)]
pub enum HostedError {
    SignedOut,
    SiteNotInAccount,
    UnverifiedSite,
    EntitlementSuspended,
    ScanBudgetExhausted,
    ScanTimeout { dashboard_url: Option<String> },
    InvalidConfiguration,
    NoFinishedScan,
    RequestFailed,
    RateLimited,
    ServiceUnavailable,
}

impl HostedError {
    pub const EXIT_CODE: u8 = 2;

    pub fn code(&self) -> &'static str {
        match self {
            Self::SignedOut => "signed_out",
            Self::SiteNotInAccount => "site_not_in_account",
            Self::UnverifiedSite => "unverified_site",
            Self::EntitlementSuspended => "entitlement_suspended",
            Self::ScanBudgetExhausted => "scan_budget_exhausted",
            Self::ScanTimeout { .. } => "scan_timeout",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::NoFinishedScan => "no_finished_scan",
            Self::RequestFailed => "request_failed",
            Self::RateLimited => "rate_limited",
            Self::ServiceUnavailable => "service_unavailable",
        }
    }

    pub fn json(&self) -> String {
        format!(r#"{{"error":{{"code":"{}"}}}}"#, self.code())
    }

    pub(super) fn command_message(&self) -> String {
        if matches!(self, Self::InvalidConfiguration) {
            return format!("{}\n{INVALID_READ_CONFIGURATION}", self.code());
        }
        format!("{}\n{self}", self.code())
    }
}

impl std::fmt::Display for HostedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SignedOut => SIGNED_OUT,
            Self::SiteNotInAccount => NOT_IN_ACCOUNT,
            Self::UnverifiedSite => UNVERIFIED,
            Self::EntitlementSuspended => SUSPENDED,
            Self::ScanBudgetExhausted => EXHAUSTED,
            Self::ScanTimeout {
                dashboard_url: Some(url),
            } => {
                return write!(f, "{TIMEOUT} {DASHBOARD} {url}");
            }
            Self::ScanTimeout {
                dashboard_url: None,
            } => TIMEOUT,
            Self::InvalidConfiguration => INVALID_CONFIGURATION,
            Self::NoFinishedScan => NO_FINISHED_SCAN,
            Self::RequestFailed => REQUEST_FAILED,
            Self::RateLimited => RATE_LIMITED,
            Self::ServiceUnavailable => UNAVAILABLE,
        })
    }
}

impl From<ConnectedServiceError> for HostedError {
    fn from(error: ConnectedServiceError) -> Self {
        match (error.status, error.code.as_str()) {
            (401, _) => Self::SignedOut,
            (403, "unverified_site") => Self::UnverifiedSite,
            (403, "entitlement_suspended") => Self::EntitlementSuspended,
            (429, "scan_budget_exhausted") => Self::ScanBudgetExhausted,
            (429, _) => Self::RateLimited,
            (500..=599, _) | (0, "transport_failed" | "response_failed") => {
                Self::ServiceUnavailable
            }
            (0, "unsafe_endpoint") => Self::InvalidConfiguration,
            _ => Self::RequestFailed,
        }
    }
}

pub(super) async fn run(target: &Url, args: &ScanArgs) -> Result<u8, HostedError> {
    let client = connect_client(args.connect_origin.as_deref())?;
    let dir = super::find_config_dir().unwrap_or_else(|| ".sitecmd".into());
    run_with(&client, target, args, Some(&dir), &SystemClock).await
}

fn connect_client(origin: Option<&str>) -> Result<ConnectedServiceClient, HostedError> {
    let (origin, source) =
        login::connect_origin(origin).map_err(|_| HostedError::InvalidConfiguration)?;
    if std::env::var("SITECMD_TOKEN").is_ok_and(|token| token.trim().is_empty()) {
        return Err(HostedError::SignedOut);
    }
    let store = CredentialStore::open_for_origin(&origin, source);
    let token = store
        .read()
        .map_err(|_| HostedError::RequestFailed)?
        .ok_or(HostedError::SignedOut)?;
    ConnectedServiceClient::for_endpoint(&origin, Some(&token.token), cfg!(test))
        .map_err(|_| HostedError::SignedOut)
}

async fn run_with(
    client: &ConnectedServiceClient,
    target: &Url,
    args: &ScanArgs,
    dir: Option<&Path>,
    clock: &impl Clock,
) -> Result<u8, HostedError> {
    let (site, site_url) = client::find_site(client, target).await?;
    let cached = dir.and_then(|dir| report::read_artifact(dir).ok());
    let mut previous = None;
    let scan = if args.latest {
        client::scans(client, &site, None)
            .await?
            .ok_or(HostedError::NoFinishedScan)?
    } else {
        if args.diff {
            if let Ok(Some(baseline)) = client::scans(client, &site, None).await {
                previous = Report::read(client, &site, &site_url, &baseline).await.ok();
            }
        }
        request_finished_scan(client, &site, clock).await?
    };
    let report = Report::read(client, &site, &site_url, &scan).await?;
    let previous = if args.diff {
        if let Ok(Some(expected)) = client::scans(client, &site, Some(&scan.id)).await {
            previous
                .filter(|old| old.scan_id == expected.id)
                .or_else(|| {
                    cached
                        .as_ref()?
                        .baseline_for(&report, &expected.id)
                        .cloned()
                })
        } else {
            None
        }
    } else {
        cached
            .as_ref()
            .and_then(|cached| cached.older_than(&report))
            .cloned()
    };
    report::finish(report, previous, args, dir)
}

enum ScanRequestError {
    StartLimited(HostedError),
    Failed(HostedError),
}

impl From<ScanRequestError> for HostedError {
    fn from(error: ScanRequestError) -> Self {
        match error {
            ScanRequestError::StartLimited(error) | ScanRequestError::Failed(error) => error,
        }
    }
}

async fn request_finished_scan(
    client: &ConnectedServiceClient,
    site: &Identifier,
    clock: &impl Clock,
) -> Result<Scan, ScanRequestError> {
    let key = idempotency_key().map_err(ScanRequestError::Failed)?;
    let deadline = clock.now() + HOSTED_SCAN_WAIT_LIMIT;
    let id = start(client, site, &key, clock, deadline).await?;
    wait(client, site, &id, clock, deadline)
        .await
        .map_err(ScanRequestError::Failed)
}

fn idempotency_key() -> Result<Digest, HostedError> {
    let mut random = [0; 32];
    getrandom::fill(&mut random).map_err(|_| HostedError::RequestFailed)?;
    Digest::try_from(hex::encode(random)).map_err(|_| HostedError::RequestFailed)
}

trait Clock {
    fn now(&self) -> Instant;
    fn wall_time(&self) -> Timestamp;
    async fn sleep(&self, delay: Duration);
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_time(&self) -> Timestamp {
        Timestamp::now()
    }

    async fn sleep(&self, delay: Duration) {
        tokio::time::sleep(delay).await;
    }
}

async fn pause(clock: &impl Clock, deadline: Instant, retry_after: Option<u64>) -> bool {
    let delay = HOSTED_SCAN_POLL_INTERVAL.max(Duration::from_secs(retry_after.unwrap_or(0)));
    clock
        .sleep(delay.min(deadline.saturating_duration_since(clock.now())))
        .await;
    clock.now() < deadline
}

async fn start(
    client: &ConnectedServiceClient,
    site_id: &Identifier,
    key: &Digest,
    clock: &impl Clock,
    deadline: Instant,
) -> Result<Identifier, ScanRequestError> {
    let timeout = || {
        ScanRequestError::Failed(HostedError::ScanTimeout {
            dashboard_url: None,
        })
    };
    tokio::time::timeout_at(deadline, async {
        let mut retried_transport = false;
        loop {
            let result = client::request_scan(client, site_id, key, || clock.wall_time()).await;
            if clock.now() >= deadline {
                return Err(timeout());
            }
            match result {
                Ok(id) => return Ok(id),
                Err(error) if error.status == 409 && error.code == "request_in_progress" => {
                    if !pause(clock, deadline, error.retry_after).await {
                        return Err(timeout());
                    }
                }
                Err(error)
                    if !retried_transport
                        && matches!(
                            error.code.as_str(),
                            "transport_failed" | "response_failed"
                        ) =>
                {
                    retried_transport = true;
                }
                Err(error)
                    if matches!(
                        (error.status, error.code.as_str()),
                        (429, "scan_budget_exhausted" | "rate_limited")
                    ) =>
                {
                    return Err(ScanRequestError::StartLimited(error.into()));
                }
                Err(error) => return Err(ScanRequestError::Failed(error.into())),
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err(timeout()))
}

async fn wait(
    client: &ConnectedServiceClient,
    site_id: &Identifier,
    scan_id: &Identifier,
    clock: &impl Clock,
    deadline: Instant,
) -> Result<Scan, HostedError> {
    let timeout = || HostedError::ScanTimeout {
        dashboard_url: dashboard_url(&client.origin(), site_id, scan_id),
    };
    tokio::time::timeout_at(deadline, async {
        let mut retry_after = None;
        let mut state = ScanState::Waiting;
        eprintln!("{QUEUED}");
        while pause(clock, deadline, retry_after).await {
            let result = client::poll(client, site_id, scan_id, || clock.wall_time()).await;
            if clock.now() >= deadline {
                break;
            }
            let scan = match result {
                Ok(scan) if scan.id == *scan_id => scan,
                Ok(_) => return Err(HostedError::RequestFailed),
                Err(error)
                    if matches!(
                        (error.status, error.code.as_str()),
                        (429, "rate_limited") | (503, "restore_in_progress")
                    ) =>
                {
                    retry_after = error.retry_after;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            retry_after = None;
            if scan.state != state {
                state = scan.state;
                let message = match state {
                    ScanState::Waiting => QUEUED,
                    ScanState::Running => RUNNING,
                    ScanState::Applied if scan.finished_at.is_some() => FINISHED_NOTICE,
                    _ => STOPPED,
                };
                eprintln!("{message}");
            }
            match state {
                ScanState::Applied if scan.finished_at.is_some() => return Ok(scan),
                ScanState::Waiting | ScanState::Running => {}
                _ => return Err(HostedError::RequestFailed),
            }
        }
        Err(timeout())
    })
    .await
    .unwrap_or_else(|_| Err(timeout()))
}

fn dashboard_url(origin: &str, site_id: &Identifier, scan_id: &Identifier) -> Option<String> {
    // The production Connect origin has a dashboard at app.sitecmd.com.
    if Url::parse(origin).ok()?.origin() != Url::parse("https://connect.sitecmd.com").ok()?.origin()
    {
        return None;
    }
    let mut url = Url::parse("https://app.sitecmd.com").ok()?;
    url.path_segments_mut()
        .ok()?
        .extend(["sites", site_id, "activity"]);
    url.query_pairs_mut()
        .append_pair("filter", "scans")
        .append_pair("scan", scan_id);
    Some(url.into())
}

#[cfg(test)]
mod tests;
