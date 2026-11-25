//! Routes CLI site scans and confines local page fetches to loopback.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant as WallClock};

use reqwest::{Response, StatusCode};
use sitecmd_protocol::engine_abi::{BodyRef, LocalSiteAnswer, LocalSiteRequest};
use tokio::time::Instant;
use url::{Host, Url};

use super::local_redirects::{RedirectWalk, WalkEnd};
use crate::constants::{HTTP_CLIENT_TIMEOUT, MAX_BODY_SIZE};
use crate::core::scan_types::{actionable, Category, ScanResult, ScanType};
use crate::http_client::BodyReadError;
use crate::network_policy::{self, LocalOrigin, UrlPolicy};

pub const LOCAL_CHECKS_NOTICE: &str =
    "The other checks run once you've deployed your site and SiteCMD scans it.";
const OFF_MACHINE: &str = "The local site redirected to a URL outside this computer.";
pub(super) const FETCH_TIMEOUT: &str = "The site fetch timed out.";
const HOSTED_DNS_TIMEOUT: &str = "Resolving the hosted site's address timed out.";
const UNSPECIFIED_ADDRESS: &str =
    "Use a specific address instead of an unspecified address such as 0.0.0.0 or [::].";
const URL_CREDENTIALS: &str = "Remove the username and password from the local site URL.";
const REDIRECT_LOOP: &str = "The local site has a redirect loop.";
const TOO_MANY_REDIRECTS: &str = "The local site redirected too many times.";
const INVALID_REDIRECT: &str = "The local site sent an invalid redirect.";
const INVALID_ENGINE_SCORE: &str = "The engine returned an invalid local scan score.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Local,
    Hosted,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("{0}")]
    Fetch(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Engine(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanPurpose {
    OneShot,
    Watch,
}

pub fn choose_lane(url: &Url, resolved: &[IpAddr]) -> Lane {
    let origin = LocalOrigin::classify_resolved_addresses(url, resolved.iter().copied());
    if origin.allows_local_dev()
        && !resolved.is_empty()
        && resolved.iter().all(|ip| ip.to_canonical().is_loopback())
    {
        Lane::Local
    } else {
        Lane::Hosted
    }
}

pub(super) struct Target {
    pub(super) url: Url,
    addresses: Vec<SocketAddr>,
    deadline: Deadline,
    start: WallClock,
}

impl Target {
    pub(super) async fn resolve(url: &str, timeout: Option<u64>) -> Result<Self, Error> {
        let start = WallClock::now();
        let url = Url::parse(url).map_err(|error| Error::Refused(error.to_string()))?;
        validate_target(&url, false)?;
        let timeout = timeout.map_or(HTTP_CLIENT_TIMEOUT, |seconds| {
            Duration::from_secs(seconds.max(1)) // allow-inline-duration: user-configurable scan timeout
        });
        let deadline = Deadline {
            started: Instant::now(),
            timeout,
        };
        let addresses = resolve_target(&url, timeout, resolve).await?;
        Ok(Self {
            url,
            addresses,
            deadline,
            start,
        })
    }

    pub(super) fn lane(&self) -> Lane {
        classify_target(&self.url, &self.addresses)
    }

    pub(super) async fn scan_local(
        self,
        scan_type: ScanType,
        purpose: ScanPurpose,
        categories: Option<Vec<Category>>,
    ) -> Result<ScanResult, Error> {
        let (mut request, body) =
            fetch_local(self.url, self.addresses, self.deadline, purpose, resolve).await?;
        request.categories = categories;
        evaluate_local(request, body, scan_type, self.start).map_err(Error::Engine)
    }
}

fn classify_target(url: &Url, addresses: &[SocketAddr]) -> Lane {
    let ips: Vec<_> = addresses.iter().map(SocketAddr::ip).collect();
    choose_lane(url, &ips)
}

fn validate_target(target: &Url, local_redirect: bool) -> Result<(), Error> {
    let ip = match target.host() {
        Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip).to_canonical()),
        _ => None,
    };
    if ip.is_some_and(|ip| ip.is_unspecified()) {
        return Err(Error::Refused(UNSPECIFIED_ADDRESS.into()));
    }
    let allows_local_dev = LocalOrigin::classify(target).allows_local_dev();
    if local_redirect && !allows_local_dev {
        return Err(Error::Refused(OFF_MACHINE.into()));
    }
    if allows_local_dev && (!target.username().is_empty() || target.password().is_some()) {
        return Err(Error::Refused(URL_CREDENTIALS.into()));
    }
    network_policy::validate_redirect_target_nonblocking(target, UrlPolicy::ScanTarget)
        .map_err(Error::Refused)
}

fn redirect_target(url: &str) -> Result<Url, Error> {
    let target = Url::parse(url).map_err(|_| Error::Fetch(INVALID_REDIRECT.into()))?;
    validate_target(&target, true)?;
    Ok(target)
}

async fn resolve_target(
    target: &Url,
    local_timeout: Duration,
    resolve: impl AsyncFnOnce(&Url) -> Result<Vec<SocketAddr>, String>,
) -> Result<Vec<SocketAddr>, Error> {
    let (timeout, message) = if LocalOrigin::classify(target).allows_local_dev() {
        (local_timeout, FETCH_TIMEOUT)
    } else {
        (HTTP_CLIENT_TIMEOUT, HOSTED_DNS_TIMEOUT)
    };
    tokio::time::timeout(timeout, resolve(target))
        .await
        .map_err(|_| Error::Fetch(message.into()))?
        .map_err(Error::Fetch)
}

struct Deadline {
    started: Instant,
    timeout: Duration,
}

impl Deadline {
    fn remaining(&self) -> Result<Duration, Error> {
        let remaining = self.timeout.saturating_sub(self.started.elapsed());
        if remaining.is_zero() {
            return Err(Error::Fetch(FETCH_TIMEOUT.into()));
        }
        Ok(remaining)
    }
}

async fn resolve(url: &Url) -> Result<Vec<SocketAddr>, String> {
    let host = url
        .host()
        .ok_or_else(|| "URL must include a host.".to_string())?;
    let port = url.port_or_known_default().unwrap_or(80);
    match host {
        Host::Ipv4(ip) => Ok(vec![SocketAddr::new(ip.into(), port)]),
        Host::Ipv6(ip) => Ok(vec![SocketAddr::new(ip.into(), port)]),
        Host::Domain(domain) => crate::dns_cache::lookup_host(domain, port)
            .await
            .map_err(|error| format!("Could not resolve URL host '{domain}': {error}")),
    }
}

async fn fetch_local(
    requested: Url,
    initial_addresses: Vec<SocketAddr>,
    deadline: Deadline,
    purpose: ScanPurpose,
    mut resolve_hop: impl AsyncFnMut(&Url) -> Result<Vec<SocketAddr>, String>,
) -> Result<(LocalSiteRequest, Vec<u8>), Error> {
    let mut target = requested.clone();
    let mut addresses = initial_addresses;
    let mut walker = RedirectWalk::new(&target);
    loop {
        if classify_target(&target, &addresses) != Lane::Local {
            return Err(Error::Refused(OFF_MACHINE.into()));
        }
        if let Some(Host::Domain(host)) = target.host() {
            for address in &addresses {
                network_policy::validate_resolved_domain_ip_target(
                    host,
                    address.ip(),
                    UrlPolicy::ScanTarget,
                )
                .map_err(Error::Refused)?;
            }
        }
        let response = crate::http_client::for_local_scan(&target, &addresses)
            .map_err(|error| Error::Fetch(error.to_string()))?
            .get(target.clone())
            .timeout(deadline.remaining()?)
            .send()
            .await
            .map_err(|error| {
                Error::Fetch(if error.is_timeout() {
                    FETCH_TIMEOUT.into()
                } else {
                    crate::http_client::fetch_failure(&target, &error)
                })
            })?;
        if !matches!(
            response.status(),
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            if purpose == ScanPurpose::Watch && response.error_for_status_ref().is_err() {
                return Err(http_status_error(response.status()));
            }
            return page_input(requested, response, deadline.remaining()?).await;
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok());
        let url = match walker.follow(location) {
            Ok(url) => url,
            Err(WalkEnd::Loop) => return Err(Error::Fetch(REDIRECT_LOOP.into())),
            Err(WalkEnd::HopLimit { url }) => {
                redirect_target(&url)?;
                return Err(Error::Fetch(TOO_MANY_REDIRECTS.into()));
            }
            Err(WalkEnd::Invalid) => return Err(Error::Fetch(INVALID_REDIRECT.into())),
        };
        target = redirect_target(&url)?;
        addresses = tokio::time::timeout(deadline.remaining()?, resolve_hop(&target))
            .await
            .map_err(|_| Error::Fetch(FETCH_TIMEOUT.into()))?
            .map_err(Error::Fetch)?;
    }
}

fn http_status_error(status: StatusCode) -> Error {
    Error::Fetch(format!("The local site returned HTTP {}.", status.as_u16()))
}

async fn page_input(
    requested: Url,
    response: Response,
    timeout: Duration,
) -> Result<(LocalSiteRequest, Vec<u8>), Error> {
    let final_url = response.url().to_string();
    let status = response.status().as_u16();
    let body = crate::http_client::read_body_limited(response, MAX_BODY_SIZE, timeout)
        .await
        .map_err(|error| {
            Error::Fetch(match error {
                BodyReadError::TimedOut { .. } => FETCH_TIMEOUT.into(),
                BodyReadError::Transport(ref cause) if cause.is_timeout() => FETCH_TIMEOUT.into(),
                _ => error.to_string(),
            })
        })?;
    let request = LocalSiteRequest {
        requested_url: requested.into(),
        final_url,
        status,
        // The local checks only read the body, so response cookies stay in the host.
        header_lines: Vec::new(),
        body: BodyRef {
            at: 0,
            len: body.len() as u32,
        },
        now_ms: crate::time::now_utc().timestamp_millis(),
        polish_only: false,
        categories: None,
    };
    Ok((request, body))
}

fn evaluate_local(
    mut request: LocalSiteRequest,
    body: Vec<u8>,
    scan_type: ScanType,
    start: WallClock,
) -> Result<ScanResult, String> {
    request.polish_only = scan_type == ScanType::Polish;
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    let answer = engine
        .local_site_evaluate(&request, &body)
        .map_err(|error| error.to_string())?;
    local_scan_result(request, answer, scan_type, start)
}

fn local_scan_result(
    request: LocalSiteRequest,
    answer: LocalSiteAnswer,
    scan_type: ScanType,
    start: WallClock,
) -> Result<ScanResult, String> {
    use sitecmd_protocol::time::UtcTimestamp;

    let overall = answer.score.overall;
    if !(0.0..=100.0).contains(&overall) || overall.fract() != 0.0 {
        return Err(INVALID_ENGINE_SCORE.into());
    }
    let categories = answer.categories.ok_or(INVALID_ENGINE_SCORE)?;
    if categories.iter().any(|row| row.score > 100) {
        return Err(INVALID_ENGINE_SCORE.into());
    }
    if answer.fix_points.len() != actionable(&answer.results).count()
        || answer
            .fix_points
            .iter()
            .map(|&points| u64::from(points))
            .sum::<u64>()
            > 100 - overall as u64
    {
        return Err(INVALID_ENGINE_SCORE.into());
    }
    Ok(ScanResult {
        url: request.final_url,
        mode: "predeploy".into(),
        scan_type,
        overall_score: overall as u32,
        categories,
        issues: answer.results,
        fix_points: answer.fix_points,
        detected_stack: None,
        duration_ms: start.elapsed().as_millis() as u64,
        timestamp: UtcTimestamp::from_timestamp_millis(request.now_ms)
            .unwrap()
            .to_rfc3339(),
    })
}

#[cfg(test)]
#[path = "lane_tests.rs"]
mod tests;

#[cfg(feature = "test-support")]
pub async fn check_local_fetch_deadline(verify: impl Fn(ScanResult)) {
    super::lane_test_support::assert_local_fetch_deadline(verify).await;
}

#[cfg(feature = "test-support")]
pub async fn check_signed_out_local_scan(test_name: &str, verify: impl FnOnce(ScanResult)) {
    super::lane_test_support::assert_local_scan_needs_no_sign_in(test_name, verify).await;
}
