//! The Connect routes and response projections used by a hosted scan.

use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;

use reqwest::Method;
use serde::Deserialize;
use sitecmd_protocol::sync::wire::{CheckId, Digest, Identifier, Timestamp};
use url::Url;

use super::report::FixGuide;
use super::{HostedError, HostedError::RequestFailed};
use crate::connected_service::{ConnectedServiceClient, ConnectedServiceError, NO_BODY};
use crate::core::scan_types::Severity;

#[derive(Deserialize)]
struct Page<T, C = Identifier> {
    items: Vec<T>,
    next_cursor: Option<C>,
}

#[derive(Deserialize)]
struct Site {
    id: Identifier,
    url: Url,
}

#[derive(Debug)]
pub(super) struct ReadError {
    pub(super) error: HostedError,
    pub(super) retry_after: Option<u64>,
}

impl From<HostedError> for ReadError {
    fn from(error: HostedError) -> Self {
        Self {
            error,
            retry_after: None,
        }
    }
}

impl From<ConnectedServiceError> for ReadError {
    fn from(error: ConnectedServiceError) -> Self {
        Self {
            retry_after: error.retry_after,
            error: error.into(),
        }
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ScanState {
    Waiting,
    Running,
    Unfinished,
    Applied,
    HistoryOnly,
    Rejected,
}

#[derive(Deserialize)]
pub(super) struct Scan {
    pub(super) id: Identifier,
    pub(super) state: ScanState,
    pub(super) finished_at: Option<Timestamp>,
}

#[derive(Deserialize)]
struct Acknowledgment {
    scan_id: Identifier,
}

#[derive(Deserialize)]
pub(super) struct SiteScore {
    pub(super) score: Score,
    pub(super) last_scan_at: Option<Timestamp>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Score {
    pub(super) overall: u32,
    pub(super) per_category: BTreeMap<String, u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum GroupState {
    Active,
    Regressed,
    ClaimedFixed,
    Dismissed,
    VerifiedFixed,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Source {
    Web,
    Code,
}

#[derive(Deserialize)]
pub(super) struct Group {
    pub(super) check: CheckId,
    pub(super) title: String,
    pub(super) category: String,
    pub(super) severity: Option<Severity>,
    pub(super) occurrences: u32,
    #[serde(default)]
    pub(super) fix_guide: Option<FixGuide>,
    state: GroupState,
    sources: Vec<Source>,
    dormant: bool,
}

impl Group {
    pub(super) fn is_open_web_group(&self) -> bool {
        !self.dormant
            && self.occurrences > 0
            && self.sources.contains(&Source::Web)
            && matches!(
                self.state,
                GroupState::Active | GroupState::Regressed | GroupState::ClaimedFixed
            )
    }
}

fn advance<C: Clone + Eq + Hash>(
    cursor: &mut Option<C>,
    next: Option<C>,
    seen: &mut HashSet<C>,
) -> Result<bool, HostedError> {
    if let Some(next) = next {
        if !seen.insert(next.clone()) {
            return Err(RequestFailed);
        }
        *cursor = Some(next);
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(super) async fn find_site(
    client: &ConnectedServiceClient,
    target: &Url,
) -> Result<(Identifier, Url), HostedError> {
    read_site(client, target, &mut |_| {})
        .await
        .map_err(|error| error.error)
}

pub(super) async fn read_site(
    client: &ConnectedServiceClient,
    target: &Url,
    observe_date: &mut impl FnMut(Option<jiff::Timestamp>),
) -> Result<(Identifier, Url), ReadError> {
    let mut cursor = None;
    let mut seen = HashSet::new();
    loop {
        let mut url = client.url(&["v1", "sites"])?;
        if let Some(cursor) = &cursor {
            url = url.with_cursor(cursor);
        }
        let page: Page<Site> = client.get_with_date(url, &mut *observe_date).await?;
        if let Some(site) = page
            .items
            .iter()
            .find(|site| same_origin(&site.url, target))
            .or_else(|| {
                page.items
                    .iter()
                    .find(|site| uses_default_https(&site.url, target))
            })
        {
            return Ok((site.id.clone(), site.url.clone()));
        }
        if !advance(&mut cursor, page.next_cursor, &mut seen)? {
            return Err(HostedError::SiteNotInAccount.into());
        }
    }
}

fn same_host(left: &Url, right: &Url) -> bool {
    fn host(url: &Url) -> Option<&str> {
        url.host_str()
            .map(|host| host.strip_suffix('.').unwrap_or(host))
    }
    host(left) == host(right)
}

pub(super) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme() && left.port() == right.port() && same_host(left, right)
}

fn uses_default_https(site: &Url, target: &Url) -> bool {
    // Connect permits one HTTPS site per host, so there is no competing HTTP entry.
    target.scheme() == "http"
        && site.scheme() == "https"
        && target.port().is_none()
        && site.port().is_none()
        && same_host(site, target)
}

pub(super) async fn scans(
    client: &ConnectedServiceClient,
    site: &Identifier,
    after: Option<&Identifier>,
) -> Result<Option<Scan>, HostedError> {
    let mut found = after.is_none();
    scan_pages(client, site, &mut |_| {}, |scan| {
        if scan.state != ScanState::Applied || scan.finished_at.is_none() {
            return None;
        }
        if found {
            return Some(scan);
        }
        found = after == Some(&scan.id);
        None
    })
    .await
    .map_err(|error| error.error)
}

pub(super) async fn finished_scans(
    client: &ConnectedServiceClient,
    site: &Identifier,
    observe_date: &mut impl FnMut(Option<jiff::Timestamp>),
) -> Result<Vec<(jiff::Timestamp, Identifier)>, ReadError> {
    let mut finished = Vec::new();
    scan_pages::<()>(client, site, observe_date, |scan| {
        let at = scan
            .finished_at
            .and_then(|at| at.parse::<jiff::Timestamp>().ok());
        if let (ScanState::Applied | ScanState::HistoryOnly | ScanState::Rejected, Some(at)) =
            (scan.state, at)
        {
            finished.push((at, scan.id));
        }
        None
    })
    .await?;
    Ok(finished)
}

async fn scan_pages<T>(
    client: &ConnectedServiceClient,
    site: &Identifier,
    observe_date: &mut impl FnMut(Option<jiff::Timestamp>),
    mut visit: impl FnMut(Scan) -> Option<T>,
) -> Result<Option<T>, ReadError> {
    let mut cursor: Option<String> = None;
    let mut seen = HashSet::new();
    loop {
        let mut url = client.url(&["v1", "sites", site, "scans"])?;
        if let Some(cursor) = &cursor {
            let (timestamp, id) = cursor.split_once(' ').ok_or(RequestFailed)?;
            let timestamp = Timestamp::try_from(timestamp).map_err(|_| RequestFailed)?;
            let id = Identifier::try_from(id).map_err(|_| RequestFailed)?;
            url = url.with_scan_cursor(&timestamp, &id);
        }
        let page: Page<Scan, String> = client
            .get_with_date(url, &mut *observe_date)
            .await
            .map_err(|error| {
                if error.status == 404 && error.code == "not_found" {
                    HostedError::SiteNotInAccount.into()
                } else {
                    ReadError::from(error)
                }
            })?;
        let has_next = advance(&mut cursor, page.next_cursor, &mut seen)?;
        if let Some(item) = page.items.into_iter().find_map(&mut visit) {
            return Ok(Some(item));
        }
        if !has_next {
            return Ok(None);
        }
    }
}

pub(super) async fn request_scan(
    client: &ConnectedServiceClient,
    site: &Identifier,
    key: &Digest,
    now: impl FnOnce() -> jiff::Timestamp,
) -> Result<Identifier, ConnectedServiceError> {
    let url = client.url(&["v1", "sites", site, "scans"])?;
    match client
        .request_at::<Acknowledgment>(Method::POST, url, Some(key), now)
        .await
    {
        Ok(answer) => Ok(answer.scan_id),
        Err(mut error) if error.status == 409 && error.code == "scan_in_progress" => {
            #[derive(Deserialize)]
            struct InProgress {
                scan_id: Identifier,
            }
            error
                .details
                .take()
                .and_then(|details| InProgress::deserialize(*details).ok())
                .map(|answer| answer.scan_id)
                .ok_or(error)
        }
        Err(error) => Err(error),
    }
}

pub(super) async fn poll(
    client: &ConnectedServiceClient,
    site: &Identifier,
    scan: &Identifier,
    now: impl FnOnce() -> jiff::Timestamp,
) -> Result<Scan, ConnectedServiceError> {
    let url = client.url(&["v1", "sites", site, "scans", scan])?;
    client.request_at(Method::GET, url, None, now).await
}

pub(super) async fn score(
    client: &ConnectedServiceClient,
    site: &Identifier,
) -> Result<SiteScore, HostedError> {
    let url = client.url(&["v1", "sites", site, "score"])?;
    Ok(client.request(Method::GET, url, None, NO_BODY).await?)
}

pub(super) async fn groups(
    client: &ConnectedServiceClient,
    site: &Identifier,
) -> Result<Vec<Group>, HostedError> {
    let mut groups = Vec::new();
    let mut cursor = None;
    let mut seen = HashSet::new();
    loop {
        let mut url = client.url(&["v1", "sites", site, "groups"])?;
        if let Some(cursor) = &cursor {
            url = url.with_group_cursor(cursor);
        }
        let page: Page<Group, CheckId> = client.request(Method::GET, url, None, NO_BODY).await?;
        groups.extend(page.items.into_iter().filter(Group::is_open_web_group));
        if !advance(&mut cursor, page.next_cursor, &mut seen)? {
            return Ok(groups);
        }
    }
}
