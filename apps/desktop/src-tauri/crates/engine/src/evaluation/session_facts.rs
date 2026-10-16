//! What one page contributes to its scan's comparison of pages.
//!
//! The facts keep no page text and no query material. An address is a key:
//! `r<n>` for the scan's planned route at position n (the first whose
//! normalized address equals it, the desktop's own page identity), `p<16 hex>`
//! for another page on the page's own origin (the first eight bytes of the
//! SHA-256 of its normalized address), and `x` for an address no scanned page
//! can be: another origin, or any address with a query or credentials. A
//! title, description or H1 is the SHA-256 of the key the comparison uses; the
//! hosted service keys those digests before anything keeps them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::origin_reads::{robots_request, sitemap_probe, sitemap_sources_read};
use super::probes::{ExecutedProbe, ProbeContext};
use super::{EvaluationError, PageArtifact, RouteSession};
use crate::checks::origin_with_port;
use crate::checks::seo::robots::robots_fetch_from_probe;
use crate::checks::seo::sitemap::{
    parse_sitemap_document, sitemap_bound_description, sitemap_urls_from_robots,
    unread_sitemaps_count, unread_sitemaps_description, SitemapBound, SitemapParse, SitemapProbe,
};
use crate::checks::seo::sitemap_walk::{SITEMAP_URL_LIMIT, SITEMAP_WALK_INCOMPLETE_REASON};
use crate::header_lines::HeaderLines;
use crate::session::signals::{extract_page_signals_with_lines, normalize_page_url};

/// The key of an address no scanned page can be.
pub const ELSEWHERE: &str = "x";

/// One page step's request for its comparison facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPageRequest {
    pub page: PageArtifact,
    /// The route's executed probes; the entry route's carry the sitemap walk.
    #[serde(default)]
    pub probe_outcomes: Vec<ExecutedProbe>,
    /// The scan's planned routes, as absolute addresses, in plan order.
    pub routes: Vec<String>,
}

/// The sitemap the walk found, as keys: its page entries, at most
/// [`SITEMAP_URL_LIMIT`], and whether that is all of it. An entry no scanned
/// page can be stays as `x`, so the entries are empty only for an index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSitemapFacts {
    pub entries: Vec<String>,
    pub partial_causes: Vec<SessionSitemapCause>,
}

impl SessionSitemapFacts {
    /// The existing sitemap-read reasons for every recorded partial cause.
    pub fn partial_because(&self) -> Option<String> {
        let reasons: Vec<String> = self
            .partial_causes
            .iter()
            .map(|cause| match *cause {
                SessionSitemapCause::Index { listed, read } => {
                    sitemap_bound_description(SitemapBound::ChildSitemaps, listed, read)
                }
                SessionSitemapCause::UrlLimit { listed } => {
                    sitemap_bound_description(SitemapBound::Urls, listed, SITEMAP_URL_LIMIT)
                }
                SessionSitemapCause::UnreadDeclarations { count } => {
                    unread_sitemaps_description(count)
                }
                SessionSitemapCause::UnfinishedWalk => SITEMAP_WALK_INCOMPLETE_REASON.to_string(),
                SessionSitemapCause::IndexUrls => sitemap_bound_description(
                    SitemapBound::IndexUrls,
                    SITEMAP_URL_LIMIT,
                    SITEMAP_URL_LIMIT,
                ),
            })
            .collect();
        (!reasons.is_empty()).then(|| reasons.join("; "))
    }
}

/// Why a sitemap's page set is incomplete, without retaining its declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum SessionSitemapCause {
    /// An index whose children this route did not all read, as on every route
    /// that names no child limit: how many it lists, and how many were read in
    /// its order before the first that was not, omitted when none was.
    Index {
        listed: usize,
        #[serde(default, skip_serializing_if = "is_zero")]
        read: usize,
    },
    UrlLimit {
        listed: usize,
    },
    UnreadDeclarations {
        count: usize,
    },
    /// An index's children's pages reached the walk's URL limit.
    IndexUrls,
    /// The found document may omit pages from sources that did not answer.
    UnfinishedWalk,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// One page's contribution to the comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPageFacts {
    /// The page's own key, from the address its response came from.
    pub page: String,
    /// The key of the route the scan asked for.
    pub requested: String,
    pub status_code: u16,
    /// Each compared value's digest, lowercase hex, or `None` when the page
    /// has nothing to compare there.
    pub title: Option<String>,
    pub description: Option<String>,
    pub h1: Option<String>,
    pub canonical: Option<String>,
    /// `null` when where a joined X-Robots-Tag line ended decides it.
    pub noindex: Option<bool>,
    /// The keys of the alternates that could be scanned pages, from the
    /// first `MAX_INTERNAL_LINKS_PER_PAGE` the page declares.
    pub hreflang: Vec<String>,
    pub hreflang_truncated: bool,
    /// The keys of the same-site links that could be scanned pages.
    pub links: Vec<String>,
    pub links_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sitemap: Option<SessionSitemapFacts>,
}

/// The scan's routes by the address the comparison compares, for one page.
struct RouteKeys {
    origin: String,
    routes: Vec<String>,
}

impl RouteKeys {
    fn new(page: &url::Url, routes: &[String]) -> Self {
        Self {
            origin: page.origin().ascii_serialization(),
            routes: routes
                .iter()
                .map(|route| normalize_page_url(route))
                .collect(),
        }
    }

    /// The key of one normalized address. An origin ignores a user name and a
    /// password, so an address carrying either is refused by name.
    fn key(&self, address: &str) -> String {
        let Ok(parsed) = url::Url::parse(address) else {
            return ELSEWHERE.into();
        };
        if parsed.origin().ascii_serialization() != self.origin
            || parsed.query().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return ELSEWHERE.into();
        }
        if let Some(position) = self.routes.iter().position(|route| route == address) {
            return format!("r{position}");
        }
        let digest = Sha256::digest(address.as_bytes());
        format!("p{}", hex::encode(&digest[..8]))
    }

    /// The keys of the addresses that could be scanned pages, in order.
    fn keys(&self, addresses: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
        addresses
            .into_iter()
            .map(|address| self.key(address.as_ref()))
            .filter(|key| key != ELSEWHERE)
            .collect()
    }
}

/// What one page contributes, or `None` when its own address cannot be
/// named without query material or credentials, which no fact may keep.
pub fn session_page(
    request: &SessionPageRequest,
) -> Result<Option<SessionPageFacts>, EvaluationError> {
    let mut route = RouteSession::open(request.page.clone())?;
    route.record(Some(request.probe_outcomes.clone()));
    route.session_page(&request.routes)
}

/// One page's facts, from the document its route kept and the outcomes it
/// recorded.
pub(super) fn page_facts(
    context: &ProbeContext,
    routes: &[String],
    lines: HeaderLines,
) -> Result<Option<SessionPageFacts>, EvaluationError> {
    let page = context.page;
    let requested = match context.requested_url {
        Some(address) => url::Url::parse(address).map_err(|_| EvaluationError::Url)?,
        None => page.url.clone(),
    };
    let compared = extract_page_signals_with_lines(
        &page.url,
        &requested,
        page.status_code,
        &page.body,
        &page.response_headers,
        lines,
    )
    .session_page();
    let keys = RouteKeys::new(&page.url, routes);
    let own = keys.key(&compared.url);
    if own == ELSEWHERE {
        return Ok(None);
    }
    // An error response is not the page the scan asked for, and the
    // comparison leaves it out, so nothing read from its body is kept. The
    // sitemap comes from the sitemap's own response, not from this one.
    if !(200..300).contains(&compared.status_code) {
        return Ok(Some(SessionPageFacts {
            page: own,
            requested: keys.key(&compared.requested_url),
            status_code: compared.status_code,
            title: None,
            description: None,
            h1: None,
            canonical: None,
            noindex: Some(false),
            hreflang: Vec::new(),
            hreflang_truncated: false,
            links: Vec::new(),
            links_truncated: false,
            sitemap: sitemap_facts(context, &keys),
        }));
    }
    Ok(Some(SessionPageFacts {
        page: own,
        requested: keys.key(&compared.requested_url),
        status_code: compared.status_code,
        title: digest(compared.title.as_deref()),
        description: digest(compared.meta_description.as_deref()),
        h1: digest(compared.h1.as_deref()),
        canonical: compared
            .canonical
            .as_deref()
            .map(|address| keys.key(address)),
        noindex: compared.noindex,
        hreflang: keys.keys(&compared.hreflang),
        hreflang_truncated: compared.hreflang_truncated,
        links: keys.keys(&compared.internal_links),
        links_truncated: compared.internal_links_truncated,
        sitemap: sitemap_facts(context, &keys),
    }))
}

/// The SHA-256 of the key the comparison uses (trimmed and ASCII-lowercased,
/// as the analysis normalizes it), over the whole value, or `None` when
/// nothing is left to compare. A replacement character means the decode
/// dropped bytes, so two values that read alike may not be alike, and neither
/// is compared, as the analysis skips them.
fn digest(value: Option<&str>) -> Option<String> {
    let key = value?.trim().to_ascii_lowercase();
    (!key.is_empty() && !key.contains('\u{FFFD}'))
        .then(|| hex::encode(&Sha256::digest(key.as_bytes())[..]))
}

/// The sitemap the walk found, on the route that walked it. An index's pages
/// are the ones its children list, as far as this route read them, and what it
/// did not read is a partial cause; a document with no entries is no sitemap,
/// as on the desktop.
fn sitemap_facts(context: &ProbeContext, keys: &RouteKeys) -> Option<SessionSitemapFacts> {
    let answer = context.outcomes.get(&robots_request(context))?;
    let robots = robots_fetch_from_probe(answer.clone());
    let SitemapProbe::Found(found) = sitemap_probe(context, &robots) else {
        return None;
    };
    let SitemapParse::WellFormed(document) = parse_sitemap_document(&found.body) else {
        return None;
    };
    let mut partial_causes = Vec::new();
    let index = document.kind.lists_child_sitemaps();
    let pages: &[String] = if index {
        let names_limit = context.sitemap_children.names_limit();
        let children = context
            .sitemap_children
            .pages(&found, &origin_with_port(&context.page.url));
        if !names_limit || children.read < children.listed {
            partial_causes.push(SessionSitemapCause::Index {
                listed: children.listed,
                read: children.read,
            });
        }
        if children.url_limited {
            partial_causes.push(SessionSitemapCause::IndexUrls);
        }
        children.pages
    } else {
        if document.locs.len() > SITEMAP_URL_LIMIT {
            partial_causes.push(SessionSitemapCause::UrlLimit {
                listed: document.locs.len(),
            });
        }
        &document.locs
    };
    let declared = robots
        .body()
        .map(sitemap_urls_from_robots)
        .unwrap_or_default();
    let count = unread_sitemaps_count(&declared, Some(&found.url));
    if count > 0 {
        partial_causes.push(SessionSitemapCause::UnreadDeclarations { count });
    } else if !sitemap_sources_read(context, &robots, &found) {
        partial_causes.push(SessionSitemapCause::UnfinishedWalk);
    }
    if !index && document.locs.is_empty() {
        return None;
    }
    Some(SessionSitemapFacts {
        entries: pages
            .iter()
            .take(SITEMAP_URL_LIMIT)
            .map(|loc| keys.key(&normalize_page_url(loc)))
            .collect(),
        partial_causes,
    })
}
