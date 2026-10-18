//! The routes a hosted scan of a site whose scope no person chose adds after
//! its entry route, read from what the entry route's session already holds:
//! the same-origin pages its document links to, in document order, then the
//! pages the sitemap walk's document lists, an index's through its children,
//! in their order. Nothing is requested for it, and nothing it finds is
//! followed. A candidate is kept only as a canonical route the hosted service
//! may store unchanged, and never one that names a file.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::discovery_robots::RobotsRules;
use super::origin_reads::{robots_request, sitemap_probe, sitemap_sources_read};
use super::probes::{ProbeContext, ProbeOutcomes};
use crate::checks::html_attrs::{attr_value, decode_url_character_references, tag_slices};
use crate::checks::origin_with_port;
use crate::checks::security::key_patterns::matches_key_pattern;
use crate::checks::seo::links::{
    effective_base_url, head_needs_get, is_reserved_path, link_get_request, link_head_request,
};
use crate::checks::seo::robots::robots_fetch_from_probe;
use crate::checks::seo::sitemap::{parse_sitemap_document, SitemapProbe};
use crate::checks::seo::sitemap_walk::{robots_was_read, SITEMAP_URL_LIMIT};
use crate::log_sanitizer::{evidence_safe_page_url, ISSUE_EVIDENCE_URL_MAX_CHARS};
use crate::page::PageContext;
use crate::probe::ProbeOutcome;
use crate::route::canonical_path;
use crate::session::signals::rel_has;

/// The routes to add, canonical paths in priority order, or `None` when the
/// entry route's document did not answer with a success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub routes: Option<Vec<String>>,
}

/// The file extensions Cloudflare caches by default, which name static files
/// rather than pages: Cloudflare Cache, "Default Cache Behavior", "Default
/// cached file extensions"
/// (<https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>),
/// a list that leaves HTML and JSON out. A candidate whose last segment ends
/// in one is not discovered; a route's own document's media type decides the
/// rest when the route is fetched.
const CACHED_FILE_EXTENSIONS: [&str; 56] = [
    "7z", "avi", "avif", "apk", "bin", "bmp", "bz2", "class", "css", "csv", "doc", "docx", "dmg",
    "ejs", "eot", "eps", "exe", "flac", "gif", "gz", "ico", "iso", "jar", "jpg", "jpeg", "js",
    "mid", "midi", "mkv", "mp3", "mp4", "ogg", "otf", "pdf", "pict", "pls", "png", "ppt", "pptx",
    "ps", "rar", "svg", "svgz", "swf", "tar", "tif", "tiff", "ttf", "webm", "webp", "woff",
    "woff2", "xls", "xlsx", "zip", "zst",
];

/// The routes the entry route's session discovers for its scan.
pub(super) fn discover(
    context: &ProbeContext,
    planned: &[String],
    limit: usize,
) -> DiscoveryResponse {
    let page = context.page;
    // An error answer is not the page the scan asked for, and nothing read
    // from its body is kept.
    if !(200..300).contains(&page.status_code) {
        return DiscoveryResponse { routes: None };
    }
    if limit == 0 {
        return DiscoveryResponse {
            routes: Some(Vec::new()),
        };
    }
    let origin = origin_with_port(&page.url);
    let requested = context
        .requested_url
        .and_then(|address| url::Url::parse(address).ok());
    let mut chosen = Chosen {
        routes: Vec::new(),
        // The entry route and the page it redirected to are the scan's own,
        // so neither is offered.
        seen: [Some(&page.url), requested.as_ref()]
            .into_iter()
            .flatten()
            .map(|url| canonical_path(url.path()))
            .collect(),
        origin: origin.clone(),
        limit,
        robots: RobotsRules::from_context(context),
    };
    for link in page_links(page, &origin) {
        if let Some(reached) = page_a_link_reaches(context.outcomes, &link) {
            chosen.offer(&reached);
        }
        if chosen.routes.len() >= limit {
            return DiscoveryResponse {
                routes: Some(chosen.routes),
            };
        }
    }
    let (locations, complete) = sitemap_pages(context, &origin);
    // At most the walk's URL limit, the bound every reader of one sitemap keeps.
    for location in locations.iter().take(SITEMAP_URL_LIMIT) {
        if let Some(reached) = url::Url::parse(location)
            .ok()
            .and_then(|url| page_a_link_reaches(context.outcomes, &url))
        {
            chosen.offer(&reached);
        }
        if chosen.routes.len() >= limit {
            return DiscoveryResponse {
                routes: Some(chosen.routes),
            };
        }
    }
    // A sitemap the walk could not finish, or a child of it that did not
    // answer, may list pages this read did not reach, so the routes the scan
    // started with stand in after the ones it did read.
    if !complete {
        for route in planned {
            if let Some(reached) = url::Url::parse(&format!("{origin}{route}"))
                .ok()
                .and_then(|url| page_a_link_reaches(context.outcomes, &url))
            {
                chosen.offer(&reached);
            }
            if chosen.routes.len() >= limit {
                break;
            }
        }
    }
    DiscoveryResponse {
        routes: Some(chosen.routes),
    }
}

/// The kept routes, entry route exclusions, and fixed selection context.
struct Chosen {
    routes: Vec<String>,
    seen: HashSet<String>,
    origin: String,
    limit: usize,
    robots: RobotsRules,
}

impl Chosen {
    /// An address on the page's own origin, with no query and no credentials,
    /// as its canonical route.
    fn offer(&mut self, url: &url::Url) {
        if origin_with_port(url) != self.origin
            || url.query().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return;
        }
        self.offer_route(&canonical_path(url.path()), url);
    }

    fn offer_route(&mut self, route: &str, url: &url::Url) {
        if self.routes.len() >= self.limit || self.seen.contains(route) {
            return;
        }
        // Rejection depends only on the route and this run's fixed context,
        // so weighing a rejected route again gives the same answer.
        if !names_a_cached_file(route)
            && storable(route, &self.origin)
            && self
                .robots
                .allowed(&url[url::Position::BeforePath..url::Position::AfterQuery])
        {
            self.seen.insert(route.to_string());
            self.routes.push(route.to_string());
        }
    }
}

/// Whether the route's last segment ends in a file extension Cloudflare
/// caches by default.
fn names_a_cached_file(route: &str) -> bool {
    route
        .rsplit('/')
        .next()
        .and_then(|segment| segment.rsplit_once('.'))
        .is_some_and(|(_, extension)| {
            CACHED_FILE_EXTENSIONS
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known))
        })
}

/// Whether the hosted service may store this route as it is. Each gate refuses
/// a route it would have to change, and a refused route is left out rather
/// than altered, because an altered route is a page the site does not serve: a
/// search path, a route the evidence rules would redact after word-slug masking,
/// an address past the length bound, and a route holding an exposed-key pattern.
fn storable(route: &str, origin: &str) -> bool {
    let address = format!("{origin}{route}");
    let masked = route
        .split('/')
        .map(|segment| if word_slug(segment) { "slug" } else { segment })
        .collect::<Vec<_>>()
        .join("/");
    let masked = format!("{origin}{masked}");
    !is_search_path(route)
        && address.chars().count() <= ISSUE_EVIDENCE_URL_MAX_CHARS
        && evidence_safe_page_url(&masked) == masked
        && !matches_key_pattern(route)
}

// Only discovery permits word slugs; every other evidence caller retains its token policy.
fn word_slug(segment: &str) -> bool {
    let pieces: Vec<_> = segment.split('-').collect();
    let uuid = pieces.iter().map(|piece| piece.len()).eq([8, 4, 4, 4, 12])
        && pieces
            .iter()
            .all(|piece| piece.bytes().all(|byte| byte.is_ascii_hexdigit()));
    !uuid
        && pieces
            .iter()
            .filter(|piece| piece.len() >= 2 && piece.bytes().all(|byte| byte.is_ascii_lowercase()))
            .count()
            >= 3
        && pieces.iter().all(|piece| {
            !piece.is_empty()
                && (piece.bytes().all(|byte| byte.is_ascii_digit())
                    || piece.bytes().all(|byte| byte.is_ascii_lowercase()))
        })
}

/// Whether a route's first segment is `search`.
fn is_search_path(route: &str) -> bool {
    route
        .trim_start_matches('/')
        .split('/')
        .next()
        .is_some_and(|first| first.eq_ignore_ascii_case("search"))
}

/// The same-origin addresses the document's anchors name, resolved lazily in
/// document order against its `<base href>`, the fragment dropped, and a
/// visitor-written `rel="ugc"` anchor left out, as the cross-page facts leave
/// it out. `tag_slices` passes over comments, scripts and styles, which are
/// not navigation, and reads the page's one shared lowercase copy.
fn page_links<'a>(page: &'a PageContext, origin: &'a str) -> impl Iterator<Item = url::Url> + 'a {
    let base = effective_base_url(page);
    tag_slices(&page.body, page.body_lower(), "a")
        .into_iter()
        .filter(|tag| !attr_value(tag, "rel").is_some_and(|rel| rel_has(&rel, "ugc")))
        .filter_map(|tag| attr_value(tag, "href"))
        .filter_map(move |href| {
            let href = decode_url_character_references(&href);
            let href = href.trim();
            if href.is_empty() || href.starts_with('#') {
                return None;
            }
            let mut url = base.join(href).ok()?;
            url.set_fragment(None);
            (origin_with_port(&url) == origin && !is_reserved_path(url.path())).then_some(url)
        })
}

/// The address a link reaches, as the link check's own probe of it found:
/// the link itself when nothing probed it, the probe's final address when the
/// probe showed a page, and nothing when it showed the link is gone
/// (404 or 410) or a success that is not HTML.
fn page_a_link_reaches(outcomes: &ProbeOutcomes<'_>, link: &url::Url) -> Option<url::Url> {
    let answer = match outcomes.get(&link_head_request(link)) {
        Some(head) if head_needs_get(head) => outcomes.get(&link_get_request(link)),
        head => head,
    };
    let Some(ProbeOutcome::Response(response)) = answer else {
        return Some(link.clone());
    };
    let reached = url::Url::parse(&response.final_url).ok()?;
    // An HTML media type, or none stated.
    let html = response.content_type.as_deref().is_none_or(|kind| {
        let essence = kind.split(';').next().unwrap_or_default().trim();
        essence.eq_ignore_ascii_case("text/html")
            || essence.eq_ignore_ascii_case("application/xhtml+xml")
    });
    let not_a_page =
        matches!(response.status, 404 | 410) || ((200..300).contains(&response.status) && !html);
    (!not_a_page).then_some(reached)
}

/// The page addresses the sitemap walk's document lists, in its order, and
/// whether they are all its pages: an index's are its children's, as far as
/// the route read them, and a missing sitemap lists none. Not all when the
/// walk could not finish, robots.txt or an earlier candidate did not answer,
/// or a child the route asked for did not answer.
fn sitemap_pages(context: &ProbeContext, origin: &str) -> (Vec<String>, bool) {
    let Some(answer) = context.outcomes.get(&robots_request(context)) else {
        return (Vec::new(), false);
    };
    let robots = robots_fetch_from_probe(answer.clone());
    match sitemap_probe(context, &robots) {
        SitemapProbe::Found(found) if found.kind.lists_child_sitemaps() => {
            let children = context.sitemap_children.pages(&found, origin);
            (
                children.pages.to_vec(),
                children.complete && sitemap_sources_read(context, &robots, &found),
            )
        }
        SitemapProbe::Found(found) => (
            parse_sitemap_document(&found.body)
                .locs()
                .iter()
                .take(SITEMAP_URL_LIMIT)
                .cloned()
                .collect(),
            sitemap_sources_read(context, &robots, &found),
        ),
        SitemapProbe::Missing { .. } if robots_was_read(answer) => (Vec::new(), true),
        _ => (Vec::new(), false),
    }
}
