//! Ephemeral per-page signals consumed by cross-page session analysis.
//! They are skipped during serialization and never reach storage or the frontend.

use crate::checks::seo::robots_tag;
use crate::header_lines::HeaderLines;
use std::sync::LazyLock;

/// Per-page cap on internal links and on hreflang alternates, for bounded session memory.
pub const MAX_INTERNAL_LINKS_PER_PAGE: usize = 200;

#[derive(Debug, Clone)]
pub struct PageSignals {
    pub url: String,
    /// The normalized URL this scan asked for, before any redirect. A page
    /// linked only through its pre-redirect URL is still a linked page.
    pub requested_url: String,
    /// Status of the final response the signals were read from. Session
    /// analysis compares pages, and an error page is not the page that was
    /// asked for, so error responses are excluded from every comparison.
    pub status_code: u16,
    pub title: Option<String>,
    pub meta_description: Option<String>,
    pub h1: Option<String>,
    pub canonical: Option<String>,
    /// `None` when the page's X-Robots-Tag lines arrived joined and where one ended decides it.
    pub noindex: Option<bool>,
    /// (hreflang value, resolved absolute href)
    pub hreflang: Vec<(String, String)>,
    /// Same-site outgoing links, resolved absolute, folded onto the scanned
    /// origin, normalized, deduped.
    pub internal_links: Vec<String>,
    /// True when more unique same-site links existed after the bounded cap.
    pub internal_links_truncated: bool,
}

static H1_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    let re = regex::Regex::new(r"(?is)<h1(?:\s[^>]*)?>(.*?)</h1\s*>");
    re.expect("static regex compiles") // allow-expect: compile-time literal regex
});
static TAG_STRIP_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?s)<[^>]*>").expect("static regex compiles")); // allow-expect: compile-time literal regex
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn rel_has(rel: &str, expected: &str) -> bool {
    rel.split_ascii_whitespace()
        .any(|token| token.eq_ignore_ascii_case(expected))
}

fn has_noindex_directive(value: &str) -> bool {
    value
        .split(|character: char| character == ',' || character.is_ascii_whitespace())
        .map(|token| token.trim_matches(':'))
        .any(|token| token.eq_ignore_ascii_case("noindex") || token.eq_ignore_ascii_case("none"))
}

fn x_robots_blocks_general_index(value: &str) -> bool {
    let mut applies_to_general_index = None;
    value.split(',').any(|clause| {
        let clause = clause.trim();
        match clause.split_once(':') {
            Some((name, directives)) => {
                let Some(agent) = robots_tag::crawler_name(name) else {
                    return false;
                };
                let applies = matches!(agent.as_str(), "googlebot" | "robots" | "*");
                applies_to_general_index = Some(applies);
                applies && has_noindex_directive(directives)
            }
            None => applies_to_general_index.unwrap_or(true) && has_noindex_directive(clause),
        }
    })
}

/// Whether the X-Robots-Tag lines mark the page noindex for the comparison,
/// or `None` when joined lines say so read one line per clause and not read
/// as they arrived. Any split of them reads as one of the two, since a clause
/// after a name addresses that name's crawler or every crawler.
fn header_noindex(headers: &http::HeaderMap, lines: HeaderLines) -> Option<bool> {
    let readings = robots_tag::readings(headers, lines);
    let blocks = |values: &[String]| {
        values
            .iter()
            .any(|value| x_robots_blocks_general_index(value))
    };
    let as_arrived = blocks(&readings.as_arrived);
    match readings.per_clause {
        Some(per_clause) if blocks(&per_clause) != as_arrived => None,
        _ => Some(as_arrived),
    }
}

/// A link to the same site as `page_url`, rewritten onto the scanned origin, or
/// `None` when the link leaves the site.
///
/// A site reached at `https://example.com` still links to itself as
/// `http://example.com/...` and `https://www.example.com/...`. Those are the
/// same pages, so an anchor written that way is a real inbound link; treating
/// the twins as foreign origins made the pages they point at look unlinked.
/// Only the scheme and a leading `www.` may differ: an explicit port and the
/// rest of the host must match, so a genuinely different host stays foreign.
pub(crate) fn same_site_link(resolved: &url::Url, page_url: &url::Url) -> Option<url::Url> {
    if !matches!(resolved.scheme(), "http" | "https") {
        return None;
    }
    if resolved.port() != page_url.port() {
        return None;
    }
    fn bare_host(url: &url::Url) -> Option<String> {
        let host = url.host_str()?.to_ascii_lowercase();
        Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
    }
    if bare_host(resolved)? != bare_host(page_url)? {
        return None;
    }
    let mut on_scanned_origin = resolved.clone();
    on_scanned_origin.set_scheme(page_url.scheme()).ok()?;
    on_scanned_origin.set_host(page_url.host_str()).ok()?;
    Some(on_scanned_origin)
}

/// Normalize a URL for cross-page identity comparison: drop the fragment,
/// lowercase host, trim a trailing slash on non-root paths.
pub fn normalize_page_url(input: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(input) else {
        return input.trim_end_matches('/').to_string();
    };
    parsed.set_fragment(None);
    let mut out = parsed.to_string();
    if parsed.path() != "/" && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Signals for a page fetched directly at `page_url` with a 200 response.
pub fn extract_page_signals(page_url: &url::Url, body: &str) -> PageSignals {
    extract_page_signals_with_headers(page_url, page_url, 200, body, &http::HeaderMap::new())
}

/// Signals for a fetched page. `page_url` is the effective (post-redirect) URL
/// the body came from, `requested_url` is the URL the scan asked for, and
/// `status_code` is the final response status.
pub fn extract_page_signals_with_headers(
    page_url: &url::Url,
    requested_url: &url::Url,
    status_code: u16,
    body: &str,
    response_headers: &http::HeaderMap,
) -> PageSignals {
    extract_page_signals_with_lines(
        page_url,
        requested_url,
        status_code,
        body,
        response_headers,
        HeaderLines::Separate,
    )
}

/// Signals for a fetched page with the header lines as the runtime handed them over.
pub fn extract_page_signals_with_lines(
    page_url: &url::Url,
    requested_url: &url::Url,
    status_code: u16,
    body: &str,
    response_headers: &http::HeaderMap,
    lines: HeaderLines,
) -> PageSignals {
    // Markup examples in scripts/comments/styles are not document metadata or
    // navigation. Use the same exclusion boundary as the page-level checks.
    let scannable = crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(body, " ");
    let lower = scannable.to_ascii_lowercase();

    // One title authority with the page-level title check: an inline SVG
    // <title> labels a graphic, not the document, and must not become the
    // title every page on the site appears to share.
    let title = crate::checks::seo::parsing::extract_document_title(body)
        .map(|t| collapse_whitespace(&TAG_STRIP_RE.replace_all(&t, " ")))
        .filter(|t| !t.is_empty());

    let h1 = H1_RE
        .captures(&scannable)
        .map(|c| collapse_whitespace(&TAG_STRIP_RE.replace_all(&c[1], " ")))
        .filter(|t| !t.is_empty());

    let mut meta_description = None;
    let mut noindex = header_noindex(response_headers, lines);
    for tag in crate::checks::html_attrs::tag_slices(&scannable, &lower, "meta") {
        let name = crate::checks::html_attrs::attr_value(tag, "name")
            .map(|name| name.to_ascii_lowercase());
        match name.as_deref() {
            Some("description") if meta_description.is_none() => {
                meta_description = crate::checks::html_attrs::attr_value(tag, "content")
                    .map(|c| collapse_whitespace(&c))
                    .filter(|c| !c.is_empty());
            }
            Some("robots") | Some("googlebot")
                if crate::checks::html_attrs::attr_value(tag, "content")
                    .is_some_and(|content| has_noindex_directive(&content)) =>
            {
                noindex = Some(true);
            }
            _ => {}
        }
    }

    let document_base = crate::checks::html_attrs::tag_slices(&scannable, &lower, "base")
        .into_iter()
        .find_map(|tag| crate::checks::html_attrs::attr_value(tag, "href"))
        .and_then(|href| page_url.join(href.trim()).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or_else(|| page_url.clone());

    let mut canonical = None;
    let mut hreflang = Vec::new();
    for tag in crate::checks::html_attrs::tag_slices(&scannable, &lower, "link") {
        let rel = crate::checks::html_attrs::attr_value(tag, "rel").unwrap_or_default();
        if canonical.is_none() && rel_has(&rel, "canonical") {
            canonical = crate::checks::html_attrs::attr_value(tag, "href")
                .and_then(|href| document_base.join(href.trim()).ok())
                .map(|u| normalize_page_url(u.as_str()));
        }
        if rel_has(&rel, "alternate") {
            if let (Some(lang), Some(href)) = (
                crate::checks::html_attrs::attr_value(tag, "hreflang"),
                crate::checks::html_attrs::attr_value(tag, "href"),
            ) {
                if let Ok(resolved) = document_base.join(href.trim()) {
                    hreflang.push((
                        lang.trim().to_ascii_lowercase(),
                        normalize_page_url(resolved.as_str()),
                    ));
                }
            }
        }
    }

    // Inbound-link evidence is deliberately generous: a rel="nofollow" anchor
    // and an anchor inside <template> or <noscript> still show that the site
    // links to the page, which is the question orphan analysis asks. Counting
    // them can only remove an orphan claim, never invent one. Anchors written
    // inside scripts, comments, and styles are excluded above because they are
    // markup examples rather than navigation. Same-site scheme and www twins are
    // folded onto the scanned origin by `same_site_link` so a page linked only
    // as its http:// or www form is not reported as unlinked.
    // An anchor marked `rel="ugc"` is the exception: a visitor wrote it, so it is
    // not kept, which can only add an orphan claim for a page only visitors link to.
    // Links already written on the scanned origin are collected first and
    // folded twins only with the budget left over. Sharing one pass would let a
    // twin take the last slot under the cap and push a real link out of the
    // set, which is the one direction this fold must never go.
    let anchors = crate::checks::html_attrs::tag_slices(&scannable, &lower, "a");
    let mut internal_links: Vec<String> = Vec::new();
    let mut internal_links_truncated = false;
    for collecting_twins in [false, true] {
        for tag in anchors.iter().copied() {
            let Some(href) = crate::checks::html_attrs::attr_value(tag, "href") else {
                continue;
            };
            // A visitor wrote this link, not the site, so nothing of it is kept.
            let rel = crate::checks::html_attrs::attr_value(tag, "rel").unwrap_or_default();
            if rel_has(&rel, "ugc") {
                continue;
            }
            let href = href.trim();
            if href.is_empty() || href.starts_with('#') {
                continue;
            }
            let Ok(resolved) = document_base.join(href) else {
                continue;
            };
            let Some(same_site) = same_site_link(&resolved, page_url) else {
                continue;
            };
            if (same_site != resolved) != collecting_twins {
                continue;
            }
            let normalized = normalize_page_url(same_site.as_str());
            if internal_links.contains(&normalized) {
                continue;
            }
            if internal_links.len() >= MAX_INTERNAL_LINKS_PER_PAGE {
                internal_links_truncated = true;
                break;
            }
            internal_links.push(normalized);
        }
    }

    PageSignals {
        url: normalize_page_url(page_url.as_str()),
        requested_url: normalize_page_url(requested_url.as_str()),
        status_code,
        title,
        meta_description,
        h1,
        canonical,
        noindex,
        hreflang,
        internal_links,
        internal_links_truncated,
    }
}

impl PageSignals {
    /// This page as the cross-page analysis compares it. Its addresses are
    /// already normalized identities; its alternates keep the link cap, and
    /// say when a page had more than the comparison keeps.
    pub fn session_page(&self) -> super::SessionPage {
        super::SessionPage {
            url: self.url.clone(),
            requested_url: self.requested_url.clone(),
            status_code: self.status_code,
            title: self.title.clone(),
            meta_description: self.meta_description.clone(),
            h1: self.h1.clone(),
            canonical: self.canonical.clone(),
            noindex: self.noindex,
            hreflang: self
                .hreflang
                .iter()
                .take(MAX_INTERNAL_LINKS_PER_PAGE)
                .map(|(_, href)| href.clone())
                .collect(),
            hreflang_truncated: self.hreflang.len() > MAX_INTERNAL_LINKS_PER_PAGE,
            internal_links: self.internal_links.clone(),
            internal_links_truncated: self.internal_links_truncated,
        }
    }
}

#[cfg(test)]
#[path = "signals_tests.rs"]
mod tests;
