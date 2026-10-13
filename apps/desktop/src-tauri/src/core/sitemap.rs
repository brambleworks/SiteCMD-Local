//! Sitemap discovery transport over the engine's shared candidates and parser.
//! Discovery may salvage page URLs from documents the check grades invalid.

use crate::constants::API_TIMEOUT_SHORT;
use reqwest::Client;
use serde::Serialize;
use sitecmd_engine::checks::seo::sitemap::{
    parse_sitemap_document, partial_reason, sitemap_candidate_urls, sitemap_urls_from_robots,
    unread_sitemaps_reason, SitemapBound, SitemapParse,
};
use sitecmd_engine::checks::seo::sitemap_walk::SITEMAP_URL_LIMIT as MAX_URLS;
use ts_rs::TS;
const MAX_CHILD_SITEMAPS: usize = 50;
/// Concurrent child-sitemap fetches per batch when walking a sitemap index.
const SITEMAP_CHILD_CONCURRENCY: usize = 5;

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct SitemapResult {
    pub status: SitemapStatus,
    pub urls: Vec<String>,
    pub source_url: Option<String>,
    /// Why this URL set is known to be shorter than what the site publishes,
    /// when it is. Scan-internal evidence for checks that must not report a
    /// clean verdict over a partial set, so it stays off the IPC contract.
    #[serde(skip)]
    #[ts(skip)]
    pub partial_because: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum SitemapStatus {
    Found,
    NotFound,
    Error,
}

/// Apply the original target's network policy to sitemap-derived URLs.
async fn validate_sitemap_target(
    url: &str,
    origin: crate::network_policy::LocalOrigin,
) -> Result<(), String> {
    crate::network_policy::validate_url(url, origin.subordinate_policy()).await
}

/// Discover sitemaps through common paths and robots.txt.
/// Derived URLs inherit the originating scan's network policy.
#[tracing::instrument(skip(client, base_url), fields(origin = ?origin))]
pub async fn discover_sitemap(
    client: &Client,
    base_url: &str,
    origin: crate::network_policy::LocalOrigin,
) -> SitemapResult {
    let base = base_url.trim_end_matches('/');

    // Candidate paths inherit the validated base; discovered URLs are revalidated.
    // A sitemap answering at a conventional path does not mean it is the only
    // one the site publishes, so robots.txt is still read for the declared set.
    for url in &sitemap_candidate_urls(base) {
        if let Some(mut result) = try_fetch_sitemap(client, url, origin).await {
            let declared = robots_sitemap_urls(client, base).await;
            note_partial(&mut result, unread_sitemaps_reason(&declared, Some(url)));
            return result;
        }
    }

    // Parse robots.txt sitemap directives.
    let declared = robots_sitemap_urls(client, base).await;
    for sitemap_url in &declared {
        // Reject sitemap URLs that point at private / metadata / loopback
        // addresses unless the original scan target was already strict-local.
        if validate_sitemap_target(sitemap_url, origin).await.is_err() {
            tracing::warn!(
                "Skipping unsafe Sitemap: directive in robots.txt at {}",
                crate::log_sanitizer::log_safe_url_target(sitemap_url),
            );
            continue;
        }
        if let Some(mut result) = try_fetch_sitemap(client, sitemap_url, origin).await {
            note_partial(
                &mut result,
                unread_sitemaps_reason(&declared, Some(sitemap_url)),
            );
            return result;
        }
    }

    SitemapResult {
        status: SitemapStatus::NotFound,
        urls: vec![],
        source_url: None,
        partial_because: None,
    }
}

/// The sitemap URLs a site declares in robots.txt, empty when robots.txt is
/// missing, unreadable, or declares none.
async fn robots_sitemap_urls(client: &Client, base: &str) -> Vec<String> {
    let robots_url = format!("{}/robots.txt", base);
    let Ok(response) = client
        .get(&robots_url)
        .timeout(API_TIMEOUT_SHORT)
        .send()
        .await
    else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    match crate::http_client::read_text_limited(
        response,
        crate::constants::MAX_PROBE_BODY_SIZE,
        API_TIMEOUT_SHORT,
    )
    .await
    {
        Ok(body) => sitemap_urls_from_robots(&body),
        Err(_) => Vec::new(),
    }
}

/// Record one more reason a set is partial, keeping any already recorded: a set
/// can be both truncated at a cap and missing a sitemap the site declares.
fn note_partial(result: &mut SitemapResult, reason: Option<String>) {
    let Some(reason) = reason else {
        return;
    };
    result.partial_because = Some(match result.partial_because.take() {
        Some(existing) => format!("{existing}; {reason}"),
        None => reason,
    });
}

/// Fetch a user-provided sitemap URL.
///
/// `origin` mirrors the scan target's reach so child
/// sitemaps inside a sitemap index get validated with the same network policy.
#[tracing::instrument(skip(client, sitemap_url), fields(origin = ?origin))]
pub async fn fetch_sitemap_url(
    client: &Client,
    sitemap_url: &str,
    origin: crate::network_policy::LocalOrigin,
) -> SitemapResult {
    match try_fetch_sitemap(client, sitemap_url, origin).await {
        Some(result) => result,
        None => SitemapResult {
            status: SitemapStatus::Error,
            urls: vec![],
            source_url: Some(sitemap_url.to_string()),
            partial_because: None,
        },
    }
}

// Sitemap targets use the shared network policy, including DNS-resolved private
// ranges and local-development allowances inherited from the scan target.

async fn try_fetch_sitemap(
    client: &Client,
    url: &str,
    origin: crate::network_policy::LocalOrigin,
) -> Option<SitemapResult> {
    let resp = client
        .get(url)
        .timeout(API_TIMEOUT_SHORT)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = crate::http_client::read_text_limited(
        resp,
        crate::constants::MAX_SITEMAP_SIZE,
        API_TIMEOUT_SHORT,
    )
    .await
    .ok()?;
    // One parser, shared with the seo.sitemap check. A document the strict
    // grammar rejects still yields locations here: discovery's job is finding
    // pages, and a malformed sitemap's URLs are real.
    let parse = parse_sitemap_document(&body);
    let locs = parse.locs();
    if locs.is_empty() {
        return None;
    }
    if let SitemapParse::Salvaged { reason, .. } = &parse {
        tracing::info!(
            "Reading pages from a malformed sitemap at {}: {}",
            crate::log_sanitizer::log_safe_url_target(url),
            reason
        );
    }

    // A sitemap index lists child sitemaps, not pages - true even when the
    // document is malformed, so this must not be read off a successful parse
    // alone.
    if !parse.lists_child_sitemaps() {
        let listed = locs.len();
        let mut urls: Vec<String> = locs.to_vec();
        urls.truncate(MAX_URLS);
        return Some(SitemapResult {
            status: SitemapStatus::Found,
            urls,
            source_url: Some(url.to_string()),
            partial_because: partial_reason(SitemapBound::Urls, listed, MAX_URLS),
        });
    }

    // Fetch child sitemaps in stable batches and stop at MAX_URLS.
    if locs.len() > MAX_CHILD_SITEMAPS {
        tracing::warn!(
            "Sitemap index has {}+ child sitemaps, capping at {}",
            locs.len(),
            MAX_CHILD_SITEMAPS
        );
    }
    let child_cap = partial_reason(SitemapBound::ChildSitemaps, locs.len(), MAX_CHILD_SITEMAPS);
    let mut url_cap = None;
    let mut all_urls = Vec::new();
    for batch in locs
        .iter()
        .take(MAX_CHILD_SITEMAPS)
        .collect::<Vec<_>>()
        .chunks(SITEMAP_CHILD_CONCURRENCY)
    {
        let fetches = batch.iter().map(|child_url| async move {
            if validate_sitemap_target(child_url, origin).await.is_err() {
                tracing::warn!(
                    "Skipping unsafe sitemap child URL: {}",
                    crate::log_sanitizer::log_safe_url_target(child_url)
                );
                return Vec::new();
            }
            let Ok(resp) = client
                .get(child_url.as_str())
                .timeout(API_TIMEOUT_SHORT)
                .send()
                .await
            else {
                return Vec::new();
            };
            if !resp.status().is_success() {
                return Vec::new();
            }
            match crate::http_client::read_text_limited(
                resp,
                crate::constants::MAX_SITEMAP_SIZE,
                API_TIMEOUT_SHORT,
            )
            .await
            {
                Ok(child_body) => parse_sitemap_document(&child_body).locs().to_vec(),
                Err(_) => Vec::new(),
            }
        });
        for mut page_urls in futures_util::future::join_all(fetches).await {
            all_urls.append(&mut page_urls);
        }
        if all_urls.len() >= MAX_URLS {
            url_cap = partial_reason(SitemapBound::IndexUrls, all_urls.len(), MAX_URLS);
            all_urls.truncate(MAX_URLS);
            break;
        }
    }

    if all_urls.is_empty() {
        return None;
    }
    let mut result = SitemapResult {
        status: SitemapStatus::Found,
        urls: all_urls,
        source_url: Some(url.to_string()),
        partial_because: child_cap,
    };
    note_partial(&mut result, url_cap);
    Some(result)
}

#[cfg(test)]
#[path = "sitemap_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "sitemap_body_tests.rs"]
mod body_tests;
