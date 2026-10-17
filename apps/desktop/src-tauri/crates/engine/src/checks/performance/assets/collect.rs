//! Policy-gated, deduplicated asset URL collection with bounded samples.

use crate::checks::html_attrs::{attr_value, tag_slices, url_attr_value};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;

/// What kind of asset a URL was referenced as. Drives the per-kind byte
/// breakdown in raw_data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Image,
    Script,
    Style,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Script => "script",
            Self::Style => "style",
        }
    }
}

/// A fetchable asset reference extracted from page markup.
#[derive(Debug, Clone)]
pub struct CollectedAsset {
    pub url: url::Url,
    pub kind: AssetKind,
    /// Whether the element declared responsive candidates.
    pub has_srcset: bool,
    /// Group whose responsive candidates count as one browser download.
    /// Scripts and styles use singleton groups.
    pub group: u32,
}

/// Everything the sampler learned from the markup before any network I/O.
#[derive(Debug, Default)]
pub struct AssetCollection {
    /// The first `limit` distinct fetchable assets, in sample order.
    pub sampled: Vec<CollectedAsset>,
    /// Distinct fetchable assets found, those past the sample included.
    pub fetchable_found: usize,
    /// Every asset reference discovered, including data URIs and skipped ones.
    pub found: usize,
    /// Inline data: URIs, counted toward page weight without fetching.
    pub data_uri_count: usize,
    pub data_uri_bytes: u64,
    /// References skipped because they cannot or must not be fetched
    /// (blob:, javascript:, unparseable, or refused by the runtime's
    /// network policy).
    pub skipped_unsupported: usize,
    /// The scanned page's `scheme://host[:port]`, used to keep same-origin
    /// asset paths unredacted in evidence.
    pub page_origin: Option<String>,
}

/// Collect, validate, dedup and cap asset URLs from page markup. Past the
/// sample, a distinct fetchable asset is counted by a hash of its address
/// rather than held, so a page naming thousands of assets costs the sample and
/// a hash each. `lower` must preserve `body` byte offsets, and `allow_target`
/// validates every untrusted resolved URL before sampling.
pub fn collect_assets(
    body: &str,
    lower: &str,
    page_url: &url::Url,
    allow_target: impl Fn(&url::Url) -> bool,
    limit: usize,
) -> AssetCollection {
    let mut collector = Collector::new(page_url, &allow_target, limit, Reach::WholePage);
    collector.scan(body, lower);
    collector.collection
}

/// The first `limit` distinct fetchable addresses, stopping at the end of the
/// element that fills the sample. Counts past it belong to the verdict.
pub fn asset_sample(
    body: &str,
    lower: &str,
    page_url: &url::Url,
    allow_target: impl Fn(&url::Url) -> bool,
    limit: usize,
) -> Vec<url::Url> {
    let mut collector = Collector::new(page_url, &allow_target, limit, Reach::Sample);
    collector.scan(body, lower);
    collector
        .collection
        .sampled
        .into_iter()
        .map(|asset| asset.url)
        .collect()
}

/// How far a scan goes: every reference for a verdict's counts, or only until
/// the sample is full for a plan.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    WholePage,
    Sample,
}

struct Collector<'a, F> {
    page_url: &'a url::Url,
    allow_target: &'a F,
    limit: usize,
    reach: Reach,
    collection: AssetCollection,
    /// The sample's addresses, exactly, to merge a later duplicate's flag.
    kept: HashMap<String, usize>,
    // 64-bit hashes of the distinct addresses past the sample; a
    // collision undercounts `fetchable_found` by one and leaves the sample
    // exact. Hold the addresses themselves if that count ever has to be exact.
    beyond: HashSet<u64>,
}

impl<'a, F: Fn(&url::Url) -> bool> Collector<'a, F> {
    fn new(page_url: &'a url::Url, allow_target: &'a F, limit: usize, reach: Reach) -> Self {
        Self {
            page_url,
            allow_target,
            limit,
            reach,
            collection: AssetCollection {
                page_origin: Some(page_url.origin().ascii_serialization()),
                ..AssetCollection::default()
            },
            kept: HashMap::new(),
            beyond: HashSet::new(),
        }
    }

    /// Whether a plan's scan may stop: its sample is full.
    fn done(&self) -> bool {
        self.reach == Reach::Sample && self.collection.sampled.len() >= self.limit
    }

    /// The passes run images first, then scripts, then stylesheets, which is
    /// the sample's priority: images dominate real-world page weight, so when
    /// the cap bites the sample keeps the bytes. Each element takes the next
    /// group id; the src and srcset candidates of one image share it.
    fn scan(&mut self, body: &str, lower: &str) {
        let mut group: u32 = 0;
        let images = tag_slices(body, lower, "img")
            .into_iter()
            .chain(tag_slices(body, lower, "source"));
        for tag in images {
            for (reference, has_srcset) in image_like_refs(tag) {
                self.add(AssetKind::Image, &reference, has_srcset, group);
            }
            group += 1;
            if self.done() {
                return;
            }
        }
        for tag in tag_slices(body, lower, "script") {
            if let Some(src) = url_attr_value(tag, "src") {
                self.add(AssetKind::Script, &src, false, group);
                group += 1;
            }
            if self.done() {
                return;
            }
        }
        for tag in tag_slices(body, lower, "link") {
            let is_stylesheet = attr_value(tag, "rel").is_some_and(|rel| {
                rel.split_whitespace()
                    .any(|token| token.eq_ignore_ascii_case("stylesheet"))
            });
            if is_stylesheet {
                if let Some(href) = url_attr_value(tag, "href") {
                    self.add(AssetKind::Style, &href, false, group);
                    group += 1;
                }
            }
            if self.done() {
                return;
            }
        }
    }

    fn add(&mut self, kind: AssetKind, raw: &str, has_srcset: bool, group: u32) {
        let reference = raw.trim();
        if reference.is_empty() {
            return;
        }
        let collection = &mut self.collection;
        collection.found += 1;

        let scheme_probe = reference.to_ascii_lowercase();
        if scheme_probe.starts_with("data:") {
            collection.data_uri_count += 1;
            collection.data_uri_bytes += data_uri_estimated_bytes(reference);
            return;
        }
        // Never fetch page-controlled non-HTTP schemes.
        if scheme_probe.starts_with("blob:") || scheme_probe.starts_with("javascript:") {
            collection.skipped_unsupported += 1;
            return;
        }
        let Ok(resolved) = self.page_url.join(reference) else {
            collection.skipped_unsupported += 1;
            return;
        };
        // SSRF gate: asset URLs come from untrusted page markup, exactly like
        // external link hrefs. The runtime's policy decides; the refusal is
        // recorded here.
        if !(self.allow_target)(&resolved) {
            collection.skipped_unsupported += 1;
            return;
        }
        let address = resolved.to_string();
        if let Some(&at) = self.kept.get(&address) {
            let kept = &mut collection.sampled[at];
            kept.has_srcset = kept.has_srcset || has_srcset;
            return;
        }
        if collection.sampled.len() < self.limit {
            self.kept.insert(address, collection.sampled.len());
            collection.sampled.push(CollectedAsset {
                url: resolved,
                kind,
                has_srcset,
                group,
            });
        } else if !self.beyond.insert(address_hash(&address)) {
            return;
        }
        collection.fetchable_found += 1;
    }
}

fn address_hash(address: &str) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    hasher.write(address.as_bytes());
    hasher.finish()
}

/// The src and srcset references of an `<img>` or `<source>` tag, each with
/// whether the element declared srcset candidates. They share one group so the
/// weight check counts one of them: a browser downloads a single candidate.
fn image_like_refs(tag: &str) -> Vec<(String, bool)> {
    // Attribute values are HTML: `&amp;` there is a single `&` on the wire.
    // Fetching the raw text asked astro.build and tailwindcss.com for image
    // URLs their optimizers answered 400, and the sampler reported those as
    // broken images.
    let candidates: Vec<String> = url_attr_value(tag, "srcset")
        .as_deref()
        .map(parse_srcset)
        .unwrap_or_default();
    let has_srcset = !candidates.is_empty();
    url_attr_value(tag, "src")
        .map(|src| (src, has_srcset))
        .into_iter()
        .chain(candidates.into_iter().map(|candidate| (candidate, true)))
        .collect()
}

/// Parse srcset URLs while preserving comma-bearing data URIs as one candidate.
pub(super) fn parse_srcset(value: &str) -> Vec<String> {
    let (head, data_tail) = match value.to_ascii_lowercase().find("data:") {
        Some(index) => (&value[..index], Some(value[index..].to_string())),
        None => (value, None),
    };
    let mut urls: Vec<String> = head
        .split(',')
        .filter_map(|candidate| {
            candidate
                .split_whitespace()
                .next()
                .map(|url| url.to_string())
        })
        .filter(|url| !url.is_empty())
        .collect();
    if let Some(tail) = data_tail {
        urls.push(tail);
    }
    urls
}

/// Estimate the byte weight an inline data: URI adds to the document.
/// base64 payloads decode to roughly 3/4 of their text length; other
/// payloads are counted as-is.
fn data_uri_estimated_bytes(value: &str) -> u64 {
    let Some(comma) = value.find(',') else {
        return 0;
    };
    let meta = &value[..comma];
    let payload = &value[comma + 1..];
    if meta.to_ascii_lowercase().contains(";base64") {
        (payload.len() as u64 * 3) / 4
    } else {
        payload.len() as u64
    }
}

#[cfg(test)]
#[path = "collect_tests.rs"]
mod tests;
