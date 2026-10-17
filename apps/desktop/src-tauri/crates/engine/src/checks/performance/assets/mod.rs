//! Verdicts over a bounded sample of page-referenced assets.
//!
//! Every runtime executes each sampled asset's request and hands back its
//! answer; this module sizes it and grades the sample. This is a sampler, not a
//! browser transfer trace.

mod collect;
mod results;
mod unanswered;

pub use collect::{asset_sample, collect_assets, AssetCollection, AssetKind, CollectedAsset};

/// How many page assets (images, scripts, stylesheets) the sample requests to
/// measure real transfer sizes. Bounded so a media-heavy page cannot turn one
/// scan into hundreds of requests.
pub const ASSET_SAMPLE_LIMIT: usize = 30;

/// One byte is enough to learn the status, the type, and the length header
/// without pulling an image the verdict never looks at.
pub const ASSET_SAMPLE_RANGE: &str = "bytes=0-0";

use crate::checks::CheckResult;
use crate::probe::{BodyPolicy, ContentCoding, ProbeMeasure, ProbeOutcome, ProbeRequest};
use serde::{Deserialize, Serialize};

/// One sampled asset after the runtime's measurement pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasuredAsset {
    pub url: String,
    pub kind: AssetKind,
    /// 0 means the request never produced a response (DNS/connect/timeout).
    pub status_code: u16,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub content_type: Option<String>,
    /// Raw Cache-Control response header, if any - a reliable signal from
    /// the same fetch that measures the bytes, no extra request.
    #[serde(default)]
    pub cache_control: Option<String>,
    /// True when the byte count is a truncated lower bound, not a total.
    #[serde(default)]
    pub measured_floor: bool,
    #[serde(default)]
    pub has_srcset: bool,
    /// Responsive-image group id carried from the collected asset; the weight
    /// check counts one representative per group. See `CollectedAsset::group`.
    pub group: u32,
}

impl MeasuredAsset {
    /// An asset we never got a response for.
    pub fn unfetched(asset: &CollectedAsset) -> Self {
        Self {
            url: asset.url.to_string(),
            kind: asset.kind,
            status_code: 0,
            bytes: None,
            content_type: None,
            cache_control: None,
            measured_floor: false,
            has_srcset: asset.has_srcset,
            group: asset.group,
        }
    }
}

/// One sampled asset's request: a one-byte range, read as the server sends it.
/// `identity` asks for the uncoded representation, so every runtime sizes the
/// same bytes whatever codings it could decode; a body that no header sizes is
/// counted, never kept.
pub fn asset_request(url: &url::Url) -> ProbeRequest {
    ProbeRequest::get(url.as_str())
        .header("range", ASSET_SAMPLE_RANGE)
        .header("accept-encoding", "identity")
        .body(BodyPolicy::Count)
        .coding(ContentCoding::Raw)
}

/// One sampled asset's measurement from its answer, read in the order the
/// sampler always read a response: the status, the type and the cache header,
/// then a 206's Content-Range total, else the declared Content-Length, else the
/// body the runtime counted.
pub fn measured_asset(
    asset: &CollectedAsset,
    outcome: &ProbeOutcome,
    measure: Option<ProbeMeasure>,
) -> MeasuredAsset {
    let mut measured = MeasuredAsset::unfetched(asset);
    let ProbeOutcome::Response(response) = outcome else {
        return measured;
    };
    measured.status_code = response.status;
    measured.content_type = response.content_type.as_deref().map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or(value)
            .trim()
            .to_ascii_lowercase()
    });
    measured.cache_control = crate::header_lines::probe_field_value(response, "cache-control");
    if response.status >= 400 {
        return measured;
    }
    // 206 Partial Content: Content-Range names the full size for one byte of
    // transfer.
    if response.status == 206 {
        measured.bytes = response
            .header("content-range")
            .and_then(parse_content_range_total);
        return measured;
    }
    if let Some(length) = response.content_length {
        measured.bytes = Some(length);
        return measured;
    }
    if let Some(measure) = measure.filter(|measure| measure.counted_bytes.is_some()) {
        measured.bytes = measure.counted_bytes;
        measured.measured_floor = measure.count_capped;
    }
    measured
}

/// Parse the total size out of a Content-Range header value such as
/// `bytes 0-0/12345`. Returns None when the total is unknown (`*`).
/// Read by `measured_asset`, so every runtime's answer is classified identically.
fn parse_content_range_total(value: &str) -> Option<u64> {
    let rest = value.trim().strip_prefix("bytes")?.trim_start();
    let (_, total) = rest.rsplit_once('/')?;
    let total = total.trim();
    if total == "*" {
        return None;
    }
    total.parse().ok()
}

/// Grade one collection plus its measurements into the sampler's four rows. A
/// verdict whose requests all went unanswered states nothing: a transport
/// failure is not an observation about the site.
pub fn evaluate_asset_sample(
    html_bytes: u64,
    collection: &AssetCollection,
    measured: &[MeasuredAsset],
) -> Vec<CheckResult> {
    let page_origin = collection.page_origin.as_deref();
    // The sampled requests of one kind, or of every kind, when not one of them
    // got a response.
    let all_unanswered = |kind: Option<AssetKind>| {
        let read: Vec<&MeasuredAsset> = measured
            .iter()
            .filter(|asset| kind.is_none_or(|kind| asset.kind == kind))
            .collect();
        (!read.is_empty() && read.iter().all(|asset| asset.status_code == 0)).then_some(read.len())
    };
    let any = all_unanswered(None);
    vec![
        any.map_or_else(
            || results::asset_weight_result(html_bytes, collection, measured),
            unanswered::weight_unmeasured,
        ),
        results::broken_images_result(measured, page_origin),
        all_unanswered(Some(AssetKind::Image)).map_or_else(
            || results::heavy_images_result(measured, page_origin),
            unanswered::heavy_unmeasured,
        ),
        any.map_or_else(
            || results::asset_caching_result(measured, page_origin),
            unanswered::caching_unassessed,
        ),
    ]
}

/// Format bytes with decimal KB/MB units, matching Chrome DevTools.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1000.0;
    const MB: f64 = 1_000_000.0;
    let value = bytes as f64;
    if value >= MB {
        format!("{:.1} MB", value / MB)
    } else if value >= KB {
        format!("{:.0} KB", value / KB)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod content_range_tests {
    use super::parse_content_range_total;

    #[test]
    fn parses_standard_content_range_totals() {
        assert_eq!(parse_content_range_total("bytes 0-0/12345"), Some(12345));
        assert_eq!(parse_content_range_total(" bytes 0-0/1 "), Some(1));
        assert_eq!(
            parse_content_range_total("bytes 0-1023/4194304"),
            Some(4_194_304)
        );
    }

    #[test]
    fn parses_unsatisfied_range_with_known_total() {
        assert_eq!(parse_content_range_total("bytes */999"), Some(999));
    }

    #[test]
    fn rejects_unknown_totals_and_garbage() {
        assert_eq!(parse_content_range_total("bytes 0-0/*"), None);
        assert_eq!(parse_content_range_total("bytes 0-0"), None);
        assert_eq!(parse_content_range_total("items 0-0/50"), None);
        assert_eq!(parse_content_range_total(""), None);
        assert_eq!(parse_content_range_total("bytes 0-0/abc"), None);
    }
}

#[cfg(test)]
#[path = "sample_tests.rs"]
mod sample_tests;
