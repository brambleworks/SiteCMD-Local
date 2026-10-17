//! Grades HTTP compression from a transport that preserves `Content-Encoding`.
//!
//! HEAD can prove compression; every inconclusive HEAD result defers to GET.

use crate::checks::{
    CheckResult, CheckStatus, IssueConfidence, PageContext, ScanCategory, Severity,
};
use crate::probe::{BodyPolicy, ContentCoding, ProbeOutcome, ProbeRequest};
use serde::{Deserialize, Serialize};

pub const CHECK_ID: &str = "performance.compression";
pub const TITLE: &str = "Compression";

/// The codings the compression probes offer, as the desktop's probe always
/// sent them.
pub const PROBE_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";

/// The status-only probe a compressed answer can settle alone, read as the
/// server sent it so `Content-Encoding` stays in evidence.
pub fn head_request(url: &url::Url) -> ProbeRequest {
    ProbeRequest::head(url.as_str())
        .header("accept-encoding", PROBE_ACCEPT_ENCODING)
        .coding(ContentCoding::Raw)
}

/// The confirmation a HEAD that proved nothing needs: the same question as a
/// GET, its body never read.
pub fn get_request(url: &url::Url) -> ProbeRequest {
    ProbeRequest::get(url.as_str())
        .body(BodyPolicy::None)
        .header("accept-encoding", PROBE_ACCEPT_ENCODING)
        .coding(ContentCoding::Raw)
}

/// What one compression probe observed, from its answer, or `None` for a
/// request that produced no response. Both headers are list fields, read whole
/// however many lines carried them.
pub fn encoding_probe(outcome: &ProbeOutcome) -> Option<EncodingProbe> {
    let ProbeOutcome::Response(response) = outcome else {
        return None;
    };
    Some(EncodingProbe {
        http_status: response.status,
        encoding: crate::header_lines::probe_field_value(response, "content-encoding")
            .map(|value| value.to_lowercase()),
        vary: crate::header_lines::probe_field_value(response, "vary")
            .map(|value| value.to_lowercase())
            .unwrap_or_default(),
    })
}

/// What one compression probe observed: the status line and the two headers
/// the verdict reads, taken from a non-decompressing transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProbe {
    pub http_status: u16,
    /// Lowercased Content-Encoding value, when the response carried one.
    #[serde(default)]
    pub encoding: Option<String>,
    /// Lowercased Vary value, empty when absent.
    #[serde(default)]
    pub vary: String,
}

impl EncodingProbe {
    fn is_2xx(&self) -> bool {
        (200..300).contains(&self.http_status)
    }
    fn compressed(&self) -> bool {
        self.encoding
            .as_ref()
            .map(|e| {
                e.contains("gzip")
                    || e.contains("br")
                    || e.contains("zstd")
                    || e.contains("deflate")
            })
            .unwrap_or(false)
    }
    fn vary_mentions_encoding(&self) -> bool {
        self.vary.contains("accept-encoding")
    }
}

/// Let HEAD finish grading only when `Content-Encoding` proves compression.
/// `Vary: Accept-Encoding` still requires GET confirmation.
fn head_may_grade(probe: &EncodingProbe) -> bool {
    probe.is_2xx() && probe.compressed()
}

/// What the verdict needs next after the HEAD probe (None = the HEAD
/// request itself failed).
pub enum CompressionStep {
    Done(Vec<CheckResult>),
    /// The HEAD proved nothing; the runtime must answer the GET probe.
    NeedsGet,
}

/// Grade the HEAD answer: it completes only on proven compression.
pub fn evaluate_compression_head(head: Option<&EncodingProbe>) -> CompressionStep {
    match head {
        Some(probe) if head_may_grade(probe) => CompressionStep::Done(vec![graded_result(probe)]),
        _ => CompressionStep::NeedsGet,
    }
}

/// Grade the GET answer (None = the GET request itself failed, so the only
/// remaining signal is the page response's own headers).
pub fn evaluate_compression_get(
    get: Option<EncodingProbe>,
    page: &PageContext,
) -> Vec<CheckResult> {
    match get {
        Some(probe) if probe.is_2xx() => vec![graded_result(&probe)],
        Some(probe) => vec![inconclusive_result(probe.http_status)],
        None => vec![check_from_headers(page)],
    }
}

/// Skipped result for localhost previews, where compression is usually
/// provided by the deployed server or CDN rather than the preview server.
pub fn localhost_skip_result() -> CheckResult {
    CheckResult {
        check_id: CHECK_ID.into(),
        category: ScanCategory::Performance,
        title: TITLE.into(),
        description: "Skipped on localhost preview. Compression is usually provided by the deployed server or CDN rather than a local preview server.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"reason": "localhost_preview_server"})),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

fn graded_result(probe: &EncodingProbe) -> CheckResult {
    let compressed = probe.compressed();
    CheckResult {
        check_id: CHECK_ID.into(),
        category: ScanCategory::Performance,
        title: if compressed {
            TITLE.into()
        } else {
            "Response served without compression".into()
        },
        description: if compressed {
            format!(
                "Response is compressed with {}. Good.",
                probe.encoding.clone().unwrap_or_default()
            )
        } else if probe.vary_mentions_encoding() {
            // Vary: Accept-Encoding only advertises that responses may
            // differ by encoding; this response actually arrived
            // uncompressed despite the probe requesting gzip/br/zstd.
            "The response arrived uncompressed even though the server sends Vary: Accept-Encoding. That header only signals capability - the actual response carried no Content-Encoding, so compression is not reaching clients."
                .into()
        } else {
            "Response is not compressed. Enable gzip or Brotli compression to reduce transfer size."
                .into()
        },
        status: if compressed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: if compressed {
            None
        } else {
            Some(
                // Prefer modern encodings while retaining gzip fallback guidance.
                "Enable response compression on whatever serves this page. Modern (2026) priority is Brotli > Zstd > gzip:\n\
                 • Nginx (with ngx_brotli): `brotli on; brotli_types text/html text/css application/javascript application/json image/svg+xml;` (then keep `gzip on;` as a fallback)\n\
                 • Apache (mod_brotli): `AddOutputFilterByType BROTLI_COMPRESS text/html text/css application/javascript application/json` (mod_deflate as fallback)\n\
                 • Caddy: `encode zstd br gzip` in your site block\n\
                 • Cloudflare / Vercel / Netlify: enabled automatically - if compression isn't reaching the browser, an upstream proxy is stripping `Accept-Encoding`; check your origin and any reverse proxies in front of it."
                    .into(),
            )
        },
        raw_data: Some(serde_json::json!({
            "content_encoding": probe.encoding,
            "vary": probe.vary,
            "probe_status": probe.http_status,
        })),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: if compressed {
            None
        } else {
            Some("Uncompressed pages transfer 3-5x more data, hurting mobile load times.".into())
        },
    }
}

fn inconclusive_result(http_status: u16) -> CheckResult {
    CheckResult {
        check_id: CHECK_ID.into(),
        category: ScanCategory::Performance,
        title: TITLE.into(),
        description: format!(
            "Couldn't check compression: the probe request returned HTTP {}, which is not the page itself, so there is nothing valid to grade.",
            http_status
        ),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"probe_status": http_status})),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// On probe failure, grade only positive page-header evidence.
/// Auto-decompression makes an absent header inconclusive.
fn check_from_headers(page: &PageContext) -> CheckResult {
    let encoding = crate::header_lines::field_value(&page.response_headers, "content-encoding")
        .map(|value| value.to_lowercase());

    let has_compression = encoding
        .as_ref()
        .map(|e| {
            e.contains("gzip") || e.contains("br") || e.contains("zstd") || e.contains("deflate")
        })
        .unwrap_or(false);

    CheckResult {
        check_id: CHECK_ID.into(),
        category: ScanCategory::Performance,
        title: TITLE.into(),
        description: if has_compression {
            format!(
                "Response is compressed with {}. Good.",
                encoding.clone().unwrap_or_default()
            )
        } else {
            "Couldn't check compression: the probe request failed, and the page response carries no usable Content-Encoding signal. Compression state is unknown, not failing."
                .into()
        },
        status: if has_compression {
            CheckStatus::Pass
        } else {
            CheckStatus::Skipped
        },
        severity: if has_compression {
            Severity::Medium
        } else {
            Severity::Low
        },
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"content_encoding": encoding})),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

#[cfg(test)]
#[path = "compression_tests.rs"]
mod tests;
