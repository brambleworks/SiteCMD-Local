//! Portable probe request and outcome vocabulary.
//!
//! Body policy, failure classification, and decoding are shared across
//! transport adapters. HEAD requests never read bodies.

use serde::{Deserialize, Serialize};

/// What a browser asks for when a person navigates to a URL.
///
/// Probes that grade a document a visitor would see must ask for it the way a
/// visitor's browser does, because origins content-negotiate on this header:
/// GitHub answers a missing path with a nine-byte `text/plain` body under
/// reqwest's default `*/*` and with its full 260 KB branded error page under
/// this one. Grading the former would be grading a response no browser
/// receives. The `*/*;q=0.8` tail keeps XML and plain-text documents
/// acceptable, so file-shaped targets still answer normally.
pub const BROWSER_PAGE_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

/// What a probe plan wants fetched and how. Adapters execute this and
/// nothing else, so a check can never smuggle runtime-specific transport
/// behavior past the parity corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub url: String,
    #[serde(default)]
    pub method: ProbeMethod,
    pub body: BodyPolicy,
    pub redirects: RedirectPolicy,
    /// The size cap the body reads under. Omitted on the wire for the probe
    /// cap, so every other request keeps its bytes and its key.
    #[serde(default, skip_serializing_if = "BodyLimit::is_probe")]
    pub limit: BodyLimit,
    /// Omitted on the wire for a decoded read, so every other request keeps
    /// its bytes and its key.
    #[serde(default, skip_serializing_if = "ContentCoding::is_decoded")]
    pub coding: ContentCoding,
    /// Set on a timing request: the runtime records how long the response
    /// head took to arrive in the executed probe's measure. The number tells
    /// repeated samples of one URL apart, so each keeps its own key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timed: Option<u8>,
    /// Extra request headers (name, value) the plan requires, e.g. a foreign
    /// `Origin` for the CORS reflection probe.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// The HTTP method a plan needs. `Head` is for status-only liveness probes
/// where a body would be wasted bandwidth; adapters must never read a body
/// for it regardless of [`BodyPolicy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    #[default]
    Get,
    Head,
}

impl ProbeRequest {
    /// The common shape: GET, follow redirects, read 2xx bodies under cap.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: ProbeMethod::Get,
            body: BodyPolicy::SuccessOnly,
            redirects: RedirectPolicy::Follow,
            limit: BodyLimit::Probe,
            coding: ContentCoding::Decoded,
            timed: None,
            headers: Vec::new(),
        }
    }

    /// A status-only HEAD probe.
    pub fn head(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: ProbeMethod::Head,
            body: BodyPolicy::None,
            redirects: RedirectPolicy::Follow,
            limit: BodyLimit::Probe,
            coding: ContentCoding::Decoded,
            timed: None,
            headers: Vec::new(),
        }
    }

    pub fn body(mut self, body: BodyPolicy) -> Self {
        self.body = body;
        self
    }

    pub fn limit(mut self, limit: BodyLimit) -> Self {
        self.limit = limit;
        self
    }

    pub fn coding(mut self, coding: ContentCoding) -> Self {
        self.coding = coding;
        self
    }

    /// A timing request, `sample` telling it apart from the other samples of
    /// the same URL.
    pub fn timed(mut self, sample: u8) -> Self {
        self.timed = Some(sample);
        self
    }

    pub fn redirects(mut self, redirects: RedirectPolicy) -> Self {
        self.redirects = redirects;
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Response body policy. `SuccessOnly` requires 2xx evidence, `Always` keeps
/// status-only results when body reads fail, `None` skips the body, and
/// `Count` reads a body only to count it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyPolicy {
    SuccessOnly,
    Always,
    None,
    /// Read a body only to count it, and only when nothing else sizes the
    /// response: a status below 400 that is not a 206 and declares no
    /// Content-Length. The bytes are counted under the probe cap and never
    /// kept; the count comes back in the executed probe's measure.
    Count,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectPolicy {
    Follow,
    /// Classify the first response as-is; a 3xx is the answer, not a hop.
    None,
}

/// Whether the runtime may decode a content-coded response before a verdict
/// reads it. Every probe reads as a visitor's client would, decoded, except one
/// that measures the coding itself or the size the server sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentCoding {
    #[default]
    Decoded,
    /// The response as the server sent it: its coding headers stay in
    /// evidence, and a counted body is counted before any decoding. A runtime
    /// that can read a coded body only decoded leaves such a body uncounted.
    Raw,
}

impl ContentCoding {
    fn is_decoded(&self) -> bool {
        matches!(self, Self::Decoded)
    }
}

/// Which size cap the runtime reads a body under. Every probe reads under the
/// probe cap except a sitemap's: a walk candidate, or a child an index lists,
/// can list thousands of pages and reads under the sitemap cap. Each runtime
/// holds its own byte values (the desktop's `MAX_SITEMAP_SIZE`, the hosted
/// transport's sitemap budget), and the published facts hold the two to one
/// number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyLimit {
    #[default]
    Probe,
    Sitemap,
    /// A child sitemap an index lists, read under the sitemap cap and keyed
    /// apart from a walk candidate, because a runtime records each child's
    /// answer on its own and the engine keeps its pages, never its document.
    SitemapChild,
}

impl BodyLimit {
    fn is_probe(&self) -> bool {
        matches!(self, Self::Probe)
    }
}

/// Outcome of one probe request, as classified by a transport adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeOutcome {
    Response(ProbeResponse),
    Failure(ProbeFailure),
}

/// Completed exchange whose body follows the request's [`BodyPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub status: u16,
    /// The URL that produced this response after any redirects.
    pub final_url: String,
    pub content_type: Option<String>,
    /// Parsed declared length; the bounded body remains the observed truth.
    #[serde(default)]
    pub content_length: Option<u64>,
    /// Every response header as (lowercase name, value), non-UTF-8 bytes
    /// decoded lossily.
    /// `content_type`/`content_length` stay as parsed conveniences.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub body: Option<ProbeBody>,
}

impl ProbeResponse {
    /// First value of a response header, by lowercase name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A successful response body after the shared lossy-UTF-8 decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeBody {
    pub text: String,
    /// Raw byte length before decoding (lossy decoding can change lengths).
    pub bytes: usize,
    pub utf8_valid: bool,
}

/// A request that produced no usable HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeFailure {
    pub class: ProbeFailureClass,
    /// The runtime's error rendering, kept verbatim so verdict evidence is
    /// stable within one runtime; verdicts must bound it before persisting.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFailureClass {
    Timeout,
    BodyCapExceeded,
    /// Name resolution returned no address for the host. Separate from
    /// `Transport` because it is an answer, not a missing one: a verdict can
    /// tell "this host does not exist" from "this host did not reply".
    DnsUnresolved,
    Transport,
}

/// What the runtime measured while it executed one probe, beyond the answer
/// itself. Present only for a request that asked for a measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeMeasure {
    /// A timed request: milliseconds from sending it to its response head,
    /// over every redirect it followed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_byte_ms: Option<u64>,
    /// A `BodyPolicy::Count` read: the body's bytes, counted and discarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counted_bytes: Option<u64>,
    /// The count stopped at the probe cap, so `counted_bytes` is a floor.
    #[serde(default, skip_serializing_if = "is_false")]
    pub count_capped: bool,
}

impl ProbeMeasure {
    pub fn timed(first_byte_ms: u64) -> Self {
        Self {
            first_byte_ms: Some(first_byte_ms),
            ..Self::default()
        }
    }

    pub fn counted(bytes: u64, capped: bool) -> Self {
        Self {
            counted_bytes: Some(bytes),
            count_capped: capped,
            ..Self::default()
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Detect SPA catch-all HTML returned for well-known-file probes.
pub fn looks_like_html_shell(content_type: &str, body: &str) -> bool {
    if content_type.contains("text/html") {
        return true;
    }
    let trimmed = body.trim_start();
    let head = &trimmed[..crate::checks::floor_char_boundary(trimmed, 64)];
    let head = head.to_ascii_lowercase();
    head.starts_with("<!doctype") || head.starts_with("<html")
}

/// The one lossy-UTF-8 decode both runtimes use for probe bodies.
pub fn decode_probe_body(bytes: Vec<u8>) -> ProbeBody {
    let raw_len = bytes.len();
    match String::from_utf8(bytes) {
        Ok(text) => ProbeBody {
            text,
            bytes: raw_len,
            utf8_valid: true,
        },
        Err(error) => ProbeBody {
            text: String::from_utf8_lossy(error.as_bytes()).into_owned(),
            bytes: raw_len,
            utf8_valid: false,
        },
    }
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
