//! Runtime-neutral page facts for synchronous checks.
//! `PageContext` excludes transport and cache state so native and hosted verdicts match.

use crate::time::UtcTimestamp;

/// Fetched page data plus scan posture for one evaluated page.
pub struct PageContext {
    /// The URL the fetch FINISHED on, after every redirect, not the URL that
    /// was requested. Verdicts read the scheme as evidence about the response
    /// they are grading: `security.https_enforcement` treats an `http` value
    /// as direct proof that the page was delivered over cleartext and never
    /// redirected to HTTPS, and fails the site for it. A caller that supplies
    /// the requested URL instead turns every correctly redirecting site into a
    /// high-severity false positive.
    pub url: url::Url,
    pub response_headers: http::HeaderMap,
    pub status_code: u16,
    pub body: String,
    pub is_localhost: bool,
    /// Strict loopback status used for TLS bypass decisions.
    pub is_strict_localhost: bool,
    pub http_version: Option<String>,
    /// Lazily cached lowercase body shared by case-insensitive checks.
    #[doc(hidden)]
    pub body_lower_cache: std::sync::OnceLock<String>,
    /// Injected clock for all time-dependent verdicts. Checks must not read an
    /// ambient clock because hosted evaluation uses the scan event time.
    pub evaluation_time: UtcTimestamp,
}

impl PageContext {
    /// Cached ASCII-lowercase body with byte offsets preserved.
    pub fn body_lower(&self) -> &str {
        self.body_lower_cache
            .get_or_init(|| self.body.to_ascii_lowercase())
    }
}

/// A page URL's origin serialized with its explicit port when one is set -
/// the base every origin-scoped probe URL (robots.txt, sitemap candidates,
/// llms.txt) is built from.
pub fn origin_with_port(url: &url::Url) -> String {
    url.origin().ascii_serialization()
}
