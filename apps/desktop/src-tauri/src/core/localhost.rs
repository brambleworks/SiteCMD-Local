//! Local environment helpers and test-only loopback transport exceptions.

pub use sitecmd_protocol::network_class::is_strict_localhost;

/// Whether an `http://` loopback endpoint may stand in for an HTTPS origin,
/// which is what lets a wire test point a service client at a local double.
/// Only a test build has an arm that can answer true, so a release binary
/// cannot honor the flag whatever a caller passes it.
#[cfg(test)]
pub fn loopback_endpoint_allowed(allowed_by_caller: bool, url: &url::Url) -> bool {
    allowed_by_caller && url.scheme() == "http" && is_strict_localhost(url)
}

#[cfg(not(test))]
pub fn loopback_endpoint_allowed(_allowed_by_caller: bool, _url: &url::Url) -> bool {
    false
}
