//! Discovery responses and the gate for storing unchanged routes.

use serde::{Deserialize, Serialize};

use crate::log_sanitizer::{contains_email, ISSUE_EVIDENCE_URL_MAX_CHARS};

/// The routes to add, canonical paths in priority order, or `None` when the
/// entry route's document did not answer with a success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub routes: Option<Vec<String>>,
}

/// Storable sitemap paths in document order, and whether the read fit its bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitemapRoutes {
    pub routes: Option<Vec<String>>,
    pub complete: bool,
}

/// Whether a connected service may store this route as it is. Each gate refuses
/// a route it would have to change, and a refused route is left out rather
/// than altered, because an altered route is a page the site does not serve: a
/// search path, a route the evidence rules would redact after decoding,
/// an address past the length bound, or a route holding an exposed-key pattern,
/// personal data or path parameters; only the path is inspected.
pub fn storable(
    route: &str,
    matches_private_pattern: fn(&str) -> bool,
    safe_page_url: fn(&str) -> String,
    contains_personal_data: fn(&str) -> bool,
) -> bool {
    // Only the path affects admission.
    let origin = "https://example.com";
    let address = format!("{origin}{route}");
    let Ok(expected) = url::Url::parse(&address) else {
        return false;
    };
    !is_search_path(route)
        && !route.contains(';')
        && !contains_email(route)
        && address.chars().count() <= ISSUE_EVIDENCE_URL_MAX_CHARS
        && !contains_personal_data(route)
        && safe_page_url(&address) == expected.as_str()
        && !matches_private_pattern(route)
}

/// Whether a route's first segment is `search`.
pub fn is_search_path(route: &str) -> bool {
    route
        .trim_start_matches('/')
        .split('/')
        .next()
        .is_some_and(|first| first.eq_ignore_ascii_case("search"))
}
