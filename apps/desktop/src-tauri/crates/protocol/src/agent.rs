//! Shared scanner identity for desktop, CLI, and hosted requests.

/// Scanner documentation URL included in the User-Agent.
pub const SCANNER_DOCS_URL: &str = "https://sitecmd.com/scanner";

/// Build the shared scanner User-Agent for a runtime release.
pub fn user_agent(version: &str) -> String {
    format!("SiteCMD/{version} (+{SCANNER_DOCS_URL})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_agent_names_the_product_version_and_its_documentation() {
        assert_eq!(
            user_agent("1.5.4"),
            "SiteCMD/1.5.4 (+https://sitecmd.com/scanner)"
        );
    }

    #[test]
    fn the_documentation_url_is_a_stable_https_page() {
        // Operators paste this out of their logs. It must be fetchable as-is,
        // not a redirect target or a scheme-relative fragment.
        assert!(SCANNER_DOCS_URL.starts_with("https://"));
        assert!(!SCANNER_DOCS_URL.ends_with('/'));
    }
}
