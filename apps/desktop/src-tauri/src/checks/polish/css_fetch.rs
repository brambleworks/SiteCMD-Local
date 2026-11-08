//! Bounded stylesheet fetcher with explicit discovery and fetch coverage.

use super::{css_signal_counts, extract_stylesheet_urls, CssSignalCounts, STYLESHEET_SAMPLE_LIMIT};
use crate::constants::CHECK_PROBE_TIMEOUT;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StylesheetFetchResult {
    pub counts: CssSignalCounts,
    pub stylesheets_discovered: usize,
    pub stylesheets_fetched: usize,
}

impl StylesheetFetchResult {
    pub fn coverage_complete(&self) -> bool {
        self.stylesheets_fetched == self.stylesheets_discovered
    }
}

/// Fetch bounded linked CSS with explicit discovery and success counts.
/// `origin` must be the scan target's, so a stylesheet reaches no further than
/// the page the person asked for and a public page cannot steer a subresource
/// request into a private network.
pub async fn fetch_stylesheets(
    html: &str,
    base_url: &url::Url,
    client: &reqwest::Client,
    origin: crate::network_policy::LocalOrigin,
) -> StylesheetFetchResult {
    fetch_stylesheets_with(html, base_url, origin, |url| async move {
        fetch_one_stylesheet(&url, client).await
    })
    .await
}

/// Apply discovery and subresource policy around an injected fetcher.
async fn fetch_stylesheets_with<F, Fut>(
    html: &str,
    base_url: &url::Url,
    origin: crate::network_policy::LocalOrigin,
    fetch_one: F,
) -> StylesheetFetchResult
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    let urls = extract_stylesheet_urls(html, base_url);
    let stylesheets_discovered = urls.len();
    let fetch_one = &fetch_one;

    // The stylesheets are independent; fetch them concurrently so the worst
    // case is one probe timeout, not the sum of all of them. join_all
    // preserves input order while each document is counted independently.
    let fetches = urls
        .iter()
        .take(STYLESHEET_SAMPLE_LIMIT)
        .map(|url| async move {
            let safe_url = crate::log_sanitizer::log_safe_url_target(url.as_str());
            // The scanned page controls this href; refuse targets that would let it
            // pivot our machine onto internal/loopback endpoints via SSRF.
            match url::Url::parse(url) {
                Ok(parsed) => {
                    if let Err(reason) = crate::network_policy::validate_page_subresource_target(
                        &parsed,
                        origin.subordinate_policy(),
                    ) {
                        tracing::warn!("Skipping disallowed CSS target {}: {}", safe_url, reason);
                        return None;
                    }
                }
                Err(e) => {
                    tracing::warn!("Skipping unparseable CSS target {}: {}", safe_url, e);
                    return None;
                }
            }
            fetch_one(url.clone()).await
        });
    let css_parts = futures_util::future::join_all(fetches).await;
    let stylesheets_fetched = css_parts.iter().filter(|part| part.is_some()).count();
    let counts = css_parts
        .into_iter()
        .flatten()
        .fold(CssSignalCounts::default(), |sum, text| {
            sum + css_signal_counts(&text, crate::checks::polish::CssTextKind::Stylesheet)
        });

    StylesheetFetchResult {
        counts,
        stylesheets_discovered,
        stylesheets_fetched,
    }
}

/// Fetch one stylesheet body within the existing size and time limits.
async fn fetch_one_stylesheet(url: &str, client: &reqwest::Client) -> Option<String> {
    let safe_url = crate::log_sanitizer::log_safe_url_target(url);
    match tokio::time::timeout(CHECK_PROBE_TIMEOUT, client.get(url).send()).await {
        Ok(Ok(resp)) if resp.status().is_success() => {
            match crate::http_client::read_text_limited(
                resp,
                crate::constants::MAX_STYLESHEET_BODY_SIZE,
                CHECK_PROBE_TIMEOUT,
            )
            .await
            {
                Ok(text) => {
                    tracing::debug!("Fetched CSS ({} bytes): {}", text.len(), safe_url);
                    Some(text)
                }
                Err(e) => {
                    tracing::warn!("Failed to read CSS body from {}: {}", safe_url, e);
                    None
                }
            }
        }
        Ok(Ok(resp)) => {
            tracing::warn!("CSS fetch returned {} for {}", resp.status(), safe_url);
            None
        }
        Ok(Err(e)) => {
            tracing::warn!("CSS fetch failed for {}: {}", safe_url, e);
            None
        }
        Err(_) => {
            tracing::warn!("CSS fetch timed out for {}", safe_url);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> url::Url {
        url::Url::parse("https://example.com/page").unwrap()
    }

    #[test]
    fn extracts_absolute_stylesheet_urls() {
        let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css">"#;
        let urls = extract_stylesheet_urls(html, &base());
        assert_eq!(urls, vec!["https://cdn.example.com/style.css"]);
    }

    #[test]
    fn extracts_relative_stylesheet_urls() {
        let html = r#"<link rel="stylesheet" href="/css/main.css">"#;
        let urls = extract_stylesheet_urls(html, &base());
        assert_eq!(urls, vec!["https://example.com/css/main.css"]);
    }

    #[test]
    fn handles_href_before_rel() {
        let html = r#"<link href="/style.css" rel="stylesheet">"#;
        let urls = extract_stylesheet_urls(html, &base());
        assert_eq!(urls, vec!["https://example.com/style.css"]);
    }

    #[test]
    fn decodes_html_entities_in_stylesheet_urls() {
        let html =
            r#"<link rel="stylesheet" href="/css/main.css?delta=1&amp;theme=site&amp;include=a">"#;
        let urls = extract_stylesheet_urls(html, &base());
        assert_eq!(
            urls,
            vec!["https://example.com/css/main.css?delta=1&theme=site&include=a"]
        );
    }

    #[test]
    fn extraction_returns_every_stylesheet_not_a_capped_prefix() {
        let html: String = (0..STYLESHEET_SAMPLE_LIMIT + 2)
            .map(|i| format!(r#"<link rel="stylesheet" href="/s{i}.css">"#))
            .collect();
        let urls = extract_stylesheet_urls(&html, &base());
        assert_eq!(urls.len(), STYLESHEET_SAMPLE_LIMIT + 2);
    }

    #[tokio::test]
    async fn pages_linking_more_stylesheets_than_the_cap_report_incomplete_coverage() {
        // Loopback rejection keeps this discovered-count test deterministic.
        let html: String = (0..STYLESHEET_SAMPLE_LIMIT + 1)
            .map(|i| format!(r#"<link rel="stylesheet" href="http://127.0.0.1/s{i}.css">"#))
            .collect();
        let result = fetch_stylesheets(
            &html,
            &base(),
            crate::http_client::client(),
            crate::network_policy::LocalOrigin::Public,
        )
        .await;
        assert_eq!(result.stylesheets_discovered, STYLESHEET_SAMPLE_LIMIT + 1);
        assert!(
            !result.coverage_complete(),
            "stylesheets past the fetch cap were not inspected; coverage must read incomplete"
        );
    }

    #[test]
    fn ignores_non_stylesheet_links() {
        let html = r#"
            <link rel="icon" href="/favicon.ico">
            <link rel="preload" href="/font.woff2" as="font">
            <link rel="stylesheet" href="/style.css">
        "#;
        let urls = extract_stylesheet_urls(html, &base());
        assert_eq!(urls, vec!["https://example.com/style.css"]);
    }

    #[tokio::test]
    async fn skips_ssrf_stylesheet_targets_without_fetching() {
        let html = r#"<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
            <link rel="stylesheet" href="http://127.0.0.1:11434/style.css">"#;
        let css = fetch_stylesheets(
            html,
            &base(),
            crate::http_client::client(),
            crate::network_policy::LocalOrigin::Public,
        )
        .await;
        assert_eq!(
            css.counts,
            CssSignalCounts::default(),
            "internal SSRF targets must be skipped, not fetched"
        );
        assert_eq!(css.stylesheets_discovered, 2);
        assert_eq!(css.stylesheets_fetched, 0);
        assert!(!css.coverage_complete());
    }
}

#[cfg(test)]
#[path = "css_fetch_parity_tests.rs"]
mod parity_tests;
