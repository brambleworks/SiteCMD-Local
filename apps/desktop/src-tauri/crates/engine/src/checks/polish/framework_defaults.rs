//! Polish signals for uncustomized framework and deployment defaults.

use super::word_lists::{lowercase_values, word_lists};
use super::{PolishContext, PolishResult, SignalCategory, SignalWeight};
use regex::Regex;
use std::sync::LazyLock;

const CATEGORY: SignalCategory = SignalCategory::FrameworkDefaults;

static SCAFFOLD_MARKERS: LazyLock<Vec<(&str, String)>> =
    LazyLock::new(|| lowercase_values(&word_lists().scaffold_markers));
static HOSTING_SUFFIXES: LazyLock<Vec<(&str, String)>> =
    LazyLock::new(|| lowercase_values(&word_lists().hosting_suffixes));

/// Default root div with nothing else
static BARE_ROOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    let ids = word_lists()
        .scaffold_root_ids
        .iter()
        .map(|entry| regex::escape(&entry.value))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!(
        r#"(?i)<div\s+id\s*=\s*["'](?:{ids})["']\s*>\s*</div>"#
    ))
    .expect("recorded bare root regex")
});

/// Flag known shared-hosting subdomains for review (LowMedium, 5).
pub fn default_deployment_subdomain(ctx: &PolishContext) -> PolishResult {
    let host = ctx.url.host_str().unwrap_or("");

    for (subdomain, lower) in HOSTING_SUFFIXES.iter() {
        if host.ends_with(lower) {
            return PolishResult::fired(
                "default-deployment-subdomain",
                "Hosting on Shared Platform Subdomain",
                SignalWeight::LowMedium,
                CATEGORY,
                format!(
                    "Running on the platform's shared subdomain: {}. Fine if intentional (project pages, internal tools); a custom domain reads as launched to visitors.",
                    host
                ),
                serde_json::json!({
                    "hostname": host,
                    "platform": subdomain.trim_start_matches('.'),
                }),
            );
        }
    }

    PolishResult::clear(
        "default-deployment-subdomain",
        "Hosting on Shared Platform Subdomain",
        SignalWeight::LowMedium,
        CATEGORY,
    )
}

/// Flag two or more framework-boilerplate markers (Low, 3).
pub fn boilerplate_html(ctx: &PolishContext) -> PolishResult {
    let lower = ctx.html_lower();
    let mut markers: Vec<String> = SCAFFOLD_MARKERS
        .iter()
        .filter(|(_, marker)| lower.contains(marker))
        .map(|(original, _)| (*original).to_string())
        .collect();
    if BARE_ROOT_RE.is_match(&ctx.html) {
        markers.push("Empty root div (SPA scaffold)".to_string());
    }

    // Default viewport with no other meta tags
    if lower.contains(r#"content="width=device-width, initial-scale=1.0""#)
        && !lower.contains("og:title")
        && !lower.contains("description")
    {
        markers.push("Minimal viewport-only meta tags".to_string());
    }

    if markers.len() >= 2 {
        PolishResult::fired(
            "boilerplate-html",
            "Default Scaffold Markers Present",
            SignalWeight::Low,
            CATEGORY,
            format!("{} scaffold markers: {}", markers.len(), markers.join(", ")),
            serde_json::json!({ "markers": markers }),
        )
    } else {
        PolishResult::clear(
            "boilerplate-html",
            "Default Scaffold Markers Present",
            SignalWeight::Low,
            CATEGORY,
        )
    }
}

/// Detect framework-specific default error-page markers.
pub fn default_error_page(ctx: &PolishContext) -> PolishResult {
    for entry in &word_lists().error_page_markers {
        if ctx.html.contains(&entry.value) {
            return PolishResult::fired(
                "default-error-page",
                "Default Error Page",
                SignalWeight::Low,
                CATEGORY,
                "Framework default error page text detected on current page".to_string(),
                serde_json::json!({ "marker": entry.value }),
            );
        }
    }

    PolishResult::clear(
        "default-error-page",
        "Default Error Page",
        SignalWeight::Low,
        CATEGORY,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_url(html: &str, url: &str) -> PolishContext<'static> {
        PolishContext::new(
            url::Url::parse(url).unwrap(),
            html.to_string().into(),
            Default::default(),
        )
    }

    fn ctx(html: &str) -> PolishContext<'static> {
        ctx_url(html, "https://example.com")
    }

    #[test]
    fn subdomain_fires_with_first_recorded_suffix() {
        let result = default_deployment_subdomain(&ctx_url(
            "",
            &format!("https://site{}", word_lists().hosting_suffixes[0].value),
        ));
        assert!(
            result.fired,
            "Should fire on the first recorded hosting suffix"
        );
    }

    #[test]
    fn subdomain_fires_with_second_recorded_suffix() {
        let result = default_deployment_subdomain(&ctx_url(
            "",
            &format!("https://site{}", word_lists().hosting_suffixes[1].value),
        ));
        assert!(
            result.fired,
            "Should fire on the second recorded hosting suffix"
        );
    }

    #[test]
    fn subdomain_clear_with_custom_domain() {
        let result = default_deployment_subdomain(&ctx_url("", "https://myproduct.com"));
        assert!(!result.fired, "Should not fire with custom domain");
    }

    #[test]
    fn boilerplate_fires_with_recorded_markers() {
        // Two recorded starter messages must retain the boilerplate finding.
        let markers = &word_lists().scaffold_markers;
        let html = format!("<p>{}</p><p>{}</p>", markers[0].value, markers[1].value);
        let result = boilerplate_html(&ctx(&html));
        assert!(
            result.fired,
            "Should fire with recorded boilerplate markers"
        );
    }

    #[test]
    fn boilerplate_clear_with_custom_html() {
        let html = r#"<html><head><meta name="description" content="My custom app"><meta property="og:title" content="Test"></head>
                       <body><div id="root"><main>Content</main></div></body></html>"#;
        let result = boilerplate_html(&ctx(html));
        assert!(!result.fired, "Should not fire with customized HTML");
    }

    #[test]
    fn error_page_fires_with_recorded_framework_marker() {
        // A recorded framework error marker must remain detectable.
        let html = format!(
            "<html><body><h2>{}</h2></body></html>",
            word_lists().error_page_markers[0].value
        );
        let result = default_error_page(&ctx(&html));
        assert!(
            result.fired,
            "Should fire with the recorded framework error marker"
        );
    }

    #[test]
    fn error_page_clear_with_help_text_mentioning_page_not_found() {
        let html = r#"<html><body>
            <h1>FAQ</h1>
            <p>If you get a 404 - page not found error, please contact support.</p>
            <p>The page you were looking for doesn't exist? Check our sitemap.</p>
        </body></html>"#;
        let result = default_error_page(&ctx(html));
        assert!(
            !result.fired,
            "Help text mentioning 404 / page not found must not fire"
        );
    }

    #[test]
    fn error_page_clear_with_normal_page() {
        let html = "<html><body><h1>Welcome</h1><p>Content here.</p></body></html>";
        let result = default_error_page(&ctx(html));
        assert!(!result.fired, "Should not fire with normal page content");
    }
}
