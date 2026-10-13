//! Ephemeral per-page signals consumed by cross-page session analysis.
//! They are skipped during serialization and never reach storage or the frontend.

pub use sitecmd_engine::session::signals::{
    extract_page_signals, extract_page_signals_with_headers, normalize_page_url, PageSignals,
    MAX_INTERNAL_LINKS_PER_PAGE,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(url: &str, body: &str) -> PageSignals {
        extract_page_signals(&url::Url::parse(url).unwrap(), body)
    }

    fn signals_with_headers(
        url: &str,
        body: &str,
        headers: &reqwest::header::HeaderMap,
    ) -> PageSignals {
        let parsed = url::Url::parse(url).unwrap();
        extract_page_signals_with_headers(&parsed, &parsed, 200, body, headers)
    }

    #[test]
    fn extracts_title_description_h1() {
        let s = signals(
            "https://example.com/page",
            r#"<title>  My   Page </title>
               <meta name="description" content="A description.">
               <h1>Main <em>Heading</em></h1>"#,
        );
        assert_eq!(s.title.as_deref(), Some("My Page"));
        assert_eq!(s.meta_description.as_deref(), Some("A description."));
        assert_eq!(s.h1.as_deref(), Some("Main Heading"));
    }

    #[test]
    fn detects_noindex_and_canonical() {
        let s = signals(
            "https://example.com/a/",
            r#"<meta name="robots" content="noindex, nofollow">
               <link rel="canonical" href="/b/">"#,
        );
        assert!(s.noindex);
        assert_eq!(s.canonical.as_deref(), Some("https://example.com/b"));
    }

    #[test]
    fn collects_same_origin_links_only_normalized() {
        let s = signals(
            "https://example.com/",
            r#"<a href="/about/">About</a>
               <a href="/about/#team">Team</a>
               <a href="https://other.com/x">External</a>
               <a href="mailto:hi@example.com">Mail</a>"#,
        );
        assert_eq!(s.internal_links, vec!["https://example.com/about"]);
    }

    #[test]
    fn same_site_scheme_and_www_twins_are_links_to_this_site() {
        let s = signals(
            "https://example.com/",
            r#"<a href="http://example.com/http-twin">h</a>
               <a href="https://www.example.com/www-twin">w</a>
               <a href="https://example.com/plain">p</a>
               <a href="https://other.com/x">o</a>
               <a href="https://example.com.evil.test/lookalike">e</a>
               <a href="https://notexample.com/x">n</a>"#,
        );
        assert_eq!(
            s.internal_links,
            vec![
                "https://example.com/plain",
                "https://example.com/http-twin",
                "https://example.com/www-twin",
            ]
        );
    }

    #[test]
    fn a_site_scanned_on_its_www_host_folds_the_bare_host_the_same_way() {
        let s = signals(
            "https://www.example.com/",
            r#"<a href="https://example.com/bare">b</a>"#,
        );
        assert_eq!(s.internal_links, vec!["https://www.example.com/bare"]);
    }

    #[test]
    fn an_explicit_port_still_separates_sites() {
        let s = signals(
            "https://example.com:8443/",
            r#"<a href="https://example.com:9443/other-port">o</a>
               <a href="http://example.com:8443/same-port">s</a>"#,
        );
        assert_eq!(s.internal_links, vec!["https://example.com:8443/same-port"]);
    }

    /// The per-page cap bounds session memory, and a folded twin must not spend
    /// it: a twin taking the last slot would drop a link written on the scanned
    /// origin and could invent the orphan claim the fold exists to remove.
    #[test]
    fn a_folded_twin_never_takes_the_slot_of_a_link_on_the_scanned_origin() {
        let mut body = String::from(r#"<a href="http://example.com/twin-first">t</a>"#);
        for i in 0..MAX_INTERNAL_LINKS_PER_PAGE {
            body.push_str(&format!(r#"<a href="/page-{i}">p</a>"#));
        }
        let s = signals("https://example.com/", &body);

        assert_eq!(s.internal_links.len(), MAX_INTERNAL_LINKS_PER_PAGE);
        assert!(
            !s.internal_links
                .contains(&"https://example.com/twin-first".to_string()),
            "the twin displaced a link written on the scanned origin"
        );
        assert!(s.internal_links.contains(&format!(
            "https://example.com/page-{}",
            MAX_INTERNAL_LINKS_PER_PAGE - 1
        )));
        assert!(s.internal_links_truncated);
    }

    #[test]
    fn extracts_hreflang_pairs() {
        let s = signals(
            "https://example.com/",
            r#"<link rel="alternate" hreflang="de" href="/de/">
               <link rel="alternate" hreflang="en" href="https://example.com/">"#,
        );
        assert_eq!(s.hreflang.len(), 2);
        assert_eq!(s.hreflang[0].0, "de");
        assert_eq!(s.hreflang[0].1, "https://example.com/de");
    }

    #[test]
    fn supports_unquoted_attributes_and_ignores_markup_examples() {
        let s = signals(
            "https://example.com/",
            r#"<script>const sample = '<a href=/fake>fake</a>';</script>
               <!-- <link rel=canonical href=/wrong> -->
               <link rel=canonical href=/real>
               <a href=/about>About</a>"#,
        );
        assert_eq!(s.canonical.as_deref(), Some("https://example.com/real"));
        assert_eq!(s.internal_links, vec!["https://example.com/about"]);
    }

    #[test]
    fn applies_the_document_base_to_resolved_page_relationships() {
        let s = signals(
            "https://example.com/docs/page",
            r#"<base href="https://example.com/locales/">
               <link rel=canonical href=en>
               <link rel=alternate hreflang=de href=de>
               <a href=help>Help</a>"#,
        );
        assert_eq!(
            s.canonical.as_deref(),
            Some("https://example.com/locales/en")
        );
        assert_eq!(s.hreflang[0].1, "https://example.com/locales/de");
        assert_eq!(s.internal_links, vec!["https://example.com/locales/help"]);
    }

    #[test]
    fn noindex_matching_uses_directive_tokens_and_response_headers() {
        let false_positive = signals(
            "https://example.com/",
            r#"<meta name=robots content=noindexif>"#,
        );
        assert!(!false_positive.noindex);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::HeaderName::from_static("x-robots-tag"),
            reqwest::header::HeaderValue::from_static("googlebot: noindex, nofollow"),
        );
        let from_header = signals_with_headers("https://example.com/", "<html></html>", &headers);
        assert!(from_header.noindex);

        let mut news_headers = reqwest::header::HeaderMap::new();
        news_headers.insert(
            reqwest::header::HeaderName::from_static("x-robots-tag"),
            reqwest::header::HeaderValue::from_static("googlebot-news: noindex"),
        );
        let news_only =
            signals_with_headers("https://example.com/", "<html></html>", &news_headers);
        assert!(!news_only.noindex);
    }

    #[test]
    fn an_inline_svg_title_is_not_the_document_title() {
        let icon_only = signals(
            "https://example.com/x",
            r#"<html><head></head><body>
               <svg viewBox="0 0 24 24"><title>Menu icon</title></svg>
               <h1>Page</h1></body></html>"#,
        );
        assert_eq!(icon_only.title, None);

        let real_title = signals(
            "https://example.com/y",
            r#"<html><head><title>Real Title</title></head><body>
               <svg><title>Menu icon</title></svg></body></html>"#,
        );
        assert_eq!(real_title.title.as_deref(), Some("Real Title"));
    }

    #[test]
    fn a_response_carries_its_status_and_the_url_that_was_requested() {
        let signals = extract_page_signals_with_headers(
            &url::Url::parse("https://example.com/new").unwrap(),
            &url::Url::parse("https://example.com/old/").unwrap(),
            404,
            "<html><head><title>Not found</title></head></html>",
            &reqwest::header::HeaderMap::new(),
        );

        assert_eq!(signals.url, "https://example.com/new");
        assert_eq!(signals.requested_url, "https://example.com/old");
        assert_eq!(signals.status_code, 404);
    }

    #[test]
    fn a_page_fetched_without_a_redirect_reports_itself_as_the_requested_url() {
        let signals = signals("https://example.com/a/", "<html></html>");

        assert_eq!(signals.requested_url, signals.url);
        assert_eq!(signals.status_code, 200);
    }

    #[test]
    fn normalize_treats_trailing_slash_and_fragment_as_same_page() {
        assert_eq!(
            normalize_page_url("https://example.com/a/"),
            normalize_page_url("https://example.com/a#x")
        );
        assert_eq!(
            normalize_page_url("https://example.com/"),
            "https://example.com/"
        );
    }
}
