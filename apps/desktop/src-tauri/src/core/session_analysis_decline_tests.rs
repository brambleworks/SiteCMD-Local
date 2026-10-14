//! Site-level session results preserve findings and standalone declines.

use super::{analyze_session, CheckStatus, SessionSitemap};
use crate::core::page_signals::{extract_page_signals, extract_page_signals_with_headers};

#[test]
fn a_desktop_partial_sitemap_finding_keeps_only_its_warn() {
    // A sitemap decline beside a finding must not repeat the finding's existing incomplete-read note.
    let pages = [
        ("https://example.com/listed", "noindex"),
        ("https://example.com/unread", "noindex"),
        ("https://example.com/known", "index"),
    ]
    .map(|(url, directive)| {
        let url = url::Url::parse(url).expect("page URL");
        extract_page_signals(
            &url,
            &format!("<meta name=\"robots\" content=\"{directive}\">"),
        )
    });
    let urls = [pages[0].url.clone()];
    let results = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: Some("unread sitemap document"),
        }),
    );
    let rows: Vec<_> = results
        .iter()
        .filter(|row| row.check_id == "seo.noindex_in_sitemap")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, CheckStatus::Warn);
    assert_eq!(rows[0].title, "1 noindex page is listed in the sitemap");
    assert!(rows[0].description.contains("SiteCMD read only part of this site's sitemap (unread sitemap document), so there may be more."));
    let evidence = rows[0].raw_data.as_ref().expect("sitemap evidence");
    assert_eq!(evidence["pages"], serde_json::json!([pages[0].url]));
    assert_eq!(evidence["sitemap_url_set_complete"], false);
}

#[test]
fn a_desktop_comparison_without_a_finding_keeps_its_decline() {
    // An incomplete sitemap must keep its standalone decline when no contradiction is established.
    let pages = ["https://example.com/a", "https://example.com/b"]
        .map(|url| extract_page_signals(&url::Url::parse(url).expect("page URL"), "<html></html>"));
    let urls = [pages[0].url.clone()];
    let results = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: Some("unread sitemap document"),
        }),
    );
    let rows: Vec<_> = results
        .iter()
        .filter(|row| row.check_id == "seo.noindex_in_sitemap")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, CheckStatus::Skipped);
    assert_eq!(rows[0].description, "SiteCMD read only part of this site's sitemap (unread sitemap document), so a noindex page listed in the part it did not read would not have been seen.");
}

#[test]
fn desktop_header_lines_keep_noindex_known() {
    // Separate response lines must keep a crawler's scope from making noindex unknown.
    let url = url::Url::parse("https://example.com/a").expect("page URL");
    for (values, expected) in [
        (&["bingbot: noarchive, noindex"][..], false),
        (&["bingbot: noarchive", "noindex"][..], true),
        (&["googlebot: noarchive, noindex"][..], true),
    ] {
        let mut headers = reqwest::header::HeaderMap::new();
        for value in values {
            headers.append(
                "x-robots-tag",
                reqwest::header::HeaderValue::from_str(value).expect("header value"),
            );
        }
        let page = extract_page_signals_with_headers(&url, &url, 200, "<html></html>", &headers);
        assert_eq!(page.noindex, Some(expected), "{values:?}");
    }
}
