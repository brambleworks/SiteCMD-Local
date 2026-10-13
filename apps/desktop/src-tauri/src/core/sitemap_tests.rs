use super::*;

/// The truncation decision, which no network test can reach: the caps are
/// 50 child sitemaps and 5000 URLs, so a fixture large enough to hit them
/// would be a five-thousand-entry document. Deciding it in a pure function
/// is what makes "SiteCMD read only part of this sitemap" testable at all.
#[test]
fn a_sitemap_read_within_its_caps_is_not_partial() {
    assert_eq!(partial_reason(SitemapBound::Urls, MAX_URLS, MAX_URLS), None);
    assert_eq!(
        partial_reason(
            SitemapBound::ChildSitemaps,
            MAX_CHILD_SITEMAPS,
            MAX_CHILD_SITEMAPS
        ),
        None
    );
    assert_eq!(partial_reason(SitemapBound::Urls, 0, MAX_URLS), None);
}

#[test]
fn a_truncated_sitemap_read_names_the_bound_that_cut_it() {
    assert_eq!(
        partial_reason(SitemapBound::Urls, 9000, MAX_URLS).as_deref(),
        Some("the sitemap lists 9000 URLs and SiteCMD read the first 5000")
    );
    assert_eq!(
        partial_reason(SitemapBound::ChildSitemaps, 120, MAX_CHILD_SITEMAPS).as_deref(),
        Some("the sitemap index lists 120 child sitemaps and SiteCMD read the first 50")
    );
}

/// The index walk stops as soon as it holds the cap, so hitting it exactly
/// still leaves children unread. The other two bounds truncate a document
/// already in hand, so reaching the cap exactly reads all of it.
#[test]
fn an_index_walk_that_stopped_on_the_url_cap_is_partial_at_the_cap_itself() {
    assert_eq!(
        partial_reason(SitemapBound::IndexUrls, MAX_URLS, MAX_URLS).as_deref(),
        Some("the sitemap index yielded more than 5000 URLs and SiteCMD read the first 5000")
    );
    assert_eq!(
        partial_reason(SitemapBound::IndexUrls, MAX_URLS - 1, MAX_URLS),
        None
    );
}

#[test]
fn a_site_declaring_only_the_sitemap_that_was_read_is_not_partial() {
    let declared = vec!["https://example.com/sitemap.xml".to_string()];
    assert_eq!(
        unread_sitemaps_reason(&declared, Some("https://example.com/sitemap.xml")),
        None
    );
    assert_eq!(
        unread_sitemaps_reason(&[], Some("https://example.com/sitemap.xml")),
        None
    );
}

/// robots.txt directives are raw text. A site scanned at its www host
/// declares its sitemap on the apex, a site on https writes http, a
/// generator appends a trailing slash, and a hand-edited robots.txt lists
/// the same URL twice. Comparing those as strings marks a whole sitemap
/// partial and turns a real Pass into a Skipped on ordinary sites.
#[test]
fn the_same_sitemap_declared_another_way_is_not_a_further_sitemap() {
    let read = Some("https://www.example.com/sitemap.xml");
    for declared in [
        vec!["https://example.com/sitemap.xml".to_string()],
        vec!["http://www.example.com/sitemap.xml".to_string()],
        vec!["https://www.example.com/sitemap.xml/".to_string()],
        vec!["https://WWW.Example.com/sitemap.xml".to_string()],
        vec![
            "https://www.example.com/sitemap.xml".to_string(),
            "https://example.com/sitemap.xml".to_string(),
        ],
    ] {
        assert_eq!(
            unread_sitemaps_reason(&declared, read),
            None,
            "{declared:?} is the sitemap that was read, written another way"
        );
    }
}

/// Two references to one unread sitemap are one unread sitemap.
#[test]
fn a_sitemap_declared_twice_counts_once() {
    let declared = vec![
        "https://example.com/sitemap.xml".to_string(),
        "https://example.com/sitemap-news.xml".to_string(),
        "https://www.example.com/sitemap-news.xml".to_string(),
    ];
    assert_eq!(
        unread_sitemaps_reason(&declared, Some("https://example.com/sitemap.xml")).as_deref(),
        Some("robots.txt declares 1 further sitemap that was not read")
    );
}

#[test]
fn a_site_declaring_sitemaps_beyond_the_one_read_is_partial() {
    let declared = vec![
        "https://example.com/sitemap.xml".to_string(),
        "https://example.com/sitemap-news.xml".to_string(),
        "https://example.com/sitemap-images.xml".to_string(),
    ];
    assert_eq!(
        unread_sitemaps_reason(&declared, Some("https://example.com/sitemap.xml")).as_deref(),
        Some("robots.txt declares 2 further sitemaps that were not read")
    );
    let one_more = vec![
        "https://example.com/sitemap.xml".to_string(),
        "https://example.com/sitemap-news.xml".to_string(),
    ];
    assert_eq!(
        unread_sitemaps_reason(&one_more, Some("https://example.com/sitemap.xml")).as_deref(),
        Some("robots.txt declares 1 further sitemap that was not read")
    );
}

/// A set can be short for more than one reason at once, and a caller that
/// overwrote instead of appending would report only the last one found.
#[test]
fn every_reason_a_set_is_partial_is_kept() {
    let mut result = SitemapResult {
        status: SitemapStatus::Found,
        urls: vec!["https://example.com/a".to_string()],
        source_url: Some("https://example.com/sitemap.xml".to_string()),
        partial_because: None,
    };
    note_partial(&mut result, None);
    assert_eq!(result.partial_because, None);

    note_partial(
        &mut result,
        partial_reason(SitemapBound::Urls, 9000, MAX_URLS),
    );
    note_partial(
        &mut result,
        unread_sitemaps_reason(
            &["https://example.com/sitemap-news.xml".to_string()],
            Some("https://example.com/sitemap.xml"),
        ),
    );
    assert_eq!(
        result.partial_because.as_deref(),
        Some(
            "the sitemap lists 9000 URLs and SiteCMD read the first 5000; robots.txt declares \
             1 further sitemap that was not read"
        )
    );
}

/// The pure helpers above prove the decision; this proves discovery still
/// asks them. Nothing observable changes when a `partial_reason` call is
/// dropped from a fetch path, so no behavioral test would notice a set
/// silently going back to reporting a clean Pass over a truncated read.
#[test]
fn every_truncation_path_records_why_the_set_is_partial() {
    const SOURCE: &str = include_str!("sitemap.rs");
    let code = SOURCE
        .split_once("#[cfg(test)]")
        .expect("sitemap.rs must have a test module")
        .0;

    for bound in [
        "SitemapBound::Urls",
        "SitemapBound::ChildSitemaps",
        "SitemapBound::IndexUrls",
    ] {
        assert!(
            code.contains(&format!("partial_reason({bound}")),
            "the {bound} truncation path must record why the set is partial"
        );
    }
    assert!(
        code.contains("note_partial(&mut result, url_cap)"),
        "the sitemap index walk must hand its URL-cap reason to the result it returns; \
         computing the reason and dropping it leaves a truncated read looking whole"
    );
    assert_eq!(
        code.matches("unread_sitemaps_reason(&declared").count(),
        2,
        "both discovery paths, the conventional candidate and the robots.txt directive, must \
         compare what was read against every sitemap the site declares"
    );
}

/// Reject private and metadata addresses supplied through robots.txt.
#[tokio::test]
async fn validate_sitemap_target_rejects_metadata_and_private_ips() {
    // Cloud metadata IP (the canonical SSRF target).
    assert!(
        validate_sitemap_target(
            "http://169.254.169.254/",
            crate::network_policy::LocalOrigin::Public
        )
        .await
        .is_err(),
        "169.254.169.254 must be refused as a sitemap URL when scan target is not loopback"
    );

    // RFC1918 ranges.
    assert!(validate_sitemap_target(
        "http://10.0.0.1/sitemap.xml",
        crate::network_policy::LocalOrigin::Public
    )
    .await
    .is_err());
    assert!(validate_sitemap_target(
        "http://192.168.1.10/sitemap.xml",
        crate::network_policy::LocalOrigin::Public
    )
    .await
    .is_err());

    // Loopback rejected when not allowed (i.e. the original target was public).
    assert!(validate_sitemap_target(
        "http://127.0.0.1/sitemap.xml",
        crate::network_policy::LocalOrigin::Public
    )
    .await
    .is_err());

    // The metadata-host literal (must hit the network_policy domain check).
    assert!(validate_sitemap_target(
        "http://metadata.google.internal/",
        crate::network_policy::LocalOrigin::Public
    )
    .await
    .is_err());
}

/// When the scan target was on the person's own network, sitemaps
/// pointing at loopback ARE allowed - that's the legitimate "scanning
/// my own dev server" case.
#[tokio::test]
async fn validate_sitemap_target_allows_loopback_when_target_is_strict_local() {
    assert!(validate_sitemap_target(
        "http://127.0.0.1:5173/sitemap.xml",
        crate::network_policy::LocalOrigin::Loopback
    )
    .await
    .is_ok());
    // But still rejects metadata and RFC1918 even under local-dev policy.
    assert!(validate_sitemap_target(
        "http://169.254.169.254/",
        crate::network_policy::LocalOrigin::Loopback
    )
    .await
    .is_err());
    assert!(validate_sitemap_target(
        "http://10.0.0.1/",
        crate::network_policy::LocalOrigin::Loopback
    )
    .await
    .is_err());
}

#[tokio::test]
async fn a_sitemap_on_the_scanned_private_network_is_reachable() {
    // A LAN target's own sitemap is on the LAN, so the scan that reached
    // the page reaches its sitemap. A public origin's never does.
    use crate::network_policy::LocalOrigin;
    assert!(validate_sitemap_target(
        "http://192.168.1.40/sitemap.xml",
        LocalOrigin::PrivateNetwork
    )
    .await
    .is_ok());
    assert!(
        validate_sitemap_target("http://169.254.169.254/", LocalOrigin::PrivateNetwork)
            .await
            .is_err()
    );
    assert!(
        validate_sitemap_target("http://192.168.1.40/sitemap.xml", LocalOrigin::Public)
            .await
            .is_err()
    );
}

/// Discovery reads locations through the shared parser, so these pin the
/// behavior discovery depends on rather than re-testing the grammar
/// (which sitemap_document_tests.rs owns).
fn discovered(body: &str) -> Vec<String> {
    parse_sitemap_document(body).locs().to_vec()
}

#[test]
fn discovery_reads_urlset_index_and_text_documents() {
    assert_eq!(
        discovered(
            r#"<urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/about</loc></url></urlset>"#
        ),
        vec!["https://example.com/", "https://example.com/about"]
    );
    assert_eq!(
        discovered(
            r#"<sitemapindex><sitemap><loc>https://example.com/posts.xml</loc></sitemap></sitemapindex>"#
        ),
        vec!["https://example.com/posts.xml"]
    );
    assert_eq!(
        discovered("https://example.com/\nhttps://example.com/about\n"),
        vec!["https://example.com/", "https://example.com/about"]
    );
}

#[test]
fn discovery_still_reads_a_malformed_sitemap() {
    // The check calls this document invalid; discovery must still find the
    // pages, because they exist.
    let salvaged = discovered(r#"<urlset><url><loc>https://example.com/page1</loc></url><url>"#);
    assert_eq!(salvaged, vec!["https://example.com/page1"]);
}

#[test]
fn discovery_finds_nothing_in_an_empty_or_non_sitemap_response() {
    assert!(discovered(r#"<?xml version="1.0"?><urlset></urlset>"#).is_empty());
    assert!(discovered("<html><body>404</body></html>").is_empty());
}
