use super::*;

#[test]
fn robots_directives_ignore_unicode_at_the_prefix_boundary() {
    assert_eq!(
        sitemap_urls_from_robots("abcdefg😃\n🙂🙂🙂\nSitemap: https://example.com/site.xml"),
        vec!["https://example.com/site.xml"]
    );
}

fn locs(parse: &SitemapParse) -> Vec<&str> {
    parse.locs().iter().map(String::as_str).collect()
}

#[test]
fn the_candidate_list_is_ordered_and_shared() {
    assert_eq!(SITEMAP_CANDIDATE_PATHS[0], "/sitemap.xml");
    assert_eq!(
        sitemap_candidate_urls("https://example.com"),
        vec![
            "https://example.com/sitemap.xml",
            "https://example.com/sitemap-index.xml",
            "https://example.com/sitemap_index.xml",
            "https://example.com/wp-sitemap.xml",
            "https://example.com/sitemap.php",
            "https://example.com/sitemap.txt",
        ]
    );
}

#[test]
fn a_trailing_slash_on_the_base_does_not_double_up() {
    assert_eq!(
        sitemap_candidate_urls("https://example.com/")[0],
        "https://example.com/sitemap.xml"
    );
}

#[test]
fn robots_declarations_are_case_insensitive_and_comment_aware() {
    let declared = sitemap_urls_from_robots(
        "User-agent: *\nSITEMAP: https://example.com/a.xml\nsitemap: https://example.com/b.xml # main\n# sitemap: https://example.com/commented.xml\nSitemap:\n",
    );
    assert_eq!(
        declared,
        vec!["https://example.com/a.xml", "https://example.com/b.xml"]
    );
}

#[test]
fn a_urlset_yields_its_entry_locations() {
    let parse = parse_sitemap_document(
        r#"<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/</loc><lastmod>2026-01-01</lastmod></url>
          <url><loc>https://example.com/about</loc></url>
        </urlset>"#,
    );
    assert!(matches!(
        parse,
        SitemapParse::WellFormed(SitemapDocument {
            kind: SitemapKind::UrlSet,
            ..
        })
    ));
    assert_eq!(
        locs(&parse),
        vec!["https://example.com/", "https://example.com/about"]
    );
}

#[test]
fn an_index_yields_its_child_sitemaps() {
    let parse = parse_sitemap_document(
        r#"<sitemapindex><sitemap><loc>https://example.com/posts.xml</loc></sitemap></sitemapindex>"#,
    );
    match &parse {
        SitemapParse::WellFormed(document) => {
            assert!(document.kind.lists_child_sitemaps());
            assert_eq!(document.kind.entry_label(), "child-sitemap");
        }
        other => panic!("expected a well-formed index, got {other:?}"),
    }
    assert_eq!(locs(&parse), vec!["https://example.com/posts.xml"]);
}

#[test]
fn entity_references_in_locations_are_decoded() {
    // Query strings in sitemaps carry &amp; constantly; a raw read hands
    // discovery a URL that 404s.
    let parse = parse_sitemap_document(
        r#"<urlset><url><loc>https://example.com/search?a=1&amp;b=2</loc></url></urlset>"#,
    );
    assert_eq!(locs(&parse), vec!["https://example.com/search?a=1&b=2"]);
}

#[test]
fn a_plain_text_sitemap_is_a_valid_sitemap() {
    // sitemaps.org defines a text format, and page discovery already read it.
    // The check has to agree, or one candidate path means two things.
    let parse =
        parse_sitemap_document("https://example.com/\n\nhttps://example.com/pricing\n   \n");
    match &parse {
        SitemapParse::WellFormed(document) => assert_eq!(document.kind, SitemapKind::Text),
        other => panic!("expected a well-formed text sitemap, got {other:?}"),
    }
    assert_eq!(
        locs(&parse),
        vec!["https://example.com/", "https://example.com/pricing"]
    );
}

#[test]
fn arbitrary_text_is_not_an_empty_sitemap() {
    let parse = parse_sitemap_document("Not found. Try again later.\n");
    assert!(matches!(parse, SitemapParse::Unusable { .. }));
    assert!(parse.locs().is_empty());
}

#[test]
fn a_malformed_document_is_salvaged_for_discovery_but_never_called_valid() {
    // The two consumers differ HERE and nowhere else: discovery still gets
    // the pages, the check still reports the document as invalid.
    let body = r#"<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc>"#;
    let parse = parse_sitemap_document(body);
    match &parse {
        SitemapParse::Salvaged { locs: salvaged, .. } => {
            assert_eq!(salvaged.len(), 2);
        }
        other => panic!("expected a salvaged parse, got {other:?}"),
    }
    assert!(sitemap_document_summary(body).is_err());
}

#[test]
fn a_salvaged_index_still_knows_its_entries_are_child_sitemaps() {
    // Reading a broken <sitemapindex> as a page list would hand discovery a
    // set of sitemap URLs and call them pages.
    let parse = parse_sitemap_document(
        r#"<sitemapindex><sitemap><loc>https://example.com/posts.xml</loc></sitemap><sitemap>"#,
    );
    assert!(matches!(parse, SitemapParse::Salvaged { .. }));
    assert!(parse.lists_child_sitemaps());

    let salvaged_urlset =
        parse_sitemap_document(r#"<urlset><url><loc>https://example.com/a</loc></url><url>"#);
    assert!(!salvaged_urlset.lists_child_sitemaps());
}

#[test]
fn an_html_error_page_is_unusable_rather_than_salvaged() {
    let parse = parse_sitemap_document("<html><body><h1>404 Not Found</h1></body></html>");
    assert!(matches!(parse, SitemapParse::Unusable { .. }));
}

#[test]
fn the_summary_keeps_reporting_the_root_and_entry_count() {
    // The seo.sitemap verdict is pinned to these exact values by the golden
    // corpus, so the refactor must not move them.
    assert_eq!(
        sitemap_document_summary("<urlset><url><loc>https://example.com/</loc></url></urlset>"),
        Ok(("urlset", 1))
    );
    assert_eq!(
        sitemap_document_summary(
            "<sitemapindex><sitemap><loc>https://example.com/a.xml</loc></sitemap></sitemapindex>"
        ),
        Ok(("sitemapindex", 1))
    );
    assert_eq!(
        sitemap_document_summary("<urlset></urlset>"),
        Ok(("urlset", 0))
    );
    assert_eq!(
        sitemap_document_summary("<urlset><url></url></urlset>"),
        Err("a sitemap entry has no non-empty loc element")
    );
    assert_eq!(
        sitemap_document_summary("<html><body>hi</body></html>"),
        Err("the XML root is not urlset or sitemapindex")
    );
}
