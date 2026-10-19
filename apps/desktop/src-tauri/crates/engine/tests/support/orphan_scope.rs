//! Orphan findings require the complete declared sitemap set to be compared.

use super::{analyze_session, page, verdict, CheckStatus, SessionPage, SessionSitemap};

fn pages() -> Vec<SessionPage> {
    let mut pages: Vec<_> = ["", "menu", "hours", "about", "contact"]
        .map(|path| page(&format!("https://example.com/{path}")))
        .into();
    pages[0].internal_links = pages[2..].iter().map(|page| page.url.clone()).collect();
    pages
}

fn assert_skipped(pages: &[SessionPage], sitemap: Option<SessionSitemap<'_>>, reason: &str) {
    let analysis = analyze_session(pages, sitemap);
    let orphan = verdict(&analysis, "seo.orphan_pages");
    assert_eq!(orphan.result.status, CheckStatus::Skipped);
    assert_eq!(orphan.result.description, reason);
    assert!(orphan.pages.is_empty());
}

#[test]
fn no_sitemap_skips_orphan_grading_even_when_no_page_looks_unlinked() {
    let mut pages = pages();
    for all_linked in [false, true] {
        if all_linked {
            let menu = pages[1].url.clone();
            pages[0].internal_links.push(menu);
        }
        assert_skipped(&pages, None, "No sitemap was found for this site, so this scan cannot tell whether the pages it compared are all of the site's pages.");
    }
}

#[test]
fn a_partial_sitemap_skips_orphan_grading_before_testing_its_pages() {
    let pages = pages();
    assert_skipped(
        &pages,
        Some(SessionSitemap { urls: &[], partial_because: Some("a child sitemap did not answer") }),
        "SiteCMD read only part of this site's sitemap (a child sitemap did not answer), so this scan cannot tell whether the pages it compared are all of the site's pages.",
    );
}

#[test]
fn an_uncompared_sitemap_page_skips_orphan_grading_and_counts_sitemap_urls() {
    let mut pages = pages();
    let mut urls: Vec<_> = pages.iter().map(|page| page.url.clone()).collect();
    urls.push("https://example.com/archive".into());
    urls.extend(
        [
            "https://example.com/menu/",
            "https://example.com/menu#x",
            "http://www.example.com/menu",
        ]
        .map(String::from),
    );
    for all_linked in [false, true] {
        if all_linked {
            let menu = pages[1].url.clone();
            pages[0].internal_links.push(menu);
        }
        assert_skipped(
            &pages,
            Some(SessionSitemap { urls: &urls, partial_because: None }),
            "This scan compared 5 of the 6 pages this site's sitemap lists, so a page with no link from a compared page may be linked from a page the scan did not read.",
        );
    }
    assert_skipped(
        &pages,
        Some(SessionSitemap { urls: &urls[5..6], partial_because: None }),
        "This scan compared 0 of the 1 page this site's sitemap lists, so a page with no link from a compared page may be linked from a page the scan did not read.",
    );
}

#[test]
fn the_whole_sitemap_compared_through_www_aliases_still_names_the_orphan() {
    let mut pages = pages();
    pages[2].requested_url = "https://example.com/old-hours".into();
    pages[0].internal_links[0] = pages[2].requested_url.clone();
    let urls: Vec<_> = pages
        .iter()
        .map(|page| {
            page.requested_url
                .replace("https://example.com", "http://www.EXAMPLE.com")
                + "/#top"
        })
        .collect();
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    );
    let orphan = verdict(&analysis, "seo.orphan_pages");
    assert_eq!(orphan.result.status, CheckStatus::Warn);
    assert_eq!(orphan.result.severity, sitecmd_engine::Severity::Low);
    assert_eq!(orphan.pages, [1]);
    assert_eq!(
        orphan.result.title,
        "1 page is not linked from any other scanned page"
    );
}

#[test]
fn errors_do_not_cover_a_sitemap_url_and_repeated_selections_cover_their_aliases() {
    let mut pages = pages();
    let mut repeated = pages[2].clone();
    repeated.requested_url = "https://example.com/old-hours".into();
    pages.push(repeated);
    let mut failed = page("https://example.com/gone");
    failed.status_code = 404;
    pages.push(failed);
    let urls: Vec<_> = ["https://example.com/old-hours", "https://example.com/gone"]
        .map(String::from)
        .into();
    assert_skipped(
        &pages,
        Some(SessionSitemap { urls: &urls, partial_because: None }),
        "This scan compared 1 of the 2 pages this site's sitemap lists, so a page with no link from a compared page may be linked from a page the scan did not read.",
    );
}

#[test]
fn entry_and_minimum_page_skips_precede_sitemap_skips() {
    let mut pages = pages();
    pages[0].status_code = 404;
    assert_skipped(
        &pages,
        None,
        "The page this scan started from did not return a successful page response, so the links it publishes are missing from the graph and every page it links to would look unreachable.",
    );
    pages[0].status_code = 200;
    assert_skipped(
        &pages[..4],
        None,
        "This check needs at least 5 scanned pages to tell an unlinked page from a small scan; this scan compared 4.",
    );
}

#[test]
fn an_empty_complete_sitemap_skips_orphan_grading() {
    assert_skipped(
        &pages(),
        Some(SessionSitemap { urls: &[], partial_because: None }),
        "This site's sitemap lists no pages, so this scan cannot tell whether the pages it compared are all of the site's pages.",
    );
}

#[test]
fn noindex_matches_a_sitemap_listing_the_same_site_www_twins() {
    let mut pages = pages();
    pages[1].noindex = Some(true);
    let urls: Vec<_> = pages
        .iter()
        .map(|p| {
            p.url
                .replace("https://example.com", "https://www.example.com")
        })
        .collect();
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    );
    let noindex = verdict(&analysis, "seo.noindex_in_sitemap");
    assert_eq!(noindex.result.status, CheckStatus::Warn);
    assert_eq!(noindex.pages, [1]);
}
