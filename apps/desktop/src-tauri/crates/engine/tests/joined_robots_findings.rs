//! Established findings retain declines for pages whose noindex is unknown.

use sitecmd_engine::session::{
    analyze_session, SessionAnalysis, SessionPage, SessionSitemap, SessionVerdict,
};
use sitecmd_engine::CheckStatus;

const SITEMAP_REASON: &str = "A page listed in the sitemap reached SiteCMD with its X-Robots-Tag lines combined, so whether it is noindex could not be told.";
const SITEMAP_CHECK: &str = "seo.noindex_in_sitemap";
const DUPLICATE_CHECKS: [(&str, &str); 3] = [
    ("seo.duplicate_title_across_pages", "title"),
    ("seo.duplicate_description_across_pages", "meta description"),
    ("seo.duplicate_h1", "H1 heading"),
];

fn page(path: &str, noindex: Option<bool>, title: &str) -> SessionPage {
    let url = format!("https://example.com{path}");
    SessionPage {
        url: url.clone(),
        requested_url: url,
        status_code: 200,
        title: Some(title.into()),
        meta_description: Some(title.into()),
        h1: Some(title.into()),
        canonical: None,
        noindex,
        hreflang: Vec::new(),
        hreflang_truncated: false,
        internal_links: Vec::new(),
        internal_links_truncated: false,
    }
}

fn rows<'a>(analysis: &'a SessionAnalysis, check: &str) -> Vec<&'a SessionVerdict> {
    analysis
        .verdicts
        .iter()
        .filter(|row| row.result.check_id == check)
        .collect()
}

fn duplicate_reason(label: &str) -> String {
    format!("A page sharing its {label} with another compared page reached SiteCMD with its X-Robots-Tag lines combined, so whether it competes for that {label} could not be told.")
}

fn assert_finding_then_decline(
    rows: &[&SessionVerdict],
    check: &str,
    named: &[usize],
    reason: &str,
) {
    assert_eq!(rows.len(), 2, "{check}");
    assert_eq!(rows[0].result.status, CheckStatus::Warn, "{check}");
    assert_eq!(rows[0].pages, named, "{check}");
    assert_eq!(rows[1].result.status, CheckStatus::Skipped, "{check}");
    assert_eq!(rows[1].result.description, reason, "{check}");
    assert!(rows[1].pages.is_empty(), "{check}");
}

#[test]
fn a_sitemap_finding_keeps_the_decline_for_an_unknown_listed_page() {
    // A known contradiction must not hide the decline for an unknown listed page.
    let pages = [
        page("/known", Some(true), "Known"),
        page("/unknown", None, "Unknown"),
    ];
    let urls = pages.clone().map(|page| page.url);
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    );
    assert_finding_then_decline(
        &rows(&analysis, SITEMAP_CHECK),
        SITEMAP_CHECK,
        &[0],
        SITEMAP_REASON,
    );
}

#[test]
fn an_unknown_unlisted_page_does_not_add_a_sitemap_decline() {
    // An unknown page outside the sitemap must not make its known contradiction decline.
    let pages = [
        page("/known", Some(true), "Known"),
        page("/unknown", None, "Unknown"),
    ];
    let urls = [pages[0].url.clone()];
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    );
    let rows = rows(&analysis, SITEMAP_CHECK);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result.status, CheckStatus::Warn);
    assert_eq!(rows[0].pages, [0]);
}

#[test]
fn a_duplicate_keeps_the_decline_for_another_unknown_group() {
    // An established duplicate must not hide an undecided group that shares another value.
    let pages = [
        page("/a", Some(false), "Shared"),
        page("/b", Some(false), "Shared"),
        page("/known", Some(false), "Other"),
        page("/unknown", None, "Other"),
    ];
    let analysis = analyze_session(&pages, None);
    for (check, label) in DUPLICATE_CHECKS {
        assert_finding_then_decline(
            &rows(&analysis, check),
            check,
            &[0, 1],
            &duplicate_reason(label),
        );
    }
}

#[test]
fn a_duplicate_keeps_the_decline_for_its_unknown_member() {
    // Two known duplicates must not hide whether an unknown third page competes too.
    let pages = [
        page("/a", Some(false), "Shared"),
        page("/b", Some(false), "Shared"),
        page("/unknown", None, "Shared"),
    ];
    let analysis = analyze_session(&pages, None);
    for (check, label) in DUPLICATE_CHECKS {
        assert_finding_then_decline(
            &rows(&analysis, check),
            check,
            &[0, 1],
            &duplicate_reason(label),
        );
    }
}

#[test]
fn known_duplicates_without_unknown_pages_do_not_add_a_decline() {
    // A fully known duplicate group must retain its single finding row.
    let pages = [
        page("/a", Some(false), "Shared"),
        page("/b", Some(false), "Shared"),
    ];
    let analysis = analyze_session(&pages, None);
    for (check, _) in DUPLICATE_CHECKS {
        let rows = rows(&analysis, check);
        assert_eq!(rows.len(), 1, "{check}");
        assert_eq!(rows[0].result.status, CheckStatus::Warn, "{check}");
        assert_eq!(rows[0].pages, [0, 1], "{check}");
    }
}

#[test]
fn a_partial_sitemap_finding_keeps_the_decline_for_unread_listings() {
    // A known contradiction must not establish passes for sitemap listings that were not read.
    let pages = [
        page("/listed", Some(true), "Listed"),
        page("/unread", Some(true), "Unread"),
        page("/known", Some(false), "Known"),
    ];
    let urls = [pages[0].url.clone()];
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: Some("unread sitemap document"),
        }),
    );
    let reason = "SiteCMD read only part of this site's sitemap (unread sitemap document), so a noindex page listed in the part it did not read would not have been seen.";
    assert_finding_then_decline(&rows(&analysis, SITEMAP_CHECK), SITEMAP_CHECK, &[0], reason);
}

#[test]
fn an_unknown_listed_page_takes_priority_over_the_partial_sitemap_decline() {
    // Two missing facts must keep the listed page's decline without adding another decline.
    let pages = [
        page("/listed", Some(true), "Listed"),
        page("/unknown", None, "Unknown"),
        page("/unread", Some(true), "Unread"),
    ];
    let urls = [pages[0].url.clone(), pages[1].url.clone()];
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: Some("unread sitemap document"),
        }),
    );
    assert_finding_then_decline(
        &rows(&analysis, SITEMAP_CHECK),
        SITEMAP_CHECK,
        &[0],
        SITEMAP_REASON,
    );
}

#[test]
fn a_complete_sitemap_finding_does_not_add_a_decline() {
    // A complete sitemap must not make an established contradiction decline.
    let pages = [
        page("/listed", Some(true), "Listed"),
        page("/unlisted", Some(true), "Unlisted"),
        page("/known", Some(false), "Known"),
    ];
    let urls = [pages[0].url.clone()];
    let analysis = analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    );
    let rows = rows(&analysis, SITEMAP_CHECK);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result.status, CheckStatus::Warn);
    assert_eq!(rows[0].pages, [0]);
}
