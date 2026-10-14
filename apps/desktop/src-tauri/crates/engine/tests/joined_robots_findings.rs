//! Established findings retain declines for pages whose noindex is unknown.

use sitecmd_engine::session::{analyze_session, SessionPage, SessionSitemap, SessionVerdict};
use sitecmd_engine::CheckStatus;

const SITEMAP_REASON: &str = "A page listed in the sitemap reached SiteCMD with its X-Robots-Tag lines combined, so whether it is noindex could not be told.";
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

fn assert_finding_then_decline(rows: &[&SessionVerdict], named: &[usize], reason: &str) {
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].result.status, CheckStatus::Warn);
    assert_eq!(rows[0].pages, named);
    assert_eq!(rows[1].result.status, CheckStatus::Skipped);
    assert_eq!(rows[1].result.description, reason);
    assert!(rows[1].pages.is_empty());
}

#[test]
fn a_sitemap_finding_keeps_the_decline_for_an_unknown_listed_page() {
    // A known contradiction previously hid the decline for an unknown listed page.
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
    let rows: Vec<_> = analysis
        .verdicts
        .iter()
        .filter(|row| row.result.check_id == "seo.noindex_in_sitemap")
        .collect();
    assert_finding_then_decline(&rows, &[0], SITEMAP_REASON);
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
    let rows: Vec<_> = analysis
        .verdicts
        .iter()
        .filter(|row| row.result.check_id == "seo.noindex_in_sitemap")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result.status, CheckStatus::Warn);
    assert_eq!(rows[0].pages, [0]);
}

#[test]
fn a_duplicate_keeps_the_decline_for_another_unknown_group() {
    // An established duplicate previously hid an undecided group sharing another value.
    let pages = [
        page("/a", Some(false), "Shared"),
        page("/b", Some(false), "Shared"),
        page("/known", Some(false), "Other"),
        page("/unknown", None, "Other"),
    ];
    let analysis = analyze_session(&pages, None);
    for (check, label) in DUPLICATE_CHECKS {
        let rows: Vec<_> = analysis
            .verdicts
            .iter()
            .filter(|row| row.result.check_id == check)
            .collect();
        let reason = format!("A page sharing its {label} with another compared page reached SiteCMD with its X-Robots-Tag lines combined, so whether it competes for that {label} could not be told.");
        assert_finding_then_decline(&rows, &[0, 1], &reason);
    }
}

#[test]
fn a_duplicate_keeps_the_decline_for_its_unknown_member() {
    // Two known duplicates previously hid whether an unknown third page competes too.
    let pages = [
        page("/a", Some(false), "Shared"),
        page("/b", Some(false), "Shared"),
        page("/unknown", None, "Shared"),
    ];
    let analysis = analyze_session(&pages, None);
    for (check, label) in DUPLICATE_CHECKS {
        let rows: Vec<_> = analysis
            .verdicts
            .iter()
            .filter(|row| row.result.check_id == check)
            .collect();
        let reason = format!("A page sharing its {label} with another compared page reached SiteCMD with its X-Robots-Tag lines combined, so whether it competes for that {label} could not be told.");
        assert_finding_then_decline(&rows, &[0, 1], &reason);
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
        let rows: Vec<_> = analysis
            .verdicts
            .iter()
            .filter(|row| row.result.check_id == check)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].result.status, CheckStatus::Warn);
        assert_eq!(rows[0].pages, [0, 1]);
    }
}
