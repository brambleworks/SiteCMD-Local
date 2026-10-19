//! A complete page set reaches the same cross-page verdicts on both lanes:
//! the desktop's page signals and the hosted lane's keyed facts, over the
//! same pages, name the same checks, statuses, severities and pages. A sitemap
//! reaches each lane by its own path: the desktop's parsed document, and the
//! hosted walk's answer on the entry route.
//! For malformed sitemaps, desktop discovery may salvage locations while
//! hosted facts omit the document and conservatively skip the sitemap comparison.
//! The hosted walk reads declarations first, while desktop discovery reads conventional paths first.
//! When an empty sitemap precedes a real one, the hosted lane skips while desktop discovery can warn.
//! When declarations exceed SITEMAP_DECLARATION_PROBE_LIMIT, the hosted lane can skip while desktop discovery reads a later sitemap and warns.

#[path = "support/session_lanes.rs"]
mod support;

use sitecmd_engine::session::signals::MAX_INTERNAL_LINKS_PER_PAGE;
use sitecmd_engine::CheckStatus;
use support::{desktop, desktop_reason, hosted, hosted_facts, page, Scan, Verdicts, NOINDEX};

/// Two noindex pages listed with trailing slashes and www twins; a query
/// identifies a different URL.
fn twin_spellings() -> Scan {
    Scan {
        routes: vec![
            "https://example.com/",
            "https://example.com/private",
            "https://example.com/open",
        ],
        pages: vec![
            ("https://example.com/", 200, page("Home", "Home", "", "")),
            (
                "https://example.com/private",
                200,
                page("Private", "Private", NOINDEX, ""),
            ),
            (
                "https://example.com/open",
                200,
                page("Open", "Open", NOINDEX, ""),
            ),
        ],
        robots: None,
        sitemaps: vec![(
            "https://example.com/sitemap.xml",
            concat!(
            "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
            "<url><loc>https://example.com/private/</loc></url>",
            "<url><loc>https://www.example.com/open</loc></url>",
            "<url><loc>https://example.com/open?ref=1</loc></url></urlset>"
        ),
        )],
    }
}

fn scans() -> Vec<(&'static str, Scan)> {
    vec![
        (
            "shared titles, descriptions and H1s, by case and spacing",
            Scan {
                routes: vec!["https://example.com/", "https://example.com/a", "https://example.com/b"],
                pages: vec![
                    ("https://example.com/", 200, page("Home", "Welcome", "", "")),
                    ("https://example.com/a", 200, page("Our Menu", "Menu", "<meta name=\"description\" content=\"Fresh daily menu\">", "")),
                    ("https://example.com/b", 200, page(" our menu ", "MENU", "<meta name=\"description\" content=\" fresh DAILY menu \">", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        (
            "trailing-slash twins are one page",
            Scan {
                routes: vec!["https://example.com/", "https://example.com/a", "https://example.com/a/"],
                pages: vec![
                    ("https://example.com/", 200, page("Home", "Home", "", "")),
                    ("https://example.com/a", 200, page("A", "A", "", "")),
                    ("https://example.com/a/", 200, page("A", "A", "", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        (
            "a redirect to an unplanned path, linked by its new address",
            Scan {
                routes: vec![
                    "https://example.com/",
                    "https://example.com/old",
                    "https://example.com/c",
                    "https://example.com/d",
                    "https://example.com/e",
                ],
                pages: vec![
                    ("https://example.com/", 200, page("Home", "Home", "", "<a href=\"/new\">New</a><a href=\"/c\">C</a><a href=\"https://www.example.com/d\">D</a>")),
                    ("https://example.com/new", 200, page("New", "New", "", "")),
                    ("https://example.com/c", 200, page("C", "C", "", "")),
                    ("https://example.com/d", 200, page("D", "D", "", "")),
                    ("https://example.com/e", 200, page("E", "E", "", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        (
            "a canonical chain through a canonical off the host, and a loop",
            Scan {
                routes: vec!["https://example.com/", "https://example.com/a", "https://example.com/b", "https://example.com/c"],
                pages: vec![
                    ("https://example.com/", 200, page("Home", "Home", "<link rel=\"canonical\" href=\"https://example.com/a\">", "")),
                    ("https://example.com/a", 200, page("A", "A", "<link rel=\"canonical\" href=\"https://www.example.com/a\">", "")),
                    ("https://example.com/b", 200, page("B", "B", "<link rel=\"canonical\" href=\"https://example.com/c\">", "")),
                    ("https://example.com/c", 200, page("C", "C", "<link rel=\"canonical\" href=\"https://example.com/b\">", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        (
            "a half-present hreflang set",
            Scan {
                routes: vec!["https://example.com/", "https://example.com/de"],
                pages: vec![
                    ("https://example.com/", 200, page("Home", "Home", "<link rel=\"alternate\" hreflang=\"de\" href=\"https://example.com/de\"><link rel=\"alternate\" hreflang=\"fr\" href=\"https://fr.example.com/\">", "")),
                    ("https://example.com/de", 200, page("Start", "Start", "", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        (
            "a noindex page and a page canonical to its sibling leave the duplicate groups",
            Scan {
                routes: vec!["https://example.com/", "https://example.com/a", "https://example.com/b", "https://example.com/c"],
                pages: vec![
                    ("https://example.com/", 200, page("Same", "Home", "", "")),
                    ("https://example.com/a", 200, page("Same", "A", "<meta name=\"robots\" content=\"noindex\">", "")),
                    ("https://example.com/b", 200, page("Other", "B", "", "")),
                    ("https://example.com/c", 200, page("Other", "C", "<link rel=\"canonical\" href=\"https://example.com/b\">", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        (
            "one page, and a page that answered 404",
            Scan {
                routes: vec!["https://example.com/", "https://example.com/gone"],
                pages: vec![
                    ("https://example.com/", 200, page("Home", "Home", "", "")),
                    ("https://example.com/gone", 404, page("Not found", "Not found", "", "")),
                ],
                robots: None, sitemaps: Vec::new(),
            },
        ),
        ("a noindex page listed in the sitemap by its twin spellings", twin_spellings()),
    ]
}

#[test]
fn both_lanes_reach_the_same_cross_page_verdicts() {
    for (name, scan) in scans() {
        assert_eq!(hosted(&scan), desktop(&scan), "{name}");
    }
}

#[test]
fn a_single_page_has_no_cross_page_verdict_on_either_lane() {
    let scan = Scan {
        routes: vec!["https://example.com/"],
        pages: vec![("https://example.com/", 200, page("Home", "Home", "", ""))],
        robots: None,
        sitemaps: Vec::new(),
    };
    assert!(desktop(&scan).is_empty());
    assert!(hosted(&scan).is_empty());
}

#[test]
fn excess_hreflang_alternates_skip_a_one_way_pair_on_both_lanes() {
    let alternates: String = (0..=MAX_INTERNAL_LINKS_PER_PAGE)
        .map(|index| format!("<link rel=\"alternate\" hreflang=\"x{index}\" href=\"/l{index}\">"))
        .collect();
    let scan = Scan {
        routes: vec![
            "https://example.com/",
            "https://example.com/a",
            "https://example.com/b",
        ],
        pages: vec![
            (
                "https://example.com/",
                200,
                page("Home", "Home", &alternates, ""),
            ),
            (
                "https://example.com/a",
                200,
                page(
                    "A",
                    "A",
                    "<link rel=\"alternate\" hreflang=\"de\" href=\"/b\">",
                    "",
                ),
            ),
            ("https://example.com/b", 200, page("B", "B", "", "")),
        ],
        robots: None,
        sitemaps: Vec::new(),
    };
    for verdicts in [desktop(&scan), hosted(&scan)] {
        let verdict = verdicts
            .iter()
            .find(|(id, ..)| id == "seo.hreflang_reciprocity")
            .expect("verdict");
        assert_eq!(verdict.1, CheckStatus::Skipped);
    }
    assert_eq!(hosted(&scan), desktop(&scan));
}

#[test]
fn a_canonical_loop_through_a_redirected_page_fails_on_both_lanes() {
    let scan = Scan {
        routes: vec!["https://example.com/", "https://example.com/old"],
        pages: vec![
            (
                "https://example.com/",
                200,
                page("Home", "Home", "<link rel=\"canonical\" href=\"/new\">", ""),
            ),
            (
                "https://example.com/new",
                200,
                page("New", "New", "<link rel=\"canonical\" href=\"/\">", ""),
            ),
        ],
        robots: None,
        sitemaps: Vec::new(),
    };
    for verdicts in [desktop(&scan), hosted(&scan)] {
        let verdict = verdicts
            .iter()
            .find(|(id, ..)| id == "seo.canonical_loop")
            .expect("verdict");
        assert_eq!(verdict.1, CheckStatus::Fail);
        assert_eq!(verdict.3, vec![0, 1]);
    }
    assert_eq!(hosted(&scan), desktop(&scan));
}

#[test]
fn a_sitemap_reaches_both_lanes_and_names_the_same_noindex_pages() {
    let named = |verdicts: Verdicts| {
        verdicts
            .into_iter()
            .find(|(check, ..)| check == "seo.noindex_in_sitemap")
            .map(|(_, status, _, pages)| (status, pages))
    };
    let scan = twin_spellings();
    assert_eq!(named(desktop(&scan)), Some((CheckStatus::Warn, vec![1, 2])));
    assert_eq!(named(hosted(&scan)), Some((CheckStatus::Warn, vec![1, 2])));
}

#[test]
fn unread_declared_sitemaps_skip_noindex_on_both_lanes() {
    let scan = Scan {
        routes: vec!["https://example.com/", "https://example.com/private"],
        pages: vec![
            ("https://example.com/", 200, page("Home", "Home", "", "")),
            (
                "https://example.com/private",
                200,
                page("Private", "Private", NOINDEX, ""),
            ),
        ],
        robots: Some(
            "Sitemap: https://example.com/pages.xml\nSitemap: https://example.com/posts.xml",
        ),
        sitemaps: vec![
            (
                "https://example.com/pages.xml",
                "<urlset><url><loc>https://example.com/</loc></url></urlset>",
            ),
            (
                "https://example.com/posts.xml",
                "<urlset><url><loc>https://example.com/private</loc></url></urlset>",
            ),
        ],
    };
    let foreign = Scan {
        routes: scan.routes.clone(),
        pages: scan.pages.clone(),
        robots: Some("Sitemap: https://other.example/posts.xml"),
        sitemaps: vec![
            (
                "https://example.com/sitemap.xml",
                "<urlset><url><loc>https://example.com/</loc></url></urlset>",
            ),
            (
                "https://other.example/posts.xml",
                "<urlset><url><loc>https://example.com/private</loc></url></urlset>",
            ),
        ],
    };
    for scan in [scan, foreign] {
        let native = desktop(&scan);
        let verdict = native
            .iter()
            .find(|(id, ..)| id == "seo.noindex_in_sitemap")
            .expect("verdict");
        assert_eq!(verdict.1, CheckStatus::Skipped);
        let reason = desktop_reason(&scan);
        assert_eq!(
            reason.as_deref(),
            Some("robots.txt declares 1 further sitemap that was not read")
        );
        assert_eq!(
            hosted_facts(&scan)[0]
                .sitemap
                .as_ref()
                .expect("sitemap")
                .partial_because(),
            reason
        );
        assert_eq!(hosted(&scan), native);
    }
}

#[test]
fn an_error_entry_keeps_the_sitemap_on_both_lanes() {
    let scan = Scan {
        routes: vec![
            "https://example.com/",
            "https://example.com/a",
            "https://example.com/private",
        ],
        pages: vec![
            (
                "https://example.com/",
                503,
                page("Unavailable", "Unavailable", "", ""),
            ),
            ("https://example.com/a", 200, page("A", "A", "", "")),
            (
                "https://example.com/private",
                200,
                page("Private", "Private", NOINDEX, ""),
            ),
        ],
        robots: None,
        sitemaps: vec![(
            "https://example.com/sitemap.xml",
            "<urlset><url><loc>https://example.com/private</loc></url></urlset>",
        )],
    };
    for verdicts in [desktop(&scan), hosted(&scan)] {
        let verdict = verdicts
            .iter()
            .find(|(id, ..)| id == "seo.noindex_in_sitemap")
            .expect("verdict");
        assert_eq!((verdict.1, &verdict.3), (CheckStatus::Warn, &vec![2]));
    }
}
