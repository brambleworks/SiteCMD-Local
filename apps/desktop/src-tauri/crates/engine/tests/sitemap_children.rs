//! An index sitemap's children, as a route session that names a limit reads
//! them: the ones on the page's own origin, in the index's order, at most that
//! limit; their pages are the comparison's sitemap set, and what was not read
//! is a partial cause. A session that names no limit reads none.

use serde_json::json;

use sitecmd_engine::checks::seo::sitemap_walk::{
    sitemap_child_request, sitemap_request, SITEMAP_URL_LIMIT,
};
use sitecmd_engine::evaluation::{
    probe_key, ExecutedProbe, PageArtifact, RouteSession, SessionSitemapCause, SessionSitemapFacts,
};
use sitecmd_engine::log_sanitizer::ISSUE_EVIDENCE_URL_MAX_CHARS;
use sitecmd_engine::probe::{
    decode_probe_body, BodyLimit, ProbeOutcome, ProbeRequest, ProbeResponse,
};

const ROUTES: [&str; 2] = ["https://example.com/", "https://example.com/listed"];
const POSTS: &str = "https://example.com/sitemap-posts.xml";
const PAGES: &str = "https://example.com/sitemap-pages.xml";
const ARCHIVE: &str = "https://example.com/sitemap-archive.xml";
const FOREIGN: &str = "https://cdn.example.net/sitemap-media.xml";

fn page() -> PageArtifact {
    PageArtifact {
        url: ROUTES[0].into(),
        requested_url: Some(ROUTES[0].into()),
        status_code: 200,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: "<!doctype html><html lang='en'><head><title>Example home</title></head><body></body></html>".into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    }
}

fn response(url: &str, status: u16, content_type: &str, body: Option<&str>) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: url.into(),
        content_type: Some(content_type.into()),
        content_length: None,
        headers: Vec::new(),
        body: body.map(|text| decode_probe_body(text.as_bytes().to_vec())),
    })
}

fn urlset(locations: &[&str]) -> String {
    let entries: String = locations
        .iter()
        .map(|loc| format!("<url><loc>{loc}</loc></url>"))
        .collect();
    format!("<?xml version='1.0'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{entries}</urlset>")
}

fn index(children: &[&str]) -> String {
    let entries: String = children
        .iter()
        .map(|loc| format!("<sitemap><loc>{loc}</loc></sitemap>"))
        .collect();
    format!("<?xml version='1.0'?><sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{entries}</sitemapindex>")
}

/// A site with no robots.txt whose `/sitemap.xml` answers `sitemap`, whose
/// children answer from `children` by address, and which answers a 404
/// everywhere else.
fn site<'a>(
    sitemap: &'a str,
    children: &'a [(&'a str, ProbeOutcome)],
) -> impl Fn(&ProbeRequest) -> ProbeOutcome + 'a {
    move |request| match request.url.as_str() {
        "https://example.com/sitemap.xml" => {
            response(&request.url, 200, "application/xml", Some(sitemap))
        }
        url => children
            .iter()
            .find(|(address, _)| *address == url)
            .map(|(_, outcome)| outcome.clone())
            .unwrap_or_else(|| response(url, 404, "text/html", None)),
    }
}

/// The route's plan driven to its fixpoint against `answer`, as a runtime
/// drives it: every address it asked for, in order, and its comparison
/// facts' sitemap.
/// A child sitemap is executed and recorded alone, and a later child no longer
/// requested is skipped.
fn walked(
    limit: usize,
    answer: impl Fn(&ProbeRequest) -> ProbeOutcome,
) -> (Vec<String>, Option<SessionSitemapFacts>) {
    let mut route = RouteSession::open(page())
        .expect("opens")
        .with_sitemap_children(limit);
    let mut asked = Vec::new();
    for _ in 0..40 {
        let plan = route.plan();
        if plan.probes.is_empty() {
            let routes: Vec<String> = ROUTES.iter().map(|route| route.to_string()).collect();
            let facts = route.session_page(&routes).expect("facts").expect("named");
            return (asked, facts.sitemap);
        }
        let mut executed = Vec::new();
        for probe in plan.probes {
            if probe.request.limit == BodyLimit::SitemapChild {
                if !route
                    .plan()
                    .probes
                    .iter()
                    .any(|wanted| wanted.key == probe.key)
                {
                    continue;
                }
                asked.push(probe.request.url.clone());
                route.record(Some(vec![ExecutedProbe::new(
                    probe.key,
                    answer(&probe.request),
                )]));
            } else {
                asked.push(probe.request.url.clone());
                executed.push(ExecutedProbe::new(probe.key, answer(&probe.request)));
            }
        }
        route.record(Some(executed));
    }
    panic!("the probe plan never reached its fixpoint");
}

/// The children among the addresses asked for, in the order asked.
fn children_asked(asked: &[String]) -> Vec<&str> {
    asked
        .iter()
        .map(String::as_str)
        .filter(|url| [POSTS, PAGES, ARCHIVE, FOREIGN].contains(url))
        .collect()
}

fn listing(url: &'static str, pages: &[&str]) -> (&'static str, ProbeOutcome) {
    (
        url,
        response(url, 200, "application/xml", Some(&urlset(pages))),
    )
}

#[test]
fn a_childs_request_is_keyed_apart_from_a_walk_candidates() {
    let child = probe_key(&sitemap_child_request(POSTS));
    assert!(child.ends_with("\u{1f}limit=sitemap_child"), "{child:?}");
    assert_ne!(child, probe_key(&sitemap_request(POSTS)));
}

#[test]
fn an_index_is_read_through_its_same_origin_children_in_index_order() {
    let sitemap = index(&[POSTS, FOREIGN, PAGES]);
    let children = [
        listing(POSTS, &["https://example.com/listed"]),
        listing(PAGES, &["https://example.com/about"]),
    ];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS, PAGES]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries.len(), 2);
    assert_eq!(sitemap.entries[0], "r1");
    // The foreign child is never read, so the index counts as read up to it.
    assert_eq!(
        sitemap.partial_causes,
        [SessionSitemapCause::Index { listed: 3, read: 1 }]
    );
}

#[test]
fn the_child_limit_reads_the_first_children_and_says_so() {
    let sitemap = index(&[POSTS, PAGES, ARCHIVE]);
    let children = [
        listing(POSTS, &["https://example.com/listed"]),
        listing(PAGES, &["https://example.com/about"]),
        listing(ARCHIVE, &["https://example.com/old"]),
    ];
    let (asked, sitemap) = walked(2, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS, PAGES]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(
        sitemap.partial_causes,
        [SessionSitemapCause::Index { listed: 3, read: 2 }]
    );
    assert_eq!(
        sitemap.partial_because().as_deref(),
        Some("the sitemap index lists 3 child sitemaps and SiteCMD read the first 2")
    );
}

#[test]
fn a_child_that_did_not_answer_leaves_the_set_partial_and_is_not_asked_again() {
    let sitemap = index(&[POSTS, PAGES]);
    let children = [
        (POSTS, response(POSTS, 503, "text/html", None)),
        listing(PAGES, &["https://example.com/listed"]),
    ];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS, PAGES]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries, ["r1"]);
    assert_eq!(
        sitemap.partial_causes,
        [SessionSitemapCause::Index { listed: 2, read: 0 }]
    );
}

#[test]
fn children_stop_at_the_walks_url_limit() {
    let sitemap = index(&[POSTS, PAGES]);
    let addresses: Vec<String> = (0..SITEMAP_URL_LIMIT)
        .map(|n| format!("https://example.com/p/{n}"))
        .collect();
    let many: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let children = [
        listing(POSTS, &many),
        listing(PAGES, &["https://example.com/listed"]),
    ];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries.len(), SITEMAP_URL_LIMIT);
    assert_eq!(
        sitemap.partial_causes,
        [
            SessionSitemapCause::Index { listed: 2, read: 1 },
            SessionSitemapCause::IndexUrls
        ]
    );
    assert!(sitemap
        .partial_because()
        .expect("reason")
        .contains("yielded more than"));
}

#[test]
fn a_nested_index_lists_no_pages_and_a_malformed_child_still_gives_its_locations() {
    let sitemap = index(&[POSTS, PAGES]);
    let nested = index(&[ARCHIVE]);
    let malformed = "<urlset><url><loc>https://example.com/listed</loc></url><url>";
    let children = [
        (
            POSTS,
            response(POSTS, 200, "application/xml", Some(&nested)),
        ),
        (
            PAGES,
            response(PAGES, 200, "application/xml", Some(malformed)),
        ),
    ];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS, PAGES]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries, ["r1"]);
    assert!(
        sitemap.partial_causes.is_empty(),
        "{:?}",
        sitemap.partial_causes
    );
}

#[test]
fn a_session_that_names_no_limit_reads_an_index_as_before() {
    let sitemap = index(&[POSTS, PAGES]);
    let children = [listing(POSTS, &["https://example.com/listed"])];
    let (asked, sitemap) = walked(0, site(&sitemap, &children));
    assert!(children_asked(&asked).is_empty());
    let sitemap = sitemap.expect("sitemap");
    assert!(sitemap.entries.is_empty());
    assert_eq!(
        serde_json::to_value(&sitemap.partial_causes).expect("wire"),
        serde_json::json!([{ "cause": "index", "listed": 2 }])
    );
}

#[test]
fn a_session_that_names_a_limit_reads_an_empty_index_completely() {
    // A limit-naming session must not call a fully read empty index partial.
    let (asked, sitemap) = walked(50, site("<sitemapindex/>", &[]));
    assert!(children_asked(&asked).is_empty());
    let sitemap = sitemap.expect("sitemap");
    assert!(sitemap.entries.is_empty());
    assert!(sitemap.partial_causes.is_empty());
}

#[test]
fn a_childs_overflow_is_serialized_as_the_index_url_limit() {
    // An overflowing child must not make a truncated set look complete.
    let sitemap = index(&[POSTS]);
    let addresses: Vec<String> = (0..=SITEMAP_URL_LIMIT)
        .map(|n| format!("https://example.com/p/{n}"))
        .collect();
    let pages: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let children = [listing(POSTS, &pages)];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries.len(), SITEMAP_URL_LIMIT);
    assert_eq!(
        serde_json::to_value(&sitemap.partial_causes).expect("wire"),
        json!([{ "cause": "index_urls" }])
    );
}

#[test]
fn a_site_written_child_field_stays_a_walk_candidate() {
    // A site written separator must not classify a walk candidate as a child.
    let candidate = "https://example.com/declared.xml\u{1f}limit=sitemap_child";
    let robots = format!("Sitemap: {candidate}");
    let document = urlset(&["https://example.com/listed"]);
    let (asked, sitemap) = walked(0, |request| {
        if request.url == "https://example.com/robots.txt" {
            response(&request.url, 200, "text/plain", Some(&robots))
        } else if request.url == candidate {
            assert_eq!(request.limit, BodyLimit::Sitemap);
            response(&request.url, 200, "application/xml", Some(&document))
        } else {
            response(&request.url, 404, "text/html", None)
        }
    });
    assert_eq!(asked.iter().filter(|url| *url == candidate).count(), 1);
    let sitemap = sitemap.expect("the declared candidate keeps its body");
    assert_eq!(sitemap.entries, ["r1"]);
    assert!(sitemap.partial_causes.is_empty());
}

#[test]
fn a_repeated_child_does_not_leave_a_read_index_partial() {
    // Repeating a child must not make a fully read index partial.
    let sitemap = index(&[POSTS, POSTS]);
    let children = [listing(POSTS, &["https://example.com/listed"])];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries, ["r1"]);
    assert!(sitemap.partial_causes.is_empty());
}

#[test]
fn a_child_drops_page_locations_past_the_evidence_bound() {
    // An oversized location must not keep a document sized address in memory.
    let sitemap = index(&[POSTS]);
    let long = format!(
        "https://example.com/{}",
        "p".repeat(ISSUE_EVIDENCE_URL_MAX_CHARS)
    );
    let children = [listing(POSTS, &[&long, "https://example.com/listed"])];
    let (asked, sitemap) = walked(50, site(&sitemap, &children));
    assert_eq!(children_asked(&asked), [POSTS]);
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries, ["r1"]);
    assert!(sitemap.partial_causes.is_empty());
}

#[test]
fn dropped_locations_do_not_count_against_the_url_limit() {
    let sitemap = index(&[POSTS]);
    let mut locations: Vec<String> = (0..SITEMAP_URL_LIMIT - 1)
        .map(|number| format!("https://example.com/p{number}"))
        .collect();
    locations.extend(["p", "q"].map(|letter| {
        format!(
            "https://example.com/{}",
            letter.repeat(ISSUE_EVIDENCE_URL_MAX_CHARS)
        )
    }));
    let refs: Vec<&str> = locations.iter().map(String::as_str).collect();
    let children = [listing(POSTS, &refs)];
    let (_, sitemap) = walked(50, site(&sitemap, &children));
    let sitemap = sitemap.expect("sitemap");
    assert_eq!(sitemap.entries.len(), SITEMAP_URL_LIMIT - 1);
    assert!(sitemap.partial_causes.is_empty());
}
