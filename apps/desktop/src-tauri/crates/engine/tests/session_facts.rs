//! One page's comparison facts: keys for every address, digests for every
//! compared value, and nothing that names the page's words or a query.

use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
use sitecmd_engine::evaluation::{
    evaluate, evaluate_session, probe_key, session_page, EvaluationRequest, ExecutedProbe,
    NotEvaluatedReason, PageArtifact, SessionPageFacts, SessionPageRequest, SessionRequest,
    SessionSitemapCause, SessionSitemapFacts, ELSEWHERE,
};
use sitecmd_engine::manifest::{capability_manifest, CheckScope, HostedLane};
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeRequest, ProbeResponse};
use sitecmd_engine::session::SESSION_CHECK_IDS;
use sitecmd_engine::CheckStatus;

const ROUTES: [&str; 3] = [
    "https://example.com/",
    "https://example.com/menu",
    "https://example.com/hours",
];

fn artifact(url: &str, requested: &str, body: &str) -> PageArtifact {
    PageArtifact {
        url: url.into(),
        requested_url: Some(requested.into()),
        status_code: 200,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: body.into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    }
}

fn facts(url: &str, requested: &str, body: &str) -> Option<SessionPageFacts> {
    session_page(&SessionPageRequest {
        page: artifact(url, requested, body),
        probe_outcomes: Vec::new(),
        routes: ROUTES.iter().map(|route| route.to_string()).collect(),
    })
    .expect("facts build")
}

#[test]
fn addresses_become_route_keys_path_keys_and_elsewhere() {
    let body = concat!(
        "<html><head><title>Menu</title>",
        "<link rel=\"canonical\" href=\"https://www.example.com/menu\">",
        "<link rel=\"alternate\" hreflang=\"de\" href=\"https://example.com/de/menu\">",
        "<link rel=\"alternate\" hreflang=\"fr\" href=\"https://fr.example.com/menu\">",
        "</head><body>",
        "<a href=\"/\">Home</a><a href=\"/hours/\">Hours</a><a href=\"/about\">About</a>",
        "<a href=\"/search?q=menu\">Search</a></body></html>"
    );
    let unscanned = facts(
        ROUTES[1],
        ROUTES[1],
        "<link rel=\"canonical\" href=\"/about\">",
    )
    .expect("the page can be named");
    assert!(unscanned.canonical.expect("canonical").starts_with('p'));
    let facts = facts(ROUTES[1], ROUTES[1], body).expect("the page can be named");
    assert_eq!(facts.page, "r1");
    assert_eq!(facts.requested, "r1");
    assert_eq!(
        facts.canonical.as_deref(),
        Some(ELSEWHERE),
        "the www twin is another origin"
    );
    assert_eq!(
        facts.hreflang.len(),
        1,
        "the alternate on another origin is dropped"
    );
    assert!(facts.hreflang[0].starts_with('p') && facts.hreflang[0].len() == 17);
    assert_eq!(
        &facts.links[..2],
        ["r0", "r2"],
        "a trailing slash is the desktop's same page"
    );
    assert!(
        facts.links[2].starts_with('p'),
        "an unscanned page of the site is a path key"
    );
    assert_eq!(facts.links.len(), 3, "a link with a query is dropped");
}

#[test]
fn compared_values_are_digests_of_the_whole_normalized_value() {
    let page = |title: &str| {
        facts(
            ROUTES[0],
            ROUTES[0],
            &format!("<html><head><title>{title}</title><meta name=\"description\" content=\"{title}\"></head><body><h1>{title}</h1></body></html>"),
        )
    };
    let shouted = page("  Welcome   Home ").expect("named");
    let quiet = page("welcome home").expect("named");
    assert_eq!(
        (&shouted.title, &shouted.description, &shouted.h1),
        (&quiet.title, &quiet.description, &quiet.h1),
        "the analysis's own trim and ASCII lowercase"
    );
    for value in [&shouted.title, &shouted.description, &shouted.h1] {
        assert_eq!(value.as_deref().map(str::len), Some(64));
    }
    let long = "\u{e9}".repeat(299);
    let first = page(&format!("{long}a")).expect("named");
    let second = page(&format!("{long}b")).expect("named");
    for (first, second) in [
        (&first.title, &second.title),
        (&first.description, &second.description),
        (&first.h1, &second.h1),
    ] {
        assert_ne!(first, second, "the digest covers the whole value");
    }
    let empty = page("").expect("named");
    assert_eq!(
        (empty.title, empty.description, empty.h1),
        (None, None, None)
    );
}

#[test]
fn a_page_with_two_titles_compares_by_the_first() {
    let page = |body: &str| facts(ROUTES[0], ROUTES[0], body).expect("named");
    let doubled = page("<html><head><title>Menu</title><title>Other</title></head></html>");
    let single = page("<html><head><title>Menu</title></head></html>");
    assert_eq!(doubled.title, single.title);
}

#[test]
fn a_title_with_invalid_utf8_is_not_compared() {
    let lossy = String::from_utf8_lossy(b"<html><head><title>Caf\xe9 menu</title></head></html>");
    let named = facts(ROUTES[1], ROUTES[1], &lossy).expect("named");
    assert_eq!(
        named.title, None,
        "a decode that replaced bytes leaves nothing to compare"
    );
    let json = serde_json::to_string(&named).expect("facts serialize");
    assert!(
        !json.contains("menu"),
        "no word of the page reaches its facts"
    );
}

#[test]
fn an_error_page_keeps_nothing_read_from_its_body() {
    let mut page = artifact(
        ROUTES[1],
        ROUTES[1],
        concat!(
            "<html><head><title>Not found</title>",
            "<link rel=\"canonical\" href=\"https://example.com/\"></head>",
            "<body><h1>Gone</h1><a href=\"/hours\">Hours</a></body></html>"
        ),
    );
    page.status_code = 404;
    let kept = session_page(&SessionPageRequest {
        page,
        probe_outcomes: Vec::new(),
        routes: ROUTES.iter().map(|route| route.to_string()).collect(),
    })
    .expect("facts build")
    .expect("the page can be named");
    assert_eq!((kept.page.as_str(), kept.status_code), ("r1", 404));
    assert_eq!((kept.title, kept.h1, kept.canonical), (None, None, None));
    assert!(kept.links.is_empty() && kept.hreflang.is_empty());
}

#[test]
fn an_address_with_credentials_is_elsewhere() {
    let body = concat!(
        "<html><head><link rel=\"canonical\" href=\"https://admin:pw@example.com/hours\"></head><body>",
        "<a href=\"https://admin:pw@example.com/menu\">Menu</a><a href=\"/hours\">Hours</a></body></html>"
    );
    let kept = facts(ROUTES[0], ROUTES[0], body).expect("named");
    assert_eq!(kept.canonical.as_deref(), Some(ELSEWHERE));
    assert_eq!(
        kept.links,
        ["r2"],
        "the credentialed link is dropped and the plain one kept"
    );
}

#[test]
fn a_page_whose_own_address_has_a_query_keeps_no_facts() {
    assert_eq!(
        facts(
            "https://example.com/menu?ref=mail",
            ROUTES[1],
            "<html></html>"
        ),
        None
    );
}

#[test]
fn a_redirect_to_an_unplanned_path_is_named_by_its_path_key() {
    let moved = facts("https://example.com/our-menu", ROUTES[1], "<html></html>").expect("named");
    assert!(moved.page.starts_with('p'));
    assert_eq!(moved.requested, "r1");
}

#[test]
fn the_cross_page_checks_are_named_session_scope_by_one_route() {
    let manifest = capability_manifest();
    let mut session: Vec<&str> = manifest
        .entries
        .iter()
        .filter(|entry| entry.scope == CheckScope::Session)
        .map(|entry| {
            assert_eq!(entry.hosted, HostedLane::Artifact, "{}", entry.check);
            entry.check.as_str()
        })
        .collect();
    let mut analyzed: Vec<&str> = SESSION_CHECK_IDS.to_vec();
    session.sort_unstable();
    analyzed.sort_unstable();
    assert_eq!(
        session, analyzed,
        "the analysis produces exactly the session rows"
    );
    let response = evaluate(&EvaluationRequest {
        page: artifact(ROUTES[0], ROUTES[0], "<html></html>"),
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    })
    .expect("evaluates");
    for id in SESSION_CHECK_IDS {
        let entry = response
            .not_evaluated
            .iter()
            .find(|verdict| verdict.check == *id)
            .expect("named");
        assert_eq!(entry.reason, NotEvaluatedReason::SessionScope, "{id}");
    }
}

fn response(url: &str, status: u16, body: &str, sitemap: bool) -> ExecutedProbe {
    ExecutedProbe {
        key: probe_key(&if sitemap {
            sitemap_request(url)
        } else {
            ProbeRequest::get(url)
        }),
        outcome: ProbeOutcome::Response(ProbeResponse {
            status,
            final_url: url.into(),
            content_type: Some(
                if sitemap {
                    "application/xml"
                } else {
                    "text/plain"
                }
                .into(),
            ),
            content_length: None,
            headers: Vec::new(),
            body: Some(decode_probe_body(body.as_bytes().to_vec())),
        }),
    }
}

#[test]
fn unread_declared_sitemaps_withhold_a_clean_noindex_verdict() {
    let root = session_page(&SessionPageRequest {
        page: artifact(ROUTES[0], ROUTES[0], "<html></html>"),
        routes: vec![ROUTES[0].into(), "https://example.com/private".into()],
        probe_outcomes: vec![
            response(
                "https://example.com/robots.txt",
                200,
                "Sitemap: https://example.com/pages.xml\nSitemap: https://example.com/posts.xml",
                false,
            ),
            response(
                "https://example.com/pages.xml",
                200,
                "<urlset><url><loc>https://example.com/</loc></url></urlset>",
                true,
            ),
            response(
                "https://example.com/posts.xml",
                200,
                "<urlset><url><loc>https://example.com/private</loc></url></urlset>",
                true,
            ),
        ],
    })
    .expect("facts")
    .expect("named");
    let private = session_page(&SessionPageRequest {
        page: artifact(
            "https://example.com/private",
            "https://example.com/private",
            "<meta name=\"robots\" content=\"noindex\">",
        ),
        routes: vec![ROUTES[0].into(), "https://example.com/private".into()],
        probe_outcomes: Vec::new(),
    })
    .expect("facts")
    .expect("named");
    let answer = evaluate_session(&SessionRequest {
        pages: vec![root.clone(), private],
    });
    let verdict = answer
        .verdicts
        .iter()
        .find(|v| v.check_id == "seo.noindex_in_sitemap")
        .expect("verdict");
    assert_eq!(verdict.status, CheckStatus::Skipped);
    let sitemap = root.sitemap.expect("sitemap");
    assert_eq!(
        sitemap.partial_causes,
        [SessionSitemapCause::UnreadDeclarations { count: 1 }]
    );
    assert_eq!(
        sitemap.partial_because().as_deref(),
        Some("robots.txt declares 1 further sitemap that was not read")
    );
}

#[test]
fn an_index_keeps_every_cause_of_its_partial_set() {
    for (robots, reason) in [
        (
            "",
            "the sitemap index lists 0 child sitemaps and SiteCMD read the first 0",
        ),
        (
            "Sitemap: https://example.com/sitemap.xml\nSitemap: https://example.com/pages.xml",
            concat!(
                "the sitemap index lists 0 child sitemaps and SiteCMD read the first 0; ",
                "robots.txt declares 1 further sitemap that was not read",
            ),
        ),
    ] {
        let facts = session_page(&SessionPageRequest {
            page: artifact(ROUTES[0], ROUTES[0], "<html></html>"),
            routes: ROUTES.iter().map(|route| route.to_string()).collect(),
            probe_outcomes: vec![
                response("https://example.com/robots.txt", 200, robots, false),
                response(
                    "https://example.com/sitemap.xml",
                    200,
                    "<sitemapindex/>",
                    true,
                ),
            ],
        })
        .expect("facts")
        .expect("named");
        let sitemap = facts.sitemap.expect("sitemap");
        assert_eq!(sitemap.partial_because().as_deref(), Some(reason));
    }
}

#[test]
fn every_supplied_sitemap_cause_has_a_reason() {
    use serde_json::json;
    use sitecmd_engine::checks::seo::sitemap_walk::SITEMAP_URL_LIMIT;

    for (cause, reason) in [
        (
            json!({"cause": "index", "listed": 0}),
            "the sitemap index lists 0 child sitemaps and SiteCMD read the first 0".to_string(),
        ),
        (
            json!({"cause": "url_limit", "listed": SITEMAP_URL_LIMIT - 1}),
            format!(
                "the sitemap lists {} URLs and SiteCMD read the first {SITEMAP_URL_LIMIT}",
                SITEMAP_URL_LIMIT - 1
            ),
        ),
        (
            json!({"cause": "unread_declarations", "count": 0}),
            "robots.txt declares 0 further sitemaps that were not read".to_string(),
        ),
    ] {
        let sitemap: SessionSitemapFacts = serde_json::from_value(json!({
            "entries": [], "partial_causes": [cause]
        }))
        .expect("causes describe the set without a redundant flag");
        assert_eq!(sitemap.partial_because().as_deref(), Some(reason.as_str()));
        assert!(serde_json::to_value(sitemap)
            .expect("wire facts")
            .get("partial")
            .is_none());
    }
}
