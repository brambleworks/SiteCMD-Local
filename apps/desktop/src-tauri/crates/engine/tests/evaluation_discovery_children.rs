//! Route discovery with incomplete reads and static file exclusions.

#[path = "support/discovery.rs"]
mod support;

pub use support::*;

use sitecmd_engine::probe::{ProbeFailure, ProbeFailureClass, ProbeOutcome, ProbeRequest};

#[test]
fn an_index_sitemaps_children_supply_its_pages_after_the_links() {
    let pages = an_index_site(response(
        PAGES,
        200,
        "application/xml",
        &urlset(&["https://example.com/about"]),
    ));
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &["/listed"], LIMIT),
        routes(&["/pricing", "/posts/first", "/about"])
    );
}

#[test]
fn a_child_that_did_not_answer_keeps_the_planned_routes_after_the_pages_it_did_read() {
    let pages = an_index_site(response(PAGES, 503, "text/html", ""));
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &["/listed"], LIMIT),
        routes(&["/pricing", "/posts/first", "/listed"])
    );
}

#[test]
fn a_route_that_reads_no_children_takes_no_pages_from_an_index() {
    let pages = an_index_site(response(
        PAGES,
        200,
        "application/xml",
        &urlset(&["https://example.com/about"]),
    ));
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered_with(0, page, site(&pages), &["/listed"], LIMIT),
        routes(&["/pricing"])
    );
}

#[test]
fn a_file_cloudflare_caches_by_default_is_never_discovered() {
    let pages = with_sitemap(&[
        "https://example.com/brochure.pdf",
        "https://example.com/guide",
    ]);
    let page = artifact(
        &home(concat!(
            "<a href='/menu.PDF'>a</a><a href='/app.js'>b</a><a href='/archive.tar.gz'>c</a>",
            "<a href='/about.html'>d</a><a href='/notes.txt'>e</a><a href='/v1.2/'>f</a>",
        )),
        200,
        "/",
    );
    // HTML is not on the list, and neither is TXT: those routes' own media
    // types decide them when they are fetched.
    assert_eq!(
        discovered(page, site(&pages), &[], LIMIT),
        routes(&["/about.html", "/notes.txt", "/v1.2/", "/guide"])
    );
}

#[test]
fn a_child_transport_failure_keeps_the_planned_routes_after_the_pages_it_did_read() {
    let pages = an_index_site(ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::Transport,
        detail: "request timed out".into(),
    }));
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &["/listed"], LIMIT),
        routes(&["/pricing", "/posts/first", "/listed"])
    );
}

#[test]
fn a_robots_transport_failure_keeps_the_planned_routes_when_no_sitemap_was_found() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => ProbeOutcome::Failure(ProbeFailure {
            class: ProbeFailureClass::Transport,
            detail: "request timed out".into(),
        }),
        url if url.contains("sitemap") => response(url, 404, "text/html", ""),
        url => response(url, 200, "text/html", ""),
    };
    let page = artifact(&home(""), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/listed"], LIMIT),
        routes(&["/listed"])
    );
}

#[test]
fn a_planned_route_the_link_check_found_gone_is_not_offered() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/gone" => response(&request.url, 404, "text/html", ""),
        url if url.contains("sitemap") => response(url, 503, "text/html", ""),
        url => response(url, 200, "text/html", ""),
    };
    let page = artifact(&home("<a href='/gone'>Gone</a>"), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/gone", "/listed"], LIMIT),
        routes(&["/listed"])
    );
}

#[test]
fn a_complete_index_after_robots_failed_keeps_the_planned_routes() {
    let mut pages = an_index_site(response(
        PAGES,
        200,
        "application/xml",
        &urlset(&["https://example.com/about"]),
    ))
    .to_vec();
    pages.push((
        "https://example.com/robots.txt",
        response("https://example.com/robots.txt", 503, "text/plain", ""),
    ));
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &["/listed"], LIMIT),
        routes(&["/listed"])
    );
}

#[test]
fn an_oversized_robots_answer_keeps_only_planned_routes_despite_a_sitemap() {
    let mut pages = with_sitemap(&["https://example.com/about"]).to_vec();
    pages.push((
        "https://example.com/robots.txt",
        ProbeOutcome::Failure(ProbeFailure {
            class: ProbeFailureClass::BodyCapExceeded,
            detail: "body exceeded cap".into(),
        }),
    ));
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &["/listed"], LIMIT),
        routes(&["/listed"])
    );
}

#[test]
fn an_oversized_robots_answer_with_no_sitemap_keeps_the_planned_routes() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => ProbeOutcome::Failure(ProbeFailure {
            class: ProbeFailureClass::BodyCapExceeded,
            detail: "body exceeded cap".into(),
        }),
        url if url.contains("sitemap") => response(url, 404, "text/html", ""),
        url => response(url, 200, "text/html", ""),
    };
    let page = artifact(&home(""), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/listed"], LIMIT),
        routes(&["/listed"])
    );
}
