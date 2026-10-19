//! What an entry route's own reads discover for its scan: the same-origin
//! pages its document links to, then the sitemap walk's pages, an index's
//! through its children, as canonical routes the hosted service may store
//! unchanged, none of them a file, and nothing the route did not already
//! request.

#[path = "support/discovery.rs"]
mod support;

use sitecmd_engine::checks::seo::links::BROKEN_LINK_INTERNAL_SAMPLE;
use sitecmd_engine::probe::ProbeRequest;
pub use support::*;

#[test]
fn home_links_lead_in_document_order_then_the_sitemap_pages() {
    let pages = with_sitemap(&[
        "https://example.com/about",
        "https://example.com/blog/",
        "https://example.com/contact",
    ]);
    let page = artifact(
        &home("<a href='/pricing'>Plans</a><a href='about'>About</a><a href='/pricing'>Again</a>"),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&pages), &[], LIMIT),
        routes(&["/pricing", "/about", "/blog/", "/contact"])
    );
}

#[test]
fn the_entry_route_and_the_page_it_redirected_to_are_never_discovered() {
    let page = artifact(
        &home("<a href='/'>Home</a><a href='/en/'>English</a><a href='/en/menu'>Menu</a>"),
        200,
        "/en/",
    );
    assert_eq!(
        discovered(page, site(&[]), &[], LIMIT),
        routes(&["/en/menu"])
    );
}

#[test]
fn only_the_pages_own_origin_is_discovered() {
    let pages = with_sitemap(&["https://www.example.com/listed", "https://example.com/kept"]);
    let page = artifact(
        &home(concat!(
            "<a href='https://www.example.com/twin'>a</a>",
            "<a href='http://example.com/plain'>b</a>",
            "<a href='https://example.com:8443/port'>c</a>",
            "<a href='https://elsewhere.example/x'>d</a>",
            "<a href='//example.com/same'>e</a>",
        )),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&pages), &[], LIMIT),
        routes(&["/same", "/kept"])
    );
}

#[test]
fn an_address_with_a_query_or_credentials_is_never_kept_and_a_fragment_is_dropped() {
    // A lone user name, a lone password, or a query must not become an ordinary path.
    let page = artifact(
        &home(concat!(
            "<a href='/shop?page=2'>a</a>",
            "<a href='https://user:secret@example.com/private'>b</a>",
            "<a href='https://user@example.com/named'>e</a>",
            "<a href='https://:secret@example.com/hidden'>f</a>",
            "<a href='/guide#install'>c</a>",
            "<a href='#top'>d</a>",
        )),
        200,
        "/",
    );
    assert_eq!(discovered(page, site(&[]), &[], LIMIT), routes(&["/guide"]));
}

#[test]
fn an_address_the_storage_rules_would_change_is_left_out_and_a_named_page_is_kept() {
    let long = "a".repeat(600);
    let anchors = format!(
        "{}{}{}{}{}{}{}",
        "<a href='/search/blue-shoes'>a</a>",
        "<a href='/users/jane@example.com'>b</a>",
        "<a href='/reset/abc123'>c</a>",
        "<a href='/files/3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e'>d</a>",
        "<a href='/share/sk-proj1234567890abcdefghij'>e</a>", // gitleaks:allow
        format_args!("<a href='/{long}'>f</a>"),
        "<a href='/team/jane-doe'>g</a>",
    );
    let page = artifact(&home(&anchors), 200, "/");
    assert_eq!(
        discovered(page, site(&[]), &[], LIMIT),
        routes(&["/team/jane-doe"])
    );
}

#[test]
fn a_visitor_written_link_is_not_discovered() {
    let page = artifact(
        &home(
            "<a rel='nofollow ugc' href='/u/someone'>a</a><a rel='nofollow' href='/partners'>b</a>",
        ),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&[]), &[], LIMIT),
        routes(&["/partners"])
    );
}

#[test]
fn a_link_the_link_check_found_missing_or_not_a_page_is_left_out() {
    let pages = [
        (
            "https://example.com/gone",
            response("https://example.com/gone", 404, "text/html", ""),
        ),
        (
            "https://example.com/menu",
            response("https://example.com/menu", 200, "application/pdf", ""),
        ),
        (
            "https://example.com/old",
            response(
                "https://example.com/new",
                200,
                "text/html; charset=utf-8",
                "",
            ),
        ),
        (
            "https://example.com/login",
            response("https://example.com/login?next=%2F", 200, "text/html", ""),
        ),
        (
            "https://example.com/away",
            response("https://elsewhere.example/landing", 200, "text/html", ""),
        ),
    ];
    let page = artifact(
        &home(concat!(
            "<a href='/gone'>a</a><a href='/menu'>b</a><a href='/old'>c</a>",
            "<a href='/login'>d</a><a href='/away'>e</a><a href='/kept'>f</a>",
        )),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&pages), &[], LIMIT),
        routes(&["/new", "/kept"])
    );
}

#[test]
fn a_link_past_the_link_checks_sample_is_discovered_unprobed() {
    // Every page the link check asked about answers 404; the one past its
    // sorted sample was never asked about.
    let anchors: String = (0..=BROKEN_LINK_INTERNAL_SAMPLE)
        .map(|index| format!("<a href='/p{index:03}'>p</a>"))
        .collect();
    let page = artifact(&home(&anchors), 200, "/");
    let answer = |request: &ProbeRequest| response(&request.url, 404, "text/html", "");
    let last = format!("/p{BROKEN_LINK_INTERNAL_SAMPLE:03}");
    assert_eq!(
        discovered(page, answer, &[], LIMIT),
        routes(&[last.as_str()])
    );
}

#[test]
fn the_cap_cuts_in_priority_order() {
    let pages = with_sitemap(&["https://example.com/three", "https://example.com/four"]);
    let page = artifact(&home("<a href='/one'>1</a><a href='/two'>2</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &[], 3),
        routes(&["/one", "/two", "/three"])
    );
}

#[test]
fn routes_take_the_protocols_canonical_identity() {
    let page = artifact(
        &home(concat!(
            "<a href='/a/./b/../c'>1</a><a href='/%7Euser'>2</a><a href='/~user'>3</a>",
            "<a href='/docs'>4</a><a href='/docs/'>5</a>",
        )),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&[]), &[], LIMIT),
        routes(&["/a/c", "/~user", "/docs", "/docs/"])
    );
}

#[test]
fn a_cdn_reserved_path_is_not_a_page() {
    let page = artifact(
        &home("<a href='/cdn-cgi/l/email-protection#abc'>mail</a><a href='/contact'>Contact</a>"),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&[]), &[], LIMIT),
        routes(&["/contact"])
    );
}

#[test]
fn an_error_answer_discovers_nothing() {
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 500, "/");
    assert_eq!(discovered(page, site(&[]), &["/kept"], LIMIT), None);
}

#[test]
fn a_sitemap_that_did_not_answer_keeps_the_planned_routes_in_its_place() {
    let answer = |request: &ProbeRequest| {
        let status = if request.url.contains("sitemap") {
            503
        } else {
            200
        };
        response(&request.url, status, "text/html", "")
    };
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/listed", "/pricing"], LIMIT),
        routes(&["/pricing", "/listed"])
    );
}

#[test]
fn a_robots_txt_that_did_not_answer_keeps_the_planned_routes_when_no_sitemap_was_found() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => response(&request.url, 503, "text/plain", ""),
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
fn a_sitemap_found_after_robots_failed_keeps_the_planned_routes() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => response(&request.url, 503, "text/plain", ""),
        SITEMAP_URL => response(
            &request.url,
            200,
            "application/xml",
            &urlset(&["https://example.com/about"]),
        ),
        url => response(url, 200, "text/html", ""),
    };
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/listed"], LIMIT),
        routes(&["/listed"])
    );
}

#[test]
fn a_sitemap_found_after_a_declared_sitemap_failed_keeps_the_planned_routes() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => response(
            &request.url,
            200,
            "text/plain",
            "Sitemap: https://example.com/declared.xml",
        ),
        "https://example.com/declared.xml" => response(&request.url, 503, "application/xml", ""),
        SITEMAP_URL => response(
            &request.url,
            200,
            "application/xml",
            &urlset(&["https://example.com/about"]),
        ),
        url => response(url, 200, "text/html", ""),
    };
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/listed"], LIMIT),
        routes(&["/pricing", "/about", "/listed"])
    );
}

#[test]
fn a_missing_declared_sitemap_leaves_the_found_sitemap_complete() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => response(
            &request.url,
            200,
            "text/plain",
            "Sitemap: https://example.com/declared.xml",
        ),
        "https://example.com/declared.xml" => response(&request.url, 404, "application/xml", ""),
        SITEMAP_URL => response(
            &request.url,
            200,
            "application/xml",
            &urlset(&["https://example.com/about"]),
        ),
        url => response(url, 200, "text/html", ""),
    };
    let page = artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/");
    assert_eq!(
        discovered(page, answer, &["/listed"], LIMIT),
        routes(&["/pricing", "/about"])
    );
}

#[test]
fn a_site_with_no_sitemap_and_no_links_discovers_none() {
    let answer = |request: &ProbeRequest| response(&request.url, 404, "text/html", "");
    let page = artifact(&home(""), 200, "/");
    assert_eq!(discovered(page, answer, &["/listed"], LIMIT), routes(&[]));
}

#[test]
fn a_media_type_with_an_html_prefix_is_not_an_html_page() {
    let pages = [
        (
            "https://example.com/sandboxed",
            response(
                "https://example.com/sandboxed",
                200,
                "text/html-sandboxed",
                "",
            ),
        ),
        (
            "https://example.com/html",
            response(
                "https://example.com/html",
                200,
                " TeXT/HTML ; charset=utf-8",
                "",
            ),
        ),
        (
            "https://example.com/xhtml",
            response(
                "https://example.com/xhtml",
                200,
                " APPLICATION/XHTML+XML ; charset=utf-8",
                "",
            ),
        ),
    ];
    let page = artifact(
        &home("<a href='/sandboxed'>a</a><a href='/html'>b</a><a href='/xhtml'>c</a>"),
        200,
        "/",
    );
    assert_eq!(
        discovered(page, site(&pages), &[], LIMIT),
        routes(&["/html", "/xhtml"])
    );
}

#[test]
fn a_probed_sitemap_redirect_is_discovered_only_at_its_destination() {
    // A probed redirect listed in a sitemap must not add its original path.
    let mut pages = Vec::from(with_sitemap(&["https://example.com/old"]));
    pages.push((
        "https://example.com/old",
        response("https://example.com/new", 200, "text/html", ""),
    ));
    let page = artifact(&home("<a href='/old'>Old</a>"), 200, "/");
    assert_eq!(
        discovered(page, site(&pages), &[], LIMIT),
        routes(&["/new"])
    );
}
