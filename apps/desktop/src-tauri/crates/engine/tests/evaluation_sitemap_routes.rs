// A stored sitemap route carries a search path, a key, a query or another origin, or the list passes its bounds.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::evaluation::{ExecutedProbe, RouteSession};
use sitecmd_engine::probe::{ProbeFailure, ProbeFailureClass, ProbeOutcome};

fn route(pages: &[(&str, ProbeOutcome)]) -> RouteSession {
    let mut route = RouteSession::open(artifact(&home(""), 200, "/"))
        .expect("route")
        .with_sitemap_children(CHILDREN);
    for _ in 0..40 {
        let plan = route.plan();
        if plan.probes.is_empty() {
            return route;
        }
        route.record(Some(
            plan.probes
                .into_iter()
                .map(|probe| ExecutedProbe::new(probe.key, site(pages)(&probe.request)))
                .collect(),
        ));
    }
    panic!("probe plan never finished");
}

#[test]
fn sitemap_routes_share_discovery_gates_without_requiring_page_reachability() {
    // Built at run time so the fixture is never a key-shaped literal in the source.
    let key_route = format!("https://example.com/d/sk_live_{}", "x".repeat(24));
    let pages = with_sitemap(&[
        "https://example.com/a",
        "https://example.com/search/x",
        "https://example.com/b?x=1",
        "https://other.example/c",
        key_route.as_str(),
        "https://example.com/u/owner@example.com",
        "https://example.com/u/owner%40example.com",
        "https://example.com/u/@owner@example.com",
        "https://example.com/u/owner@example.com@1.0.0",
        "https://example.com/u/owner@example.com@latest",
        "https://example.com/@alice@mastodon.social",
        "https://user:pass@example.com/private",
        "https://example.com/a.css",
        "https://example.com/blocked",
        "https://example.com/blog/top-10-ways-to-improve-your-website-speed",
        "https://example.com/orders/1234567",
        "https://example.com/people/alice",
        "https://example.com/",
        "https://example.com/a",
        "https://example.com/e#x",
    ]);
    let mut pages = pages.to_vec();
    pages.push((
        "https://example.com/robots.txt",
        response(
            "https://example.com/robots.txt",
            200,
            "text/plain",
            "User-agent: SiteCMD\nDisallow: /blocked\nSitemap: https://example.com/sitemap.xml\n",
        ),
    ));
    pages.push((
        "https://example.com/a",
        response("https://example.com/a", 404, "text/html", ""),
    ));
    let mut route = route(&pages);
    let url = url::Url::parse("https://example.com/a").expect("URL");
    route.record(Some(
        [
            sitecmd_engine::checks::seo::links::link_head_request(&url),
            sitecmd_engine::checks::seo::links::link_get_request(&url),
        ]
        .iter()
        .map(|request| {
            ExecutedProbe::new(
                sitecmd_engine::evaluation::probe_key(request),
                response("https://example.com/a", 404, "text/html", ""),
            )
        })
        .collect(),
    ));
    let kept = route.sitemap_routes(5_000, 1_048_576);
    assert_eq!(
        kept.routes,
        routes(&[
            "/a",
            "/blog/top-10-ways-to-improve-your-website-speed",
            "/orders/1234567",
            "/people/alice",
            "/",
            "/e"
        ])
    );
    assert!(kept.complete);
    assert_eq!(
        route.discover(&[], LIMIT).routes,
        routes(&[
            "/blog/top-10-ways-to-improve-your-website-speed",
            "/orders/1234567",
            "/people/alice",
            "/e"
        ])
    );
}

#[test]
fn path_parameters_are_refused_by_both_route_readers() {
    // A matrix parameter persists a session identifier even when it is short.
    let pages = with_sitemap(&[
        "https://example.com/a;jsessionid=1A2B3C4D5E6F7A8B",
        "https://example.com/a;v=1",
        "https://example.com/a",
    ]);
    let route = route(&pages);
    assert_eq!(
        route.sitemap_routes(5_000, 1_048_576).routes,
        routes(&["/a"])
    );
    assert_eq!(route.discover(&[], LIMIT).routes, routes(&["/a"]));
}

#[test]
fn an_index_cut_at_the_page_limit_reports_an_incomplete_read() {
    // A truncated index falsely authorizes deleting pages outside its first 5,000.
    let posts: Vec<_> = (0..5_000)
        .map(|i| format!("https://example.com/posts/{i}"))
        .collect();
    let pages = [
        (
            SITEMAP_URL,
            response(
                SITEMAP_URL,
                200,
                "application/xml",
                &index_of(&[POSTS, PAGES]),
            ),
        ),
        (
            POSTS,
            response(
                POSTS,
                200,
                "application/xml",
                &urlset(&posts.iter().map(String::as_str).collect::<Vec<_>>()),
            ),
        ),
        (
            PAGES,
            response(
                PAGES,
                200,
                "application/xml",
                &urlset(&["https://example.com/last"]),
            ),
        ),
    ];
    let kept = route(&pages).sitemap_routes(5_000, 1_048_576);
    let routes = kept.routes.expect("routes");
    assert_eq!(routes.len(), 5_000);
    assert_eq!(routes.first().map(String::as_str), Some("/posts/0"));
    assert_eq!(routes.last().map(String::as_str), Some("/posts/4999"));
    assert!(!kept.complete);
}

#[test]
fn an_unanswered_index_child_marks_the_routes_incomplete() {
    let pages = an_index_site(ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::Timeout,
        detail: String::new(),
    }));
    let kept = route(&pages).sitemap_routes(5_000, 1_048_576);
    assert_eq!(kept.routes, routes(&["/posts/first"]));
    assert!(!kept.complete);
}

#[test]
fn the_route_count_bound_marks_a_truncated_sitemap_incomplete() {
    let locations: Vec<_> = (0..5_001)
        .map(|i| format!("https://example.com/page/{i}"))
        .collect();
    let pages = with_sitemap(&locations.iter().map(String::as_str).collect::<Vec<_>>());
    let route = route(&pages);
    let kept = route.sitemap_routes(5_000, 1_048_576);
    assert_eq!(kept.routes.expect("routes").len(), 5_000);
    assert!(!kept.complete);
    let kept = route.sitemap_routes(2, 1_048_576);
    assert_eq!(kept.routes, routes(&["/page/0", "/page/1"]));
    assert!(!kept.complete);
}

#[test]
fn the_byte_bound_counts_the_json_array_including_quotes_and_commas() {
    let slug = "word-".repeat(87);
    let locations: Vec<_> = (0..3_000)
        .map(|i| format!("https://example.com/{slug}page/x{i:08}"))
        .collect();
    let pages = with_sitemap(&locations.iter().map(String::as_str).collect::<Vec<_>>());
    let kept = route(&pages).sitemap_routes(5_000, 1_048_576);
    let kept_routes = kept.routes.expect("routes");
    assert_eq!(kept_routes[0].len(), 450);
    assert_eq!(kept_routes.len(), 2_314);
    let bytes = serde_json::to_vec(&kept_routes).expect("JSON").len();
    assert!(bytes <= 1_048_576);
    assert!(bytes + 453 > 1_048_576);
    assert!(!kept.complete);
}

#[test]
fn exact_bounds_and_duplicates_do_not_falsely_mark_a_sitemap_incomplete() {
    let pages = with_sitemap(&[
        "https://example.com/a",
        "https://example.com/a",
        "https://other.example/b",
    ]);
    let route = route(&pages);
    let kept = route.sitemap_routes(1, 6);
    assert_eq!(kept.routes, routes(&["/a"]));
    assert!(kept.complete);
    let too_small = route.sitemap_routes(1, 5);
    assert_eq!(too_small.routes, routes(&[]));
    assert!(!too_small.complete);
    assert!(!route.sitemap_routes(0, 6).complete);
}

#[test]
fn an_error_entry_document_yields_no_sitemap_routes() {
    let route = RouteSession::open(artifact(&home(""), 500, "/")).expect("route");
    let kept = route.sitemap_routes(5_000, 1_048_576);
    assert_eq!(kept.routes, None);
    assert!(!kept.complete);
}
