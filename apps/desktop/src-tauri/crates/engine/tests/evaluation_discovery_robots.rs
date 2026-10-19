//! Route discovery follows the scanner's robots.txt group.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::probe::ProbeRequest;

fn discover_with_rules(rules: &str, links: &str, planned: &[&str]) -> Option<Vec<String>> {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => response(&request.url, 200, "text/plain", rules),
        url if url.contains("sitemap") => response(url, 503, "text/plain", ""),
        url => response(url, 200, "text/html", ""),
    };
    discovered(artifact(&home(links), 200, "/"), answer, planned, LIMIT)
}

#[test]
fn disallowed_links_and_planned_routes_are_not_discovered() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow: /private",
            "<a href='/private/link'>Private</a><a href='/public'>Public</a>",
            &["/private/planned", "/other"]
        ),
        routes(&["/public", "/other"])
    );
}

#[test]
fn a_disallowed_sitemap_page_is_not_discovered() {
    let mut pages =
        with_sitemap(&["https://example.com/private", "https://example.com/public"]).to_vec();
    pages.push((
        "https://example.com/robots.txt",
        response(
            "https://example.com/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nDisallow: /private",
        ),
    ));
    assert_eq!(
        discovered(artifact(&home(""), 200, "/"), site(&pages), &[], LIMIT),
        routes(&["/public"])
    );
}

#[test]
fn the_sitecmd_group_overrides_the_wildcard_case_insensitively() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow: /\nUser-agent: sItEcMd\nDisallow: /private",
            "<a href='/private'>Private</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/public"])
    );
}

#[test]
fn equally_specific_allow_wins_and_longer_rules_take_precedence() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow: /private\nAllow: /private\nDisallow: /private/secret",
            "<a href='/private'>Allowed</a><a href='/private/secret'>Secret</a>",
            &[]
        ),
        routes(&["/private"])
    );
}

#[test]
fn wildcards_and_the_end_anchor_match_the_written_path() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow: /private/*/end$",
            "<a href='/private/a/end'>Blocked</a><a href='/private/a/end/more'>Allowed</a>",
            &[]
        ),
        routes(&["/private/a/end/more"])
    );
}

#[test]
fn repeated_matching_groups_are_combined_and_other_agents_do_not_apply() {
    assert_eq!(
        discover_with_rules(
            concat!(
                "User-agent: SiteCMD\nDisallow: /one\n",
                "User-agent: Other\nDisallow: /public\nUser-agent: SiteCMD\nDisallow: /two"
            ),
            "<a href='/one'>One</a><a href='/two'>Two</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/public"])
    );
}

#[test]
fn unavailable_robots_allows_discovery_except_when_rate_limited() {
    for status in [400, 401, 403, 404, 410, 499] {
        let pages = [(
            "https://example.com/robots.txt",
            response(
                "https://example.com/robots.txt",
                status,
                "text/plain",
                "User-agent: *\nDisallow: /",
            ),
        )];
        assert_eq!(
            discovered(
                artifact(&home("<a href='/public'>Public</a>"), 200, "/"),
                site(&pages),
                &[],
                LIMIT
            ),
            routes(&["/public"])
        );
    }
}

#[test]
fn the_owners_entry_is_read_even_when_the_root_is_disallowed() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow: /\nAllow: /public",
            "<a href='/private'>Private</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/public"])
    );
}

#[test]
fn plain_robots_with_an_html_type_still_filters_discovery() {
    let answer = |request: &ProbeRequest| match request.url.as_str() {
        "https://example.com/robots.txt" => response(
            &request.url,
            200,
            "text/html",
            "User-agent: *\nDisallow: /private",
        ),
        url if url.contains("sitemap") => response(url, 404, "text/plain", ""),
        url => response(url, 200, "text/html", ""),
    };
    assert_eq!(
        discovered(
            artifact(
                &home("<a href='/private'>Private</a><a href='/public'>Public</a>"),
                200,
                "/"
            ),
            answer,
            &[],
            LIMIT
        ),
        routes(&["/public"])
    );
}

#[test]
fn a_logged_user_agent_value_selects_the_scanners_group() {
    let logged = sitecmd_engine::agent::user_agent("1.5");
    for agent in [
        logged
            .split_whitespace()
            .next()
            .expect("product and version"),
        "SiteCMD (+https://sitecmd.com/scanner)",
    ] {
        assert_eq!(
            discover_with_rules(
                &format!("User-agent: *\nAllow: /\nUser-agent: {agent}\nDisallow: /private"),
                "<a href='/private'>Private</a><a href='/public'>Public</a>",
                &[]
            ),
            routes(&["/public"]),
            "{agent}"
        );
    }
}

#[test]
fn lone_carriage_returns_separate_robots_lines() {
    assert_eq!(
        discover_with_rules(
            "User-agent: SiteCMD\rDisallow: /private\r",
            "<a href='/private'>Private</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/public"])
    );
}

#[test]
fn an_empty_disallow_keeps_both_links() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow:",
            "<a href='/private'>Private</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/private", "/public"])
    );
}

#[test]
fn a_trailing_comment_is_not_a_disallow_path() {
    assert_eq!(
        discover_with_rules(
            "User-agent: *\nDisallow: /private # staff only",
            "<a href='/private'>Private</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/public"])
    );
}

#[test]
fn a_byte_order_mark_does_not_hide_the_first_group() {
    assert_eq!(
        discover_with_rules(
            "\u{feff}User-agent: *\nDisallow: /private",
            "<a href='/private'>Private</a><a href='/public'>Public</a>",
            &[]
        ),
        routes(&["/public"])
    );
}
