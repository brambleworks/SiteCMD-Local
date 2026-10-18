//! Route selection retains document order through rejected and repeated links.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::checks::seo::links::BROKEN_LINK_INTERNAL_SAMPLE;
use sitecmd_engine::probe::{ProbeMethod, ProbeOutcome, ProbeRequest};
use std::cell::Cell;

fn robots_disallows_everything(request: &ProbeRequest) -> ProbeOutcome {
    if request.method == ProbeMethod::Get && request.url == format!("{ORIGIN}/robots.txt") {
        response(
            &request.url,
            200,
            "text/plain",
            "User-agent: *\nDisallow: /",
        )
    } else {
        response(&request.url, 200, "text/html", "")
    }
}

#[test]
fn encoded_then_plain_robots_txt_has_one_canonical_selection() {
    for encoded in ["/robot%73.txt", "/robots%2Etxt", "/robots%2etxt"] {
        for paths in [[encoded, "/robots.txt"], ["/robots.txt", encoded]] {
            let links = format!(
                "<a href='{}'>First</a><a href='{}'>Second</a>",
                paths[0], paths[1]
            );
            assert_eq!(
                discovered(
                    artifact(&home(&links), 200, "/"),
                    robots_disallows_everything,
                    &[],
                    LIMIT
                ),
                routes(&["/robots.txt"]),
                "{paths:?}"
            );
        }
    }
}

#[test]
fn an_encoded_robots_txt_link_is_implicitly_allowed() {
    let page = artifact(&home("<a href='/robot%73.txt'>Robots</a>"), 200, "/");
    assert_eq!(
        discovered(page, robots_disallows_everything, &[], LIMIT),
        routes(&["/robots.txt"])
    );
}

#[test]
fn robots_txt_spellings_past_the_probe_sample_share_the_exemption() {
    let mut links: String = (0..BROKEN_LINK_INTERNAL_SAMPLE + 20)
        .map(|index| format!("<a href='/a{index:03}'>Page</a>"))
        .collect();
    links.push_str("<a href='/robot%73.txt'>Encoded</a><a href='/robots.txt'>Plain</a>");
    let robots_heads = Cell::new(0);
    let answer = |request: &ProbeRequest| {
        if request.method == ProbeMethod::Head && request.url.contains("/robot") {
            robots_heads.set(robots_heads.get() + 1);
        }
        robots_disallows_everything(request)
    };
    assert_eq!(
        discovered(artifact(&home(&links), 200, "/"), answer, &[], LIMIT),
        routes(&["/robots.txt"])
    );
    assert_eq!(robots_heads.get(), 0);
}

#[test]
fn redirected_robots_txt_spellings_share_the_exemption() {
    for targets in [
        ["/robot%73.txt", "/robots.txt"],
        ["/robots.txt", "/robots%2Etxt"],
    ] {
        let answer = |request: &ProbeRequest| match request.url.as_str() {
            "https://example.com/first" => {
                response(&format!("{ORIGIN}{}", targets[0]), 200, "text/html", "")
            }
            "https://example.com/second" => {
                response(&format!("{ORIGIN}{}", targets[1]), 200, "text/html", "")
            }
            _ => robots_disallows_everything(request),
        };
        assert_eq!(
            discovered(
                artifact(
                    &home("<a href='/first'>First</a><a href='/second'>Second</a>"),
                    200,
                    "/"
                ),
                answer,
                &[],
                LIMIT
            ),
            routes(&["/robots.txt"]),
            "{targets:?}"
        );
    }
}

#[test]
fn an_encoded_robots_txt_redirect_target_is_implicitly_allowed() {
    let answer = |request: &ProbeRequest| {
        if request.url == format!("{ORIGIN}/old") {
            response(&format!("{ORIGIN}/robot%73.txt"), 200, "text/html", "")
        } else {
            robots_disallows_everything(request)
        }
    };
    assert_eq!(
        discovered(
            artifact(&home("<a href='/old'>Robots</a>"), 200, "/"),
            answer,
            &[],
            LIMIT
        ),
        routes(&["/robots.txt"])
    );
}

#[test]
fn many_rejected_links_preserve_the_first_kept_routes_at_the_limit() {
    let mut links = String::from("<a href='/'>Home</a><a href='/en/'>English</a>");
    for index in 0..150 {
        links.push_str(&format!(
            "<a href='/{index}.css'>File</a><a href='/search/{index}'>Search</a>\
             <a href='/private/{index}'>Private</a><a href='/search/{index}'>Again</a>"
        ));
        if index % 20 == 0 {
            links.push_str(&format!(
                "<a href='/page/{index}#top'>Page</a><a href='/page/{index}'>Again</a>"
            ));
        }
    }
    let pages = [(
        "https://example.com/robots.txt",
        response(
            "https://example.com/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nDisallow: /private",
        ),
    )];
    assert_eq!(
        discovered(artifact(&home(&links), 200, "/en/"), site(&pages), &[], 5),
        routes(&["/page/0", "/page/20", "/page/40", "/page/60", "/page/80"])
    );
}
