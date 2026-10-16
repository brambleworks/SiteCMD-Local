//! Plain robots.txt bodies remain readable when the server labels them HTML.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::checks::seo::robots::{
    evaluate_robots_txt, robots_fetch_from_probe, RobotsTxtFetch,
};
use sitecmd_engine::checks::seo::robots_directives::evaluate_sitemap_in_robots;
use sitecmd_engine::checks::seo::sitemap_walk::sitemap_candidates;
use sitecmd_engine::probe::looks_like_html_shell;
use sitecmd_engine::CheckStatus;

#[test]
fn plain_robots_with_an_html_type_keeps_its_sitemap_declarations() {
    let text = "User-agent: *\nAllow: /\nSitemap: https://example.com/custom.xml";
    let fetch = robots_fetch_from_probe(response(
        &format!("{ORIGIN}/robots.txt"),
        200,
        "text/html; charset=utf-8",
        text,
    ));
    assert_eq!(
        sitemap_candidates(ORIGIN, &fetch)[0],
        "https://example.com/custom.xml"
    );
    assert_eq!(
        evaluate_sitemap_in_robots(&fetch)[0].status,
        CheckStatus::Pass
    );
    assert!(looks_like_html_shell("text/html", text));
}

#[test]
fn a_wrong_html_type_warns_without_losing_the_rules_outcome() {
    for body in ["User-agent: *\nAllow: /", "User-agent: *\nDisallow: /"] {
        let plain = evaluate_robots_txt(&robots_fetch_from_probe(response(
            "https://example.com/robots.txt",
            200,
            "text/plain",
            body,
        )))
        .remove(0);
        let html = evaluate_robots_txt(&robots_fetch_from_probe(response(
            "https://example.com/robots.txt",
            200,
            "Text/Html; charset=utf-8",
            body,
        )))
        .remove(0);
        assert_eq!(html.status, CheckStatus::Warn);
        assert_eq!(html.severity, plain.severity);
        assert_eq!(html.raw_data, plain.raw_data);
        assert!(html
            .description
            .contains("robots.txt is served as text/html; text/plain is expected."));
        assert!(html
            .manual_fix
            .as_deref()
            .expect("fix")
            .contains("Serve robots.txt with a Content-Type header of text/plain."));
    }
}

#[test]
fn html_bodies_remain_html_shells_for_every_media_type() {
    for content_type in ["text/html", "text/plain"] {
        for (body, plain_is_html) in [
            ("  <!doctype html><html>App</html>", true),
            ("\u{feff}  <!doctype html><html>App</html>", false),
            (" <!-- built --><html>App</html>", false),
            (" <?xml version='1.0'?><html>App</html>", false),
            (" <head><title>App</title></head>", false),
        ] {
            let fetch = robots_fetch_from_probe(response(
                "https://example.com/robots.txt",
                200,
                content_type,
                body,
            ));
            let html = content_type == "text/html" || plain_is_html;
            assert_eq!(
                matches!(fetch, RobotsTxtFetch::HtmlShell),
                html,
                "{content_type} {body:?}"
            );
            if html {
                assert_eq!(evaluate_robots_txt(&fetch)[0].status, CheckStatus::Skipped);
            } else {
                assert!(matches!(fetch, RobotsTxtFetch::Found { .. }));
            }
        }
    }
}
