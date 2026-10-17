//! Robots.txt readers agree across CR, LF and CRLF records and product tokens.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::checks::seo::robots::{evaluate_robots_txt, RobotsTxtFetch};
use sitecmd_engine::checks::seo::robots_directives::{
    evaluate_sitemap_in_robots, has_sitemap_directive,
};
use sitecmd_engine::checks::seo::sitemap::{
    evaluate_sitemap, sitemap_urls_from_robots, SitemapProbe,
};
use sitecmd_engine::checks::seo::sitemap_walk::{sitemap_candidates, sitemap_request};
use sitecmd_engine::evaluation::{
    evaluate, probe_key, session_page, EvaluationRequest, ExecutedProbe, SessionPageRequest,
    SessionSitemapCause,
};
use sitecmd_engine::probe::ProbeRequest;
use sitecmd_engine::CheckStatus;

const BODY: &str = "User-agent: *\nDisallow: /\nSitemap: https://example.com/custom.xml\n";

fn variants(body: &str) -> [String; 3] {
    [
        body.into(),
        body.replace('\n', "\r"),
        body.replace('\n', "\r\n"),
    ]
}

#[test]
fn discovery_keeps_the_lf_answer_for_every_line_ending() {
    for body in variants(BODY) {
        let pages = [
            (
                "https://example.com/robots.txt",
                response("https://example.com/robots.txt", 200, "text/plain", &body),
            ),
            (
                "https://example.com/custom.xml",
                response(
                    "https://example.com/custom.xml",
                    200,
                    "application/xml",
                    &urlset(&["https://example.com/public"]),
                ),
            ),
        ];
        assert_eq!(
            discovered(
                artifact(&home("<a href='/public'>Public</a>"), 200, "/"),
                site(&pages),
                &[],
                LIMIT
            ),
            routes(&[])
        );
    }
}

#[test]
fn robots_policy_keeps_the_lf_answer_for_every_line_ending() {
    let expected = evaluate_robots_txt(&RobotsTxtFetch::Found { body: BODY.into() });
    assert_eq!(expected[0].status, CheckStatus::Warn);
    for body in variants(BODY) {
        let actual = evaluate_robots_txt(&RobotsTxtFetch::Found { body });
        assert_eq!(
            serde_json::to_value(actual).expect("rows"),
            serde_json::to_value(&expected).expect("rows")
        );
    }
}

#[test]
fn sitemap_walk_keeps_the_lf_declarations_for_every_line_ending() {
    let expected = vec!["https://example.com/custom.xml".to_string()];
    for body in variants(BODY) {
        assert_eq!(sitemap_urls_from_robots(&body), expected);
        let fetch = RobotsTxtFetch::Found { body };
        assert_eq!(sitemap_candidates(ORIGIN, &fetch)[0], expected[0]);
    }
}

#[test]
fn sitemap_hint_keeps_the_lf_answer_for_every_line_ending() {
    for body in variants(BODY) {
        assert!(has_sitemap_directive(&body));
        assert_eq!(
            evaluate_sitemap_in_robots(&RobotsTxtFetch::Found { body })[0].status,
            CheckStatus::Pass
        );
    }
}

#[test]
fn sitemap_grading_keeps_the_lf_answer_for_every_line_ending() {
    let body = "User-agent: *\nDisallow: /\nSitemap: https://cdn.example.com/custom.xml\n";
    let page = artifact(&home(""), 200, "/")
        .into_page_context()
        .expect("page");
    let missing = SitemapProbe::Missing {
        observations: vec![],
    };
    let expected = evaluate_sitemap(
        &page,
        &RobotsTxtFetch::Found { body: body.into() },
        &missing,
    );
    for body in variants(body) {
        let actual = evaluate_sitemap(&page, &RobotsTxtFetch::Found { body }, &missing);
        assert_eq!(
            serde_json::to_value(actual).expect("rows"),
            serde_json::to_value(&expected).expect("rows")
        );
    }
}

#[test]
fn sitemap_comparison_keeps_the_lf_answer_for_every_line_ending() {
    let body = "User-agent: *\nDisallow: /private\nSitemap: https://example.com/custom.xml\nSitemap: https://example.com/other.xml\n";
    for body in variants(body) {
        let facts = session_page(&SessionPageRequest {
            page: artifact(&home(""), 200, "/"),
            routes: vec![format!("{ORIGIN}/")],
            probe_outcomes: vec![
                ExecutedProbe::new(
                    probe_key(&ProbeRequest::get(format!("{ORIGIN}/robots.txt"))),
                    response(&format!("{ORIGIN}/robots.txt"), 200, "text/plain", &body),
                ),
                ExecutedProbe::new(
                    probe_key(&sitemap_request("https://example.com/custom.xml")),
                    response(
                        "https://example.com/custom.xml",
                        200,
                        "application/xml",
                        &urlset(&[ORIGIN]),
                    ),
                ),
            ],
        })
        .expect("facts")
        .expect("named");
        assert_eq!(
            facts.sitemap.expect("sitemap").partial_causes,
            [SessionSitemapCause::UnreadDeclarations { count: 1 }]
        );
    }
}

#[test]
fn ai_policy_reads_leading_product_tokens_for_every_line_ending() {
    let body = "User-agent: GPTBot/1.0\nUser-agent: OAI-SearchBot (+https://example.com/bot)\nDisallow: /\n";
    for body in variants(body) {
        let result = evaluate(&EvaluationRequest {
            page: artifact(&home(""), 200, "/"),
            resolver_facts: None,
            vulnerability_facts: None,
            tls_facts: None,
            browser_facts: None,
            probe_outcomes: Some(vec![ExecutedProbe::new(
                probe_key(&ProbeRequest::get(format!("{ORIGIN}/robots.txt"))),
                response(&format!("{ORIGIN}/robots.txt"), 200, "text/plain", &body),
            )]),
        })
        .expect("evaluated");
        let row = result
            .results
            .iter()
            .find(|row| row.check_id == "seo.ai_crawler_blocking")
            .expect("AI row");
        assert_eq!(row.status, CheckStatus::Warn);
        assert!(row.description.contains("OpenAI model-training crawler"));
    }
}
