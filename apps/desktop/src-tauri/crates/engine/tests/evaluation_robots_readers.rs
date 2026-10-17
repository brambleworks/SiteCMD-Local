//! Every robots.txt reader keeps declarations and rules served with an HTML type.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::checks::seo::robots::robots_fetch_from_probe;
use sitecmd_engine::checks::seo::sitemap::{evaluate_sitemap, SitemapProbe};
use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
use sitecmd_engine::evaluation::{
    evaluate, probe_key, session_page, EvaluationRequest, ExecutedProbe, SessionPageRequest,
    SessionSitemapCause,
};
use sitecmd_engine::probe::ProbeRequest;
use sitecmd_engine::CheckStatus;

fn html_robots(body: &str) -> ExecutedProbe {
    let url = format!("{ORIGIN}/robots.txt");
    ExecutedProbe::new(
        probe_key(&ProbeRequest::get(&url)),
        response(&url, 200, "text/html", body),
    )
}

#[test]
fn an_html_typed_robots_second_sitemap_keeps_the_comparison_partial() {
    let first = format!("{ORIGIN}/pages.xml");
    let body = format!("Sitemap: {first}\nSitemap: {ORIGIN}/posts.xml");
    let facts = session_page(&SessionPageRequest {
        page: artifact(&home(""), 200, "/"),
        routes: vec![format!("{ORIGIN}/")],
        probe_outcomes: vec![
            html_robots(&body),
            ExecutedProbe::new(
                probe_key(&sitemap_request(&first)),
                response(&first, 200, "application/xml", &urlset(&[ORIGIN])),
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

#[test]
fn html_typed_robots_keeps_training_and_discovery_crawler_policies() {
    for (agents, expected) in [
        ("User-agent: GPTBot", CheckStatus::Pass),
        (
            "User-agent: GPTBot\nUser-agent: OAI-SearchBot",
            CheckStatus::Warn,
        ),
    ] {
        let result = evaluate(&EvaluationRequest {
            page: artifact(&home(""), 200, "/"),
            resolver_facts: None,
            vulnerability_facts: None,
            tls_facts: None,
            probe_outcomes: Some(vec![html_robots(&format!("{agents}\nDisallow: /"))]),
            browser_facts: None,
        })
        .expect("evaluated");
        let row = result
            .results
            .iter()
            .find(|row| row.check_id == "seo.ai_crawler_blocking")
            .expect("AI crawler row");
        assert_eq!(row.status, expected);
        assert!(row.description.contains("OpenAI model-training crawler"));
    }
}

#[test]
fn an_html_typed_robots_cross_origin_sitemap_is_named() {
    let fetch = robots_fetch_from_probe(
        html_robots("User-agent: *\nSitemap: https://cdn.example-assets.net/sitemap.xml").outcome,
    );
    let page = artifact(&home(""), 200, "/")
        .into_page_context()
        .expect("page");
    let result = evaluate_sitemap(
        &page,
        &fetch,
        &SitemapProbe::Missing {
            observations: vec![],
        },
    );
    assert_eq!(result[0].status, CheckStatus::Warn);
    assert_eq!(
        result[0].raw_data.as_ref().expect("data")["cross_origin_declared"],
        serde_json::json!(["https://cdn.example-assets.net/sitemap.xml"])
    );
}

#[test]
fn unread_robots_outcomes_never_carry_a_policy_body() {
    use sitecmd_engine::checks::seo::sitemap_walk::robots_was_read;
    use sitecmd_engine::probe::{ProbeFailure, ProbeFailureClass, ProbeOutcome};

    let statuses = (100..=599).map(|status| {
        response(
            "https://example.com/robots.txt",
            status,
            "text/plain",
            "User-agent: *\nDisallow: /",
        )
    });
    let failures = [
        ProbeFailureClass::Timeout,
        ProbeFailureClass::BodyCapExceeded,
        ProbeFailureClass::DnsUnresolved,
        ProbeFailureClass::Transport,
    ]
    .into_iter()
    .map(|class| {
        ProbeOutcome::Failure(ProbeFailure {
            class,
            detail: "failed".into(),
        })
    });
    for outcome in statuses.chain(failures) {
        if !robots_was_read(&outcome) {
            assert!(robots_fetch_from_probe(outcome).body().is_none());
        }
    }
}
