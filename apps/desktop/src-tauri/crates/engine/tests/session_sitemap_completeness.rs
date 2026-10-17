//! Cross-page comparisons require every source of the sitemap set to answer.

#[path = "support/discovery.rs"]
mod support;

pub use support::*;

use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
use sitecmd_engine::evaluation::{
    evaluate_session, probe_key, session_page, ExecutedProbe, SessionPageRequest, SessionRequest,
    SessionResponse, SessionSitemapFacts,
};
use sitecmd_engine::probe::{ProbeFailure, ProbeFailureClass, ProbeOutcome, ProbeRequest};
use sitecmd_engine::CheckStatus;

fn compare(robots: ProbeOutcome) -> (SessionSitemapFacts, SessionResponse) {
    let routes = vec![format!("{ORIGIN}/"), format!("{ORIGIN}/listed")];
    let root = session_page(&SessionPageRequest {
        page: artifact(&home(""), 200, "/"),
        routes: routes.clone(),
        probe_outcomes: vec![
            ExecutedProbe::new(
                probe_key(&ProbeRequest::get(format!("{ORIGIN}/robots.txt"))),
                robots,
            ),
            ExecutedProbe::new(
                probe_key(&sitemap_request(SITEMAP_URL)),
                response(
                    SITEMAP_URL,
                    200,
                    "application/xml",
                    &urlset(&["https://example.com/listed"]),
                ),
            ),
        ],
    })
    .expect("facts")
    .expect("named");
    let mut listed = artifact("<html></html>", 200, "/listed");
    listed.requested_url = Some(listed.url.clone());
    let listed = session_page(&SessionPageRequest {
        page: listed,
        routes,
        probe_outcomes: Vec::new(),
    })
    .expect("facts")
    .expect("named");
    let answer = evaluate_session(&SessionRequest {
        pages: vec![root.clone(), listed],
    });
    (root.sitemap.expect("sitemap"), answer)
}

#[test]
fn a_sitemap_found_after_robots_failed_keeps_the_comparison_partial() {
    let (sitemap, answer) = compare(response(
        &format!("{ORIGIN}/robots.txt"),
        503,
        "text/plain",
        "",
    ));
    let verdict = answer
        .verdicts
        .iter()
        .find(|verdict| verdict.check_id == "seo.noindex_in_sitemap")
        .expect("verdict");
    assert_eq!(verdict.status, CheckStatus::Skipped);
    assert_eq!(
        serde_json::to_value(&sitemap.partial_causes).expect("serialized causes"),
        serde_json::json!([{ "cause": "unfinished_walk" }])
    );
    assert_eq!(
        sitemap.partial_because().as_deref(),
        Some("robots.txt or an earlier sitemap did not answer")
    );
}

#[test]
fn an_oversized_robots_answer_keeps_the_comparison_complete() {
    let (sitemap, answer) = compare(ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::BodyCapExceeded,
        detail: "body exceeded cap".into(),
    }));
    let verdict = answer
        .verdicts
        .iter()
        .find(|verdict| verdict.check_id == "seo.noindex_in_sitemap")
        .expect("verdict");
    assert_eq!(verdict.status, CheckStatus::Pass);
    assert!(sitemap.partial_causes.is_empty());
    assert_eq!(sitemap.partial_because(), None);
}
