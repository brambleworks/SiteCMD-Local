//! The head metadata checks run through the portable evaluation from the page
//! alone, so every runtime grades a page's title, description, canonical,
//! viewport, charset, robots directives, social cards and hreflang the same way.

use sitecmd_engine::evaluation::{evaluate, EvaluationRequest, NotEvaluatedReason, PageArtifact};
use sitecmd_engine::{CheckResult, CheckStatus};

const HEAD_CHECKS: [&str; 13] = [
    "seo.canonical",
    "seo.charset",
    "seo.duplicate_description",
    "seo.duplicate_meta",
    "seo.duplicate_title",
    "seo.hreflang",
    "seo.meta_description",
    "seo.noindex",
    "seo.og_image_relative",
    "seo.open_graph",
    "seo.title",
    "seo.twitter_cards",
    "seo.viewport",
];

fn request(body: &str) -> EvaluationRequest {
    EvaluationRequest {
        page: PageArtifact {
            url: "https://example.com/".into(),
            requested_url: Some("https://example.com/".into()),
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: body.into(),
            evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
        },
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    }
}

fn rows<'a>(results: &'a [CheckResult], id: &str) -> Vec<&'a CheckResult> {
    results.iter().filter(|row| row.check_id == id).collect()
}

#[test]
fn every_head_check_is_planned_from_the_page_alone() {
    let response = evaluate(&request("<html><head><title>Example</title></head></html>"))
        .expect("request evaluates");
    for id in HEAD_CHECKS {
        assert!(
            response.planned.iter().any(|row| row.check == id),
            "{id} is planned"
        );
        assert!(
            !response
                .not_evaluated
                .iter()
                .any(|row| row.check == id && row.reason == NotEvaluatedReason::UnsupportedLane),
            "{id} names a hosted lane"
        );
    }
}

#[test]
fn a_page_with_no_title_fails_the_title_and_passes_the_duplicate() {
    let body = "<html><head></head><body><svg><title>Icon</title></svg></body></html>";
    let response = evaluate(&request(body)).expect("request evaluates");
    let title = rows(&response.results, "seo.title");
    assert_eq!(title.len(), 1);
    assert_eq!(title[0].status, CheckStatus::Fail);
    assert_eq!(title[0].title, "Missing title tag");
    let duplicate = rows(&response.results, "seo.duplicate_title");
    assert_eq!(
        duplicate.len(),
        1,
        "a clean page states its duplicate-title verdict"
    );
    assert_eq!(duplicate[0].status, CheckStatus::Pass);
    let description = rows(&response.results, "seo.duplicate_description");
    assert_eq!(description.len(), 1);
    assert_eq!(description[0].status, CheckStatus::Pass);
}

#[test]
fn a_page_with_two_titles_fails_the_duplicate_and_grades_the_first_title() {
    let body = concat!(
        "<html><head><title>Home</title>",
        "<title>A much longer second title for the page</title></head></html>"
    );
    let response = evaluate(&request(body)).expect("request evaluates");
    let duplicate = rows(&response.results, "seo.duplicate_title");
    assert_eq!(duplicate.len(), 1);
    assert_eq!(duplicate[0].status, CheckStatus::Fail);
    assert_eq!(
        rows(&response.results, "seo.title")[0].title,
        "Short title tag needs review"
    );
    assert!(rows(&response.results, "seo.duplicate_meta").is_empty());
}

#[test]
fn a_very_long_title_warns_and_bounds_its_evidence() {
    let long = "\u{e9}".repeat(300);
    let body = format!("<html><head><title>{long}</title></head></html>");
    let response = evaluate(&request(&body)).expect("request evaluates");
    let title = rows(&response.results, "seo.title");
    assert_eq!(title[0].status, CheckStatus::Warn);
    assert_eq!(title[0].title, "Long title tag needs review");
    let raw = title[0].raw_data.as_ref().expect("evidence");
    assert_eq!(raw["length"], 300);
    assert_eq!(raw["title_evidence_truncated"], true);
    assert_eq!(raw["title"].as_str().expect("evidence text").len(), 503);
}
