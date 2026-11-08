// A hosted scan grades HTTP/2 with no observation, on a page nobody observed, or reads an unknown protocol token as HTTP/1.x.

use sitecmd_engine::checks::performance::protocol::Http2Check;
use sitecmd_engine::evaluation::{
    evaluate, EvaluationRequest, EvaluationResponse, PageArtifact, RouteFacts, RouteSession,
};
use sitecmd_engine::manifest::{capability_manifest, CheckScope};
use sitecmd_engine::{Check, CheckResult, CheckStatus};

const ID: &str = "performance.http2";

fn page(version: Option<&str>) -> PageArtifact {
    serde_json::from_value(serde_json::json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "<title>Example</title>", "http_version": version,
        "evaluation_time": "2026-10-30T00:00:00Z"
    }))
    .unwrap()
}

fn facts(protocol: &str) -> RouteFacts {
    serde_json::from_value(serde_json::json!({
        "negotiated_protocol": {"protocol": protocol, "observed_at": "2026-10-30T00:00:00Z"}
    }))
    .unwrap()
}

fn row(response: &EvaluationResponse) -> &CheckResult {
    response
        .results
        .iter()
        .find(|r| r.check_id == ID)
        .expect("HTTP/2 result")
}

#[test]
fn negotiated_tokens_grade_like_native_protocol_versions() {
    // A hosted token must reach the same grader as a native protocol observation.
    for (token, version) in [
        ("h2", "HTTP/2"),
        ("h3", "HTTP/3"),
        ("http/1.1", "HTTP/1.1"),
        ("http/1.0", "HTTP/1.0"),
    ] {
        let response = RouteSession::open(page(None))
            .unwrap()
            .evaluate(&facts(token));
        let direct = Http2Check.run(&page(Some(version)).page_context().unwrap());
        assert_eq!(
            serde_json::to_value(row(&response)).unwrap(),
            serde_json::to_value(&direct[0]).unwrap(),
            "{token}"
        );
        assert!(response.planned.iter().any(|r| r.check == ID));
    }
}

#[test]
fn unobserved_tokens_skip_instead_of_warning_about_http1() {
    // Unknown protocol strings cannot become evidence of an HTTP/1.x response.
    for token in ["other", "unknown", "HTTP/2", ""] {
        let response = RouteSession::open(page(None))
            .unwrap()
            .evaluate(&facts(token));
        assert_eq!(row(&response).status, CheckStatus::Skipped, "{token}");
        assert_eq!(
            row(&response).raw_data.as_ref().unwrap()["reason"],
            "protocol_not_observed"
        );
    }
}

#[test]
fn an_absent_fact_is_named_in_both_hosted_partitions() {
    // A missing protocol observation must remain missing, without claiming a verdict.
    let route = RouteSession::open(page(None)).unwrap();
    let response = route.evaluate(&RouteFacts::default());
    let missing = response
        .not_evaluated
        .iter()
        .find(|r| r.check == ID)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&missing.reason).unwrap(),
        serde_json::json!({"reason": "missing_fact", "fact": "negotiated_protocol"})
    );
    let not_planned = route
        .plan()
        .not_planned
        .into_iter()
        .find(|r| r.check == ID)
        .unwrap();
    assert_eq!(not_planned.reason, missing.reason);
    assert!(!response.results.iter().any(|r| r.check_id == ID));
}

#[test]
fn origin_scope_claims_only_the_entry_route_pair() {
    // Page scope would claim HTTP/2 for a second route nobody observed.
    let manifest = capability_manifest();
    assert_eq!(manifest.entry(ID).unwrap().scope, CheckScope::Origin);
    let mut claimed = Vec::new();
    for (index, path) in ["/", "/inner"].iter().enumerate() {
        let mut page = page(None);
        page.url = format!("https://example.com{path}");
        let response = RouteSession::open(page).unwrap().evaluate(&facts("h2"));
        for check in response.planned.iter().filter(|r| r.check == ID) {
            if index == 0 || check.scope == CheckScope::Page {
                claimed.push((*path, check.check.clone()));
            }
        }
    }
    assert_eq!(claimed, vec![("/", ID.to_string())]);
}

#[test]
fn native_page_protocol_takes_precedence_over_the_fact() {
    // A secondary observation must not overwrite the protocol the page fetch negotiated.
    for (version, token) in [("HTTP/1.1", "h2"), ("HTTP/2", "http/1.1")] {
        let page = page(Some(version));
        let direct = Http2Check.run(&page.page_context().unwrap());
        let response = RouteSession::open(page).unwrap().evaluate(&facts(token));
        assert_eq!(
            serde_json::to_value(row(&response)).unwrap(),
            serde_json::to_value(&direct[0]).unwrap()
        );
    }
}

#[test]
fn the_whole_request_carries_the_protocol_fact() {
    // Whole-request evaluation must forward the fact just as route evaluation does.
    let request: EvaluationRequest = serde_json::from_value(serde_json::json!({
        "page": page(None), "negotiated_protocol": {"protocol": "h2", "observed_at": "2026-10-30T00:00:00Z"}
    })).unwrap();
    let response = evaluate(&request).unwrap();
    assert_eq!(row(&response).status, CheckStatus::Pass);
    assert!(serde_json::to_value(&response.facts_present)
        .unwrap()
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("negotiated_protocol")));
}

#[test]
fn negotiated_protocol_and_advertised_http3_are_independent_observations() {
    // A negotiated h3 token must not invent an advertisement or upgrade an HTTP/1.1 verdict.
    let mut observed = Vec::new();
    for (token, headers) in [
        ("h3", vec![]),
        ("http/1.1", vec![("alt-svc".into(), "h3=\":443\"".into())]),
    ] {
        let mut page = page(None);
        page.headers = headers;
        let response = RouteSession::open(page).unwrap().evaluate(&facts(token));
        let result = row(&response);
        observed.push((
            result.status,
            result.raw_data.as_ref().unwrap()["alt_svc_h3"].clone(),
            result.description.to_ascii_lowercase().contains("advertis"),
            result.raw_data.as_ref().unwrap()["http_version"].clone(),
        ));
    }
    assert_eq!(
        observed,
        vec![
            (
                CheckStatus::Pass,
                serde_json::json!(false),
                false,
                serde_json::json!("HTTP/3")
            ),
            (
                CheckStatus::Warn,
                serde_json::json!(true),
                false,
                serde_json::json!("HTTP/1.1")
            ),
        ]
    );
}

#[test]
fn passing_rows_preserve_observed_http3_advertisements() {
    // A passing response loses its observed advertisement when the protocol token supplies the flag.
    let mut observed = Vec::new();
    for token in ["h2", "h3"] {
        let mut page = page(None);
        page.headers = vec![("alt-svc".into(), "h3=\":443\"".into())];
        let response = RouteSession::open(page).unwrap().evaluate(&facts(token));
        let result = row(&response);
        observed.push((
            result.status,
            result.raw_data.as_ref().unwrap()["alt_svc_h3"].clone(),
            result
                .description
                .contains("response advertises HTTP/3 via Alt-Svc"),
            result.raw_data.as_ref().unwrap()["http_version"].clone(),
        ));
    }
    assert_eq!(
        observed,
        vec![
            (
                CheckStatus::Pass,
                serde_json::json!(true),
                true,
                serde_json::json!("HTTP/2")
            ),
            (
                CheckStatus::Pass,
                serde_json::json!(true),
                true,
                serde_json::json!("HTTP/3")
            ),
        ]
    );
}
