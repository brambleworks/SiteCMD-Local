//! Native parity tests for the wasm probe-plan loop.
//!
//! Planning must converge after callers append each probe outcome.

#[path = "support/abi.rs"]
mod abi;

use sitecmd_engine::evaluation::{
    evaluate, EvaluationRequest, EvaluationResponse, ExecutedProbe, PageArtifact, PlannedProbe,
    ProbePlan, RouteSession, PROBE_CHECKS,
};
use sitecmd_engine::manifest::{capability_manifest, HostedLane, RuntimeFact};
use sitecmd_engine::probe::{ProbeOutcome, ProbeResponse};
use sitecmd_engine_wasm::{engine_route_evaluate, engine_route_open, engine_route_plan};

// These two state nothing until robots.txt answers with a body or the walk
// finds a sitemap, as on the desktop.
const SILENT_WITHOUT_INPUT: [&str; 2] = ["seo.ai_crawler_blocking", "seo.sitemap_freshness"];

/// Record `fresh` on this thread's open route and answer its plan.
fn plan_through_abi(fresh: &[ExecutedProbe]) -> ProbePlan {
    let payload = abi::call_json(
        engine_route_plan,
        &serde_json::json!({ "probe_outcomes": fresh }),
    );
    serde_json::from_slice(&payload).unwrap_or_else(|error| {
        panic!(
            "payload is a ProbePlan, not {error}: {}",
            String::from_utf8_lossy(&payload[..payload.len().min(400)])
        )
    })
}

fn evaluate_through_abi() -> EvaluationResponse {
    serde_json::from_slice(&abi::call(engine_route_evaluate, b"{}"))
        .expect("payload is an EvaluationResponse")
}

fn artifact() -> PageArtifact {
    PageArtifact {
        url: "https://example.com/".into(),
        requested_url: Some("https://example.com/".into()),
        status_code: 200,
        http_version: Some("HTTP/2.0".into()),
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: concat!(
            "<html><head><link rel=\"icon\" href=\"/icon.png\"></head>",
            "<body><a href=\"/about\">About</a></body></html>"
        )
        .into(),
        evaluation_time: "2026-08-05T00:00:00Z"
            .parse()
            .expect("static evaluation time"),
    }
}

fn request() -> EvaluationRequest {
    EvaluationRequest {
        page: artifact(),
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    }
}

// Engine tests own grading; this response only advances the probe loop.
fn execute(planned: &PlannedProbe) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status: 200,
        final_url: planned.request.url.clone(),
        content_type: Some("image/png".into()),
        content_length: None,
        headers: Vec::new(),
        body: None,
    })
}

/// Drive the route's plan to its fixpoint through the ABI, recording each
/// batch with the next call; answers every outcome executed, and the calls made.
fn run_to_fixpoint() -> (Vec<ExecutedProbe>, usize) {
    abi::open(&artifact());
    let mut gathered: Vec<ExecutedProbe> = Vec::new();
    let mut fresh: Vec<ExecutedProbe> = Vec::new();
    for call in 1..=8 {
        let plan = plan_through_abi(&std::mem::take(&mut fresh));
        assert_eq!(plan.manifest_digest, capability_manifest().digest());
        if plan.probes.is_empty() {
            return (gathered, call);
        }
        for planned in &plan.probes {
            let executed = ExecutedProbe {
                key: planned.key.clone(),
                outcome: execute(planned),
            };
            gathered.push(executed.clone());
            fresh.push(executed);
        }
    }
    panic!("the plan never reached a fixpoint through the ABI");
}

#[test]
fn the_framed_plan_equals_the_in_process_plan() {
    abi::open(&artifact());
    let mut route = RouteSession::open(artifact()).expect("opens in process");
    route.record(Some(Vec::new()));
    let native = serde_json::to_value(route.plan()).expect("serializes");
    let framed = serde_json::to_value(plan_through_abi(&[])).expect("serializes");
    assert_eq!(framed, native);
}

#[test]
fn identical_requests_produce_identical_plan_payloads() {
    abi::open(&artifact());
    let bytes = b"{\"probe_outcomes\": []}";
    assert_eq!(
        abi::call(engine_route_plan, bytes),
        abi::call(engine_route_plan, bytes)
    );
}

#[test]
fn every_plan_partitions_the_probe_lane() {
    let manifest = capability_manifest();
    abi::open(&artifact());
    let plan = plan_through_abi(&[]);
    let lane = manifest
        .entries
        .iter()
        .filter(|entry| entry.hosted == HostedLane::ProbeAdapter)
        .count();
    assert!(lane > 0);
    assert_eq!(plan.planned.len() + plan.not_planned.len(), lane);
    assert!(!plan.probes.is_empty(), "the sample page needs fetches");
}

#[test]
fn executing_the_framed_plan_produces_framed_verdicts() {
    abi::open(&artifact());
    let before = evaluate_through_abi();
    assert_eq!(before.facts_present, vec![RuntimeFact::PageArtifact]);

    let (gathered, calls) = run_to_fixpoint();
    assert!(
        calls >= 2,
        "at least one batch of probes, then an empty one"
    );
    let after = evaluate_through_abi();
    assert_eq!(
        after.facts_present,
        vec![
            RuntimeFact::PageArtifact,
            RuntimeFact::Fetch,
            RuntimeFact::Rdap,
        ]
    );
    for check in PROBE_CHECKS {
        for id in check.covers {
            if !after.planned.iter().any(|row| &row.check == id) {
                assert!(matches!(
                    after
                        .not_evaluated
                        .iter()
                        .find(|row| &row.check == id)
                        .map(|row| &row.reason),
                    Some(
                        sitecmd_engine::evaluation::NotEvaluatedReason::MissingFact {
                            fact: RuntimeFact::Resolver | RuntimeFact::VulnerabilityCorpus
                        }
                    )
                ));
                continue;
            }
            if SILENT_WITHOUT_INPUT.contains(id) {
                continue;
            }
            assert!(
                after.results.iter().any(|row| &row.check_id == id),
                "'{id}' produced a verdict row through the ABI"
            );
            assert!(
                before.results.iter().all(|row| &row.check_id != id),
                "'{id}' produced no row before its probes were executed"
            );
        }
    }
    assert_eq!(
        serde_json::to_value(&after).expect("serializes"),
        serde_json::to_value(
            evaluate(&EvaluationRequest {
                page: artifact(),
                probe_outcomes: Some(gathered),
                ..request()
            })
            .expect("evaluates in process")
        )
        .expect("serializes")
    );
}

#[test]
fn a_malformed_plan_request_returns_an_error_payload() {
    abi::open(&artifact());
    let payload = abi::call(engine_route_plan, b"{ not json");
    assert!(!abi::refusal(&payload)
        .expect("error carries a message")
        .is_empty());
}

#[test]
fn an_unparseable_page_url_returns_an_error_payload() {
    let mut broken = artifact();
    broken.url = "not a url".into();
    let payload = abi::call_json(engine_route_open, &serde_json::json!({ "page": broken }));
    assert!(abi::refusal(&payload)
        .expect("error carries a message")
        .contains("url"));
}
