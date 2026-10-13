//! Native parity tests for the wasm probe-plan loop.
//!
//! Planning must converge after callers append each probe outcome.

use sitecmd_engine::evaluation::{
    evaluate, probe_plan, EvaluationRequest, EvaluationResponse, ExecutedProbe, PageArtifact,
    PlannedProbe, ProbePlan, PROBE_CHECKS,
};
use sitecmd_engine::manifest::{capability_manifest, HostedLane, RuntimeFact};
use sitecmd_engine::probe::{ProbeOutcome, ProbeResponse};
use sitecmd_engine_wasm::{engine_evaluate, engine_probe_plan, scorer_alloc, scorer_free};

// These two state nothing until robots.txt answers with a body or the walk
// finds a sitemap, as on the desktop.
const SILENT_WITHOUT_INPUT: [&str; 2] = ["seo.ai_crawler_blocking", "seo.sitemap_freshness"];

fn call_through_abi(
    entry: unsafe extern "C" fn(*mut u8, u32) -> *const u8,
    request: &[u8],
) -> Vec<u8> {
    unsafe {
        let input = scorer_alloc(request.len() as u32);
        core::ptr::copy_nonoverlapping(request.as_ptr(), input, request.len());
        let frame = entry(input, request.len() as u32) as *mut u8;
        let mut length_bytes = [0u8; 4];
        core::ptr::copy_nonoverlapping(frame, length_bytes.as_mut_ptr(), 4);
        let payload_length = u32::from_le_bytes(length_bytes) as usize;
        let payload = core::slice::from_raw_parts(frame.add(4), payload_length).to_vec();
        scorer_free(frame, (4 + payload_length) as u32);
        payload
    }
}

fn plan_through_abi(request: &EvaluationRequest) -> ProbePlan {
    let bytes = serde_json::to_vec(request).expect("request serializes");
    let payload = call_through_abi(engine_probe_plan, &bytes);
    serde_json::from_slice(&payload).unwrap_or_else(|error| {
        panic!(
            "payload is a ProbePlan, not {error}: {}",
            String::from_utf8_lossy(&payload[..payload.len().min(400)])
        )
    })
}

fn evaluate_through_abi(request: &EvaluationRequest) -> EvaluationResponse {
    let bytes = serde_json::to_vec(request).expect("request serializes");
    let payload = call_through_abi(engine_evaluate, &bytes);
    serde_json::from_slice(&payload).expect("payload is an EvaluationResponse")
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

fn run_to_fixpoint() -> (EvaluationRequest, usize) {
    let mut evaluation = request();
    let mut gathered: Vec<ExecutedProbe> = Vec::new();
    for round in 1..=8 {
        evaluation.probe_outcomes = Some(gathered.clone());
        let plan = plan_through_abi(&evaluation);
        assert_eq!(plan.manifest_digest, capability_manifest().digest());
        if plan.probes.is_empty() {
            return (evaluation, round);
        }
        for planned in &plan.probes {
            gathered.push(ExecutedProbe {
                key: planned.key.clone(),
                outcome: execute(planned),
            });
        }
    }
    panic!("the plan never reached a fixpoint through the ABI");
}

#[test]
fn the_framed_plan_equals_the_in_process_plan() {
    let request = request();
    let native =
        serde_json::to_value(probe_plan(&request).expect("plans in process")).expect("serializes");
    let framed = serde_json::to_value(plan_through_abi(&request)).expect("serializes");
    assert_eq!(framed, native);
}

#[test]
fn identical_requests_produce_identical_plan_payloads() {
    let bytes = serde_json::to_vec(&request()).expect("request serializes");
    assert_eq!(
        call_through_abi(engine_probe_plan, &bytes),
        call_through_abi(engine_probe_plan, &bytes)
    );
}

#[test]
fn every_plan_partitions_the_probe_lane() {
    let manifest = capability_manifest();
    let plan = plan_through_abi(&request());
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
    let (evaluated, rounds) = run_to_fixpoint();
    assert!(
        rounds >= 2,
        "at least one round of probes, then an empty one"
    );

    let before = evaluate_through_abi(&request());
    assert_eq!(before.facts_present, vec![RuntimeFact::PageArtifact]);

    let after = evaluate_through_abi(&evaluated);
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
        serde_json::to_value(evaluate(&evaluated).expect("evaluates in process"))
            .expect("serializes")
    );
}

#[test]
fn a_malformed_plan_request_returns_an_error_payload() {
    let payload = call_through_abi(engine_probe_plan, b"{ not json");
    let value: serde_json::Value = serde_json::from_slice(&payload).expect("error frame is JSON");
    assert!(!value["error"]
        .as_str()
        .expect("error carries a message")
        .is_empty());
}

#[test]
fn an_unparseable_page_url_returns_an_error_payload() {
    let mut broken = request();
    broken.page.url = "not a url".into();
    let bytes = serde_json::to_vec(&broken).expect("request serializes");
    let value: serde_json::Value =
        serde_json::from_slice(&call_through_abi(engine_probe_plan, &bytes))
            .expect("error frame is JSON");
    assert!(value["error"]
        .as_str()
        .expect("error carries a message")
        .contains("url"));
}
