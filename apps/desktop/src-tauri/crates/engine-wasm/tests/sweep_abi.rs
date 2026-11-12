//! The candidate-path sweeps through the route ABI: planned once each under
//! the sweep limit, and never planned again once answered.

#[path = "support/abi.rs"]
mod abi;

use serde_json::{json, Value};
use sitecmd_engine::checks::security::{
    directory_listing::PROBE_DIRS, exposed_files::SENSITIVE_PATHS,
};
use sitecmd_engine::evaluation::PageArtifact;
use sitecmd_engine_wasm::engine_route_plan;

fn page() -> PageArtifact {
    serde_json::from_value(json!({
        "url": "https://example.com/nested/page", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-10-30T00:00:00Z"
    }))
    .expect("page")
}

#[test]
fn sweep_gets_are_framed_and_a_large_recorded_answer_is_not_planned_again() {
    // Missing sweep requests or a lost answered marker repeats a sensitive path through the ABI.
    abi::open(&page());
    let frame: Value = serde_json::from_slice(&abi::call(engine_route_plan, b"{}")).unwrap();
    let probes = frame["probes"].as_array().expect("plan probes");
    let sweeps = probes
        .iter()
        .filter(|p| p["request"]["limit"] == "sweep")
        .collect::<Vec<_>>();
    assert_eq!(sweeps.len(), 32);
    for path in SENSITIVE_PATHS
        .iter()
        .map(|(p, _, _)| *p)
        .chain(PROBE_DIRS.iter().copied())
    {
        let url = format!("https://example.com{path}");
        assert_eq!(
            sweeps
                .iter()
                .filter(|p| p["request"]["url"] == url && p["request"]["method"] == "get")
                .count(),
            1,
            "{path}"
        );
    }
    let key = sweeps[0]["key"].clone();
    let text = "x".repeat(512 * 1024);
    let recorded = abi::call_json(
        engine_route_plan,
        &json!({"probe_outcomes": [{
            "key": key, "outcome": {"kind": "response", "status": 200, "final_url": "https://example.com/.env", "content_type": "text/plain", "content_length": text.len(), "headers": [], "body": {"text": text, "bytes": text.len(), "utf8_valid": true}}
        }]}),
    );
    assert!(abi::refusal(&recorded).is_none());
    let next: Value = serde_json::from_slice(&abi::call(engine_route_plan, b"{}")).unwrap();
    assert!(!next["probes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["key"] == key));
    assert_eq!(
        next["probes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["request"]["limit"] == "sweep")
            .count(),
        31
    );
}
