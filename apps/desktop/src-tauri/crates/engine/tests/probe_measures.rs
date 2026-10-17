//! The probe vocabulary's raw reads, counted bodies and timings: what each
//! adds to a request's identity, and how an answer's measure is found again.

use std::collections::HashSet;

use sitecmd_engine::evaluation::{probe_key, ExecutedProbe, ProbeOutcomes};
use sitecmd_engine::probe::{
    BodyPolicy, ContentCoding, ProbeMeasure, ProbeOutcome, ProbeRequest, ProbeResponse,
};

fn answered() -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status: 200,
        final_url: "https://example.com/".into(),
        content_type: None,
        content_length: None,
        headers: Vec::new(),
        body: None,
    })
}

#[test]
fn a_plain_request_keeps_the_key_it_always_had() {
    assert_eq!(
        probe_key(&ProbeRequest::get("https://example.com/a.png")),
        "get\u{1f}https://example.com/a.png\u{1f}body=success_only\u{1f}redirects=follow"
    );
}

#[test]
fn a_raw_read_a_count_and_each_timing_sample_key_apart() {
    let plain = ProbeRequest::get("https://example.com/");
    let keys = [
        probe_key(&plain),
        probe_key(&plain.clone().coding(ContentCoding::Raw)),
        probe_key(&plain.clone().body(BodyPolicy::Count)),
        probe_key(&plain.clone().timed(1)),
        probe_key(&plain.clone().timed(2)),
    ];
    let distinct: HashSet<&String> = keys.iter().collect();
    assert_eq!(distinct.len(), keys.len(), "{keys:?}");
    assert!(keys[1].ends_with("\u{1f}coding=raw"), "{}", keys[1]);
    assert!(keys[2].contains("\u{1f}body=count\u{1f}"), "{}", keys[2]);
    assert!(keys[4].ends_with("\u{1f}timed=2"), "{}", keys[4]);
}

#[test]
fn the_measure_of_an_answer_is_found_by_its_request_alone() {
    let timed = ProbeRequest::get("https://example.com/").timed(1);
    let plain = ProbeRequest::get("https://example.com/");
    let mut measured = ExecutedProbe::new(probe_key(&timed), answered());
    measured.measure = Some(ProbeMeasure::timed(140));
    let executed = vec![measured, ExecutedProbe::new(probe_key(&plain), answered())];
    let outcomes = ProbeOutcomes::index(&executed);
    assert_eq!(outcomes.measure(&timed), Some(ProbeMeasure::timed(140)));
    assert_eq!(outcomes.measure(&plain), None);
    assert!(outcomes.get(&timed).is_some());
}

#[test]
fn an_executed_probe_that_measured_nothing_reads_and_writes_as_it_always_did() {
    let wire =
        serde_json::to_value(ExecutedProbe::new("k".into(), answered())).expect("serializes");
    assert!(wire.get("measure").is_none(), "{wire}");
    let back: ExecutedProbe = serde_json::from_value(serde_json::json!({
        "key": "k",
        "outcome": { "kind": "failure", "class": "timeout", "detail": "timeout" }
    }))
    .expect("an executed probe without a measure parses");
    assert!(back.measure.is_none());
}

#[test]
fn an_executed_probe_reads_its_measure_from_the_wire() {
    // A renamed measure field silently drops the runtime's timing and count.
    let executed: ExecutedProbe = serde_json::from_str(
        r#"{
            "key": "k",
            "outcome": {
                "kind": "response",
                "status": 200,
                "final_url": "https://example.com/",
                "content_type": null,
                "content_length": null,
                "headers": [],
                "body": null
            },
            "measure": {
                "first_byte_ms": 37,
                "counted_bytes": 12,
                "count_capped": true
            }
        }"#,
    )
    .expect("executed probe parses");
    let measure = executed.measure.expect("the wire measure is retained");
    assert_eq!(measure.first_byte_ms, Some(37));
    assert_eq!(measure.counted_bytes, Some(12));
    assert!(measure.count_capped);
}
