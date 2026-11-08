//! A recorded-alone answer keeps its document in the route session, an existing probe changes its key, or a sweep reads under the wrong cap.

#[path = "support/probe_corpus.rs"]
mod probe_corpus;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

use serde_json::{json, Value};
use sitecmd_engine::evaluation::{
    probe_key, sweep_reading, ExecutedProbe, PageArtifact, RouteSession,
};
use sitecmd_engine::probe::{
    decode_probe_body, BodyLimit, ContentCoding, ProbeFailure, ProbeFailureClass, ProbeOutcome,
    ProbeRequest, ProbeResponse,
};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size(), Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        System.dealloc(pointer, layout);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn route() -> RouteSession {
    let page: PageArtifact = serde_json::from_value(json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-10-30T00:00:00Z"
    }))
    .expect("page");
    RouteSession::open(page).expect("route")
}

fn response(status: u16, text: &str) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: "https://example.com/probe".into(),
        content_type: Some("text/plain".into()),
        content_length: Some(text.len() as u64),
        headers: Vec::new(),
        body: Some(decode_probe_body(text.as_bytes().to_vec())),
    })
}

#[test]
fn existing_probe_requests_and_keys_keep_their_boundary_bytes() {
    // The corpus driver's recorded requests or keys change.
    let _serial = SERIAL.lock().unwrap();
    let mut lines = include_str!("fixtures/probe_keys.jsonl").lines();
    let dictionary: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let mut expected: Vec<Value> = lines
        .map(|line| {
            let mut case: Value = serde_json::from_str(line).unwrap();
            for round in case["rounds"].as_array_mut().unwrap() {
                for request in round.as_array_mut().unwrap() {
                    *request = dictionary["requests"][request.as_u64().unwrap() as usize].clone();
                }
            }
            case
        })
        .collect();
    // Cases added after these keys were recorded (the HTTP/2 pair and the
    // RFC 9989 DMARC cases) retain the blank document's recorded rounds.
    let baseline = expected
        .iter()
        .find(|case| case["name"] == "valid_well_known_file_passes")
        .unwrap()["rounds"]
        .clone();
    let recorded: Vec<Value> = expected.iter().map(|case| case["name"].clone()).collect();
    // The candidate-path sweeps and security.txt joined the plan after these
    // keys were recorded; every other request keeps its round and bytes.
    let mut actual =
        probe_corpus::probe_corpus_keys(include_str!("../fixtures/checks/golden_probes.json"));
    for case in &mut actual {
        let rounds = case["rounds"].as_array_mut().unwrap();
        for round in rounds.iter_mut() {
            round.as_array_mut().unwrap().retain(|probe| {
                let request: Value =
                    serde_json::from_str(probe["request"].as_str().unwrap()).unwrap();
                request["limit"] != "sweep"
                    && !request["url"].as_str().unwrap().ends_with("/security.txt")
            });
        }
        rounds.retain(|round| !round.as_array().unwrap().is_empty());
    }
    for case in &actual {
        if !recorded.contains(&case["name"]) {
            expected.push(json!({"name": case["name"], "rounds": baseline}));
        }
    }
    let by_name = |a: &Value, b: &Value| a["name"].as_str().cmp(&b["name"].as_str());
    actual.sort_by(by_name);
    expected.sort_by(by_name);
    assert_eq!(actual, expected);
}

#[test]
fn recorded_alone_limits_serialize_and_key_apart_from_ordinary_requests() {
    // A sweep or stylesheet must not reuse an ordinary answer for the same URL.
    let _serial = SERIAL.lock().unwrap();
    let ordinary = ProbeRequest::get("https://example.com/probe");
    assert!(serde_json::to_value(&ordinary)
        .unwrap()
        .get("limit")
        .is_none());
    let mut keys = vec![probe_key(&ordinary)];
    for (limit, wire) in [
        (BodyLimit::Sweep, "sweep"),
        (BodyLimit::Stylesheet, "stylesheet"),
    ] {
        let request = ordinary.clone().limit(limit);
        let bytes = serde_json::to_string(&request).unwrap();
        assert!(bytes.contains(&format!("\"limit\":\"{wire}\"")));
        let decoded: ProbeRequest = serde_json::from_str(&bytes).unwrap();
        assert_eq!(decoded.limit, limit);
        let key = probe_key(&decoded);
        assert!(!keys.contains(&key));
        keys.push(key);
    }
}

#[test]
fn recording_a_sweep_releases_its_half_mebibyte_body() {
    // Keeping the response document would retain at least 512 KiB after record.
    let _serial = SERIAL.lock().unwrap();
    let mut route = route();
    route.plan();
    let before = LIVE.load(Relaxed);
    let request = ProbeRequest::get("https://example.com/probe")
        .limit(BodyLimit::Sweep)
        .coding(ContentCoding::Raw)
        .timed(1)
        .header("accept", "text/plain");
    let outcome = response(200, &"x".repeat(512 * 1024));
    route.record(Some(vec![ExecutedProbe::new(probe_key(&request), outcome)]));
    let retained = LIVE.load(Relaxed).saturating_sub(before);
    eprintln!("retained sweep bytes: {retained}");
    assert!(retained < 64 * 1024, "sweep retained {retained} bytes");
}

#[test]
fn a_listing_beyond_the_signature_sample_is_still_read() {
    // Sampling before checking the whole document would miss a late listing marker.
    let _serial = SERIAL.lock().unwrap();
    let text = format!("{}<title>Index of /backup/</title>", "🦀".repeat(4097));
    let reading = sweep_reading(&response(200, &text));
    assert!(reading.listing);
    assert_eq!(reading.sample.as_deref(), Some("🦀".repeat(4096).as_str()));
    assert_eq!(reading.status, Some(200));
    assert_eq!(reading.content_type.as_deref(), Some("text/plain"));
    assert_eq!(reading.content_length, Some(text.len() as u64));
    assert!(reading.failure.is_none());
}

#[test]
fn failed_sweeps_keep_the_failure_class_and_detail() {
    // Collapsing failures loses the reason a sweep could not answer.
    let _serial = SERIAL.lock().unwrap();
    for class in [
        ProbeFailureClass::Timeout,
        ProbeFailureClass::BodyCapExceeded,
        ProbeFailureClass::DnsUnresolved,
        ProbeFailureClass::Transport,
    ] {
        let reading = sweep_reading(&ProbeOutcome::Failure(ProbeFailure {
            class,
            detail: "injected failure".into(),
        }));
        let failure = reading.failure.expect("failure retained");
        assert_eq!(failure.class, class);
        assert_eq!(failure.detail, "injected failure");
        assert_eq!(reading.status, None);
        assert!(reading.content_type.is_none());
        assert!(reading.content_length.is_none());
        assert!(reading.sample.is_none());
        assert!(!reading.listing);
    }
}

#[test]
fn only_successful_bodies_supply_a_sample() {
    // An error page's body must not become evidence that a sensitive file exists.
    let _serial = SERIAL.lock().unwrap();
    for status in [199, 200, 204, 299, 300, 404, 500] {
        let reading = sweep_reading(&response(status, "Index of /backup/"));
        assert_eq!(reading.status, Some(status));
        assert_eq!(reading.sample.is_some(), (200..300).contains(&status));
        assert_eq!(
            reading.listing,
            (200..300).contains(&status),
            "{status}: listing requires a successful body"
        );
    }
}
