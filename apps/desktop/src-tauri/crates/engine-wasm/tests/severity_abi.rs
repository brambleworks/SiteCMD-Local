//! The severity corpus crosses the ABI, and malformed requests return error frames.

use sitecmd_engine::severity_policy::SeverityAnswer;
use sitecmd_engine_wasm::{scorer_alloc, scorer_free, severity_apply};

const CORPUS: &str = include_str!("../../engine/fixtures/severity/golden.json");

fn call_through_abi(request: &[u8]) -> Vec<u8> {
    unsafe {
        let input = scorer_alloc(request.len() as u32);
        core::ptr::copy_nonoverlapping(request.as_ptr(), input, request.len());
        let frame = severity_apply(input, request.len() as u32) as *mut u8;
        let mut length_bytes = [0u8; 4];
        core::ptr::copy_nonoverlapping(frame, length_bytes.as_mut_ptr(), 4);
        let payload_length = u32::from_le_bytes(length_bytes) as usize;
        let payload = core::slice::from_raw_parts(frame.add(4), payload_length).to_vec();
        scorer_free(frame, (4 + payload_length) as u32);
        payload
    }
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    request: serde_json::Value,
    expected: Option<SeverityAnswer>,
}

fn replay(value: serde_json::Value) {
    let slots = value["cases"].as_array().expect("cases array");
    assert!(!slots.is_empty());
    for slot in slots {
        let case: Case = serde_json::from_value(slot.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", slot["name"]));
        assert!(
            case.expected.is_some(),
            "{} needs an expected answer",
            case.name
        );
        let payload =
            call_through_abi(&serde_json::to_vec(&case.request).expect("request serializes"));
        let answer: SeverityAnswer = serde_json::from_slice(&payload)
            .unwrap_or_else(|error| panic!("{}: payload is an answer, not {error}", case.name));
        assert_eq!(
            serde_json::to_value(answer).unwrap(),
            slot["expected"],
            "{}",
            case.name
        );
    }
}

#[test]
fn golden_corpus_round_trips_the_abi() {
    replay(serde_json::from_str(CORPUS).unwrap());
}

#[test]
#[should_panic(expected = "pass_and_skipped_rows_are_low")]
fn missing_answer_keys_name_the_case() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][0]["expected"]
        .as_object_mut()
        .unwrap()
        .remove("code");
    replay(value);
}

#[test]
#[should_panic(expected = "pass_and_skipped_rows_are_low")]
fn an_extra_null_answer_member_does_not_replay() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][0]["expected"]["extra"] = serde_json::Value::Null;
    replay(value);
}

#[test]
fn a_malformed_request_comes_back_as_an_error_frame() {
    let payload = call_through_abi(
        br#"{"web":[{"check_id":"seo.title","status":"maybe","severity":"high"}]}"#,
    );
    let frame: serde_json::Value = serde_json::from_slice(&payload).expect("the frame is JSON");
    assert!(
        frame["error"]
            .as_str()
            .is_some_and(|message| message.contains("unknown variant")),
        "{frame}"
    );
}

#[test]
fn an_oversized_broken_count_comes_back_as_an_error_frame() {
    let payload = call_through_abi(
        br#"{"web":[{"check_id":"seo.broken_links","status":"fail","severity":"high","broken_count":4294967296}]}"#,
    );
    let frame: serde_json::Value = serde_json::from_slice(&payload).expect("the frame is JSON");
    assert!(frame["error"].as_str().is_some(), "{frame}");
}

#[test]
fn a_negative_broken_count_comes_back_as_an_error_frame() {
    let payload = call_through_abi(
        br#"{"web":[{"check_id":"seo.broken_links","status":"fail","severity":"high","broken_count":-1}]}"#,
    );
    let frame: serde_json::Value = serde_json::from_slice(&payload).expect("the frame is JSON");
    assert!(frame["error"].as_str().is_some(), "{frame}");
}
