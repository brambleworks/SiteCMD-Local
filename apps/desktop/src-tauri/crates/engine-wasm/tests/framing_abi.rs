//! Request framing and body-reference refusals remain ordinary JSON answers.

#[path = "support/abi.rs"]
mod abi;

use serde_json::{json, Value};
use sitecmd_engine::evaluation::PageArtifact;
use sitecmd_engine_wasm::{
    engine_route_discover, engine_route_evaluate, engine_route_open, engine_route_plan,
    engine_route_session_page, engine_session_evaluate,
};

fn page() -> PageArtifact {
    serde_json::from_value(json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-08-05T00:00:00Z"
    }))
    .expect("page")
}

fn entries() -> [abi::Entry; 6] {
    [
        engine_route_open,
        engine_route_plan,
        engine_route_evaluate,
        engine_route_session_page,
        engine_route_discover,
        engine_session_evaluate,
    ]
}

fn assert_refused(entry: abi::Entry, bytes: &[u8]) {
    let payload = abi::call_raw(entry, bytes);
    let error = abi::refusal(&payload).expect("an error frame");
    assert!(!error.is_empty());
    assert_ne!(error, "no route is open on this instance");
}

#[test]
fn every_route_entry_refuses_short_prefixes_and_json_past_the_buffer() {
    for entry in entries() {
        abi::open(&page());
        for length in 0..4 {
            assert_refused(entry, &vec![0; length]);
        }
        for bytes in [
            [3u32.to_le_bytes().as_slice(), b"{}"].concat(),
            u32::MAX.to_le_bytes().to_vec(),
            abi::frame(b"{ broken", &[]),
        ] {
            assert_refused(entry, &bytes);
        }
    }
}

#[test]
fn all_six_entries_accept_their_framed_requests() {
    abi::open(&page());
    for (entry, request) in [
        (engine_route_plan as abi::Entry, json!({})),
        (engine_route_evaluate, json!({})),
        (engine_route_session_page, json!({"routes": []})),
        (engine_route_discover, json!({"limit": 0})),
        (engine_session_evaluate, json!({"pages": []})),
    ] {
        let json = serde_json::to_vec(&request).expect("JSON");
        assert!(abi::refusal(&abi::call(entry, &json)).is_none());
    }
}

fn with_body(entry: abi::Entry, body: Value) -> Vec<u8> {
    let mut request = if std::ptr::fn_addr_eq(entry, engine_route_open as abi::Entry) {
        json!({"page": page()})
    } else {
        json!({"probe_outcomes": [{"key": "probe", "outcome": {
            "kind": "response", "status": 200, "final_url": "https://example.com/",
            "content_type": null, "body": null
        }}]})
    };
    let path = if request.get("page").is_some() {
        "/page/body"
    } else {
        "/probe_outcomes/0/outcome/body"
    };
    *request.pointer_mut(path).expect("body field") = body;
    abi::frame(&serde_json::to_vec(&request).expect("JSON"), b"x")
}

#[test]
fn body_references_outside_the_region_are_refused() {
    for entry in [
        engine_route_open as abi::Entry,
        engine_route_plan,
        engine_route_evaluate,
    ] {
        for body in [
            json!({"at": 2, "len": 0}),
            json!({"at": 0, "len": 2}),
            json!({"at": 1, "len": 1}),
            json!({"at": u64::MAX, "len": 1}),
            json!({"at": 1, "len": u64::MAX}),
        ] {
            abi::open(&page());
            assert_refused(entry, &with_body(entry, body));
        }
    }
}

#[test]
fn inline_bodies_and_malformed_references_are_refused() {
    for entry in [
        engine_route_open as abi::Entry,
        engine_route_plan,
        engine_route_evaluate,
    ] {
        for body in [
            json!("inline"),
            json!({"text": "inline", "bytes": 6, "utf8_valid": true}),
            json!({}),
            json!({"at": 0}),
            json!({"len": 0}),
            json!({"at": -1, "len": 0}),
            json!({"at": 0, "len": 0.5}),
            json!([]),
        ] {
            abi::open(&page());
            assert_refused(entry, &with_body(entry, body));
        }
    }
    let body = json!({"text": "Sitemap: https://example.com/hidden-sitemap.xml", "bytes": 47,
        "utf8_valid": true});
    let response = json!({"kind": "response", "status": 200,
        "final_url": "https://example.com/robots.txt", "content_type": "text/plain", "body": body});
    let probe = json!({"key": "robots", "outcome": response});
    let mut accepted = Vec::new();
    for (name, entry) in [
        ("plan", engine_route_plan as abi::Entry),
        ("evaluate", engine_route_evaluate),
    ] {
        for (shape, request) in [
            (
                "probe array",
                json!({"probe_outcomes": [["robots", response]]}),
            ),
            (
                "outcome array",
                json!({"probe_outcomes": [{"key": "robots", "outcome":
                ["response", 200, "https://example.com/robots.txt", "text/plain", null, [], body]}]}),
            ),
        ] {
            abi::open(&page());
            let payload = abi::call_raw(
                entry,
                &abi::frame(&serde_json::to_vec(&request).expect("JSON"), &[]),
            );
            if abi::refusal(&payload).is_none() {
                accepted.push(format!("{name}: {shape}"));
            }
        }
    }
    abi::open(&page());
    let payload = abi::call_raw(
        engine_route_plan,
        &abi::frame(&serde_json::to_vec(&json!([[probe]])).expect("JSON"), &[]),
    );
    if abi::refusal(&payload).is_none() {
        accepted.push("request array".into());
    }
    for entry in [
        engine_route_open as abi::Entry,
        engine_route_plan,
        engine_route_evaluate,
    ] {
        abi::open(&page());
        if abi::refusal(&abi::call_raw(entry, &with_body(entry, json!([0, 1])))).is_none() {
            accepted.push("reference array".into());
        }
    }
    assert!(accepted.is_empty(), "accepted inline shapes: {accepted:?}");
}

#[test]
fn empty_references_at_the_region_end_and_null_probe_bodies_are_accepted() {
    for entry in [
        engine_route_open as abi::Entry,
        engine_route_plan,
        engine_route_evaluate,
    ] {
        abi::open(&page());
        assert!(abi::refusal(&abi::call_raw(
            entry,
            &with_body(entry, json!({"at": 1, "len": 0}))
        ))
        .is_none());
        if !std::ptr::fn_addr_eq(entry, engine_route_open as abi::Entry) {
            assert!(abi::refusal(&abi::call_raw(entry, &with_body(entry, Value::Null))).is_none());
        }
    }
}

#[test]
fn legacy_plain_json_route_requests_are_refused() {
    for entry in entries() {
        abi::open(&page());
        let legacy = serde_json::to_vec(&json!({"page": page()})).expect("legacy JSON");
        assert_refused(entry, &legacy);
    }
}

#[test]
fn overlapping_references_cannot_read_more_than_the_region() {
    for entry in [engine_route_plan as abi::Entry, engine_route_evaluate] {
        for (length, refused) in [(2, false), (3, true)] {
            abi::open(&page());
            let request = json!({"probe_outcomes": ([0, 1].map(|at| json!({
                "key": format!("probe-{at}"), "outcome": {"kind": "response", "status": 200,
                "final_url": "https://example.com/", "content_type": null,
                "body": {"at": at, "len": length}}})))});
            let payload = abi::call_raw(
                entry,
                &abi::frame(&serde_json::to_vec(&request).expect("JSON"), b"xxxx"),
            );
            assert_eq!(abi::refusal(&payload).is_some(), refused);
        }
    }
}

#[test]
fn bodiless_entries_refuse_duplicate_fields_with_locations() {
    for (entry, json) in [
        (
            engine_route_session_page as abi::Entry,
            br#"{"routes":[],"routes":[]}"#.as_slice(),
        ),
        (
            engine_route_discover,
            br#"{"limit":0,"limit":1}"#.as_slice(),
        ),
        (
            engine_session_evaluate,
            br#"{"pages":[],"pages":[]}"#.as_slice(),
        ),
    ] {
        abi::open(&page());
        let error = abi::refusal(&abi::call(entry, json)).expect("duplicate field refusal");
        assert!(
            error.contains("duplicate field") && error.contains("line 1 column"),
            "{error}"
        );
    }
}

#[test]
fn malformed_reference_errors_are_fixed_and_do_not_echo_values() {
    for entry in [
        engine_route_open as abi::Entry,
        engine_route_plan,
        engine_route_evaluate,
    ] {
        for body in [
            json!("sensitive".repeat(1024)),
            json!({"at": "private", "len": 0}),
            json!({"at": 0, "len": "secret"}),
            json!({"text": "private"}),
            json!([0, 1]),
        ] {
            abi::open(&page());
            let error = abi::refusal(&abi::call_raw(entry, &with_body(entry, body)))
                .expect("reference refusal");
            assert_eq!(error, "invalid body reference");
        }
    }
}

#[test]
fn fixture_metadata_must_describe_its_utf8_text() {
    for (bytes, valid) in [(2, true), (1, false)] {
        let fixture = "fixture-robots";
        let request = json!({"probe_outcomes": [{"key": fixture, "outcome": {
            "kind": "response", "status": 200, "final_url": "https://example.com/robots.txt",
            "content_type": null, "body": {"text": "x", "bytes": bytes, "utf8_valid": valid}
        }}]});
        abi::open(&page());
        let result = std::panic::catch_unwind(|| abi::call_json(engine_route_plan, &request));
        assert!(
            result.is_err(),
            "noncanonical fixture must fail before packing"
        );
        let panic = result.expect_err("fixture assertion failed");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("panic text");
        assert!(message.contains(fixture), "{message}");
    }
}
