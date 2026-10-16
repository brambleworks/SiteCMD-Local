//! The framed exports called from a native test as the hosted runtime calls
//! them: allocate, copy the request in, call, read the frame, free it.

use sitecmd_engine::evaluation::PageArtifact;
use sitecmd_engine_wasm::{engine_route_open, scorer_alloc, scorer_free};

pub type Entry = unsafe extern "C" fn(*mut u8, u32) -> *const u8;

pub fn call_raw(entry: Entry, request: &[u8]) -> Vec<u8> {
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

pub fn frame(json: &[u8], body: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(4 + json.len() + body.len());
    request.extend_from_slice(&(json.len() as u32).to_le_bytes());
    request.extend_from_slice(json);
    request.extend_from_slice(body);
    request
}

pub fn call(entry: Entry, json: &[u8]) -> Vec<u8> {
    call_raw(entry, &frame(json, &[]))
}

pub fn call_json(entry: Entry, request: &serde_json::Value) -> Vec<u8> {
    let mut request = request.clone();
    let mut region = Vec::new();
    if let Some(body) = request.pointer_mut("/page/body") {
        append_body(body, &mut region);
    }
    if let Some(outcomes) = request
        .get_mut("probe_outcomes")
        .and_then(serde_json::Value::as_array_mut)
    {
        for probe in outcomes {
            let fixture = probe["key"].as_str().expect("fixture probe key").to_owned();
            if let Some(body) = probe.pointer_mut("/outcome/body") {
                if !body.is_null() {
                    let text_len = body["text"].as_str().expect("fixture body text").len();
                    assert_eq!(
                        body["bytes"].as_u64(),
                        Some(text_len as u64),
                        "{fixture}: fixture bytes differ from its UTF-8 text length"
                    );
                    assert_eq!(
                        body["utf8_valid"].as_bool(),
                        Some(true),
                        "{fixture}: fixture text cannot reproduce invalid UTF-8 bytes"
                    );
                    append_body(&mut body["text"], &mut region);
                    *body = body["text"].take();
                }
            }
        }
    }
    let json = serde_json::to_vec(&request).expect("request serializes");
    call_raw(entry, &frame(&json, &region))
}

fn append_body(body: &mut serde_json::Value, region: &mut Vec<u8>) {
    let text = body.as_str().expect("fixture body is UTF-8");
    let reference = serde_json::json!({ "at": region.len(), "len": text.len() });
    region.extend_from_slice(text.as_bytes());
    *body = reference;
}

/// Open this thread's route on `page`, failing the test on a refusal.
pub fn open(page: &PageArtifact) -> Vec<u8> {
    let opened = call_json(engine_route_open, &serde_json::json!({ "page": page }));
    assert!(
        refusal(&opened).is_none(),
        "{}",
        String::from_utf8_lossy(&opened)
    );
    opened
}

/// The refusal a frame carries, if it is one.
pub fn refusal(frame: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(frame).expect("a JSON frame");
    value
        .get("error")
        .and_then(|error| error.as_str())
        .map(str::to_string)
}
