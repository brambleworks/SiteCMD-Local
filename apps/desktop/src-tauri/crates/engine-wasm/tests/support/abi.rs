//! The framed exports called from a native test as the hosted runtime calls
//! them: allocate, copy the request in, call, read the frame, free it.

use sitecmd_engine::evaluation::PageArtifact;
use sitecmd_engine_wasm::{engine_route_open, scorer_alloc, scorer_free};

pub type Entry = unsafe extern "C" fn(*mut u8, u32) -> *const u8;

pub fn call(entry: Entry, request: &[u8]) -> Vec<u8> {
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

pub fn call_json(entry: Entry, request: &serde_json::Value) -> Vec<u8> {
    call(
        entry,
        &serde_json::to_vec(request).expect("request serializes"),
    )
}

/// Open this thread's route on `page`, failing the test on a refusal.
pub fn open(page: &PageArtifact) -> Vec<u8> {
    let opened = call_json(engine_route_open, &serde_json::json!({ "page": page }));
    let frame: serde_json::Value = serde_json::from_slice(&opened).expect("a JSON frame");
    assert!(frame.get("error").is_none(), "{frame}");
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
