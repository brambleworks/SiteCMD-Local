//! Minimal C ABI for the portable scorer, the severity policy and the optional check evaluator.
//!
//! Entry points consume UTF-8 JSON buffers and return length-prefixed JSON.
//! Malformed input returns an error frame; internal panics trap.

use sitecmd_engine::scoring::calculator::{compute_score, ScoreInputGroup};

/// The request shape: the golden corpus's case fields, minus the expectation.
#[derive(serde::Deserialize)]
struct ScoreRequest {
    groups: Vec<ScoreInputGroup>,
    now_ms: i64,
}

/// The one refusal shape all calls answer with, so a caller has a single
/// "is this an error frame?" test rather than one per entry point.
#[derive(serde::Serialize)]
struct AbiError {
    error: String,
}

/// Leak a framed `[len: u32 LE][payload]` buffer to the caller. Reclaimed by
/// `scorer_free` with the full framed length.
fn leak_framed(payload: Vec<u8>) -> *const u8 {
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(&payload);
    Box::into_raw(framed.into_boxed_slice()) as *const u8
}

/// Allocate `len` zeroed bytes inside the instance's memory for the caller to
/// fill. Ownership passes back through `scorer_score` or `severity_apply`
/// (which consume request buffers) or `scorer_free` (which releases buffers).
#[no_mangle]
pub extern "C" fn scorer_alloc(len: u32) -> *mut u8 {
    Box::into_raw(vec![0u8; len as usize].into_boxed_slice()) as *mut u8
}

/// Release a buffer this module handed out: a `scorer_score` or
/// `severity_apply` result frame (`len` = 4 + payload length), or an unused
/// `scorer_alloc` buffer.
///
/// # Safety
///
/// `ptr` must be a pointer previously returned by `scorer_alloc` or
/// `scorer_score` or `severity_apply` with exactly the allocation's full
/// length, not yet consumed or freed.
#[no_mangle]
pub unsafe extern "C" fn scorer_free(ptr: *mut u8, len: u32) {
    drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
        ptr,
        len as usize,
    )));
}

/// Score a request buffer and return a framed JSON result (see the module
/// doc for the frame layout). Consumes the request buffer.
///
/// # Safety
///
/// `ptr` must be a buffer of exactly `len` bytes obtained from
/// `scorer_alloc` and not yet freed; after this call the caller must not
/// use it again.
#[no_mangle]
pub unsafe extern "C" fn scorer_score(ptr: *mut u8, len: u32) -> *const u8 {
    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let payload = match serde_json::from_slice::<ScoreRequest>(&request) {
        Ok(parsed) => {
            let snapshot = compute_score(&parsed.groups, parsed.now_ms);
            // Canonicalize map order so identical requests produce stable ABI bytes.
            serde_json::to_value(&snapshot)
                .and_then(|value| serde_json::to_vec(&value))
                .unwrap_or_else(|error| error_payload(&error))
        }
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

/// Apply the severity policy to a request buffer and return a framed JSON
/// answer. Consumes the request buffer. The default build includes this export
/// because Connect normalizes hosted verdicts with it.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[no_mangle]
pub unsafe extern "C" fn severity_apply(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::severity_policy::{apply, SeverityRequest};

    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let payload = match serde_json::from_slice::<SeverityRequest>(&request) {
        Ok(parsed) => serde_json::to_value(apply(&parsed))
            .and_then(|value| serde_json::to_vec(&value))
            .unwrap_or_else(|error| error_payload(&error)),
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

/// Evaluate gathered route facts and return framed JSON with coverage reasons.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_evaluate(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::{evaluate, EvaluationRequest};

    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let payload = match serde_json::from_slice::<EvaluationRequest>(&request) {
        // Malformed requests and unusable artifacts return data rather than trap.
        Ok(parsed) => match evaluate(&parsed) {
            // Canonicalize arbitrary `raw_data` maps for deterministic bytes.
            Ok(response) => serde_json::to_value(&response)
                .and_then(|value| serde_json::to_vec(&value))
                .unwrap_or_else(|error| error_payload(&error)),
            Err(error) => error_payload(&error),
        },
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

/// Return the next framed probe plan for a route.
/// Named omissions distinguish a complete plan from unsupported probe checks.
///
/// # Safety
///
/// `ptr` must be a buffer of exactly `len` bytes obtained from
/// `scorer_alloc` and not yet freed; after this call the caller must not
/// use it again.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_probe_plan(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::{probe_plan, EvaluationRequest};

    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let payload = match serde_json::from_slice::<EvaluationRequest>(&request) {
        // Malformed requests and unusable artifacts return data rather than trap.
        Ok(parsed) => match probe_plan(&parsed) {
            // The same Value round trip, so identical requests produce
            // identical payloads.
            Ok(plan) => serde_json::to_value(&plan)
                .and_then(|value| serde_json::to_vec(&value))
                .unwrap_or_else(|error| error_payload(&error)),
            Err(error) => error_payload(&error),
        },
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

/// Return one page's comparison facts as framed JSON, `null` for a page whose
/// own address cannot be named without query material or credentials.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_session_page(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::{session_page, SessionPageRequest};

    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let payload = match serde_json::from_slice::<SessionPageRequest>(&request) {
        Ok(parsed) => match session_page(&parsed) {
            Ok(facts) => serde_json::to_value(&facts)
                .and_then(|value| serde_json::to_vec(&value))
                .unwrap_or_else(|error| error_payload(&error)),
            Err(error) => error_payload(&error),
        },
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

/// Compare one scan's pages and return its cross-page verdicts as framed JSON.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_session_evaluate(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::{evaluate_session, SessionRequest};

    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let payload = match serde_json::from_slice::<SessionRequest>(&request) {
        Ok(parsed) => serde_json::to_value(evaluate_session(&parsed))
            .and_then(|value| serde_json::to_vec(&value))
            .unwrap_or_else(|error| error_payload(&error)),
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

fn error_payload(error: &dyn core::fmt::Display) -> Vec<u8> {
    serde_json::to_vec(&AbiError {
        error: error.to_string(),
    })
    .expect("a flat string struct always serializes")
}
