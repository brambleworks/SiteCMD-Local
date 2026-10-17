//! Minimal C ABI for the portable scorer, the severity policy and the optional check evaluator.
//!
//! Entry points consume UTF-8 JSON buffers (the `checks` entries framed as `[JSON length: u32 LE]`
//! `[JSON][body region]`, see `request.rs`) and return length-prefixed JSON. Malformed input
//! returns an error frame; internal panics trap.
//!
//! With the `checks` feature an instance evaluates one route: `engine_route_open` reads the
//! route's document once, and each route call after it carries only what is new: the probe
//! outcomes executed since the previous call, and the facts or routes that call reads.

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

// The framing every `checks` entry reads its request in.
#[cfg(feature = "checks")]
mod request;
#[cfg(feature = "checks")]
use request::{read_request, BodyFields};

/// Serialize through a `Value`, which orders map keys, so identical answers
/// are identical bytes.
#[cfg(feature = "checks")]
fn canonical(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_value(value)
        .and_then(|value| serde_json::to_vec(&value))
        .unwrap_or_else(|error| error_payload(&error))
}

#[cfg(feature = "checks")]
thread_local! {
    /// The route this instance evaluates. An instance serves one route and
    /// dies with it, so one slot is all the state it keeps.
    static ROUTE: std::cell::RefCell<Option<sitecmd_engine::evaluation::RouteSession>> =
        const { std::cell::RefCell::new(None) };
}

/// Answer from the open route, or refuse when none is open.
#[cfg(feature = "checks")]
fn with_route(
    answer: impl FnOnce(&mut sitecmd_engine::evaluation::RouteSession) -> Vec<u8>,
) -> Vec<u8> {
    ROUTE.with(|slot| match slot.borrow_mut().as_mut() {
        Some(route) => answer(route),
        None => error_payload(&"no route is open on this instance"),
    })
}

/// Open this instance's route on its document and answer the external facts
/// its evaluation reads. Replaces any route already open; a refused open
/// leaves none open.
/// Its request is framed (see `request.rs`), `page.body` a reference
/// `{"at": offset, "len": byte_length}` into the body region.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_route_open(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::{RouteOpenRequest, RouteSession};

    let parsed = read_request::<RouteOpenRequest>(ptr, len, BodyFields::Page);
    ROUTE.with(|slot| *slot.borrow_mut() = None);
    let payload = match parsed.map(|open| {
        RouteSession::open_with(open.page, open.header_lines)
            .map(|route| route.with_sitemap_children(open.sitemap_children))
    }) {
        Ok(Ok(route)) => {
            let opened = canonical(&route.opened());
            ROUTE.with(|slot| *slot.borrow_mut() = Some(route));
            opened
        }
        Ok(Err(error)) => error_payload(&error),
        Err(error) => error_payload(&error),
    };
    leak_framed(payload)
}

/// Record the outcomes executed since the previous call and answer the
/// route's next probe plan.
/// Its request is framed (see `request.rs`): each response `body` in `probe_outcomes`
/// is null or a reference `{"at": offset, "len": byte_length}` into the body region.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_route_plan(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::RouteCall;

    let parsed = read_request::<RouteCall>(ptr, len, BodyFields::Probes);
    leak_framed(match parsed {
        Ok(call) => with_route(|route| {
            route.record(call.probe_outcomes);
            canonical(&route.plan())
        }),
        Err(error) => error_payload(&error),
    })
}

/// Record the outcomes executed since the previous call and answer the
/// route's evaluation with these facts.
/// Its request is framed (see `request.rs`): each response `body` in `probe_outcomes`
/// is null or a reference `{"at": offset, "len": byte_length}` into the body region.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_route_evaluate(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::RouteEvaluationRequest;

    let parsed = read_request::<RouteEvaluationRequest>(ptr, len, BodyFields::Probes);
    leak_framed(match parsed {
        Ok(call) => with_route(|route| {
            route.record(call.probe_outcomes);
            canonical(&route.evaluate(&call.facts))
        }),
        Err(error) => error_payload(&error),
    })
}

/// Answer the route's comparison facts, `null` for a page whose own address
/// cannot be named without query material or credentials.
/// Its request is framed (see `request.rs`); the body region goes unread.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_route_session_page(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::RouteSessionPageRequest;

    let parsed = read_request::<RouteSessionPageRequest>(ptr, len, BodyFields::None);
    leak_framed(match parsed {
        Ok(call) => with_route(|route| match route.session_page(&call.routes) {
            Ok(facts) => canonical(&facts),
            Err(error) => error_payload(&error),
        }),
        Err(error) => error_payload(&error),
    })
}

/// Answer the routes the open route's reads discover for its scan.
/// Its request is framed (see `request.rs`); the body region goes unread.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_route_discover(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::RouteDiscoverRequest;

    let parsed = read_request::<RouteDiscoverRequest>(ptr, len, BodyFields::None);
    leak_framed(match parsed {
        Ok(call) => with_route(|route| canonical(&route.discover(&call.planned, call.limit))),
        Err(error) => error_payload(&error),
    })
}

/// Compare one scan's pages and return its cross-page verdicts as framed JSON.
/// Its request is framed (see `request.rs`); the body region goes unread.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
/// This call consumes the buffer.
#[cfg(feature = "checks")]
#[no_mangle]
pub unsafe extern "C" fn engine_session_evaluate(ptr: *mut u8, len: u32) -> *const u8 {
    use sitecmd_engine::evaluation::{evaluate_session, SessionRequest};

    let parsed = read_request::<SessionRequest>(ptr, len, BodyFields::None);
    let payload = match parsed {
        Ok(parsed) => canonical(&evaluate_session(&parsed)),
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
