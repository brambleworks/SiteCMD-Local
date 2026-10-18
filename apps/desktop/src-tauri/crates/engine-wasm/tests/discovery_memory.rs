//! Discovery allocation follows the page byte cap and the selected route limit.

#[path = "support/abi.rs"]
mod abi;

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

use serde_json::json;
use sitecmd_engine::evaluation::PageArtifact;
use sitecmd_engine::log_sanitizer::ISSUE_EVIDENCE_URL_MAX_CHARS;
use sitecmd_engine_wasm::{engine_route_discover, engine_route_plan};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static MEASUREMENT: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Relaxed) + layout.size();
            PEAK.fetch_max(live, Relaxed);
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

const PAGE_BYTES: usize = 1_048_576;
const ROUTE_LIMIT: usize = 99;
// Three page buffers cover borrowed tag-slice storage and its capacity growth;
// each kept route has two UTF-8 copies of at most four bytes per stored character.
const DISCOVERY_HEADROOM: usize =
    3 * PAGE_BYTES + ROUTE_LIMIT * 2 * 4 * ISSUE_EVIDENCE_URL_MAX_CHARS;

fn discovery_peak(extension: &str) -> serde_json::Value {
    let _measurement = MEASUREMENT
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut body = String::with_capacity(PAGE_BYTES);
    for index in 0.. {
        let anchor = format!("<a href=/{index}{extension}>");
        if body.len() + anchor.len() > PAGE_BYTES {
            break;
        }
        write!(body, "{anchor}").expect("anchor");
    }
    body.extend(std::iter::repeat_n(' ', PAGE_BYTES - body.len()));
    assert_eq!(body.len(), PAGE_BYTES);
    let page: PageArtifact = serde_json::from_value(json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": body, "evaluation_time": "2026-10-18T00:00:00Z"
    }))
    .expect("page");
    abi::open(&page);
    // Hosted discovery follows planning, which initializes shared page caches.
    abi::call(engine_route_plan, b"{}");
    let request = serde_json::to_vec(&json!({"limit": ROUTE_LIMIT})).expect("request");
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let answer = abi::call(engine_route_discover, &request);
    let peak = PEAK.load(Relaxed).saturating_sub(before);
    eprintln!("extension {extension:?}: discovery peak {peak}; bound {DISCOVERY_HEADROOM}");
    assert!(
        peak <= DISCOVERY_HEADROOM,
        "discovery allocated {peak} bytes above baseline; bound {DISCOVERY_HEADROOM}"
    );
    serde_json::from_slice(&answer).expect("discovery response")
}

#[test]
fn short_page_links_stay_within_page_and_chosen_route_headroom() {
    let answer = discovery_peak("");
    let expected: Vec<String> = (0..ROUTE_LIMIT).map(|index| format!("/{index}")).collect();
    assert_eq!(answer, json!({"routes": expected}));
}

#[test]
fn rejected_cached_files_stay_within_page_and_chosen_route_headroom() {
    assert_eq!(discovery_peak(".css"), json!({"routes": []}));
}
