//! Invalid sitemap bytes cross the ABI without an expanded text allocation.

#[path = "support/abi.rs"]
mod abi;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use serde_json::json;
use sitecmd_engine::checks::seo::sitemap_walk::{sitemap_child_request, sitemap_request};
use sitecmd_engine::evaluation::{probe_key, PageArtifact};
use sitecmd_engine_wasm::engine_route_plan;

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

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

#[test]
fn invalid_sitemap_batch_including_child_stays_within_request_copy_headroom() {
    let page: PageArtifact = serde_json::from_value(json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-10-16T00:00:00Z"
    }))
    .expect("page");
    abi::open(&page);
    abi::call(engine_route_plan, b"{}");
    let mut region = Vec::with_capacity(4 * 2_097_152);
    let mut outcomes = Vec::new();
    for (path, root, entry, child) in [
        ("sitemap.xml", "html", "p", false),
        ("declared.xml", "urlset", "url", false),
        ("index.xml", "sitemapindex", "sitemap", false),
        ("child.xml", "urlset", "url", true),
    ] {
        let at = region.len();
        let prefix =
            format!("<{root}><{entry}><loc>https://example.com/child.xml</loc></{entry}><!--");
        let suffix = format!("--></{root}>");
        region.extend_from_slice(prefix.as_bytes());
        region.resize(at + 2_097_152 - suffix.len(), 0xff);
        region.extend_from_slice(suffix.as_bytes());
        let url = format!("https://example.com/{path}");
        let request = if child {
            sitemap_child_request(&url)
        } else {
            sitemap_request(&url)
        };
        outcomes.push(json!({"key": probe_key(&request), "outcome": {
            "kind": "response", "status": 200, "final_url": url,
            "content_type": "application/xml", "body": {"at": at, "len": 2_097_152}
        }}));
    }
    let json = serde_json::to_vec(&json!({"probe_outcomes": outcomes})).expect("JSON");
    let frame = abi::frame(&json, &region);
    drop(region);
    drop(outcomes);
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let answer = abi::call_raw(engine_route_plan, &frame);
    let peak = PEAK.load(Relaxed).saturating_sub(before);
    let beyond_request_copy = peak
        .checked_sub(frame.len())
        .expect("peak includes the request copy");
    eprintln!(
        "request copy: {}; peak: {peak}; beyond request copy: {beyond_request_copy}",
        frame.len()
    );
    assert!(abi::refusal(&answer).is_none());
    assert!(
        beyond_request_copy < 2_097_152,
        "invalid sitemap batch allocated {beyond_request_copy} bytes beyond the request copy"
    );
}
