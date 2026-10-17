//! Invalid sitemap bytes cross the ABI without an expanded text allocation.

#[path = "support/abi.rs"]
mod abi;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use serde_json::json;
use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
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
fn invalid_sitemap_batch_uses_less_than_eight_mib_above_the_caller_frame() {
    let page: PageArtifact = serde_json::from_value(json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-10-16T00:00:00Z"
    }))
    .expect("page");
    abi::open(&page);
    abi::call(engine_route_plan, b"{}");
    let mut region = Vec::with_capacity(3 * 2_097_152);
    let mut outcomes = Vec::new();
    for (path, root, entry) in [
        ("sitemap.xml", "html", "p"),
        ("declared.xml", "urlset", "url"),
        ("index.xml", "sitemapindex", "sitemap"),
    ] {
        let at = region.len();
        let prefix =
            format!("<{root}><{entry}><loc>https://example.com/child.xml</loc></{entry}><!--");
        let suffix = format!("--></{root}>");
        region.extend_from_slice(prefix.as_bytes());
        region.resize(at + 2_097_152 - suffix.len(), 0xff);
        region.extend_from_slice(suffix.as_bytes());
        let url = format!("https://example.com/{path}");
        outcomes.push(
            json!({"key": probe_key(&sitemap_request(&url)), "outcome": {
                "kind": "response", "status": 200, "final_url": url,
                "content_type": "application/xml", "body": {"at": at, "len": 2_097_152}
            }}),
        );
    }
    let json = serde_json::to_vec(&json!({"probe_outcomes": outcomes})).expect("JSON");
    let frame = abi::frame(&json, &region);
    drop(region);
    drop(outcomes);
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let answer = abi::call_raw(engine_route_plan, &frame);
    let peak = PEAK.load(Relaxed).saturating_sub(before);
    eprintln!("peak invalid sitemap batch bytes: {peak}");
    assert!(abi::refusal(&answer).is_none());
    assert!(
        peak < 8_388_608,
        "invalid sitemap batch allocated {peak} bytes"
    );
}
