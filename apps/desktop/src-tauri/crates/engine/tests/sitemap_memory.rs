//! A route does not retain expanded text for invalid sitemap responses.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
use sitecmd_engine::evaluation::{probe_key, ExecutedProbe, PageArtifact, RouteSession};
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeResponse};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);

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

#[test]
fn invalid_sitemap_text_is_released_when_recorded() {
    let page: PageArtifact = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/", "status_code": 200, "headers": [],
        "body": "", "evaluation_time": "2026-10-16T00:00:00Z"
    }))
    .expect("page");
    let mut route = RouteSession::open(page).expect("route");
    route.plan();
    let before = LIVE.load(Relaxed);
    let outcomes = (0..3)
        .map(|index| {
            let url = format!("https://example.com/{index}.xml");
            let request = sitemap_request(&url);
            ExecutedProbe::new(
                probe_key(&request),
                ProbeOutcome::Response(ProbeResponse {
                    status: 200,
                    final_url: url,
                    content_type: Some("application/xml".into()),
                    content_length: Some(2_097_152),
                    headers: Vec::new(),
                    body: Some(decode_probe_body(vec![0xff; 2_097_152])),
                }),
            )
        })
        .collect();
    route.record(Some(outcomes));
    let retained = LIVE.load(Relaxed).saturating_sub(before);
    eprintln!("retained invalid sitemap bytes: {retained}");
    assert!(
        retained < 65_536,
        "invalid sitemap text retained {retained} bytes"
    );
}
