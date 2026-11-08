// Page-only polish work must not copy a commented page to build unused CSS counts.

use sitecmd_engine::checks::polish::{
    ai_aesthetic, css_signal_counts, run_page_signals, CssTextKind, PolishContext,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct CountingAllocator;
static WATCH_SIZE: AtomicUsize = AtomicUsize::new(usize::MAX);
static LARGE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && layout.size() >= WATCH_SIZE.load(Relaxed) {
            LARGE_ALLOCATIONS.fetch_add(1, Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn watched<T>(size: usize, run: impl FnOnce() -> T) -> (T, usize) {
    LARGE_ALLOCATIONS.store(0, Relaxed);
    WATCH_SIZE.store(size, Relaxed);
    let value = run();
    WATCH_SIZE.store(usize::MAX, Relaxed);
    (value, LARGE_ALLOCATIONS.load(Relaxed))
}

#[test]
fn counts_wait_for_a_stylesheet_signal_and_are_reused_afterward() {
    // Eager page counting copies comment-bearing HTML before any CSS signal needs it.
    css_signal_counts("<p>Warm</p><!--warm-->", CssTextKind::Page);
    let html = format!("<p>Page</p><!--{}-->", "x".repeat(4096));
    let url = url::Url::parse("https://example.com/").unwrap();
    let (ctx, allocations) = watched(html.len(), || {
        PolishContext::new(url, std::borrow::Cow::Borrowed(&html), Default::default())
    });
    assert_eq!(
        allocations, 0,
        "constructing a context must not count or copy its page"
    );
    assert_eq!(ctx.html.as_ptr(), html.as_ptr());
    run_page_signals(&ctx);
    let (first, allocations) = watched(html.len(), || ai_aesthetic::gradient_backgrounds(&ctx));
    assert!(
        allocations > 0,
        "page-only signals must leave counts for the first CSS reader"
    );
    let (second, allocations) = watched(html.len(), || ai_aesthetic::gradient_backgrounds(&ctx));
    assert_eq!(
        allocations, 0,
        "a repeated CSS grade must reuse the page counts"
    );
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(second).unwrap()
    );
}
