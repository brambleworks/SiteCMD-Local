//! Capability metadata for performance checks and browser measurements.
//!
//! Protocol and compression compare within a transport profile; timing samples
//! remain outside finding lifecycle.

use crate::manifest::{CompareDimension, Entry, MeasurementUnit};

pub const ENTRIES: &[Entry] = &[
    // Revision 2 declines to grade a sample nobody answered.
    Entry::new("performance.asset_caching").probe().revision(2),
    Entry::new("performance.asset_weight").probe().revision(2),
    Entry::new("performance.broken_images").probe(),
    Entry::new("performance.cache"),
    Entry::new("performance.cls")
        .browser()
        .measurement(MeasurementUnit::Ratio),
    Entry::new("performance.compression")
        .probe()
        .compare_on(&[CompareDimension::TransportProfile]),
    Entry::new("performance.dom_size"),
    Entry::new("performance.fcp")
        .browser()
        .measurement(MeasurementUnit::Milliseconds),
    Entry::new("performance.fonts"),
    Entry::new("performance.http2").compare_on(&[CompareDimension::TransportProfile]),
    Entry::new("performance.images"),
    Entry::new("performance.images.dimensions"),
    Entry::new("performance.images.format"),
    Entry::new("performance.images.heavy").probe().revision(2),
    Entry::new("performance.images.lazy"),
    Entry::new("performance.inline_css"),
    Entry::new("performance.lcp")
        .browser()
        .measurement(MeasurementUnit::Milliseconds),
    Entry::new("performance.long_task_blocking")
        .browser()
        .measurement(MeasurementUnit::Milliseconds),
    // Graded from the already-fetched body's byte count. The desktop runs it
    // through an async shell, which is a scheduling detail rather than a
    // transport need: nothing is requested that the page fetch did not
    // already return.
    Entry::new("performance.page_weight"),
    Entry::new("performance.preconnect"),
    Entry::new("performance.redirect_chain").probe(),
    Entry::new("performance.render_blocking"),
    Entry::new("performance.third_party"),
    // The transport lane is the primary producer and the one the hosted
    // runner uses; the browser navigation reports the same field through the
    // same grading ladder when a browser pass ran. Either way it is a timing.
    Entry::new("performance.ttfb")
        .probe()
        .measurement(MeasurementUnit::Milliseconds),
    Entry::new("performance.unminified"),
    // Errors the page threw during a real navigation. A finding rather than a
    // value, so it stays in the lifecycle, but only a browser can observe it
    // and engines differ about what throws.
    Entry::new("polish.js-errors").browser(),
];
