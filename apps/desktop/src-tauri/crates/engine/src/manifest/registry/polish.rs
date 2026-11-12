//! Polish signal manifest entries: the signals that read only the page on the
//! artifact lane, and the ones that also read linked stylesheets on the probe
//! lane, origin-scoped.

use crate::manifest::Entry;

pub const ENTRIES: &[Entry] = &[
    Entry::new("polish.ai-buzzword-dictionary").revision(3),
    Entry::new("polish.ai-header-formulas").revision(3),
    Entry::new("polish.boilerplate-html").revision(2),
    Entry::new("polish.button-vs-clickable-div"),
    Entry::new("polish.console-log-production"),
    Entry::new("polish.dead-social-links"),
    Entry::new("polish.default-deployment-subdomain").revision(2),
    Entry::new("polish.default-error-page").revision(2),
    Entry::new("polish.default-favicon").revision(2),
    Entry::new("polish.default-page-title").revision(2),
    Entry::new("polish.div-soup-ratio"),
    Entry::new("polish.em-dash-density"),
    Entry::new("polish.emoji-as-icons"),
    Entry::new("polish.excessive-border-radius")
        .probe()
        .origin(),
    Entry::new("polish.eyebrow-labels"),
    Entry::new("polish.floating-blobs").probe().origin(),
    Entry::new("polish.form-accessibility").revision(2),
    Entry::new("polish.glassmorphism").probe().origin(),
    Entry::new("polish.glow-shadows").probe().origin(),
    Entry::new("polish.gradient-backgrounds")
        .revision(2)
        .probe()
        .origin(),
    Entry::new("polish.gradient-text").probe().origin(),
    Entry::new("polish.heading-hierarchy"),
    Entry::new("polish.inclusive-framing"),
    Entry::new("polish.inline-style-density").revision(2),
    Entry::new("polish.missing-lang"),
    Entry::new("polish.missing-og-tags"),
    Entry::new("polish.no-css-architecture").revision(2),
    Entry::new("polish.no-sitemap-robots"),
    Entry::new("polish.placeholder-text"),
    Entry::new("polish.scroll-animations"),
    Entry::new("polish.source-maps-production"),
    Entry::new("polish.tailwind-class-density"),
    Entry::new("polish.three-column-grid"),
];
