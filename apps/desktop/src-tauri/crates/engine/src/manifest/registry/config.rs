//! Configuration and pre-deploy manifest entries with explicit page or origin scope.

use crate::manifest::Entry;

pub const ENTRIES: &[Entry] = &[
    Entry::new("config.analytics"),
    Entry::new("config.console_logs"),
    Entry::new("config.custom_404").probe().origin().revision(2),
    Entry::new("config.debug_mode"),
    Entry::new("config.deprecated_html"),
    Entry::new("config.dev_dependencies"),
    Entry::new("config.favicon").probe(),
    Entry::new("config.localhost_refs"),
    Entry::new("config.placeholder_content"),
    Entry::new("config.print_stylesheet"),
    Entry::new("config.responsive_design"),
    Entry::new("config.sitemap_in_robots").probe().origin(),
    Entry::new("config.todo_comments"),
    Entry::new("config.trailing_slash"),
    Entry::new("config.web_manifest").probe(),
    // Revision 2 declines to grade failed alternate-host probes.
    Entry::new("config.www_redirect")
        .probe()
        .origin()
        .revision(2),
];
