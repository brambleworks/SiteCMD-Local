//! Configuration and pre-deploy manifest entries with explicit page or origin scope.

use crate::manifest::Entry;

pub const ENTRIES: &[Entry] = &[
    Entry::new("config.analytics"),
    Entry::new("config.custom_404").probe().origin().revision(2),
    Entry::new("config.deprecated_html"),
    Entry::new("config.favicon").probe(),
    Entry::new("config.print_stylesheet"),
    Entry::new("config.responsive_design"),
    Entry::new("config.sitemap_in_robots").probe().origin(),
    Entry::new("config.trailing_slash"),
    Entry::new("config.web_manifest").probe(),
    // Revision 2 declines to grade failed alternate-host probes.
    Entry::new("config.www_redirect")
        .probe()
        .origin()
        .revision(2),
    // These checks require localhost, so a hosted page cannot produce them.
    Entry::new("config.console_logs").unsupported(),
    Entry::new("config.debug_mode").unsupported(),
    Entry::new("config.dev_dependencies").unsupported(),
    Entry::new("config.localhost_refs").unsupported(),
    Entry::new("config.placeholder_content").unsupported(),
    Entry::new("config.todo_comments").unsupported(),
];
