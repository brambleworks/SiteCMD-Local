//! Accessibility capability registry.
//! Markup checks compare directly; browser-dependent axe checks use broader comparison fields.

use crate::browser::payload::AXE_CORE_VERSION;
use crate::checks::accessibility::axe::CHECK_ID_PREFIX as AXE_CHECK_ID_PREFIX;
use crate::manifest::{CompareDimension, Entry};

pub const ENTRIES: &[Entry] = &[
    Entry::new("accessibility.aria_usage"),
    Entry::new("accessibility.autoplay"),
    Entry::new("accessibility.color_contrast_hints"),
    Entry::new("accessibility.empty_headings"),
    Entry::new("accessibility.focus_indicators"),
    Entry::new("accessibility.form_labels").revision(2),
    Entry::new("accessibility.headings"),
    Entry::new("accessibility.iframe_title"),
    Entry::new("accessibility.image_alt"),
    Entry::new("accessibility.landmarks"),
    Entry::new("accessibility.lang"),
    Entry::new("accessibility.link_text"),
    Entry::new("accessibility.redundant_alt"),
    Entry::new("accessibility.skip_nav"),
    Entry::new("accessibility.tabindex"),
    Entry::new("accessibility.viewport_zoom"),
    // axe family contracts include the pinned version because rule semantics
    // can change between releases.
    Entry::new(AXE_CHECK_ID_PREFIX)
        .family()
        .browser()
        .contract_extra(&[AXE_CORE_VERSION])
        .compare_on(&[
            CompareDimension::AxeVersion,
            CompareDimension::BrowserEngine,
            CompareDimension::BrowserEpoch,
        ]),
];
