//! The SEO head checks' runners, and the artifact-lane checks this build
//! deliberately leaves without one.
//!
//! Evaluation runs `RUNNERS` before this table to preserve response order.

use super::runners::Runner;
use crate::checks::seo::meta;
use crate::checks::Check;

/// Artifact-lane manifest entries intentionally excluded from runner coverage,
/// paired with the required reason.
pub const EXCLUDED_ARTIFACT_CHECKS: &[(&str, &str)] = &[
    // Heading-order review stays with accessibility.headings; the H1 count
    // runs separately as the SEO-owned seo.headings.h1.
    (
        "seo.headings.hierarchy",
        "HeadingCheck is unregistered on the desktop; accessibility.headings owns heading order",
    ),
];

/// The head checks, in the manifest order of the first id each covers.
pub const SEO_RUNNERS: &[Runner] = &[
    Runner {
        covers: &["seo.canonical"],
        run: |inputs| meta::CanonicalCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.charset"],
        run: |inputs| meta::MetaCharsetCheck.run(inputs.page),
    },
    Runner {
        covers: &[
            "seo.duplicate_description",
            "seo.duplicate_meta",
            "seo.duplicate_title",
        ],
        run: |inputs| meta::DuplicateMetaCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.hreflang"],
        run: |inputs| meta::HreflangCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.meta_description"],
        run: |inputs| meta::MetaDescriptionCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.noindex"],
        run: |inputs| meta::NoindexCheck::evaluate(inputs.page, inputs.header_lines),
    },
    Runner {
        covers: &["seo.og_image_relative"],
        run: |inputs| meta::OgImageAbsoluteCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.open_graph"],
        run: |inputs| meta::OpenGraphCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.title"],
        run: |inputs| meta::TitleTagCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.twitter_cards"],
        run: |inputs| meta::TwitterCardCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.viewport"],
        run: |inputs| meta::ViewportCheck.run(inputs.page),
    },
];
