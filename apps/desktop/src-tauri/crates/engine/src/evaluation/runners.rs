//! Registry mapping compiled verdicts to manifest IDs.
//!
//! Every page- and origin-scoped artifact-lane entry has exactly
//! one runner, here or in `runners_seo.rs`, or an explicit exclusion
//! there, and no runner may claim an unpublished ID.

use super::EvaluationInputs;
use crate::checks::seo::robots_conflicts::MetaRobotsConflictCheck;
use crate::checks::Check;
use crate::vocab::CheckResult;

/// One compiled verdict and the manifest ids it is the sole producer of.
pub struct Runner {
    /// The manifest ids this runner claims. More than one when the check
    /// emits sub-verdicts under their own ids.
    pub covers: &'static [&'static str],
    /// A plain fn pointer, so the table stays a compile-time constant and
    /// cannot acquire per-call state that would make two evaluations of the
    /// same artifact differ.
    pub run: fn(&EvaluationInputs) -> Vec<CheckResult>,
}

/// Runner table in deterministic response order.
pub const RUNNERS: &[Runner] = &[
    Runner {
        covers: &["accessibility.axe."],
        run: |inputs| {
            inputs
                .browser_facts
                .map(|facts| {
                    crate::checks::accessibility::axe::evaluate_axe_report(&facts.axe_report)
                })
                .unwrap_or_default()
        },
    },
    Runner {
        covers: &[
            "performance.cls",
            "performance.fcp",
            "performance.lcp",
            "performance.long_task_blocking",
            "polish.js-errors",
        ],
        run: |inputs| {
            inputs
                .browser_facts
                .map(|facts| {
                    let mut browser_metrics = facts.core_web_vitals.clone();
                    // `performance.ttfb` belongs to the probe lane in the
                    // hosted manifest. Emitting the browser sample here would
                    // create two rows under one planned pair and attribute a
                    // browser measurement to the transport layer.
                    browser_metrics.ttfb_ms = None;
                    crate::checks::performance::browser_vitals::evaluate_core_web_vitals(
                        &browser_metrics,
                    )
                })
                .unwrap_or_default()
        },
    },
    Runner {
        covers: &[
            "security.headers.csp",
            "security.headers.hsts",
            "security.headers.permissions_policy",
            "security.headers.referrer_policy",
            "security.headers.x_content_type_options",
            "security.headers.x_frame_options",
        ],
        run: |inputs| crate::checks::security::headers::SecurityHeadersCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.headers.cross_origin"],
        run: |inputs| {
            crate::checks::security::cross_origin::CrossOriginIsolationCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["security.mixed_content"],
        run: |inputs| crate::checks::security::mixed_content::MixedContentCheck.run(inputs.page),
    },
    // Claim the family prefix because this runner also emits dynamic
    // `security.cookies.<name>` verdicts. The literal keeps manifest drift testable.
    Runner {
        covers: &[
            "security.cookies",
            "security.cookies.",
            "security.cookies.malformed_header",
            "security.cookies.unreadable_headers",
        ],
        run: |inputs| crate::checks::security::cookies::CookieSecurityCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.email_exposure"],
        run: |inputs| crate::checks::security::email_exposure::EmailExposureCheck.run(inputs.page),
    },
    Runner {
        covers: &[
            "security.server_info.server_header",
            "security.server_info.x_powered_by",
        ],
        run: |inputs| crate::checks::security::server_info::ServerInfoCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.sri"],
        run: |inputs| crate::checks::security::sri::SubresourceIntegrityCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.cors"],
        run: |inputs| crate::checks::security::cors::CorsCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.insecure_form"],
        run: |inputs| crate::checks::security::forms::InsecureFormCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.form_action_hijack"],
        run: |inputs| crate::checks::security::forms::FormActionHijackCheck.run(inputs.page),
    },
    Runner {
        covers: &[
            "security.vibe.exposed_keys",
            "security.vibe.exposed_keys.public",
        ],
        run: |inputs| crate::checks::security::exposed_keys::ExposedApiKeysCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.vibe.hardcoded_secrets"],
        run: |inputs| {
            crate::checks::security::hardcoded_secrets::HardcodedSecretsCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["security.vibe.client_auth"],
        run: |inputs| crate::checks::security::client_auth::ClientAuthCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.vibe.csrf"],
        run: |inputs| crate::checks::security::csrf::CsrfCheck.run(inputs.page),
    },
    Runner {
        covers: &["security.vibe.env_exposure"],
        run: |inputs| crate::checks::security::env_exposure::EnvExposureCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.url_structure"],
        run: |inputs| crate::checks::seo::url_structure::UrlStructureCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.headings.h1"],
        run: |inputs| crate::checks::seo::headings::H1Check.run(inputs.page),
    },
    Runner {
        covers: &["seo.meta_refresh"],
        run: |inputs| crate::checks::seo::meta_refresh::MetaRefreshCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.link_count"],
        run: |inputs| crate::checks::seo::link_count::LinkCountCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.thin_content"],
        run: |inputs| crate::checks::seo::content::ThinContentCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.canonical_mismatch"],
        run: |inputs| crate::checks::seo::canonical_meta::CanonicalMismatchCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.meta_conflicts"],
        run: |inputs| MetaRobotsConflictCheck::evaluate(inputs.page, inputs.header_lines),
    },
    Runner {
        covers: &["seo.page_speed_hints"],
        run: |inputs| crate::checks::seo::speed_hints::PageSpeedHintsCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.citation_meta"],
        run: |inputs| crate::checks::seo::geo::metadata::CitationMetaCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.content_freshness"],
        run: |inputs| crate::checks::seo::geo::metadata::ContentFreshnessCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.organization_identity"],
        run: |inputs| crate::checks::seo::geo::metadata::OrganizationIdentityCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.faq_schema"],
        run: |inputs| crate::checks::seo::geo::metadata::FaqSchemaCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.semantic_html"],
        run: |inputs| crate::checks::seo::geo::structure::SemanticHtmlCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.source_citations"],
        run: |inputs| crate::checks::seo::geo::structure::SourceCitationsCheck.run(inputs.page),
    },
    Runner {
        covers: &["seo.js_only_content"],
        run: |inputs| crate::checks::seo::geo::structure::JsOnlyContentCheck.run(inputs.page),
    },
    // Three ids from one pass over the document: the presence verdict always,
    // and the two JSON-LD sub-verdicts only when a block fails to parse or a
    // recognized type falls short of its profile.
    Runner {
        covers: &[
            "seo.structured_data",
            "seo.structured_data.incomplete",
            "seo.structured_data.invalid",
        ],
        run: |inputs| crate::checks::seo::structured_data::StructuredDataCheck.run(inputs.page),
    },
    Runner {
        covers: &["performance.cache"],
        run: |inputs| crate::checks::performance::cache::CacheHeadersCheck.run(inputs.page),
    },
    Runner {
        covers: &[
            "performance.images",
            "performance.images.dimensions",
            "performance.images.format",
            "performance.images.lazy",
        ],
        run: |inputs| crate::checks::performance::images::ImageOptimizationCheck.run(inputs.page),
    },
    Runner {
        covers: &["performance.fonts"],
        run: |inputs| crate::checks::performance::images::FontLoadingCheck.run(inputs.page),
    },
    Runner {
        covers: &["performance.render_blocking"],
        run: |inputs| {
            crate::checks::performance::render_blocking::RenderBlockingCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["performance.dom_size"],
        run: |inputs| crate::checks::performance::dom_size::DomSizeCheck.run(inputs.page),
    },
    Runner {
        covers: &["performance.third_party"],
        run: |inputs| {
            crate::checks::performance::third_party::ThirdPartyScriptsCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["performance.preconnect"],
        run: |inputs| crate::checks::performance::preconnect::PreconnectCheck.run(inputs.page),
    },
    Runner {
        covers: &["performance.unminified"],
        run: |inputs| crate::checks::performance::unminified::UnminifiedCodeCheck.run(inputs.page),
    },
    Runner {
        covers: &["performance.inline_css"],
        run: |inputs| crate::checks::performance::protocol::InlineCssSizeCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.lang"],
        run: |inputs| {
            crate::checks::accessibility::html_checks::LangAttributeCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.image_alt"],
        run: |inputs| {
            crate::checks::accessibility::html_checks::ImageAltAccessibilityCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.headings"],
        run: |inputs| crate::checks::accessibility::html_checks::HeadingOrderCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.form_labels"],
        run: |inputs| crate::checks::accessibility::form_labels::FormLabelsCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.landmarks"],
        run: |inputs| {
            crate::checks::accessibility::html_checks::AriaLandmarksCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.link_text"],
        run: |inputs| crate::checks::accessibility::html_checks::LinkTextCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.skip_nav"],
        run: |inputs| crate::checks::accessibility::html_checks::SkipNavCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.autoplay"],
        run: |inputs| crate::checks::accessibility::html_checks::AutoplayCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.color_contrast_hints"],
        run: |inputs| {
            crate::checks::accessibility::extra_checks::ColorContrastHintsCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.focus_indicators"],
        run: |inputs| {
            crate::checks::accessibility::extra_checks::FocusIndicatorCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.aria_usage"],
        run: |inputs| crate::checks::accessibility::extra_checks::AriaUsageCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.tabindex"],
        run: |inputs| crate::checks::accessibility::extra_checks::TabindexCheck.run(inputs.page),
    },
    Runner {
        covers: &["accessibility.viewport_zoom"],
        run: |inputs| {
            crate::checks::accessibility::markup_checks::ViewportZoomCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.empty_headings"],
        run: |inputs| {
            crate::checks::accessibility::markup_checks::EmptyHeadingsCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.iframe_title"],
        run: |inputs| {
            crate::checks::accessibility::markup_checks::IframeTitleCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["accessibility.redundant_alt"],
        run: |inputs| {
            crate::checks::accessibility::markup_checks::RedundantAltTextCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["compliance.trackers"],
        run: |inputs| crate::checks::compliance::trackers::ThirdPartyTrackerCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.form_consent"],
        run: |inputs| crate::checks::compliance::trackers::FormConsentCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.cookie_consent"],
        run: |inputs| {
            crate::checks::compliance::cookie_consent::CookieConsentCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["compliance.consent_mode"],
        run: |inputs| crate::checks::compliance::consent_mode::ConsentModeCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.data_controller_contact"],
        run: |inputs| crate::checks::compliance::gdpr::DataControllerContactCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.cookie_expiration"],
        run: |inputs| crate::checks::compliance::gdpr::CookieExpirationCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.dnt_respect"],
        run: |inputs| crate::checks::compliance::gdpr::DntRespectCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.ccpa_notice"],
        run: |inputs| crate::checks::compliance::statements::CcpaNoticeCheck.run(inputs.page),
    },
    Runner {
        covers: &["compliance.accessibility_statement"],
        run: |inputs| {
            crate::checks::compliance::statements::AccessibilityStatementCheck.run(inputs.page)
        },
    },
    Runner {
        covers: &["config.analytics"],
        run: |inputs| crate::checks::config::analytics::AnalyticsCheck.run(inputs.page),
    },
    Runner {
        covers: &["config.deprecated_html"],
        run: |inputs| crate::checks::config::deprecated_html::DeprecatedHtmlCheck.run(inputs.page),
    },
    Runner {
        covers: &["config.print_stylesheet"],
        run: |inputs| crate::checks::config::extras::PrintStylesheetCheck.run(inputs.page),
    },
    Runner {
        covers: &["config.responsive_design"],
        run: |inputs| crate::checks::config::extras::ResponsiveDesignCheck.run(inputs.page),
    },
    Runner {
        covers: &["config.trailing_slash"],
        run: |inputs| crate::checks::config::extras::TrailingSlashCheck.run(inputs.page),
    },
    // Page weight remains artifact-derived despite its desktop async shell.
    Runner {
        covers: &["performance.page_weight"],
        run: |inputs| {
            vec![crate::checks::performance::page_weight::html_size_result(
                inputs.page.body.len(),
            )]
        },
    },
    // TLS verdicts require caller-supplied handshake facts. Missing inputs emit
    // explicit skipped rows rather than an empty result that could imply success.
    Runner {
        covers: &[
            "security.ssl.chain",
            "security.ssl.expiry",
            "security.ssl.hostname",
            "security.ssl.protocol",
        ],
        run: |inputs| {
            use crate::checks::security::tls::{
                evaluate_tls, tls_unavailable_results, TlsUnavailable,
            };
            let Some(facts) = inputs.tls_facts else {
                return tls_unavailable_results(&TlsUnavailable::ProbeFailed {
                    detail: "the request carried no certificate facts".into(),
                });
            };
            let Some(host) = inputs.page.url.host_str() else {
                return tls_unavailable_results(&TlsUnavailable::NoHost);
            };
            evaluate_tls(host, facts, inputs.page.evaluation_time)
        },
    },
];
