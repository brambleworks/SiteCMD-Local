//! The web half of the severity policy: each check's grade, by check id and
//! verdict status.

use super::WebSeverityInput;
use crate::vocab::{CheckStatus, Severity};

pub fn web_policy_severity(input: &WebSeverityInput) -> Option<Severity> {
    let check_id = input.check_id.as_str();
    Some(match check_id {
        // Preserve this check's graded Medium/Low branches.
        "polish.missing-og-tags" => input.severity,
        id if id.starts_with("polish.") => polish_signal_severity(id),
        id if id.starts_with("accessibility.axe.") => axe_violation_severity(input),

        "accessibility.aria_usage"
        | "accessibility.empty_headings"
        | "accessibility.focus_indicators"
        | "accessibility.form_labels"
        | "accessibility.iframe_title"
        | "accessibility.image_alt"
        | "accessibility.landmarks"
        | "accessibility.lang"
        | "accessibility.link_text"
        | "accessibility.skip_nav"
        | "accessibility.tabindex" => Severity::Medium,
        // Static markup establishes autoplay intent but not whether playback
        // occurs, its duration, or the controls present at runtime. The check
        // grades unmuted declarations Medium and muted motion review Low.
        "accessibility.autoplay" => input.severity,
        "accessibility.headings" => Severity::Low,
        // Zoom-disabling viewport tags block reading for low-vision users
        // (WCAG 1.4.4); a real barrier, not a nicety.
        "accessibility.viewport_zoom" => Severity::High,
        "accessibility.color_contrast_hints" | "accessibility.redundant_alt" => Severity::Low,

        "compliance.privacy_policy" => Severity::Medium,
        "compliance.consent_mode" | "compliance.cookie_consent" => Severity::Medium,
        "compliance.accessibility_statement"
        | "compliance.ccpa_notice"
        | "compliance.cookie_expiration"
        | "compliance.data_controller_contact"
        | "compliance.dnt_respect"
        | "compliance.form_consent"
        | "compliance.terms"
        | "compliance.trackers" => Severity::Low,

        "config.localhost_refs" => Severity::Medium,
        // Preserve source-only evidence without claiming rendered responsiveness.
        "config.responsive_design" => input.severity,
        "config.debug_mode" => input.severity,
        "config.dev_dependencies" => Severity::Low,
        "config.placeholder_content" | "config.www_redirect" => Severity::Medium,
        "config.analytics"
        | "config.console_logs"
        | "config.custom_404"
        | "config.deprecated_html"
        | "config.favicon"
        | "config.print_stylesheet"
        | "config.sitemap_in_robots"
        | "config.todo_comments"
        | "config.trailing_slash"
        | "config.web_manifest" => Severity::Low,

        // Both the preliminary HTTP probe and its browser-navigation replacement
        // are single samples, so TTFB never grades above Medium.
        "performance.ttfb" => Severity::Medium,
        "performance.cls" | "performance.fcp" | "performance.lcp" => {
            status_severity(input, Severity::Medium, Severity::High)
        }
        // PageSpeed Insights supplies real Lighthouse TBT; the lightweight
        // browser probe below intentionally has a different identity.
        "performance.tbt" => status_severity(input, Severity::Medium, Severity::High),
        "performance.long_task_blocking" => status_severity(input, Severity::Low, Severity::Medium),
        "performance.inline_css" | "performance.render_blocking" | "performance.unminified" => {
            input.severity
        }
        "performance.broken_images"
        | "performance.cache"
        | "performance.compression"
        | "performance.http2"
        | "performance.images.heavy" => Severity::Medium,
        // Threshold checks that grade Warn at the advisory tier and Fail at
        // the real-cost tier; a Warn must not count as a full Medium.
        "performance.dom_size" | "performance.third_party" => {
            status_severity(input, Severity::Low, Severity::Medium)
        }
        // A caching miss on immutable assets is a pure optimization.
        "performance.asset_caching" => Severity::Low,
        // An oversized HTML document is a directly observed transfer cost, so
        // it escalates on Fail.
        "performance.page_weight" => status_severity(input, Severity::Medium, Severity::High),
        // The asset sampler sums decoded sizes over a bounded sample and says
        // so in its own text ("not observed navigation transfer"), so its Warn
        // is advisory and its Fail tops out at Medium.
        "performance.asset_weight" => status_severity(input, Severity::Low, Severity::Medium),
        "performance.fonts"
        | "performance.http_requests"
        | "performance.images"
        | "performance.images.dimensions"
        | "performance.images.format"
        | "performance.images.lazy"
        | "performance.preconnect"
        | "performance.redirect_chain" => status_severity(input, Severity::Low, Severity::Medium),

        // The certificate sub-checks each grade themselves: expiry and
        // hostname reach Critical on direct evidence, chain splits
        // definitive rejections from trust-store differences, and protocol
        // tops out at High.
        "security.ssl.expiry" | "security.ssl.hostname" | "security.ssl.chain" => {
            status_severity(input, Severity::High, Severity::Critical)
        }
        "security.ssl.protocol" => status_severity(input, Severity::Medium, Severity::High),
        // HTTP enforcement grades direct 2xx evidence High, ambiguous chains
        // Medium, and temporary/error outcomes Low. Preserve those branches.
        "security.https_enforcement" => input.severity,
        "security.insecure_form" => status_severity(input, Severity::Medium, Severity::Critical),
        // These grade themselves per branch. `security.env_leak` is a
        // localhost-preview heuristic (credential-shaped literal = High,
        // unresolved reference = Medium); the live-page secret checks retain
        // their own verified/review branch grading.
        "security.env_leak"
        | "security.vibe.env_exposure"
        | "security.vibe.exposed_keys"
        | "security.vibe.exposed_keys.public"
        | "security.vibe.hardcoded_secrets" => input.severity,
        "security.cors"
        | "security.cors_reflection"
        | "security.directory_listing"
        | "security.form_action_hijack"
        | "security.open_redirect" => status_severity(input, Severity::Medium, Severity::High),
        // Direct active mixed content on an HTTPS page is High; passive or
        // responsive candidates are Medium, and localhost preview references
        // are a Medium review. Preserve the producer's evidence-based branch.
        "security.mixed_content" => input.severity,
        // Local-preview references do not prove a map is publicly deployed.
        "security.source_maps" => input.severity,
        // CSP/HSTS author every branch deliberately (missing enforcement is
        // Medium; contextual hardening advisories are Low); keep that grading.
        "security.headers.csp" | "security.headers.hsts" => input.severity,
        "security.vibe.client_auth" | "security.vibe.csrf" => {
            status_severity(input, Severity::Medium, Severity::High)
        }
        // Cookie branches distinguish direct contract failures from
        // contextual missing-attribute reviews and redact live values.
        "security.cookies" => input.severity,
        id if id.starts_with("security.cookies.") => input.severity,
        "security.email_exposure" | "security.headers.cross_origin" | "security.security_txt" => {
            Severity::Low
        }
        // Severity comes from the worst OSV advisory found for the library.
        "security.vulnerable_libraries" => input.severity,
        // SPF/DMARC grade themselves via MX gating and record content; domain
        // expiry grades by days remaining; a dangling www CNAME grades the
        // observed availability failure without assuming provider claimability.
        "security.dns.spf"
        | "security.dns.dmarc"
        | "security.dns.dangling_cname"
        | "security.domain_expiry" => input.severity,
        "security.dns.caa" | "security.dns.dkim" | "security.dns.dnssec" | "security.dns.mx" => {
            Severity::Low
        }
        // The header checks grade each branch deliberately (missing header
        // advisories at Low, leaky values at Medium, absent protections at
        // Medium/High); flattening them inflated Warn advisories.
        "security.headers.permissions_policy"
        | "security.headers.referrer_policy"
        | "security.headers.x_content_type_options"
        | "security.headers.x_frame_options"
        | "security.sri" => input.severity,
        "security.server_info.server_header" | "security.server_info.x_powered_by" => Severity::Low,
        id if id.starts_with("security.exposed_files.") => input.severity,

        "seo.title" => status_severity(input, Severity::Medium, Severity::High),
        // Warn = charset declared past the 1024-byte window; Fail = no
        // declaration anywhere, which garbles non-ASCII text unpredictably.
        "seo.charset" => status_severity(input, Severity::Low, Severity::Medium),
        // Branches distinguish an empty document, an optional missing sitemap,
        // an unverified cross-origin declaration, and an inconclusive probe.
        "seo.sitemap" => input.severity,
        "seo.robots_txt" => input.severity,
        "seo.viewport" => input.severity,
        // The directive is direct evidence; intent is contextual. Root-entry
        // pages grade High, while interior pages grade Medium.
        "seo.noindex" => input.severity,
        // The check grades a redirect Medium and a timed reload Low.
        "seo.meta_refresh" => input.severity,
        "seo.broken_links" => broken_link_severity(input),
        "seo.canonical_mismatch" => canonical_mismatch_severity(input),
        "seo.meta_conflicts" | "seo.meta_robots_conflicts" => meta_conflict_severity(input),
        "seo.broken_external_links"
        | "seo.duplicate_description"
        | "seo.duplicate_description_across_pages"
        | "seo.duplicate_meta"
        | "seo.duplicate_title"
        | "seo.duplicate_title_across_pages"
        | "seo.image_alt"
        | "seo.js_only_content"
        | "seo.meta_description"
        | "seo.og_image_relative"
        | "seo.og_image_status" => Severity::Medium,
        // Missing self-canonicals are contextual; the producer grades the
        // presence-only advisory Low and richer mismatch checks separately.
        "seo.canonical" | "seo.open_graph" | "seo.structured_data" => input.severity,
        "seo.headings.h1" => Severity::Low,
        // Warn = thin-ish page (advisory), Fail = near-empty body.
        "seo.thin_content" => status_severity(input, Severity::Low, Severity::Medium),
        "seo.ai_crawler_blocking" => input.severity,
        // Emitted severity varies: invalid JSON is Medium, recommended-only
        // property gaps are Low.
        "seo.structured_data.invalid" | "seo.structured_data.incomplete" => input.severity,
        // Cross-page (session-level) findings from the engine's session module.
        "seo.canonical_loop" | "seo.noindex_in_sitemap" => Severity::Medium,
        "seo.duplicate_h1" | "seo.hreflang_reciprocity" | "seo.orphan_pages" => Severity::Low,
        "seo.citation_meta"
        | "seo.content_freshness"
        | "seo.faq_schema"
        | "seo.headings.hierarchy"
        | "seo.hreflang"
        | "seo.link_count"
        | "seo.llms_txt"
        | "seo.organization_identity"
        | "seo.page_speed_hints"
        | "seo.semantic_html"
        | "seo.sitemap_freshness"
        | "seo.source_citations"
        | "seo.temporary_redirect"
        | "seo.twitter_cards"
        | "seo.url_structure" => Severity::Low,

        _ => return None,
    })
}

pub fn polish_signal_severity(check_id: &str) -> Severity {
    let signal_id = check_id.strip_prefix("polish.").unwrap_or(check_id);
    match signal_id {
        "form-accessibility" | "button-vs-clickable-div" | "js-errors" => Severity::Medium,
        // The Polish signal observes only a sourceMappingURL reference; it
        // does not request the map. Keep it below the verified-exposure tier.
        "source-maps-production" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn axe_violation_severity(input: &WebSeverityInput) -> Severity {
    match input.severity {
        Severity::Critical | Severity::High => Severity::High,
        Severity::Medium => Severity::Medium,
        Severity::Low => Severity::Low,
    }
}

fn broken_link_severity(input: &WebSeverityInput) -> Severity {
    if input.broken_count.unwrap_or(1) >= 3 {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn canonical_mismatch_severity(input: &WebSeverityInput) -> Severity {
    let _ = input;
    // A differing canonical target is directly observed but can be deliberate
    // for duplicate or syndicated content. Until equivalence, target state,
    // and owner intent are verified, a cross-host target is not a High defect.
    Severity::Medium
}

fn meta_conflict_severity(input: &WebSeverityInput) -> Severity {
    match input.severity {
        Severity::Critical | Severity::High => Severity::High,
        _ => Severity::Medium,
    }
}

fn status_severity(input: &WebSeverityInput, warn: Severity, fail: Severity) -> Severity {
    match input.status {
        CheckStatus::Fail => fail,
        CheckStatus::Warn => warn,
        CheckStatus::Pass | CheckStatus::Skipped => Severity::Low,
    }
}
