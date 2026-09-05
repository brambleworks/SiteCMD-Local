use super::*;
use crate::checks::{CheckResult, CheckStatus, ScanCategory};

fn web_result(check_id: &str, status: CheckStatus, severity: Severity) -> CheckResult {
    CheckResult {
        check_id: check_id.to_string(),
        category: ScanCategory::Seo,
        title: String::new(),
        description: String::new(),
        status,
        severity,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

fn code_issue(id: &str, severity: Severity) -> CodeIssue {
    CodeIssue {
        check_id: String::new(),
        id: id.to_string(),
        category: "ai-safety".into(),
        severity,
        title: String::new(),
        description: String::new(),
        relative_path: String::new(),
        absolute_path: String::new(),
        line: None,
        source_excerpt: None,
        evidence: None,
        why_now: None,
        likely_fix: None,
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        verify_hint: None,
    }
}

#[test]
fn seo_sitemap_and_robots_preserve_their_evidence_bounded_branch_grading() {
    assert_eq!(
        normalized_web_issue_severity(&web_result("seo.sitemap", CheckStatus::Warn, Severity::Low)),
        Severity::Low
    );

    // A confirmed missing file is an intentional Skipped result because the
    // standard behavior is unrestricted crawling, not an SEO defect.
    let robots = web_result("seo.robots_txt", CheckStatus::Skipped, Severity::Low);

    assert_eq!(normalized_web_issue_severity(&robots), Severity::Low);
}

#[test]
fn robots_blocking_all_crawlers_stays_high() {
    let mut robots = web_result("seo.robots_txt", CheckStatus::Warn, Severity::High);
    robots.raw_data = Some(serde_json::json!({
        "issues": ["Disallow: / blocks all crawlers from the entire site"]
    }));

    assert_eq!(normalized_web_issue_severity(&robots), Severity::High);
}

#[test]
fn title_length_warning_is_medium_but_missing_title_stays_high() {
    assert_eq!(
        normalized_web_issue_severity(&web_result("seo.title", CheckStatus::Warn, Severity::High)),
        Severity::Medium
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result("seo.title", CheckStatus::Fail, Severity::High)),
        Severity::High
    );
}

#[test]
fn polish_copy_and_structure_findings_are_not_critical() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "polish.ai-buzzword-dictionary",
            CheckStatus::Fail,
            Severity::Critical
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "polish.div-soup-ratio",
            CheckStatus::Fail,
            Severity::Critical
        )),
        Severity::Low
    );
}

#[test]
fn form_consent_static_heuristic_stays_low_until_purpose_and_law_are_known() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "compliance.form_consent",
            CheckStatus::Warn,
            Severity::Medium
        )),
        Severity::Low
    );
}

#[test]
fn compliance_applicability_heuristics_do_not_grade_as_proven_high_impact() {
    for check_id in ["compliance.terms", "compliance.trackers"] {
        assert_eq!(
            normalized_web_issue_severity(&web_result(check_id, CheckStatus::Warn, Severity::High)),
            Severity::Low,
            "{check_id}"
        );
    }
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "compliance.privacy_policy",
            CheckStatus::Warn,
            Severity::High
        )),
        Severity::Medium
    );
}

#[test]
fn direct_critical_findings_stay_critical_while_source_heuristics_do_not() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.ssl.expiry",
            CheckStatus::Fail,
            Severity::Critical
        )),
        Severity::Critical
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "js-command-injection:src/app/route.ts",
            Severity::Critical
        )),
        Severity::Critical
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "hardcoded-secret:src/app/page.tsx",
            Severity::Critical
        )),
        Severity::High
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "client-ai-sdk:src/app/page.tsx",
            Severity::Critical
        )),
        Severity::High
    );
}

#[test]
fn normalize_code_issues_rewrites_severities_in_place() {
    // Exercises the code-scan finalize chokepoint's normalize call: policy
    // slug tables win over whatever severity the analyzer wrote.
    let mut issues = vec![
        code_issue("csrf-missing:src/api/route.ts", Severity::Low),
        code_issue("unused-dependency", Severity::Critical),
    ];

    normalize_code_issues(&mut issues);

    assert_eq!(issues[0].severity, Severity::High);
    assert_eq!(issues[1].severity, Severity::Low);
}

#[test]
fn accidental_non_security_critical_findings_are_capped_at_high() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "accessibility.axe.color-contrast",
            CheckStatus::Fail,
            Severity::Critical
        )),
        Severity::High
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "unknown-generated-critical",
            Severity::Critical
        )),
        Severity::High
    );
}

#[test]
fn passing_and_skipped_web_results_are_low_for_counts() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "seo.sitemap",
            CheckStatus::Pass,
            Severity::High
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.headers.csp",
            CheckStatus::Skipped,
            Severity::High
        )),
        Severity::Low
    );
}

#[test]
fn ai_cost_guardrail_findings_are_capped_at_medium() {
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "ai-rate-limit:src/api/chat.ts",
            Severity::Critical
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "ai-loop-risk:src/api/chat.ts",
            Severity::Critical
        )),
        Severity::Medium
    );
}

#[test]
fn warn_grade_findings_never_land_critical() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.https_enforcement",
            CheckStatus::Warn,
            Severity::Low
        )),
        Severity::Low,
        "temporary-redirect advisory must stay Low"
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.env_leak",
            CheckStatus::Warn,
            Severity::High
        )),
        Severity::High,
        "refs-only env_leak warn keeps its branch grading"
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.vibe.env_exposure",
            CheckStatus::Fail,
            Severity::High
        )),
        Severity::High,
        "window.__env-only exposure keeps its per-pattern High, not Critical"
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.vibe.client_auth",
            CheckStatus::Warn,
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.vibe.csrf",
            CheckStatus::Warn,
            Severity::High
        )),
        Severity::Medium
    );

    // Directly verified transport/form failures keep their Critical teeth.
    for id in ["security.https_enforcement", "security.insecure_form"] {
        assert_eq!(
            normalized_web_issue_severity(&web_result(id, CheckStatus::Fail, Severity::Critical)),
            Severity::Critical,
            "{id} Fail/Critical must stay Critical"
        );
    }
    // Credential-shaped static text is review evidence, not a provider-
    // validated secret. Defense in depth clamps accidental Critical emissions.
    for id in [
        "security.env_leak",
        "security.vibe.env_exposure",
        "security.vibe.exposed_keys",
        "security.vibe.hardcoded_secrets",
    ] {
        assert_eq!(
            normalized_web_issue_severity(&web_result(id, CheckStatus::Fail, Severity::Critical)),
            Severity::High,
            "{id} must not normalize a static format match to Critical"
        );
    }

    // Defense in depth: no registered check id may normalize a Warn to
    // Critical, whatever severity the emit site stamped on it.
    let (sync_checks, async_checks) = crate::core::scanner::collect_checks(&None);
    for id in sync_checks
        .iter()
        .map(|check| check.id().to_string())
        .chain(async_checks.iter().map(|check| check.id().to_string()))
    {
        assert_ne!(
            normalized_web_issue_severity(&web_result(&id, CheckStatus::Warn, Severity::Critical)),
            Severity::Critical,
            "{id}: a Warn advisory must never carry Critical scoring weight"
        );
    }
}

#[test]
fn header_advisories_keep_their_authored_severity() {
    for id in [
        "security.headers.referrer_policy",
        "security.headers.permissions_policy",
        "security.headers.hsts",
    ] {
        assert_eq!(
            normalized_web_issue_severity(&web_result(id, CheckStatus::Warn, Severity::Low)),
            Severity::Low,
            "{id} Warn/Low advisory must stay Low"
        );
    }
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.headers.csp",
            CheckStatus::Fail,
            Severity::High
        )),
        Severity::High
    );
}

#[test]
fn advisory_warns_do_not_count_as_full_severity() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.dom_size",
            CheckStatus::Warn,
            Severity::Low
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.third_party",
            CheckStatus::Warn,
            Severity::Low
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "seo.thin_content",
            CheckStatus::Warn,
            Severity::Low
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "seo.thin_content",
            CheckStatus::Fail,
            Severity::Medium
        )),
        Severity::Medium
    );
    // Missing robots.txt is the allow-all default the check itself calls
    // non-blocking; only blocking every crawler escalates.
    let mut robots_missing = web_result("seo.robots_txt", CheckStatus::Warn, Severity::Low);
    robots_missing.raw_data = Some(serde_json::json!({ "issues": ["No robots.txt found"] }));
    assert_eq!(
        normalized_web_issue_severity(&robots_missing),
        Severity::Low
    );
    // A sampled, decoded asset byte sum is not a navigation transfer
    // measurement, so its Warn is advisory and its Fail stops at Medium even
    // when the producer wrote High.
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.asset_weight",
            CheckStatus::Warn,
            Severity::Medium
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.asset_weight",
            CheckStatus::Fail,
            Severity::High
        )),
        Severity::Medium
    );
    // The HTML document size the page-weight row grades is directly observed,
    // so it keeps the escalating tier.
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.page_weight",
            CheckStatus::Fail,
            Severity::High
        )),
        Severity::High
    );
    // Static-probe TTFB never grades higher than Medium (timing.rs promise).
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.ttfb",
            CheckStatus::Fail,
            Severity::High
        )),
        Severity::Medium
    );
    // missing-og-tags grades itself: partial gap Low, all-three-missing Medium.
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "polish.missing-og-tags",
            CheckStatus::Fail,
            Severity::Low
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "polish.missing-og-tags",
            CheckStatus::Fail,
            Severity::Medium
        )),
        Severity::Medium
    );
}

#[test]
fn common_web_overstatements_are_downgraded_to_launch_relevant_severity() {
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "accessibility.lang",
            CheckStatus::Fail,
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "performance.ttfb",
            CheckStatus::Warn,
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "seo.llms_txt",
            CheckStatus::Warn,
            Severity::Medium
        )),
        Severity::Low
    );
    // referrer_policy authors its branches (missing header = Warn/Low,
    // leaky value = Warn/Medium); the policy passes those through.
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "security.headers.referrer_policy",
            CheckStatus::Warn,
            Severity::Medium
        )),
        Severity::Medium
    );
    // The source-only responsive check emits Pass or Skipped; it never turns
    // absent source evidence into a rendered-layout issue.
    assert_eq!(
        normalized_web_issue_severity(&web_result(
            "config.responsive_design",
            CheckStatus::Skipped,
            Severity::Low
        )),
        Severity::Low
    );
}

#[test]
fn broken_links_and_canonical_mismatches_scale_by_launch_impact() {
    let mut one_broken = web_result("seo.broken_links", CheckStatus::Fail, Severity::High);
    one_broken.raw_data = Some(serde_json::json!({ "broken": ["https://example.com/a"] }));
    assert_eq!(normalized_web_issue_severity(&one_broken), Severity::Medium);

    let mut several_broken = web_result("seo.broken_links", CheckStatus::Fail, Severity::High);
    several_broken.raw_data = Some(serde_json::json!({
        "broken": ["https://example.com/a", "https://example.com/b", "https://example.com/c"]
    }));
    assert_eq!(
        normalized_web_issue_severity(&several_broken),
        Severity::High
    );

    let mut same_domain = web_result("seo.canonical_mismatch", CheckStatus::Warn, Severity::High);
    same_domain.raw_data = Some(serde_json::json!({ "different_domain": false }));
    assert_eq!(
        normalized_web_issue_severity(&same_domain),
        Severity::Medium
    );

    let mut different_domain = web_result(
        "seo.canonical_mismatch",
        CheckStatus::Warn,
        Severity::Medium,
    );
    different_domain.raw_data = Some(serde_json::json!({ "different_domain": true }));
    assert_eq!(
        normalized_web_issue_severity(&different_domain),
        Severity::Medium
    );
}

#[test]
fn code_hygiene_and_reproducibility_findings_are_not_security_severity() {
    // Hook findings pass their graded severity through; the advisory cap
    // still keeps them below High.
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "pre-commit-hooks-missing:package.json",
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "pre-commit-hooks-missing:package.json",
            Severity::Low
        )),
        Severity::Low
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "no-automated-tests:package.json",
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "empty-catch-blocks:src/api/orders.ts",
            Severity::Medium
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "lockfile-missing:package.json",
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "direct-url-dependency:package.json:lib",
            Severity::High
        )),
        Severity::Medium
    );
}

#[test]
fn code_launch_breakers_and_direct_exposure_stay_elevated() {
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "lockfile-mismatch:package.json:zod",
            Severity::High
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "ai-loop-risk:src/api/chat.ts",
            Severity::Critical
        )),
        Severity::Medium
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "client-ai-sdk:src/app/page.tsx",
            Severity::Critical
        )),
        Severity::High
    );
    assert_eq!(
        normalized_code_issue_severity(&code_issue(
            "config-secret:.cursor/mcp.json",
            Severity::Critical
        )),
        Severity::High
    );
}

#[test]
fn known_web_issue_families_have_explicit_policy() {
    let ids = [
        "accessibility.aria_usage",
        "accessibility.autoplay",
        "accessibility.axe.color-contrast",
        "accessibility.color_contrast_hints",
        "accessibility.empty_headings",
        "accessibility.focus_indicators",
        "accessibility.form_labels",
        "accessibility.headings",
        "accessibility.iframe_title",
        "accessibility.image_alt",
        "accessibility.landmarks",
        "accessibility.lang",
        "accessibility.link_text",
        "accessibility.redundant_alt",
        "accessibility.skip_nav",
        "accessibility.tabindex",
        "accessibility.viewport_zoom",
        "compliance.accessibility_statement",
        "compliance.ccpa_notice",
        "compliance.consent_mode",
        "compliance.cookie_consent",
        "compliance.cookie_expiration",
        "compliance.data_controller_contact",
        "compliance.dnt_respect",
        "compliance.form_consent",
        "compliance.privacy_policy",
        "compliance.terms",
        "compliance.trackers",
        "config.analytics",
        "config.console_logs",
        "config.custom_404",
        "config.debug_mode",
        "config.deprecated_html",
        "config.dev_dependencies",
        "config.favicon",
        "config.localhost_refs",
        "config.placeholder_content",
        "config.print_stylesheet",
        "config.responsive_design",
        "config.sitemap_in_robots",
        "config.todo_comments",
        "config.trailing_slash",
        "config.web_manifest",
        "config.www_redirect",
        "performance.asset_caching",
        "performance.asset_weight",
        "performance.broken_images",
        "performance.cache",
        "performance.cls",
        "performance.compression",
        "performance.dom_size",
        "performance.fcp",
        "performance.fonts",
        "performance.http2",
        "performance.http_requests",
        "performance.images",
        "performance.images.dimensions",
        "performance.images.format",
        "performance.images.heavy",
        "performance.images.lazy",
        "performance.inline_css",
        "performance.lcp",
        "performance.long_task_blocking",
        "performance.page_weight",
        "performance.preconnect",
        "performance.redirect_chain",
        "performance.render_blocking",
        "performance.tbt",
        "performance.third_party",
        "performance.ttfb",
        "performance.unminified",
        "polish.ai-buzzword-dictionary",
        "polish.js-errors",
        "security.cookies",
        "security.cookies.session",
        "security.cors",
        "security.cors_reflection",
        "security.directory_listing",
        "security.dns.caa",
        "security.dns.dangling_cname",
        "security.dns.dkim",
        "security.dns.dmarc",
        "security.dns.dnssec",
        "security.dns.mx",
        "security.dns.spf",
        "security.domain_expiry",
        "security.email_exposure",
        "security.env_leak",
        "security.exposed_files.env",
        "security.exposed_files.source_secrets",
        "security.exposed_files.summary",
        "security.form_action_hijack",
        "security.headers.cross_origin",
        "security.headers.csp",
        "security.headers.hsts",
        "security.headers.permissions_policy",
        "security.headers.referrer_policy",
        "security.headers.x_content_type_options",
        "security.headers.x_frame_options",
        "security.https_enforcement",
        "security.insecure_form",
        "security.mixed_content",
        "security.open_redirect",
        "security.server_info.server_header",
        "security.server_info.x_powered_by",
        "security.security_txt",
        "security.source_maps",
        "security.sri",
        "security.ssl.chain",
        "security.ssl.expiry",
        "security.ssl.hostname",
        "security.ssl.protocol",
        "security.vibe.client_auth",
        "security.vibe.csrf",
        "security.vulnerable_libraries",
        "security.vibe.env_exposure",
        "security.vibe.exposed_keys",
        "security.vibe.exposed_keys.public",
        "security.vibe.hardcoded_secrets",
        "seo.ai_crawler_blocking",
        "seo.broken_external_links",
        "seo.broken_links",
        "seo.canonical",
        "seo.canonical_loop",
        "seo.canonical_mismatch",
        "seo.charset",
        "seo.citation_meta",
        "seo.content_freshness",
        "seo.duplicate_description",
        "seo.duplicate_description_across_pages",
        "seo.duplicate_h1",
        "seo.duplicate_meta",
        "seo.duplicate_title",
        "seo.duplicate_title_across_pages",
        "seo.faq_schema",
        "seo.headings.h1",
        "seo.headings.hierarchy",
        "seo.hreflang",
        "seo.hreflang_reciprocity",
        "seo.image_alt",
        "seo.js_only_content",
        "seo.llms_txt",
        "seo.meta_conflicts",
        "seo.meta_robots_conflicts",
        "seo.meta_description",
        "seo.noindex",
        "seo.og_image_relative",
        "seo.og_image_status",
        "seo.noindex_in_sitemap",
        "seo.orphan_pages",
        "seo.open_graph",
        "seo.organization_identity",
        "seo.page_speed_hints",
        "seo.robots_txt",
        "seo.semantic_html",
        "seo.sitemap",
        "seo.sitemap_freshness",
        "seo.source_citations",
        "seo.structured_data",
        "seo.structured_data.incomplete",
        "seo.structured_data.invalid",
        "seo.temporary_redirect",
        "seo.thin_content",
        "seo.title",
        "seo.twitter_cards",
        "seo.url_structure",
        "seo.viewport",
    ];

    for id in ids {
        assert!(
            web_policy_severity(&web_result(id, CheckStatus::Fail, Severity::High)).is_some(),
            "missing web severity policy for {id}"
        );
    }
}

// Container IDs paired with a representative emitted sub-check.
const CONTAINER_CHECKS: &[(&str, &str)] = &[
    ("security.exposed_files", "security.exposed_files.env"),
    ("security.headers", "security.headers.csp"),
    ("security.server_info", "security.server_info.server_header"),
    ("security.ssl", "security.ssl.expiry"),
];

#[test]
fn every_registered_web_check_id_has_explicit_policy() {
    let (sync_checks, async_checks) = crate::core::scanner::collect_checks(&None);
    let mut ids: Vec<String> = sync_checks
        .iter()
        .map(|check| check.id().to_string())
        .chain(async_checks.iter().map(|check| check.id().to_string()))
        .collect();
    ids.sort();
    ids.dedup();
    assert!(
        ids.len() >= 110,
        "check registry collapsed ({} ids) - the enumeration is broken",
        ids.len()
    );

    for (container, representative) in CONTAINER_CHECKS {
        assert!(
            ids.iter().any(|id| id == container),
            "CONTAINER_CHECKS lists {container}, which is no longer a registered check id"
        );
        assert!(
            web_policy_severity(&web_result(
                representative,
                CheckStatus::Fail,
                Severity::High
            ))
            .is_some(),
            "missing web severity policy for container sub-id {representative}"
        );
    }

    let missing: Vec<&String> = ids
        .iter()
        .filter(|id| {
            !CONTAINER_CHECKS
                .iter()
                .any(|(container, _)| container == &id.as_str())
        })
        .filter(|id| {
            web_policy_severity(&web_result(id, CheckStatus::Fail, Severity::High)).is_none()
        })
        .collect();
    assert!(
        missing.is_empty(),
        "registered checks with no severity policy arm (add one to web_policy_severity, or a passthrough `result.severity` arm if the check grades itself): {missing:?}"
    );
}

#[test]
fn every_emitted_check_id_literal_has_explicit_policy() {
    fn collect_sources(dir: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("readable checks source dir") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                collect_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let content = std::fs::read_to_string(&path).expect("readable check source");
                // Production half only: inline test modules build synthetic
                // CheckResults with ids that need no policy.
                let production = content
                    .split("#[cfg(test)]")
                    .next()
                    .unwrap_or("")
                    .to_string();
                out.push(production);
            }
        }
    }

    // Both check trees: the desktop's and the engine crate's, which check
    // modules move into as the connected-service extraction proceeds.
    let manifest_dir = std::path::Path::new(env!("SITECMD_SOURCE_ROOT"));
    let mut sources = Vec::new();
    collect_sources(&manifest_dir.join("src/checks"), &mut sources);
    collect_sources(&manifest_dir.join("crates/engine/src/checks"), &mut sources);

    let literal = regex::Regex::new(r#"check_id: "([^"]+)""#).expect("valid literal regex");
    let mut ids: Vec<String> = sources
        .iter()
        .flat_map(|source| literal.captures_iter(source))
        .map(|capture| capture[1].to_string())
        .collect();
    ids.sort();
    ids.dedup();
    assert!(
        ids.len() >= 70,
        "check_id literal scan collapsed ({} ids) - the extraction is broken",
        ids.len()
    );

    let missing: Vec<&String> = ids
        .iter()
        .filter(|id| {
            web_policy_severity(&web_result(id, CheckStatus::Fail, Severity::High)).is_none()
        })
        .collect();
    assert!(
        missing.is_empty(),
        "emitted check ids with no severity policy arm: {missing:?}"
    );
}

#[test]
fn known_code_issue_families_have_explicit_policy() {
    let ids = [
        "ai-cache-dedupe:src/api/chat.ts",
        "ai-concurrency:src/api/chat.ts",
        "ai-conversation-artifacts:src/lib/generated.ts",
        "ai-kill-switch-missing:src/ai.ts",
        "ai-loop-risk:src/api/chat.ts",
        "ai-observability:src/api/chat.ts",
        "ai-observability-integration-missing:package.json",
        "ai-output-cap:src/api/chat.ts",
        "ai-rate-limit:src/api/chat.ts",
        "ai-retry-bounds:src/api/chat.ts",
        "ai-spend-guardrails:src/api/chat.ts",
        "ai-timeout:src/api/chat.ts",
        "ai-user-controlled-model:src/api/chat.ts",
        "ai-user-controlled-settings:src/api/chat.ts",
        "backup-restore-plan-missing:README.md",
        "build-script-missing:package.json",
        "ci-only-builds:package.json",
        "ci-quality-gate-missing:.github/workflows/ci.yml",
        "ci-workflow-missing:package.json",
        "client-ai-sdk:src/app/page.tsx",
        "client-auth-without-server-enforcement:src/app/page.tsx",
        "client-db-access:src/app/page.tsx",
        "client-env-secret:src/app/page.tsx",
        "config-secret:.cursor/mcp.json",
        "console-log-error-handling:src/api/orders.ts",
        "cors-credentials-wildcard:src/api/orders.ts",
        "critical-path-no-test:src/api/orders.ts",
        "csrf-missing:src/api/orders.ts",
        "db-in-route:src/api/orders.ts",
        "db-index-hints-missing:schema.sql",
        "db-scattered-across-routes:src/api/orders.ts",
        "deploy-rollback-plan-missing:package.json",
        "direct-url-dependency:package.json:lib",
        "duplicate-utility-deps:date-utils:package.json",
        "empty-catch-blocks:src/api/orders.ts",
        "env-drift:.env.local",
        "env-example-incomplete:.env.example",
        "env-example-missing:src/config.ts",
        "error-boundary-missing:src/App.tsx",
        "error-reporting-missing:package.json",
        "eval-exec-injection:src/api/orders.ts",
        "external-call-retry:src/api/orders.ts",
        "external-call-timeout:src/api/orders.ts",
        "gitignore-missing:package.json",
        "gitignore-missing-env:.gitignore",
        "god-module:src/lib/service.ts",
        "god-route:src/api/orders.ts",
        "hardcoded-localhost-url:src/api/orders.ts",
        "hardcoded-secret:src/lib/config.ts",
        "healthcheck-missing:src/server.ts",
        "job-visibility-missing:src/jobs.ts",
        "jsx-inline-style-density:src/App.tsx",
        "jwt-decode-without-verify:src/api/auth.ts",
        "linter-missing:package.json",
        "local-db-target-remote:.env.local",
        "local-drizzle-migration-drift:db.sqlite",
        "local-postgres-missing-foreign-keys:public.users",
        "local-prisma-migration-history-missing:db.sqlite",
        "local-sqlite-unindexed-lookups:db.sqlite",
        "localstorage-auth-token:src/App.tsx",
        "lockfile-mismatch:package.json:zod",
        "lockfile-missing:package.json",
        "migration-workflow-missing:package.json",
        "multi-write-no-transaction:src/api/orders.ts",
        "n-plus-one-query:src/api/orders.ts",
        "no-automated-tests:package.json",
        "no-pagination:src/api/orders.ts",
        "oauth-callback-pkce:src/api/auth/callback.ts",
        "oauth-callback-state:src/api/auth/callback.ts",
        "one-time-token-no-expiry:src/api/invite.ts",
        "one-time-token-no-single-use:src/api/invite.ts",
        "one-time-token-raw-lookup:src/api/invite.ts",
        "open-redirect:src/api/auth/callback.ts",
        "oversized-module:src/lib/service.ts",
        "php-dynamic-command:public/api/run.php",
        "php-file-inclusion:public/api/page.php",
        "php-object-injection:public/api/session.php",
        "placeholder-density:src/lib/service.ts",
        "plaintext-password:src/api/register.ts",
        "pre-commit-hooks-missing:package.json",
        "pre-commit-hooks-not-installed:.husky/pre-commit",
        "pre-commit-hooks-weak:package.json",
        "public-endpoint-rate-limit:src/api/orders.ts",
        "python-code-execution:app/api/run.py",
        "python-command-injection:app/api/run.py",
        "python-sql-injection:app/api/run.py",
        "python-template-injection:app/api/run.py",
        "python-unsafe-deserialization:app/api/run.py",
        "raw-sql-unsafe:src/api/orders.ts",
        "recovery-runbook-missing:package.json",
        "registry-host-mismatch:package.json:zod",
        "schema-join-nullable-relations:schema.prisma:User.posts",
        "sensitive-auth:src/api/admin.ts",
        "sensitive-authz:src/api/admin.ts",
        "session-cookie-flags:src/api/auth.ts",
        "shell-injection:src/api/jobs.ts",
        "stripe-checkout-idempotency:src/api/checkout.ts",
        "stripe-user-controlled-price:src/api/checkout.ts",
        "stripe-user-controlled-redirect:src/api/checkout.ts",
        "structured-logging-missing:src/server.ts",
        "supabase-policy-operation-missing:profiles:select",
        "supabase-rls-missing:profiles",
        "supabase-service-role-client:src/lib/supabase.ts",
        "suspicious-manifest-package:package.json:reaact",
        "suspicious-package:src/App.tsx:reaact",
        "tenant-scope-missing:src/api/orders.ts",
        "tests-not-enforced:.github/workflows/ci.yml",
        "typescript-any-abuse:src/lib/types.ts",
        "undeclared-package:src/App.tsx:lodash",
        "unused-dependency:package.json:lodash",
        "upload-key-scope:src/api/upload.ts",
        "upload-validation:src/api/upload.ts",
        "unsafe-html:src/app/page.tsx",
        "user-controlled-fetch:src/api/fetch.ts",
        "weak-default-credential:src/api/config.ts",
        "webhook-idempotency:src/api/webhook.ts",
        "webhook-signature:src/api/webhook.ts",
    ];

    for id in ids {
        assert!(
            code_policy_severity(&code_issue(id, Severity::High)).is_some(),
            "missing code severity policy for {id}"
        );
    }
}

#[test]
fn code_confidence_policy_distinguishes_observations_inferences_and_review_leads() {
    use crate::checks::IssueConfidence::{Confirmed, High, NeedsReview};

    // Static pattern-based detections must
    // ship as NeedsReview so the user sees triage signal, not a verdict.
    let heuristic_slugs = [
        "webhook-signature",
        "raw-sql-unsafe",
        "public-endpoint-rate-limit",
        "sensitive-auth",
        "sensitive-authz",
        "localstorage-auth-token",
        "jwt-decode-without-verify",
        "client-env-secret",
        "typescript-any-abuse",
        "ai-conversation-artifacts",
        "ai-spend-guardrails",
        "ai-cache-dedupe",
        "ai-timeout",
        "external-call-timeout",
        "no-pagination",
        "user-controlled-fetch",
        "eval-exec-injection",
        "shell-injection",
        "unsafe-html",
        "plaintext-password",
        "tenant-scope-missing",
        "csrf-missing",
        "session-cookie-flags",
        "client-ai-sdk",
        "client-db-access",
        "cors-credentials-wildcard",
        "supabase-policy-operation-missing",
        "supabase-policy-set-empty",
        "supabase-open-policy",
        "supabase-policy-not-auth-scoped",
        "suspicious-package",
        "suspicious-manifest-package",
        // These remain review leads because they are co-occurrence or
        // effective-runtime heuristics rather than bounded inferences.
        "open-redirect",
        "ai-loop-risk",
        "ai-concurrency",
        "ai-observability",
        "hardcoded-localhost-url",
        "hardcoded-secret",
        "npmrc-committed-token",
        "config-secret",
        "supabase-service-role-client",
        "registry-host-mismatch",
        "framework-debug-enabled",
        "ai-output-cap",
        "console-log-error-handling",
        "php-file-inclusion",
        "php-object-injection",
        "php-dynamic-command",
        "php-code-execution",
        "php-path-traversal",
        "python-command-injection",
        "python-unsafe-deserialization",
        "python-code-execution",
        "python-sql-injection",
        "python-template-injection",
        "python-open-redirect",
        "python-path-traversal",
        "js-command-injection",
        "tls-verification-disabled",
        "nextconfig-errors-ignored",
        "cors-origin-reflection",
    ];
    for slug in heuristic_slugs {
        let (confidence, reason) = crate::core::confidence_policy::code_issue_confidence(slug);
        assert_eq!(
            confidence, NeedsReview,
            "{slug} is heuristic and must ship as NeedsReview"
        );
        assert!(
            reason.is_some(),
            "{slug} must include a confidence_reason explaining the heuristic"
        );
    }

    // Directly counted or compared structural facts are Confirmed. This says
    // the condition exists, not that the same remediation fits every project.
    let direct_slugs = [
        "empty-catch-blocks",
        "env-example-missing",
        "env-example-incomplete",
        "jsx-inline-style-density",
        "placeholder-density",
    ];
    for slug in direct_slugs {
        let (confidence, _) = crate::core::confidence_policy::code_issue_confidence(slug);
        assert_eq!(
            confidence, Confirmed,
            "{slug} is a direct structural fact - should be Confirmed"
        );
    }

    // Bounded structural analysis provides strong evidence, while still
    // leaving room for project-specific conventions. Dependency resolution is
    // not on this list: an import can resolve through machinery the static
    // walk does not model, and a package can be loaded by name at runtime, so
    // `undeclared-package` and `unused-dependency` ship as NeedsReview.
    let high_slugs = ["god-route", "god-module", "oversized-module"];
    for slug in high_slugs {
        let (confidence, reason) = crate::core::confidence_policy::code_issue_confidence(slug);
        assert_eq!(
            confidence, High,
            "{slug} is a bounded inference - should be High confidence"
        );
        assert!(
            reason.is_some(),
            "{slug} should explain the remaining caveat"
        );
    }

    // Unknown slugs default to NeedsReview (safer than High).
    let (unknown_confidence, unknown_reason) =
        crate::core::confidence_policy::code_issue_confidence("not-a-real-slug");
    assert_eq!(unknown_confidence, NeedsReview);
    assert!(unknown_reason.is_some());
}

#[test]
fn polish_subjective_signals_are_needs_review() {
    use crate::checks::IssueConfidence::{Confirmed, NeedsReview};

    let needs_review_signals = [
        "glassmorphism",
        "gradient-backgrounds",
        "scroll-animations",
        "excessive-border-radius",
        "glow-shadows",
        "floating-blobs",
        "three-column-grid",
        "ai-buzzword-dictionary",
        "ai-header-formulas",
        "default-favicon",
        "default-error-page",
        "default-deployment-subdomain",
        "tailwind-class-density",
        "utility-to-custom-ratio",
        "no-css-architecture",
        "inline-style-density",
        "div-soup-ratio",
        "em-dash-density",
        "source-maps-production",
        "default-page-title",
        "console-log-production",
    ];
    for id in needs_review_signals {
        let (confidence, reason) = crate::core::confidence_policy::polish_signal_confidence(id);
        assert_eq!(
            confidence, NeedsReview,
            "polish signal {id} must ship as NeedsReview (heuristic with known FP risk)"
        );
        assert!(
            reason.is_some(),
            "polish signal {id} must include a confidence_reason explaining the heuristic"
        );
    }

    // Direct structural facts are Confirmed observations.
    let confirmed_signals = ["missing-lang", "missing-og-tags"];
    for id in confirmed_signals {
        let (confidence, _) = crate::core::confidence_policy::polish_signal_confidence(id);
        assert_eq!(
            confidence, Confirmed,
            "polish signal {id} is a direct structural fact - should be Confirmed"
        );
    }

    // Unknown signal IDs default to NeedsReview (safer than High).
    let (unknown_confidence, unknown_reason) =
        crate::core::confidence_policy::polish_signal_confidence("not-a-real-signal");
    assert_eq!(unknown_confidence, NeedsReview);
    assert!(unknown_reason.is_some());
}

#[test]
fn contextual_heading_structure_signal_is_low_severity() {
    assert_eq!(
        crate::core::severity_policy::polish_signal_severity("polish.heading-hierarchy"),
        Severity::Low
    );
}

#[test]
fn polish_review_only_signals_are_low_severity() {
    let review_only = [
        "inline-style-density",
        "tailwind-class-density",
        "no-css-architecture",
        "utility-to-custom-ratio",
        "div-soup-ratio",
        "default-page-title",
        "missing-og-tags",
        "console-log-production",
        "default-deployment-subdomain",
        "default-error-page",
    ];

    for signal in review_only {
        assert_eq!(
            crate::core::severity_policy::polish_signal_severity(signal),
            Severity::Low,
            "{signal} is a contextual polish review signal"
        );
    }

    for signal in ["form-accessibility", "button-vs-clickable-div", "js-errors"] {
        assert_eq!(
            crate::core::severity_policy::polish_signal_severity(signal),
            Severity::Medium,
            "{signal} represents a potentially user-blocking defect"
        );
    }
}
