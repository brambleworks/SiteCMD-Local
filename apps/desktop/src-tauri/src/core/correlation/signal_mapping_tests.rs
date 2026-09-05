use super::*;

#[test]
fn resolves_known_psi_signal() {
    assert_eq!(
        resolve_check_id("psi", "render-blocking-resources"),
        "performance.render_blocking"
    );
}

#[test]
fn falls_back_for_unknown_signal() {
    assert_eq!(
        resolve_check_id("psi", "never-heard-of-this"),
        "psi.never-heard-of-this"
    );
}

/// The polish signals that re-grade a defect a Web Scan check already reports.
/// Each fires only in conditions its authority also fires in, so they share an
/// identity and the score charges the defect once.
const POLISH_REGRADES: &[(&str, &str)] = &[
    ("polish.missing-og-tags", "seo.open_graph"),
    ("polish.form-accessibility", "accessibility.form_labels"),
    ("polish.missing-lang", "accessibility.lang"),
    ("polish.heading-hierarchy", "accessibility.headings"),
    ("polish.no-sitemap-robots", "seo.canonical"),
];

#[test]
fn a_polish_signal_that_regrades_a_web_check_shares_its_identity() {
    for (signal, authority) in POLISH_REGRADES {
        assert_eq!(&resolve_check_id("web_scan", signal), authority, "{signal}");
        assert_eq!(web_scan_check_id(signal), Some(*authority), "{signal}");
    }

    // Negative control: a polish signal that grades its own defect keeps its
    // own identity, so it still deducts on its own.
    assert_eq!(
        resolve_check_id("web_scan", "polish.div-soup-ratio"),
        "polish.div-soup-ratio"
    );
    assert_eq!(web_scan_check_id("polish.div-soup-ratio"), None);
}

#[test]
fn a_regrading_polish_signal_does_not_deduct_beside_its_authority() {
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

    let finding = |check_id: &str, category| CheckResult {
        check_id: check_id.into(),
        category,
        title: "t".into(),
        description: "d".into(),
        status: CheckStatus::Fail,
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    };
    let score = |results: &[CheckResult]| {
        crate::scoring::calculator::calculate_scores_with_identity(results, |result| {
            web_scan_check_id(&result.check_id).unwrap_or(result.check_id.as_str())
        })
        .0
    };

    for (signal, authority) in POLISH_REGRADES {
        let alone = score(&[finding(authority, ScanCategory::Seo)]);
        let both = score(&[
            finding(authority, ScanCategory::Seo),
            finding(signal, ScanCategory::Polish),
        ]);
        assert_eq!(both, alone, "{signal} deducted a second time");
    }

    // Negative control: two unrelated findings still cost two deductions.
    let one = score(&[finding("seo.open_graph", ScanCategory::Seo)]);
    let two = score(&[
        finding("seo.open_graph", ScanCategory::Seo),
        finding("polish.div-soup-ratio", ScanCategory::Polish),
    ]);
    assert!(two < one, "independent findings each deduct");
}

#[test]
fn every_mapping_has_distinct_source_signal_pair() {
    let mut seen: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
    for m in SIGNAL_MAPPINGS {
        assert!(
            seen.insert((m.source, m.source_signal)),
            "duplicate mapping: {}:{}",
            m.source,
            m.source_signal
        );
    }
}

#[test]
fn resolves_plausible_mappings() {
    assert_eq!(
        resolve_check_id("plausible", "traffic-drop"),
        "analytics.traffic-drop"
    );
    assert_eq!(
        resolve_check_id("plausible", "goal-drop"),
        "analytics.conversion-drop"
    );
    assert_eq!(
        resolve_check_id("plausible", "entry-page-anomaly"),
        "analytics.landing-page-change"
    );
}

#[test]
fn resolves_cloudflare_mappings() {
    assert_eq!(
        resolve_check_id("cloudflare", "5xx-rate-high"),
        "infrastructure.server-errors"
    );
    assert_eq!(
        resolve_check_id("cloudflare", "cache-hit-low"),
        "performance.cache_headers"
    );
    assert_eq!(
        resolve_check_id("cloudflare", "origin-error"),
        "infrastructure.origin-error"
    );
    assert_eq!(
        resolve_check_id("cloudflare", "bot-traffic-spike"),
        "security.bot-traffic"
    );
}

#[test]
fn resolves_uptimerobot_mappings() {
    assert_eq!(
        resolve_check_id("uptimerobot", "monitor-down"),
        "infrastructure.uptime"
    );
    assert_eq!(
        resolve_check_id("uptimerobot", "slow-response"),
        "performance.ttfb"
    );
    assert_eq!(
        resolve_check_id("uptimerobot", "ssl-mismatch"),
        "infrastructure.ssl-mismatch"
    );
}

#[test]
fn resolves_code_scan_canonical_mappings() {
    assert_eq!(
        resolve_check_id("code_scan", "security_headers"),
        "security.csp"
    );
    assert_eq!(
        resolve_check_id("code_scan", "env_exposure"),
        "security.exposed-env"
    );
    assert_eq!(
        resolve_check_id("code_scan", "mixed_content"),
        "security.mixed_content"
    );
    assert_eq!(
        resolve_check_id("code_scan", "cors_wildcard"),
        "security.cors"
    );
    assert_eq!(
        resolve_check_id("code_scan", "cookie_flags"),
        "security.cookie-flags"
    );
    assert_eq!(resolve_check_id("code_scan", "robots_config"), "seo.robots");
    assert_eq!(
        resolve_check_id("code_scan", "canonical_missing"),
        "seo.canonical.missing"
    );
    assert_eq!(
        resolve_check_id("code_scan", "sitemap_missing"),
        "seo.sitemap.missing"
    );
    assert_eq!(
        resolve_check_id("code_scan", "https_redirect"),
        "security.https"
    );
    assert_eq!(
        resolve_check_id("code_scan", "hsts_missing"),
        "security.hsts"
    );
}

#[test]
fn unmapped_code_scan_signal_falls_through() {
    assert_eq!(
        resolve_check_id("code_scan", "supply_chain_typosquat"),
        "code_scan.supply_chain_typosquat"
    );
}

#[test]
fn every_signal_mapping_target_is_canonical() {
    let canonical: std::collections::HashSet<&str> = CANONICAL_CHECK_IDS.iter().copied().collect();
    for m in SIGNAL_MAPPINGS {
        assert!(
            canonical.contains(m.check_id),
            "SignalMapping target `{}` (from {}:{}) is not in CANONICAL_CHECK_IDS",
            m.check_id,
            m.source,
            m.source_signal,
        );
    }
}

#[test]
fn canonical_set_has_no_duplicates() {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for id in CANONICAL_CHECK_IDS {
        assert!(seen.insert(id), "duplicate canonical id: {}", id);
    }
}

#[test]
fn web_scan_mappings_canonicalize_known_aliases() {
    assert_eq!(
        resolve_check_id("web_scan", "security.headers.csp"),
        "security.csp"
    );
    assert_eq!(
        resolve_check_id("web_scan", "security.headers.hsts"),
        "security.hsts"
    );
    assert_eq!(
        resolve_check_id("web_scan", "security.headers.x_frame_options"),
        "security.x_frame_options"
    );
    assert_eq!(
        resolve_check_id("web_scan", "security.headers.x_content_type_options"),
        "security.x_content_type_options"
    );
    assert_eq!(
        resolve_check_id("web_scan", "security.headers.referrer_policy"),
        "security.referrer_policy"
    );
    assert_eq!(
        resolve_check_id("web_scan", "security.headers.permissions_policy"),
        "security.permissions_policy"
    );
    assert_eq!(
        resolve_check_id("web_scan", "security.https_enforcement"),
        "security.https"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.missing-lang"),
        "accessibility.lang"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.heading-hierarchy"),
        "accessibility.headings"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.form-accessibility"),
        "accessibility.form_labels"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.default-page-title"),
        "seo.title"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.missing-og-tags"),
        "seo.open_graph"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.default-favicon"),
        "config.favicon"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.source-maps-production"),
        "security.source_maps"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.console-log-production"),
        "config.console_logs"
    );
    assert_eq!(
        resolve_check_id("web_scan", "seo.headings.h1"),
        "accessibility.headings"
    );
    assert_eq!(
        resolve_check_id("web_scan", "seo.headings.hierarchy"),
        "accessibility.headings"
    );
    assert_eq!(
        resolve_check_id("web_scan", "seo.image_alt"),
        "accessibility.image_alt"
    );
}

#[test]
fn web_scan_unmapped_id_falls_through_unchanged() {
    assert_eq!(
        resolve_check_id("web_scan", "accessibility.image_alt"),
        "accessibility.image_alt"
    );
    assert_eq!(
        resolve_check_id("web_scan", "polish.div-soup-ratio"),
        "polish.div-soup-ratio"
    );
}

#[test]
fn reverse_lookup_returns_every_web_producer_for_a_canonical_group() {
    let mut headings = source_signals_for_check_id("web_scan", "accessibility.headings");
    headings.sort_unstable();
    assert_eq!(
        headings,
        vec![
            "polish.heading-hierarchy",
            "seo.headings.h1",
            "seo.headings.hierarchy",
        ]
    );
    assert_eq!(
        source_signals_for_check_id("web_scan", "security.csp"),
        vec!["security.headers.csp"]
    );
}

// Every producer ID a Web Scan check can emit: registered check ids, the
// `check_id: "..."` literals in production check sources (container sub-ids),
// and the Polish signal set under its `polish.` check-id prefix.
fn emittable_web_producer_ids() -> std::collections::BTreeSet<String> {
    let mut ids = std::collections::BTreeSet::new();

    let (sync_checks, async_checks) = crate::core::scanner::collect_checks(&None);
    ids.extend(sync_checks.iter().map(|check| check.id().to_string()));
    ids.extend(async_checks.iter().map(|check| check.id().to_string()));

    fn collect_sources(dir: &std::path::Path, out: &mut Vec<String>) {
        let test_module = regex::Regex::new(r#"#\[cfg\(test\)\]\s*(?:#\[path[^\]]*\]\s*)?mod\s"#)
            .expect("valid test-module regex");
        for entry in std::fs::read_dir(dir).expect("readable checks source dir") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                collect_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains("test"))
                {
                    continue;
                }
                let content = std::fs::read_to_string(&path).expect("readable check source");
                let production = match test_module.find(&content) {
                    Some(found) => content[..found.start()].to_string(),
                    None => content,
                };
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
    ids.extend(
        sources
            .iter()
            .flat_map(|source| literal.captures_iter(source))
            .map(|capture| capture[1].to_string()),
    );

    let polish_ctx = crate::checks::polish::PolishContext {
        url: url::Url::parse("https://example.com").expect("fixture url"),
        html: "<!doctype html><html><head><title>t</title></head><body></body></html>".into(),
        css: String::new(),
        html_lower_cache: std::sync::OnceLock::new(),
    };
    ids.extend(
        crate::checks::polish::run_all_signals(&polish_ctx)
            .iter()
            .map(|signal| format!("polish.{}", signal.id)),
    );

    assert!(
        ids.len() >= 150,
        "emittable-producer enumeration collapsed ({} ids) - the scan is broken",
        ids.len()
    );
    ids
}

#[test]
fn every_live_web_mapping_points_at_an_emittable_producer() {
    let emittable = emittable_web_producer_ids();

    let dead: Vec<&str> = SIGNAL_MAPPINGS
        .iter()
        .filter(|m| m.source == "web_scan" && !is_historical_web_producer(m.source_signal))
        .filter(|m| !emittable.contains(m.source_signal))
        .map(|m| m.source_signal)
        .collect();
    assert!(
        dead.is_empty(),
        "web_scan mappings whose source_signal has no emitter (verification of their group \
         would always fail): {dead:?}. Either restore the producer or add the signal to \
         HISTORICAL_WEB_PRODUCERS."
    );

    for historical in HISTORICAL_WEB_PRODUCERS {
        assert!(
            SIGNAL_MAPPINGS
                .iter()
                .any(|m| m.source == "web_scan" && m.source_signal == *historical),
            "HISTORICAL_WEB_PRODUCERS lists {historical}, which has no web_scan mapping \
             left to protect - remove the stale entry"
        );
        assert!(
            !emittable.contains(*historical),
            "{historical} is marked historical but a producer still emits it - drop it from \
             HISTORICAL_WEB_PRODUCERS so verification requires the real result again"
        );
    }
}

#[test]
fn live_reverse_lookup_excludes_historical_producers_but_keeps_aliasing() {
    // The retired producer stays out of the set verification requires...
    assert!(live_source_signals_for_check_id("web_scan", "accessibility.image_alt").is_empty());
    assert_eq!(
        resolve_check_id("web_scan", "seo.image_alt"),
        "accessibility.image_alt"
    );
    // Live mappings are unaffected by the filter.
    assert_eq!(
        live_source_signals_for_check_id("web_scan", "security.csp"),
        vec!["security.headers.csp"]
    );
}
