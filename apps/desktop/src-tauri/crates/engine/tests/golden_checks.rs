//! Exact cross-runtime fixtures for page-artifact verdicts.
//!
//! Regenerate with `cargo test -p sitecmd-engine --test golden_checks -- --ignored regenerate`.

use serde::Deserialize;
use sitecmd_engine::checks::security::headers::SecurityHeadersCheck;
use sitecmd_engine::evaluation::PageArtifact;
use sitecmd_engine::{Check, CheckResult, CheckStatus};

const CORPUS: &str = include_str!("../fixtures/checks/golden.json");

#[derive(Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    comment: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    check: String,
    page: PageArtifact,
    expected: Option<Vec<CheckResult>>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("golden.json parses")
}

fn check_by_id(id: &str) -> Box<dyn Check> {
    use sitecmd_engine::checks as c;
    match id {
        "security.headers" => Box::new(SecurityHeadersCheck),
        "accessibility.form_labels" => Box::new(c::accessibility::form_labels::FormLabelsCheck),
        "performance.render_blocking" => {
            Box::new(c::performance::render_blocking::RenderBlockingCheck)
        }
        "performance.unminified" => Box::new(c::performance::unminified::UnminifiedCodeCheck),
        "seo.headings" => Box::new(c::seo::headings::HeadingCheck),
        "accessibility.skip_nav" => Box::new(c::accessibility::html_checks::SkipNavCheck),
        "security.mixed_content" => Box::new(c::security::mixed_content::MixedContentCheck),
        "config.deprecated_html" => Box::new(c::config::deprecated_html::DeprecatedHtmlCheck),
        "compliance.trackers" => Box::new(c::compliance::trackers::ThirdPartyTrackerCheck),
        "compliance.form_consent" => Box::new(c::compliance::trackers::FormConsentCheck),
        "compliance.ccpa_notice" => Box::new(c::compliance::statements::CcpaNoticeCheck),
        "compliance.accessibility_statement" => {
            Box::new(c::compliance::statements::AccessibilityStatementCheck)
        }
        "compliance.dnt_respect" => Box::new(c::compliance::gdpr::DntRespectCheck),
        "config.analytics" => Box::new(c::config::analytics::AnalyticsCheck),
        "config.localhost_refs" => Box::new(c::predeploy::LocalhostRefsCheck),
        "security.email_exposure" => Box::new(c::security::email_exposure::EmailExposureCheck),
        "security.vibe.csrf" => Box::new(c::security::csrf::CsrfCheck),
        "security.vibe.exposed_keys" => Box::new(c::security::exposed_keys::ExposedApiKeysCheck),
        "seo.title" => Box::new(c::seo::meta::TitleTagCheck),
        "seo.meta_description" => Box::new(c::seo::meta::MetaDescriptionCheck),
        "seo.canonical" => Box::new(c::seo::meta::CanonicalCheck),
        "seo.viewport" => Box::new(c::seo::meta::ViewportCheck),
        "seo.open_graph" => Box::new(c::seo::meta::OpenGraphCheck),
        "seo.og_image_relative" => Box::new(c::seo::meta::OgImageAbsoluteCheck),
        "seo.charset" => Box::new(c::seo::meta::MetaCharsetCheck),
        "seo.twitter_cards" => Box::new(c::seo::meta::TwitterCardCheck),
        "seo.noindex" => Box::new(c::seo::meta::NoindexCheck),
        "seo.hreflang" => Box::new(c::seo::meta::HreflangCheck),
        "seo.duplicate_meta" => Box::new(c::seo::meta::DuplicateMetaCheck),
        other => panic!("no engine check registered for corpus id '{other}'"),
    }
}

fn run_case(case: &Case) -> Vec<CheckResult> {
    let context = case.page.page_context().expect("fixture artifact converts");
    check_by_id(&case.check).run(&context)
}

#[test]
fn golden_cases_reproduce_their_verdicts() {
    let corpus = corpus();
    assert!(!corpus.cases.is_empty(), "corpus has cases");
    for case in &corpus.cases {
        let expected = case.expected.as_ref().unwrap_or_else(|| {
            panic!(
                "case '{}' has no expected block; run the ignored `regenerate` test",
                case.name
            )
        });
        let actual = run_case(case);
        assert_eq!(
            actual.len(),
            expected.len(),
            "{}: result row count",
            case.name
        );
        for (index, (actual_row, expected_row)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(
                serde_json::to_value(actual_row).expect("actual row serializes"),
                serde_json::to_value(expected_row).expect("expected row serializes"),
                "{}[{index}] ({})",
                case.name,
                actual_row.check_id
            );
        }
    }
}

#[test]
fn headline_verdicts_match_the_documented_checks() {
    let corpus = corpus();
    let statuses = |name: &str| -> Vec<(String, CheckStatus)> {
        let case = corpus
            .cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("case '{name}' present"));
        run_case(case)
            .into_iter()
            .map(|row| (row.check_id, row.status))
            .collect()
    };
    let status_of = |rows: &[(String, CheckStatus)], id: &str| -> CheckStatus {
        rows.iter()
            .find(|(check_id, _)| check_id == id)
            .unwrap_or_else(|| panic!("row '{id}' present"))
            .1
    };

    // A fully hardened response passes all six header verdicts.
    let hardened = statuses("hardened_page_all_six_header_verdicts_pass");
    assert_eq!(hardened.len(), 6);
    assert!(hardened.iter().all(|(_, s)| *s == CheckStatus::Pass));

    let bare = statuses("bare_page_policy_failures_and_hardening_advisories");
    assert_eq!(status_of(&bare, "security.headers.csp"), CheckStatus::Fail);
    assert_eq!(status_of(&bare, "security.headers.hsts"), CheckStatus::Fail);
    for advisory in [
        "security.headers.x_frame_options",
        "security.headers.x_content_type_options",
        "security.headers.referrer_policy",
        "security.headers.permissions_policy",
    ] {
        assert_eq!(status_of(&bare, advisory), CheckStatus::Warn);
    }

    // Localhost previews skip all six: edge/proxy-controlled headers cannot
    // be graded against a dev server.
    let localhost = statuses("localhost_preview_skips_all_six");
    assert_eq!(localhost.len(), 6);
    assert!(localhost.iter().all(|(_, s)| *s == CheckStatus::Skipped));

    // unsafe-inline/unsafe-eval/data: make the CSP a failure even though the
    // header exists, and a sub-minimum HSTS max-age cannot pass.
    let weak = statuses("weak_csp_with_unsafe_sources_fails");
    assert_eq!(status_of(&weak, "security.headers.csp"), CheckStatus::Fail);
    assert_ne!(status_of(&weak, "security.headers.hsts"), CheckStatus::Pass);

    // CSP frame-ancestors is the modern clickjacking control; X-Frame-Options
    // is not required alongside it.
    let framed = statuses("csp_frame_ancestors_satisfies_clickjacking_without_xfo");
    assert_eq!(
        status_of(&framed, "security.headers.x_frame_options"),
        CheckStatus::Pass
    );

    // A meta-delivered enforced CSP counts (browsers honor it); the
    // commented-out variant in the same document must not.
    let meta = statuses("meta_delivered_csp_counts_commented_meta_does_not");
    assert_ne!(status_of(&meta, "security.headers.csp"), CheckStatus::Fail);

    // A text input with no label, aria-label, or wrapping label element is an
    // accessibility failure, not an advisory.
    let labels = statuses("unlabeled_text_input_flags_form_labels");
    assert_eq!(
        status_of(&labels, "accessibility.form_labels"),
        CheckStatus::Fail
    );

    // A synchronous script in <head> blocks first paint: advisory warning.
    let blocking = statuses("blocking_head_script_flags_render_blocking");
    assert_eq!(
        status_of(&blocking, "performance.render_blocking"),
        CheckStatus::Warn
    );

    // A page whose first heading is an h2 warns on the missing h1 while the
    // hierarchy sub-verdict (no skipped levels below the top) still passes.
    let headings = statuses("missing_h1_flags_heading_structure");
    assert_eq!(status_of(&headings, "seo.headings.h1"), CheckStatus::Warn);
    assert_eq!(
        status_of(&headings, "seo.headings.hierarchy"),
        CheckStatus::Pass
    );

    // Active mixed content (an http:// script on an https:// page) is a
    // failure: browsers block it and it breaks the page's transport promise.
    let mixed = statuses("http_script_on_https_page_is_mixed_content");
    assert_eq!(
        status_of(&mixed, "security.mixed_content"),
        CheckStatus::Fail
    );

    let marquee = statuses("marquee_tag_is_deprecated_html");
    assert_eq!(
        status_of(&marquee, "config.deprecated_html"),
        CheckStatus::Warn
    );
    let tracker = statuses("google_analytics_script_is_a_third_party_tracker");
    assert_eq!(
        status_of(&tracker, "compliance.trackers"),
        CheckStatus::Warn
    );
    let loopback = statuses("hardcoded_loopback_url_flags_predeploy_localhost_refs");
    assert_eq!(
        status_of(&loopback, "config.localhost_refs"),
        CheckStatus::Warn
    );

    let description = statuses("a_long_meta_description_needs_review");
    assert_eq!(
        status_of(&description, "seo.meta_description"),
        CheckStatus::Warn
    );

    let canonical = statuses("a_page_with_no_canonical_link");
    assert_eq!(status_of(&canonical, "seo.canonical"), CheckStatus::Warn);

    let viewport = statuses("a_viewport_without_device_width");
    assert_eq!(status_of(&viewport, "seo.viewport"), CheckStatus::Warn);

    let open_graph = statuses("open_graph_without_an_image");
    assert_eq!(status_of(&open_graph, "seo.open_graph"), CheckStatus::Warn);

    let relative_image = statuses("a_relative_og_image");
    assert_eq!(
        status_of(&relative_image, "seo.og_image_relative"),
        CheckStatus::Warn
    );

    let charset = statuses("no_declared_charset");
    assert_eq!(status_of(&charset, "seo.charset"), CheckStatus::Fail);

    let card = statuses("no_twitter_card_beside_complete_open_graph");
    assert_eq!(status_of(&card, "seo.twitter_cards"), CheckStatus::Warn);

    let noindex = statuses("an_x_robots_tag_noindex_header");
    assert_eq!(status_of(&noindex, "seo.noindex"), CheckStatus::Warn);

    let hreflang = statuses("hreflang_alternates_without_a_self_reference");
    assert_eq!(status_of(&hreflang, "seo.hreflang"), CheckStatus::Warn);
}

// Regenerate stable check fixtures after an intentional verdict change.
#[test]
#[ignore]
fn regenerate() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("golden.json parses");
    let cases: Vec<Case> =
        serde_json::from_value(value.get("cases").expect("cases array present").clone())
            .expect("cases parse");
    let out = value
        .get_mut("cases")
        .and_then(|c| c.as_array_mut())
        .expect("cases array");
    for (slot, case) in out.iter_mut().zip(&cases) {
        let rows = run_case(case);
        slot["expected"] = serde_json::to_value(&rows).expect("rows serialize");
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/checks/golden.json");
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("corpus serializes")
    );
    std::fs::write(path, rendered).expect("write golden.json");
    println!("regenerated {path}");
}
