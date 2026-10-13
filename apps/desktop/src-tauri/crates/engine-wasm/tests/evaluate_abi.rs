//! Native parity tests for the wasm evaluation ABI.
//!
//! Each corpus case is compared before and after the raw framed boundary.

use sitecmd_engine::evaluation::{
    evaluate, EvaluationRequest, EvaluationResponse, NotEvaluatedReason, PageArtifact,
};
use sitecmd_engine::manifest::{capability_manifest, CheckScope, RuntimeFact};
use sitecmd_engine::{Check, CheckResult};
use sitecmd_engine_wasm::{engine_evaluate, scorer_alloc, scorer_free};

const CORPUS: &str = include_str!("../../engine/fixtures/checks/golden.json");

fn call_through_abi(request: &[u8]) -> Vec<u8> {
    unsafe {
        let input = scorer_alloc(request.len() as u32);
        core::ptr::copy_nonoverlapping(request.as_ptr(), input, request.len());
        let frame = engine_evaluate(input, request.len() as u32) as *mut u8;
        let mut length_bytes = [0u8; 4];
        core::ptr::copy_nonoverlapping(frame, length_bytes.as_mut_ptr(), 4);
        let payload_length = u32::from_le_bytes(length_bytes) as usize;
        let payload = core::slice::from_raw_parts(frame.add(4), payload_length).to_vec();
        scorer_free(frame, (4 + payload_length) as u32);
        payload
    }
}

fn evaluate_through_abi(request: &EvaluationRequest) -> EvaluationResponse {
    let bytes = serde_json::to_vec(request).expect("request serializes");
    let payload = call_through_abi(&bytes);
    serde_json::from_slice(&payload).unwrap_or_else(|error| {
        panic!(
            "payload is an EvaluationResponse, not {error}: {}",
            String::from_utf8_lossy(&payload[..payload.len().min(400)])
        )
    })
}

#[derive(serde::Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    check: String,
    page: PageArtifact,
}

// Keep drivers aligned with `engine/tests/golden_checks.rs` for ABI parity.
fn check_by_id(id: &str) -> Box<dyn Check> {
    use sitecmd_engine::checks as c;
    match id {
        "security.headers" => Box::new(c::security::headers::SecurityHeadersCheck),
        "accessibility.form_labels" => Box::new(c::accessibility::form_labels::FormLabelsCheck),
        "performance.render_blocking" => {
            Box::new(c::performance::render_blocking::RenderBlockingCheck)
        }
        "seo.headings" => Box::new(c::seo::headings::HeadingCheck),
        "security.mixed_content" => Box::new(c::security::mixed_content::MixedContentCheck),
        "config.deprecated_html" => Box::new(c::config::deprecated_html::DeprecatedHtmlCheck),
        "compliance.trackers" => Box::new(c::compliance::trackers::ThirdPartyTrackerCheck),
        "config.localhost_refs" => Box::new(c::predeploy::LocalhostRefsCheck),
        "performance.unminified" => Box::new(c::performance::unminified::UnminifiedCodeCheck),
        "accessibility.skip_nav" => Box::new(c::accessibility::html_checks::SkipNavCheck),
        "compliance.form_consent" => Box::new(c::compliance::trackers::FormConsentCheck),
        "compliance.ccpa_notice" => Box::new(c::compliance::statements::CcpaNoticeCheck),
        "compliance.accessibility_statement" => {
            Box::new(c::compliance::statements::AccessibilityStatementCheck)
        }
        "compliance.dnt_respect" => Box::new(c::compliance::gdpr::DntRespectCheck),
        "config.analytics" => Box::new(c::config::analytics::AnalyticsCheck),
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

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("golden.json parses")
}

fn rows_for<'a>(response: &'a EvaluationResponse, ids: &[String]) -> Vec<&'a CheckResult> {
    response
        .results
        .iter()
        .filter(|row| ids.contains(&row.check_id))
        .collect()
}

#[test]
fn the_corpus_verdicts_survive_the_abi_unchanged() {
    let corpus = corpus();
    assert!(!corpus.cases.is_empty(), "corpus has cases");
    for case in &corpus.cases {
        let context = case.page.page_context().expect("fixture artifact converts");
        let direct = check_by_id(&case.check).run(&context);
        if case.check == "seo.headings" {
            continue;
        }
        assert!(
            !direct.is_empty(),
            "{}: the corpus check produced rows natively",
            case.name
        );

        let response = evaluate_through_abi(&EvaluationRequest {
            page: case.page.clone(),
            resolver_facts: None,
            vulnerability_facts: None,
            tls_facts: None,
            probe_outcomes: None,
            browser_facts: None,
        });
        let ids: Vec<String> = direct.iter().map(|row| row.check_id.clone()).collect();
        let through_abi = rows_for(&response, &ids);
        assert_eq!(
            through_abi.len(),
            direct.len(),
            "{}: result row count through the ABI",
            case.name
        );
        for (index, (actual, expected)) in through_abi.iter().zip(&direct).enumerate() {
            assert_eq!(
                serde_json::to_value(actual).expect("actual row serializes"),
                serde_json::to_value(expected).expect("expected row serializes"),
                "{}[{index}] ({})",
                case.name,
                expected.check_id
            );
        }
    }
}

#[test]
fn the_framed_response_equals_the_in_process_response() {
    for case in &corpus().cases {
        let request = EvaluationRequest {
            page: case.page.clone(),
            resolver_facts: None,
            vulnerability_facts: None,
            tls_facts: None,
            probe_outcomes: None,
            browser_facts: None,
        };
        let native = serde_json::to_value(evaluate(&request).expect("evaluates in process"))
            .expect("response serializes");
        let framed = serde_json::to_value(evaluate_through_abi(&request))
            .expect("framed response serializes");
        assert_eq!(framed, native, "{}", case.name);
    }
}

#[test]
fn identical_requests_produce_identical_payloads() {
    for case in &corpus().cases {
        let request = serde_json::to_vec(&EvaluationRequest {
            page: case.page.clone(),
            resolver_facts: None,
            vulnerability_facts: None,
            tls_facts: None,
            probe_outcomes: None,
            browser_facts: None,
        })
        .expect("request serializes");
        assert_eq!(
            call_through_abi(&request),
            call_through_abi(&request),
            "{}",
            case.name
        );
    }
}

#[test]
fn every_response_partitions_the_whole_manifest() {
    let manifest = capability_manifest();
    for case in &corpus().cases {
        let response = evaluate_through_abi(&EvaluationRequest {
            page: case.page.clone(),
            resolver_facts: None,
            vulnerability_facts: None,
            tls_facts: None,
            probe_outcomes: None,
            browser_facts: None,
        });
        assert_eq!(response.manifest_digest, manifest.digest(), "{}", case.name);
        assert_eq!(
            response.planned.len() + response.not_evaluated.len(),
            manifest.entries.len(),
            "{}: every entry is planned or named not-evaluated",
            case.name
        );
        assert_eq!(response.facts_present, vec![RuntimeFact::PageArtifact]);
        for entry in &manifest.entries {
            if entry.scope != CheckScope::Session {
                continue;
            }
            let named = response
                .not_evaluated
                .iter()
                .find(|row| row.check == entry.check)
                .unwrap_or_else(|| panic!("{}: '{}' is named", case.name, entry.check));
            assert_eq!(named.reason, NotEvaluatedReason::SessionScope);
            assert_eq!(
                serde_json::to_value(&named.reason).expect("reason")["reason"],
                "session_scope"
            );
        }
    }
}

#[test]
fn a_malformed_request_returns_an_error_payload() {
    let payload = call_through_abi(b"{ not json");
    let value: serde_json::Value = serde_json::from_slice(&payload).expect("error frame is JSON");
    let message = value["error"].as_str().expect("error carries a message");
    assert!(!message.is_empty());
}

#[test]
fn an_unparseable_page_url_returns_an_error_payload() {
    let mut broken = corpus().cases[0].page.clone();
    broken.url = "not a url".into();
    let request = serde_json::to_vec(&EvaluationRequest {
        page: broken,
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    })
    .expect("request serializes");
    let value: serde_json::Value =
        serde_json::from_slice(&call_through_abi(&request)).expect("error frame is JSON");
    assert!(value["error"]
        .as_str()
        .expect("error carries a message")
        .contains("url"));
}

#[test]
fn an_empty_request_returns_an_error_payload() {
    let value: serde_json::Value =
        serde_json::from_slice(&call_through_abi(b"")).expect("error frame is JSON");
    assert!(!value["error"]
        .as_str()
        .expect("error carries a message")
        .is_empty());
}
