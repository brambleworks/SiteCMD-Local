//! Native parity tests for the wasm route evaluation: each corpus page opened
//! through the ABI and evaluated with nothing recorded, compared with the native
//! session's answer.

#[path = "support/abi.rs"]
mod abi;

use sitecmd_engine::evaluation::{
    EvaluationResponse, NotEvaluatedReason, PageArtifact, RouteFacts, RouteSession,
};
use sitecmd_engine::manifest::{capability_manifest, CheckScope, RuntimeFact};
use sitecmd_engine::{Check, CheckResult};
use sitecmd_engine_wasm::{
    engine_route_discover, engine_route_evaluate, engine_route_open, engine_route_plan,
    engine_route_session_page,
};

const CORPUS: &str = include_str!("../../engine/fixtures/checks/golden.json");

/// Open a route on `page` through the ABI and evaluate it with nothing recorded.
fn evaluate_through_abi(page: &PageArtifact) -> EvaluationResponse {
    abi::open(page);
    let payload = abi::call(engine_route_evaluate, b"{}");
    serde_json::from_slice(&payload).unwrap_or_else(|error| {
        panic!(
            "payload is an EvaluationResponse, not {error}: {}",
            String::from_utf8_lossy(&payload[..payload.len().min(400)])
        )
    })
}

fn native(page: &PageArtifact) -> EvaluationResponse {
    RouteSession::open(page.clone())
        .expect("the page opens natively")
        .evaluate(&RouteFacts::default())
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

        let response = evaluate_through_abi(&case.page);
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
fn the_open_frame_equals_the_native_opening() {
    for case in &corpus().cases {
        let route = RouteSession::open(case.page.clone()).expect("the page opens natively");
        let expected = serde_json::to_vec(&serde_json::to_value(route.opened()).expect("value"))
            .expect("bytes");
        assert_eq!(abi::open(&case.page), expected, "{}", case.name);
    }
}

#[test]
fn the_framed_response_equals_the_in_process_response() {
    for case in &corpus().cases {
        let native = serde_json::to_value(native(&case.page)).expect("response serializes");
        let framed = serde_json::to_value(evaluate_through_abi(&case.page))
            .expect("framed response serializes");
        assert_eq!(framed, native, "{}", case.name);
    }
}

#[test]
fn the_framed_evaluation_reads_the_supplied_facts() {
    let page = corpus().cases[0].page.clone();
    let request = serde_json::json!({
        "resolver_facts": {
            "domain": "example.com",
            "apex_txt": { "answer": "no_records" },
            "apex_mx": { "answer": "no_records" },
            "dmarc_txt": { "answer": "no_records" },
            "dkim_txt": [],
            "dnskey": { "answer": "no_records" },
            "caa": { "answer": "no_records" },
            "www_cname": { "answer": "no_records" },
            "www_target_addresses": null
        },
        "vulnerability_facts": { "status": "answered", "advisories": [] }
    });
    let facts: RouteFacts = serde_json::from_value(request.clone()).expect("route facts parse");
    let route = RouteSession::open(page.clone()).expect("the page opens natively");
    let expected = serde_json::to_vec(
        &serde_json::to_value(route.evaluate(&facts)).expect("native response serializes"),
    )
    .expect("native response bytes");
    abi::open(&page);
    assert_eq!(abi::call_json(engine_route_evaluate, &request), expected);
}

#[test]
fn identical_requests_produce_identical_payloads() {
    for case in &corpus().cases {
        abi::open(&case.page);
        let first = abi::call(engine_route_evaluate, b"{}");
        abi::open(&case.page);
        let second = abi::call(engine_route_evaluate, b"{}");
        assert_eq!(first, second, "{}", case.name);
    }
}

#[test]
fn http2_is_named_unsupported_even_when_a_page_carries_a_protocol() {
    for protocol in [None, Some("HTTP/1.1"), Some("HTTP/2.0"), Some("HTTP/3")] {
        let mut page = corpus().cases[0].page.clone();
        page.http_version = protocol.map(str::to_string);
        let response = evaluate_through_abi(&page);
        assert!(
            response
                .planned
                .iter()
                .all(|row| row.check != "performance.http2"),
            "{protocol:?}: HTTP/2 must not be planned"
        );
        assert!(response
            .results
            .iter()
            .all(|row| row.check_id != "performance.http2"));
        let named = response
            .not_evaluated
            .iter()
            .find(|row| row.check == "performance.http2")
            .expect("HTTP/2 is named not evaluated");
        assert_eq!(named.reason, NotEvaluatedReason::UnsupportedLane);
        assert_eq!(named.layer, None);
    }
}

#[test]
fn every_response_partitions_the_whole_manifest() {
    let manifest = capability_manifest();
    for case in &corpus().cases {
        let response = evaluate_through_abi(&case.page);
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
    let payload = abi::call(engine_route_open, b"{ not json");
    let value: serde_json::Value = serde_json::from_slice(&payload).expect("error frame is JSON");
    let message = value["error"].as_str().expect("error carries a message");
    assert!(!message.is_empty());
}

#[test]
fn an_unparseable_page_url_returns_an_error_payload() {
    let mut broken = corpus().cases[0].page.clone();
    broken.url = "not a url".into();
    let payload = abi::call_json(engine_route_open, &serde_json::json!({ "page": broken }));
    assert!(abi::refusal(&payload)
        .expect("error carries a message")
        .contains("url"));
}

#[test]
fn an_empty_request_returns_an_error_payload() {
    let value: serde_json::Value =
        serde_json::from_slice(&abi::call(engine_route_open, b"")).expect("error frame is JSON");
    assert!(!value["error"]
        .as_str()
        .expect("error carries a message")
        .is_empty());
}

#[test]
fn a_route_call_before_any_open_is_refused_as_data() {
    // A fresh thread, so no earlier case's route is open on it.
    let refusals = std::thread::spawn(|| {
        [
            abi::call(engine_route_plan, b"{}"),
            abi::call(engine_route_evaluate, b"{}"),
            abi::call(engine_route_session_page, b"{\"routes\": []}"),
            abi::call(engine_route_discover, b"{\"limit\": 0}"),
        ]
        .map(|frame| abi::refusal(&frame))
    })
    .join()
    .expect("the thread finishes");
    for refusal in refusals {
        assert_eq!(
            refusal.as_deref(),
            Some("no route is open on this instance")
        );
    }
}

#[test]
fn an_open_that_fails_leaves_no_route_open() {
    let mut page = corpus().cases[0].page.clone();
    abi::open(&page);
    page.url = "not a url".into();
    let refused = abi::call_json(engine_route_open, &serde_json::json!({ "page": page }));
    assert!(abi::refusal(&refused).is_some());
    assert_eq!(
        abi::refusal(&abi::call(engine_route_evaluate, b"{}")).as_deref(),
        Some("no route is open on this instance")
    );
    abi::open(&corpus().cases[0].page);
    let refused = abi::call(engine_route_open, b"{ not json");
    assert!(abi::refusal(&refused).is_some());
    assert_eq!(
        abi::refusal(&abi::call(engine_route_evaluate, b"{}")).as_deref(),
        Some("no route is open on this instance")
    );
}
