//! The session ABI answers byte for byte what the native functions answer.

use serde::Deserialize;
use sitecmd_engine::evaluation::{
    evaluate_session, session_page, PageArtifact, SessionPageFacts, SessionPageRequest,
    SessionRequest, SessionResponse,
};
use sitecmd_engine::CheckStatus;
use sitecmd_engine_wasm::{
    engine_session_evaluate, engine_session_page, scorer_alloc, scorer_free,
};

const CORPUS: &str = include_str!("../../engine/fixtures/session/golden.json");

fn call_through_abi(
    entry: unsafe extern "C" fn(*mut u8, u32) -> *const u8,
    request: &[u8],
) -> Vec<u8> {
    unsafe {
        let input = scorer_alloc(request.len() as u32);
        core::ptr::copy_nonoverlapping(request.as_ptr(), input, request.len());
        let frame = entry(input, request.len() as u32) as *mut u8;
        let mut length_bytes = [0u8; 4];
        core::ptr::copy_nonoverlapping(frame, length_bytes.as_mut_ptr(), 4);
        let payload_length = u32::from_le_bytes(length_bytes) as usize;
        let payload = core::slice::from_raw_parts(frame.add(4), payload_length).to_vec();
        scorer_free(frame, (4 + payload_length) as u32);
        payload
    }
}

fn request(url: &str) -> SessionPageRequest {
    SessionPageRequest {
        page: PageArtifact {
            url: url.into(),
            requested_url: Some(url.into()),
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: Vec::new(),
            body: "<html><head><title>Shared</title></head></html>".into(),
            evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
        },
        probe_outcomes: Vec::new(),
        routes: vec![
            "https://example.com/".into(),
            "https://example.com/menu".into(),
        ],
    }
}

#[test]
fn each_supplied_sitemap_cause_skips_comparison_through_the_abi() {
    use serde_json::json;
    use sitecmd_engine::checks::seo::sitemap_walk::SITEMAP_URL_LIMIT;

    let mut pages = ["https://example.com/", "https://example.com/menu"]
        .map(|url| session_page(&request(url)).expect("facts").expect("named"));
    pages[1].noindex = true;
    for cause in [
        json!({"cause": "index", "listed": 0}),
        json!({"cause": "url_limit", "listed": SITEMAP_URL_LIMIT - 1}),
        json!({"cause": "unread_declarations", "count": 0}),
    ] {
        let mut input = json!({"pages": pages});
        input["pages"][0]["sitemap"] = json!({"entries": ["r0"], "partial_causes": [cause]});
        let bytes = call_through_abi(
            engine_session_evaluate,
            &serde_json::to_vec(&input).expect("input"),
        );
        assert!(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .expect("answer")
                .get("error")
                .is_none(),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let answer: SessionResponse =
            serde_json::from_slice(&bytes).expect("causes-only request accepted");
        assert_eq!(
            answer
                .verdicts
                .iter()
                .find(|v| v.check_id == "seo.noindex_in_sitemap")
                .expect("verdict")
                .status,
            CheckStatus::Skipped
        );
    }
}

#[test]
fn page_facts_and_the_comparison_match_the_native_answers() {
    let mut pages: Vec<SessionPageFacts> = Vec::new();
    for url in ["https://example.com/", "https://example.com/menu"] {
        let native = serde_json::to_vec(
            &serde_json::to_value(session_page(&request(url)).expect("facts")).expect("value"),
        )
        .expect("bytes");
        let through = call_through_abi(
            engine_session_page,
            &serde_json::to_vec(&request(url)).expect("request"),
        );
        assert_eq!(through, native);
        pages.push(
            serde_json::from_slice::<Option<SessionPageFacts>>(&through)
                .expect("facts")
                .expect("named"),
        );
    }
    let compare = SessionRequest { pages };
    let native =
        serde_json::to_vec(&serde_json::to_value(evaluate_session(&compare)).expect("value"))
            .expect("bytes");
    let through = call_through_abi(
        engine_session_evaluate,
        &serde_json::to_vec(&compare).expect("request"),
    );
    assert_eq!(through, native);
    let response: SessionResponse = serde_json::from_slice(&through).expect("a session response");
    let shared = response
        .verdicts
        .iter()
        .find(|verdict| verdict.check_id == "seo.duplicate_title_across_pages")
        .expect("the shared title is a verdict");
    assert_eq!(shared.status, CheckStatus::Warn);
    assert_eq!(shared.pages, vec![0, 1]);
}

#[test]
fn a_malformed_comparison_is_refused_as_data() {
    let answer = call_through_abi(engine_session_evaluate, b"{\"pages\": 3}");
    assert!(String::from_utf8(answer)
        .expect("utf8")
        .starts_with("{\"error\":"));
}

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    routes: Vec<String>,
    pages: Vec<CasePage>,
    expected: serde_json::Value,
}
#[derive(Deserialize)]
struct CasePage {
    page: PageArtifact,
    #[serde(default)]
    probe_outcomes: Vec<sitecmd_engine::evaluation::ExecutedProbe>,
}

#[test]
fn every_corpus_answer_survives_both_framed_exports() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus");
    for case in corpus.cases {
        let mut facts = Vec::new();
        for input in case.pages {
            let request = SessionPageRequest {
                page: input.page,
                routes: case.routes.clone(),
                probe_outcomes: input.probe_outcomes,
            };
            let native =
                serde_json::to_value(session_page(&request).expect("facts")).expect("value");
            let through = call_through_abi(
                engine_session_page,
                &serde_json::to_vec(&request).expect("request"),
            );
            assert_eq!(
                through,
                serde_json::to_vec(&native).expect("bytes"),
                "{}",
                case.name
            );
            facts
                .push(serde_json::from_slice::<Option<SessionPageFacts>>(&through).expect("facts"));
        }
        assert_eq!(
            serde_json::to_value(&facts).expect("facts"),
            case.expected["facts"],
            "{}",
            case.name
        );
        let request = SessionRequest {
            pages: facts.into_iter().flatten().collect(),
        };
        let native = serde_json::to_value(evaluate_session(&request)).expect("value");
        let through = call_through_abi(
            engine_session_evaluate,
            &serde_json::to_vec(&request).expect("request"),
        );
        assert_eq!(
            through,
            serde_json::to_vec(&native).expect("bytes"),
            "{}",
            case.name
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&through).expect("response"),
            case.expected["response"],
            "{}",
            case.name
        );
    }
}

#[test]
fn an_unparseable_page_address_is_refused_through_the_abi() {
    let request = request("not a URL");
    let native = session_page(&request).expect_err("invalid address");
    let through = call_through_abi(
        engine_session_page,
        &serde_json::to_vec(&request).expect("request"),
    );
    let answer: serde_json::Value = serde_json::from_slice(&through).expect("error payload");
    assert_eq!(answer["error"], native.to_string());
}
