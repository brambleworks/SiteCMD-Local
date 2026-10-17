//! The session ABI answers byte for byte what the native functions answer.

#[path = "support/abi.rs"]
mod abi;

use serde::Deserialize;
use sitecmd_engine::evaluation::{
    evaluate_session, session_page, PageArtifact, RouteDiscoverRequest, RouteFacts, RouteSession,
    SessionPageFacts, SessionPageRequest, SessionRequest, SessionResponse,
};
use sitecmd_engine::header_lines::HeaderLines;
use sitecmd_engine::CheckStatus;
use sitecmd_engine_wasm::{
    engine_route_discover, engine_route_evaluate, engine_route_open, engine_route_plan,
    engine_route_session_page, engine_session_evaluate,
};

const CORPUS: &str = include_str!("../../engine/fixtures/session/golden.json");

/// This thread's route opened on the request's page, its outcomes recorded,
/// and its facts read through the ABI.
fn facts_through_abi(request: &SessionPageRequest, children: usize) -> Vec<u8> {
    let opened = abi::call_json(
        engine_route_open,
        &serde_json::json!({ "page": request.page, "sitemap_children": children }),
    );
    assert!(abi::refusal(&opened).is_none());
    let recorded = abi::call_json(
        engine_route_plan,
        &serde_json::json!({ "probe_outcomes": request.probe_outcomes }),
    );
    assert!(abi::refusal(&recorded).is_none());
    abi::call_json(
        engine_route_session_page,
        &serde_json::json!({ "routes": request.routes }),
    )
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
    pages[1].noindex = Some(true);
    for cause in [
        json!({"cause": "index", "listed": 0}),
        json!({"cause": "url_limit", "listed": SITEMAP_URL_LIMIT - 1}),
        json!({"cause": "unread_declarations", "count": 0}),
    ] {
        let mut input = json!({"pages": pages});
        input["pages"][0]["sitemap"] = json!({"entries": ["r0"], "partial_causes": [cause]});
        let bytes = abi::call(
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
fn an_unknown_noindex_fact_skips_a_sitemap_comparison_through_the_abi() {
    // Defaulting null noindex to false makes an undecided sitemap listing pass.
    let pages = ["https://example.com/", "https://example.com/menu"]
        .map(|url| session_page(&request(url)).expect("facts").expect("named"));
    let mut input = serde_json::json!({"pages": pages});
    input["pages"][0]["sitemap"] = serde_json::json!({"entries": ["r1"], "partial_causes": []});
    for (noindex, expected) in [
        (serde_json::Value::Null, CheckStatus::Skipped),
        (serde_json::json!(true), CheckStatus::Warn),
    ] {
        input["pages"][1]["noindex"] = noindex;
        let bytes = abi::call_json(engine_session_evaluate, &input);
        let answer: SessionResponse = serde_json::from_slice(&bytes).expect("answer");
        assert_eq!(
            answer
                .verdicts
                .iter()
                .find(|verdict| verdict.check_id == "seo.noindex_in_sitemap")
                .expect("verdict")
                .status,
            expected,
        );
    }
}

#[test]
fn a_sitemap_finding_keeps_an_unknown_listing_decline_through_the_abi() {
    // A known contradiction must not hide the decline for an unknown listed page, through the ABI too.
    let mut pages = ["https://example.com/", "https://example.com/menu"]
        .map(|url| session_page(&request(url)).expect("facts").expect("named"));
    pages[0].noindex = Some(true);
    pages[1].noindex = None;
    let mut input = serde_json::json!({"pages": pages});
    input["pages"][0]["sitemap"] =
        serde_json::json!({"entries": ["r0", "r1"], "partial_causes": []});
    let bytes = abi::call_json(engine_session_evaluate, &input);
    let answer: SessionResponse = serde_json::from_slice(&bytes).expect("answer");
    let rows: Vec<_> = answer
        .verdicts
        .iter()
        .filter(|row| row.check_id == "seo.noindex_in_sitemap")
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].status, CheckStatus::Warn);
    assert_eq!(rows[0].pages, [0]);
    assert_eq!(rows[1].status, CheckStatus::Skipped);
    assert!(rows[1].pages.is_empty());
}

#[test]
fn page_facts_and_the_comparison_match_the_native_answers() {
    let mut pages: Vec<SessionPageFacts> = Vec::new();
    for url in ["https://example.com/", "https://example.com/menu"] {
        let native = serde_json::to_vec(
            &serde_json::to_value(session_page(&request(url)).expect("facts")).expect("value"),
        )
        .expect("bytes");
        let through = facts_through_abi(&request(url), 0);
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
    let through = abi::call(
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
    let answer = abi::call(engine_session_evaluate, b"{\"pages\": 3}");
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
    #[serde(default)]
    sitemap_children: usize,
    #[serde(default)]
    discover: Option<RouteDiscoverRequest>,
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
            let mut native = RouteSession::open(request.page.clone())
                .expect("fixture opens")
                .with_sitemap_children(case.sitemap_children);
            native.record(Some(request.probe_outcomes.clone()));
            let native = serde_json::to_value(native.session_page(&case.routes).expect("facts"))
                .expect("value");
            let through = facts_through_abi(&request, case.sitemap_children);
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
        let through = abi::call(
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
    let through = abi::call_json(
        engine_route_open,
        &serde_json::json!({ "page": request.page }),
    );
    assert_eq!(
        abi::refusal(&through).as_deref(),
        Some(native.to_string().as_str())
    );
}

#[test]
fn the_open_frame_preserves_the_joined_header_line_form() {
    // Ignoring the wire's joined value leaves a repeated X-Frame-Options value unrecognized.
    let mut page = request("https://example.com/").page;
    page.headers = vec![("x-frame-options".into(), "DENY, SAMEORIGIN".into())];
    let opened = abi::call_json(
        engine_route_open,
        &serde_json::json!({ "page": page, "header_lines": "joined" }),
    );
    assert!(abi::refusal(&opened).is_none());
    let joined = abi::call_json(engine_route_evaluate, &serde_json::json!({}));
    let native = RouteSession::open_with(page.clone(), HeaderLines::Joined)
        .expect("opens")
        .evaluate(&RouteFacts::default());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&joined).expect("answer"),
        serde_json::to_value(native).expect("native answer")
    );
    abi::open(&page);
    let separate = abi::call_json(engine_route_evaluate, &serde_json::json!({}));
    assert_ne!(joined, separate);
}

#[test]
fn a_joined_robots_scope_serializes_unknown_noindex_as_null() {
    // Omitting unknown noindex must not make an undecided fact disappear from the wire.
    let request = request("https://example.com/");
    let mut page = request.page;
    page.headers = vec![("x-robots-tag".into(), "bingbot: noarchive, noindex".into())];
    let opened = abi::call_json(
        engine_route_open,
        &serde_json::json!({"page": page, "header_lines": "joined"}),
    );
    assert!(abi::refusal(&opened).is_none());
    let bytes = abi::call_json(
        engine_route_session_page,
        &serde_json::json!({"routes": request.routes}),
    );
    let frame: serde_json::Value = serde_json::from_slice(&bytes).expect("frame");
    let native = RouteSession::open_with(page, HeaderLines::Joined)
        .expect("opens")
        .session_page(&request.routes)
        .expect("facts");
    assert_eq!(frame, serde_json::to_value(native).expect("native frame"));
    assert_eq!(frame.get("noindex"), Some(&serde_json::Value::Null));
}

#[test]
fn every_corpus_discovery_survives_the_framed_export() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus");
    let mut discovering = 0;
    for case in corpus.cases {
        let Some(mut discover) = case.discover else {
            continue;
        };
        discovering += 1;
        let entry = case.pages.into_iter().next().expect("entry page");
        let mut native = RouteSession::open(entry.page.clone())
            .expect("opens")
            .with_sitemap_children(case.sitemap_children);
        native.record(Some(entry.probe_outcomes.clone()));
        let opened = abi::call_json(
            engine_route_open,
            &serde_json::json!({ "page": entry.page, "sitemap_children": case.sitemap_children }),
        );
        assert!(abi::refusal(&opened).is_none(), "{}", case.name);
        let recorded = abi::call_json(
            engine_route_plan,
            &serde_json::json!({ "probe_outcomes": entry.probe_outcomes }),
        );
        assert!(abi::refusal(&recorded).is_none(), "{}", case.name);
        let requested_limit = discover.limit;
        for limit in [requested_limit, 1] {
            discover.limit = limit;
            let expected = serde_json::to_value(native.discover(&discover.planned, discover.limit))
                .expect("value");
            let through = abi::call_json(
                engine_route_discover,
                &serde_json::to_value(&discover).expect("request"),
            );
            assert_eq!(
                through,
                serde_json::to_vec(&expected).expect("bytes"),
                "{}",
                case.name
            );
            if limit == requested_limit {
                assert_eq!(expected, case.expected["discovered"], "{}", case.name);
            }
        }
    }
    assert!(discovering > 0, "the corpus holds no discovering case");
}

#[test]
fn a_malformed_discovery_request_is_an_error_frame_not_a_trap() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus");
    let entry = corpus
        .cases
        .into_iter()
        .next()
        .expect("a case")
        .pages
        .into_iter()
        .next()
        .expect("a page");
    abi::open(&entry.page);
    let bytes = abi::call(engine_route_discover, br#"{"limit": "many"}"#);
    assert!(abi::refusal(&bytes).is_some());
}
