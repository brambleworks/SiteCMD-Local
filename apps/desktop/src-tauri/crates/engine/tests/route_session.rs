//! A route session answers what the whole-request calls answer for the same
//! document and the same probe outcomes, however the outcomes arrive, and it
//! reads the document once.

use sitecmd_engine::evaluation::{
    evaluate, probe_plan, session_page, EvaluationError, EvaluationRequest, ExecutedProbe,
    PageArtifact, PlannedProbe, RouteFacts, RouteSession, SessionPageRequest,
};
use sitecmd_engine::manifest::RuntimeFact;
use sitecmd_engine::probe::{
    ProbeBody, ProbeFailure, ProbeFailureClass, ProbeOutcome, ProbeResponse,
};

const CORPUS: &str = include_str!("../fixtures/checks/golden.json");
const ROUTES: [&str; 2] = ["https://example.com/", "https://example.com/about"];

/// A page whose plan walks robots.txt and a sitemap, probes links on and off
/// the site, and checks a favicon, so most probe planners take a turn.
fn linked_page() -> PageArtifact {
    PageArtifact {
        url: "https://example.com/".into(),
        requested_url: Some("https://example.com/".into()),
        status_code: 200,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: concat!(
            "<html><head><title>Home</title><link rel=\"icon\" href=\"/icon.png\"></head>",
            "<body><a href=\"/about\">About</a><a href=\"/team\">Team</a>",
            "<a href=\"https://elsewhere.example.net/\">Elsewhere</a></body></html>"
        )
        .into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    }
}

fn pages() -> Vec<PageArtifact> {
    let corpus: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
    let mut pages: Vec<PageArtifact> = corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| serde_json::from_value(case["page"].clone()).expect("a page artifact"))
        .collect();
    pages.push(linked_page());
    pages
}

/// Answers a probe by what it asks for: robots.txt declares a sitemap, the
/// sitemap lists the about page, the about page answers, and everything else
/// fails, so the walk, the link checks and the failures each take their turn.
fn answer(planned: &PlannedProbe) -> ProbeOutcome {
    let url = planned.request.url.as_str();
    let (content_type, text) = match url {
        "https://example.com/robots.txt" => (
            "text/plain",
            "User-agent: *\nSitemap: https://example.com/sitemap.xml\n",
        ),
        "https://example.com/sitemap.xml" => (
            "application/xml",
            "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://example.com/about</loc></url></urlset>",
        ),
        "https://example.com/about" => ("text/html", "<html></html>"),
        _ => {
            return ProbeOutcome::Failure(ProbeFailure {
                class: ProbeFailureClass::Transport,
                detail: "network_failure".into(),
            })
        }
    };
    ProbeOutcome::Response(ProbeResponse {
        status: 200,
        final_url: url.into(),
        content_type: Some(content_type.into()),
        content_length: None,
        headers: Vec::new(),
        body: Some(ProbeBody {
            text: text.into(),
            bytes: text.len(),
            utf8_valid: true,
        }),
    })
}

fn whole(page: &PageArtifact, outcomes: Option<Vec<ExecutedProbe>>) -> EvaluationRequest {
    EvaluationRequest {
        page: page.clone(),
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: outcomes,
        browser_facts: None,
    }
}

fn value(serializable: impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(serializable).expect("serializes")
}

#[test]
fn every_call_answers_what_the_whole_request_answers_over_the_same_outcomes() {
    let routes: Vec<String> = ROUTES.iter().map(|route| route.to_string()).collect();
    for page in pages() {
        let mut route = RouteSession::open(page.clone()).expect("the page opens");
        let mut gathered: Vec<ExecutedProbe> = Vec::new();
        let mut fresh: Vec<ExecutedProbe> = Vec::new();
        for _ in 0..24 {
            route.record(Some(std::mem::take(&mut fresh)));
            let plan = route.plan();
            let whole_plan = probe_plan(&whole(&page, Some(gathered.clone()))).expect("plans");
            assert_eq!(value(&plan), value(&whole_plan), "{}", page.url);
            if plan.probes.is_empty() {
                break;
            }
            for planned in &plan.probes {
                let executed = ExecutedProbe::new(planned.key.clone(), answer(planned));
                gathered.push(executed.clone());
                fresh.push(executed);
            }
        }
        route.record(Some(fresh));
        let whole_evaluation = evaluate(&whole(&page, Some(gathered.clone()))).expect("evaluates");
        assert_eq!(
            value(route.evaluate(&RouteFacts::default())),
            value(whole_evaluation),
            "{}",
            page.url
        );
        let whole_facts = session_page(&SessionPageRequest {
            page: page.clone(),
            probe_outcomes: gathered,
            routes: routes.clone(),
        })
        .expect("facts");
        assert_eq!(
            route.session_page(&routes).expect("facts"),
            whole_facts,
            "{}",
            page.url
        );
    }
}

#[test]
fn the_fetch_lane_is_present_once_a_call_carries_outcomes_and_not_before() {
    let mut route = RouteSession::open(linked_page()).expect("opens");
    route.record(None);
    assert_eq!(
        route.evaluate(&RouteFacts::default()).facts_present,
        vec![RuntimeFact::PageArtifact]
    );
    route.record(Some(Vec::new()));
    assert_eq!(
        route.evaluate(&RouteFacts::default()).facts_present,
        vec![
            RuntimeFact::PageArtifact,
            RuntimeFact::Fetch,
            RuntimeFact::Rdap
        ]
    );
}

#[test]
fn opening_answers_the_external_fact_plan_the_evaluation_reads() {
    for page in pages() {
        let mut route = RouteSession::open(page).expect("opens");
        let opened = value(route.opened().external_fact_plan);
        let outcomes: Vec<ExecutedProbe> = route
            .plan()
            .probes
            .iter()
            .map(|planned| ExecutedProbe::new(planned.key.clone(), answer(planned)))
            .collect();
        route.record(Some(outcomes));
        let evaluated = route.evaluate(&RouteFacts::default());
        assert_eq!(opened, value(evaluated.external_fact_plan));
    }
}

#[test]
fn a_page_with_no_address_the_engine_can_read_is_refused_when_it_opens() {
    let mut page = linked_page();
    page.url = "not a url".into();
    assert_eq!(RouteSession::open(page).err(), Some(EvaluationError::Url));
}
