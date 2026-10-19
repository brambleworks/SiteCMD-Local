//! Session corpus inputs and native replay helpers.

use serde::{Deserialize, Serialize};
use sitecmd_engine::evaluation::{
    evaluate_session, DiscoveryResponse, ExecutedProbe, PageArtifact, RouteDiscoverRequest,
    RouteSession, SessionPageFacts, SessionRequest, SessionResponse,
};

#[derive(Deserialize)]
pub(super) struct Corpus {
    pub(super) cases: Vec<Case>,
}

#[derive(Deserialize)]
pub(super) struct Case {
    pub(super) name: String,
    pub(super) routes: Vec<String>,
    pub(super) pages: Vec<CasePage>,
    #[serde(default)]
    pub(super) sitemap_children: usize,
    #[serde(default)]
    pub(super) discover: Option<RouteDiscoverRequest>,
    #[serde(default)]
    pub(super) orphan_skip_reason: Option<String>,
    pub(super) expected: Option<Expected>,
}

#[derive(Deserialize)]
pub(super) struct CasePage {
    pub(super) page: PageArtifact,
    #[serde(default)]
    pub(super) probe_outcomes: Vec<ExecutedProbe>,
}

#[derive(Deserialize, Serialize)]
pub(super) struct Expected {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) discovered: Option<DiscoveryResponse>,
    pub(super) facts: Vec<Option<SessionPageFacts>>,
    pub(super) response: SessionResponse,
}

/// One page's route session, opened with the case's child limit and every
/// outcome recorded at once, as the stateless calls record them.
fn route(case: &Case, input: &CasePage) -> RouteSession {
    let mut route = RouteSession::open(input.page.clone())
        .expect("fixture opens")
        .with_sitemap_children(case.sitemap_children);
    route.record(Some(input.probe_outcomes.clone()));
    route
}

pub(super) fn run_case(case: &Case) -> Expected {
    let facts: Vec<_> = case
        .pages
        .iter()
        .map(|input| {
            route(case, input)
                .session_page(&case.routes)
                .expect("fixture builds facts")
        })
        .collect();
    let response = evaluate_session(&SessionRequest {
        pages: facts.iter().flatten().cloned().collect(),
    });
    let discovered = case
        .discover
        .as_ref()
        .map(|discover| route(case, &case.pages[0]).discover(&discover.planned, discover.limit));

    Expected {
        discovered,
        facts,
        response,
    }
}

fn native_case(case: &Case) -> sitecmd_engine::session::SessionAnalysis {
    use sitecmd_engine::checks::seo::sitemap::parse_sitemap_document;
    use sitecmd_engine::probe::ProbeOutcome;
    use sitecmd_engine::session::signals::extract_page_signals_with_headers;
    use sitecmd_engine::session::{analyze_session, SessionSitemap};

    let pages: Vec<_> = case
        .pages
        .iter()
        .map(|input| {
            extract_page_signals_with_headers(
                &url::Url::parse(&input.page.url).expect("page URL"),
                &url::Url::parse(
                    input
                        .page
                        .requested_url
                        .as_deref()
                        .unwrap_or(&input.page.url),
                )
                .expect("requested URL"),
                input.page.status_code,
                &input.page.body,
                &http::HeaderMap::new(),
            )
            .session_page()
        })
        .collect();
    let urls: Vec<_> = case.pages[0]
        .probe_outcomes
        .iter()
        .filter_map(|probe| {
            let ProbeOutcome::Response(response) = &probe.outcome else {
                return None;
            };
            response
                .body
                .as_ref()
                .map(|body| parse_sitemap_document(&body.text).locs().to_vec())
        })
        .flatten()
        .collect();
    analyze_session(
        &pages,
        Some(SessionSitemap {
            urls: &urls,
            partial_because: None,
        }),
    )
}

pub(super) fn assert_orphan_skip_reason(case: &Case) {
    let analysis = native_case(case);
    let orphan = analysis
        .verdicts
        .iter()
        .find(|v| v.result.check_id == "seo.orphan_pages")
        .expect("orphan outcome");
    assert_eq!(
        Some(&orphan.result.description),
        case.orphan_skip_reason.as_ref()
    );
}

pub(super) fn assert_native_matches(case: &Case, actual: &Expected) {
    let native = native_case(case);
    for row in &actual.response.verdicts {
        let found = native
            .verdicts
            .iter()
            .find(|v| v.result.check_id == row.check_id)
            .expect("native verdict");
        assert_eq!(
            (found.result.status, found.result.severity, &found.pages),
            (row.status, row.severity, &row.pages),
            "{}: {}",
            case.name,
            row.check_id
        );
    }
}
