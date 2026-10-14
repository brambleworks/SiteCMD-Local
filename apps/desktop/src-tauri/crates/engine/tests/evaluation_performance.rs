//! The bounded asset sample's and compression probes' requests and the verdicts
//! their answers produce.
//! The timing samples are graded and emitted once for each route.

use sitecmd_engine::evaluation::{
    evaluate, probe_plan, EvaluationRequest, EvaluationResponse, ExecutedProbe, PageArtifact,
};
use sitecmd_engine::manifest::{CheckClass, MeasurementUnit};
use sitecmd_engine::probe::{
    BodyPolicy, ContentCoding, ProbeFailure, ProbeFailureClass, ProbeMeasure, ProbeOutcome,
    ProbeRequest, ProbeResponse,
};
use sitecmd_engine::CheckStatus;

const ORIGIN: &str = "https://example.com";

fn request(body: &str, outcomes: Option<Vec<ExecutedProbe>>) -> EvaluationRequest {
    EvaluationRequest {
        page: PageArtifact {
            url: format!("{ORIGIN}/"),
            requested_url: Some(format!("{ORIGIN}/")),
            status_code: 200,
            http_version: None,
            is_localhost: false,
            is_strict_localhost: false,
            headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
            body: body.into(),
            evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
        },
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: outcomes,
        browser_facts: None,
    }
}

fn answer(status: u16, headers: &[(&str, &str)]) -> ProbeOutcome {
    let named = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| *header == name)
            .map(|(_, value)| (*value).to_string())
    };
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: String::new(),
        content_type: named("content-type"),
        content_length: named("content-length").and_then(|value| value.parse().ok()),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        body: None,
    })
}

fn unanswered() -> ProbeOutcome {
    ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::Transport,
        detail: "connection refused".into(),
    })
}

/// Answer every probe a page's plan asks for, round by round; return the
/// evaluation at the fixpoint and each round's requests.
fn drive(
    body: &str,
    answer: impl Fn(&ProbeRequest) -> (ProbeOutcome, Option<ProbeMeasure>),
) -> (EvaluationResponse, Vec<Vec<ProbeRequest>>) {
    drive_request(request(body, Some(Vec::new())), answer)
}

fn drive_request(
    mut request: EvaluationRequest,
    answer: impl Fn(&ProbeRequest) -> (ProbeOutcome, Option<ProbeMeasure>),
) -> (EvaluationResponse, Vec<Vec<ProbeRequest>>) {
    let mut rounds = Vec::new();
    for _ in 0..40 {
        let plan = probe_plan(&request).expect("plan builds");
        if plan.probes.is_empty() {
            let response = evaluate(&request).expect("evaluates");
            return (response, rounds);
        }
        rounds.push(
            plan.probes
                .iter()
                .map(|probe| probe.request.clone())
                .collect(),
        );
        for probe in plan.probes {
            let (outcome, measure) = answer(&probe.request);
            request
                .probe_outcomes
                .get_or_insert_with(Vec::new)
                .push(ExecutedProbe {
                    key: probe.key,
                    outcome,
                    measure,
                });
        }
    }
    panic!("the plan never reached a fixpoint");
}

fn status(response: &EvaluationResponse, id: &str) -> CheckStatus {
    response
        .results
        .iter()
        .find(|row| row.check_id == id)
        .unwrap_or_else(|| panic!("{id} is graded"))
        .status
}

const ASSETS_PAGE: &str = concat!(
    "<html><head><title>Example home page for the scan</title>",
    "<link rel=\"stylesheet\" href=\"/assets/site-3f9a8c2b1e.css\">",
    "<script src=\"https://cdn.example.net/app.js\"></script>",
    "</head><body><img src=\"/img/hero.jpg\" alt=\"Hero\"><img src=\"/img/gone.png\" alt=\"Gone\">",
    "</body></html>"
);

fn assets_site(request: &ProbeRequest) -> (ProbeOutcome, Option<ProbeMeasure>) {
    match request.url.as_str() {
        "https://example.com/img/hero.jpg" => (
            answer(
                206,
                &[
                    ("content-type", "image/jpeg"),
                    ("content-range", "bytes 0-0/900000"),
                ],
            ),
            None,
        ),
        "https://example.com/assets/site-3f9a8c2b1e.css" => (
            answer(
                200,
                &[
                    ("content-type", "text/css"),
                    ("content-length", "2000"),
                    ("cache-control", "max-age=60"),
                ],
            ),
            None,
        ),
        "https://cdn.example.net/app.js" => (
            answer(200, &[("content-type", "text/javascript")]),
            Some(ProbeMeasure::counted(40_000, false)),
        ),
        _ => (answer(404, &[]), None),
    }
}

#[test]
fn the_first_probes_ask_for_each_sampled_asset_as_a_raw_one_byte_range() {
    let plan = probe_plan(&request(ASSETS_PAGE, Some(Vec::new()))).expect("plan builds");
    let assets: Vec<&ProbeRequest> = plan
        .probes
        .iter()
        .map(|probe| &probe.request)
        .filter(|request| request.body == BodyPolicy::Count)
        .collect();
    let urls: Vec<&str> = assets.iter().map(|request| request.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "https://example.com/img/hero.jpg",
            "https://example.com/img/gone.png",
            "https://cdn.example.net/app.js",
            "https://example.com/assets/site-3f9a8c2b1e.css",
        ]
    );
    for request in assets {
        assert_eq!(request.coding, ContentCoding::Raw);
        assert!(request
            .headers
            .contains(&("range".into(), "bytes=0-0".into())));
    }
}

#[test]
fn the_sample_asks_for_no_more_assets_than_its_limit() {
    let images: String = (0..40)
        .map(|index| format!("<img src=\"/i/{index}.png\" alt=\"\">"))
        .collect();
    let page = format!("<html><body>{images}</body></html>");
    let plan = probe_plan(&request(&page, Some(Vec::new()))).expect("plan builds");
    let asked = plan
        .probes
        .iter()
        .filter(|probe| probe.request.body == BodyPolicy::Count)
        .count();
    assert_eq!(asked, 30);
}

#[test]
fn the_answers_grade_the_sample_as_the_desktop_grades_it() {
    let (response, _) = drive(ASSETS_PAGE, assets_site);
    // Dropping the counted script's measure loses bytes without changing the status.
    let weight = response
        .results
        .iter()
        .find(|row| row.check_id == "performance.asset_weight")
        .expect("weight row");
    assert_eq!(
        weight.raw_data.as_ref().expect("weight data")["measured_asset_bytes"],
        942_000
    );
    assert_eq!(
        status(&response, "performance.asset_weight"),
        CheckStatus::Pass
    );
    assert_eq!(
        status(&response, "performance.broken_images"),
        CheckStatus::Warn
    );
    assert_eq!(
        status(&response, "performance.images.heavy"),
        CheckStatus::Warn
    );
    assert_eq!(
        status(&response, "performance.asset_caching"),
        CheckStatus::Warn
    );
}

#[test]
fn a_sample_nobody_answers_states_no_asset_verdict() {
    let (response, _) = drive(ASSETS_PAGE, |_| (unanswered(), None));
    for id in [
        "performance.asset_weight",
        "performance.broken_images",
        "performance.images.heavy",
        "performance.asset_caching",
    ] {
        assert_eq!(status(&response, id), CheckStatus::Skipped, "{id}");
    }
}

fn compression_site(
    head: (u16, &'static [(&'static str, &'static str)]),
) -> impl Fn(&ProbeRequest) -> (ProbeOutcome, Option<ProbeMeasure>) {
    move |request| {
        let offers = request
            .headers
            .iter()
            .any(|(name, _)| name == "accept-encoding")
            && request.coding == ContentCoding::Raw
            && request.body != BodyPolicy::Count;
        match (offers, request.method) {
            (true, sitecmd_engine::probe::ProbeMethod::Head) => (answer(head.0, head.1), None),
            (true, sitecmd_engine::probe::ProbeMethod::Get) => (answer(200, &[]), None),
            _ => (answer(404, &[]), None),
        }
    }
}

#[test]
fn a_head_that_shows_compression_settles_it_without_a_get() {
    let (response, rounds) = drive(
        "<html></html>",
        compression_site((200, &[("content-encoding", "br")])),
    );
    assert_eq!(
        status(&response, "performance.compression"),
        CheckStatus::Pass
    );
    let gets = rounds
        .iter()
        .flatten()
        .filter(|request| {
            request.coding == ContentCoding::Raw
                && request.method == sitecmd_engine::probe::ProbeMethod::Get
                && request.body == BodyPolicy::None
        })
        .count();
    assert_eq!(gets, 0);
}

#[test]
fn a_head_that_proves_nothing_asks_for_the_get_that_decides() {
    for head in [(405u16, &[][..]), (200, &[("vary", "Accept-Encoding")][..])] {
        let (response, rounds) = drive("<html></html>", compression_site(head));
        assert_eq!(
            status(&response, "performance.compression"),
            CheckStatus::Fail,
            "{head:?}"
        );
        let asked: Vec<&ProbeRequest> = rounds
            .iter()
            .flatten()
            .filter(|request| {
                request.coding == ContentCoding::Raw && request.body != BodyPolicy::Count
            })
            .collect();
        assert_eq!(asked.len(), 2, "{head:?}");
    }
}

#[test]
fn compression_nobody_answers_reads_the_page_header_or_states_nothing() {
    // Ignoring positive page headers makes unanswered compression probes skip.
    let (response, _) = drive("<html></html>", |_| (unanswered(), None));
    assert_eq!(
        status(&response, "performance.compression"),
        CheckStatus::Skipped
    );

    let mut page = request("<html></html>", Some(Vec::new()));
    page.page
        .headers
        .push(("content-encoding".into(), "br".into()));
    let (response, _) = drive_request(page, |_| (unanswered(), None));
    assert_eq!(
        status(&response, "performance.compression"),
        CheckStatus::Pass
    );
}

#[test]
fn the_first_probes_ask_for_two_timed_reads_of_the_page_and_none_of_its_body() {
    // Timing the origin root or requested URL measures a different page or its
    // redirects.
    let mut request = request("<html></html>", Some(Vec::new()));
    request.page.url = "https://example.com/blog/post?id=7".into();
    request.page.requested_url = Some("http://example.com/old-post".into());
    let plan = probe_plan(&request).expect("plan builds");
    let timed: Vec<&ProbeRequest> = plan
        .probes
        .iter()
        .map(|probe| &probe.request)
        .filter(|request| request.timed.is_some())
        .collect();
    assert_eq!(timed.len(), 2);
    assert!(timed.iter().all(
        |request| request.url == "https://example.com/blog/post?id=7"
            && request.body == BodyPolicy::None
    ));
    assert_ne!(timed[0].timed, timed[1].timed);
}

#[test]
fn the_fastest_timing_is_the_routes_sample_and_never_a_lifecycle_row() {
    let (response, _) = drive("<html></html>", |request| match request.timed {
        Some(1) => (answer(200, &[]), Some(ProbeMeasure::timed(310))),
        Some(_) => (answer(500, &[]), Some(ProbeMeasure::timed(120))),
        None => (answer(404, &[]), None),
    });
    let samples: Vec<_> = response
        .measurement_samples
        .iter()
        .filter(|sample| sample.check == "performance.ttfb")
        .collect();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].value, 120.0);
    assert_eq!(samples[0].unit, MeasurementUnit::Milliseconds);
    assert!(response
        .planned
        .iter()
        .any(|row| row.check == "performance.ttfb" && row.class == CheckClass::Measurement));
}

#[test]
fn a_page_that_never_answers_its_timings_has_no_sample() {
    let (response, _) = drive("<html></html>", |_| (unanswered(), None));
    assert!(response
        .measurement_samples
        .iter()
        .all(|sample| sample.check != "performance.ttfb"));
    assert_eq!(status(&response, "performance.ttfb"), CheckStatus::Skipped);
}
