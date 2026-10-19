//! Unknown robots policies retain only the routes already adopted by the scan.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::checks::seo::robots::{
    evaluate_robots_txt, robots_fetch_from_probe, RobotsTxtFetch,
};
use sitecmd_engine::checks::seo::robots_directives::evaluate_sitemap_in_robots;
use sitecmd_engine::evaluation::{probe_key, ExecutedProbe, RouteSession};
use sitecmd_engine::probe::{ProbeFailure, ProbeFailureClass, ProbeOutcome, ProbeRequest};
use sitecmd_engine::{CheckStatus, IssueConfidence, Severity};

fn keeps_planned(robots: ProbeOutcome) {
    let mut pages = with_sitemap(&["https://example.com/about"]).to_vec();
    pages.push(("https://example.com/robots.txt", robots));
    for planned in [&[][..], &["/kept", "/old/"][..]] {
        assert_eq!(
            discovered(
                artifact(&home("<a href='/public'>Public</a>"), 200, "/"),
                site(&pages),
                planned,
                LIMIT,
            ),
            routes(planned),
            "{planned:?}",
        );
    }
}

#[test]
fn server_errors_and_rate_limits_adopt_no_new_routes() {
    for status in [500, 503, 599, 429] {
        keeps_planned(response(
            &format!("{ORIGIN}/robots.txt"),
            status,
            "text/plain",
            "",
        ));
    }
}

#[test]
fn failed_and_capped_robots_reads_adopt_no_new_routes() {
    for class in [
        ProbeFailureClass::Transport,
        ProbeFailureClass::Timeout,
        ProbeFailureClass::DnsUnresolved,
        ProbeFailureClass::BodyCapExceeded,
    ] {
        keeps_planned(ProbeOutcome::Failure(ProbeFailure {
            class,
            detail: "unread".into(),
        }));
    }
}

#[test]
fn a_success_without_a_readable_body_adopts_no_new_routes() {
    let ProbeOutcome::Response(mut robots) =
        response(&format!("{ORIGIN}/robots.txt"), 200, "text/plain", "")
    else {
        unreachable!()
    };
    robots.body = None;
    keeps_planned(ProbeOutcome::Response(robots));
}

#[test]
fn an_unmade_or_refused_robots_request_keeps_the_plan_unchanged() {
    let mut session =
        RouteSession::open(artifact(&home("<a href='/public'>Public</a>"), 200, "/")).unwrap();
    let planned = vec!["/old/".to_string(), "/kept".to_string()];
    for refused in [false, true] {
        if refused {
            session.record(Some(vec![ExecutedProbe::new(
                probe_key(&ProbeRequest::get(format!("{ORIGIN}/robots.txt"))),
                ProbeOutcome::Failure(ProbeFailure {
                    class: ProbeFailureClass::Transport,
                    detail: "probe_budget_exhausted".into(),
                }),
            )]));
        }
        assert_eq!(session.discover(&planned, 1).routes, Some(planned.clone()));
    }
}

#[test]
fn policies_above_either_parser_limit_adopt_no_new_routes() {
    for directives in [
        "Disallow: /private\n".repeat(8001),
        "Disallow: /private*\n".repeat(401),
    ] {
        keeps_planned(response(
            &format!("{ORIGIN}/robots.txt"),
            200,
            "text/plain",
            &format!("User-agent: *\n{directives}"),
        ));
    }
}

#[test]
fn server_error_rows_carry_the_server_error_copy_and_rate_limits_stay_skipped() {
    for code in [500, 502, 503, 599] {
        let rows = evaluate_robots_txt(&robots_fetch_from_probe(response(
            &format!("{ORIGIN}/robots.txt"),
            code,
            "text/html",
            "",
        )));
        let row = &rows[0];
        assert_eq!(row.status, CheckStatus::Fail);
        assert_eq!(row.severity, Severity::High);
        assert_eq!(row.confidence, IssueConfidence::High);
        assert_eq!(row.confidence_reason, None);
        assert_eq!(row.title, "robots.txt answers a server error");
        assert_eq!(row.description, format!("robots.txt answered HTTP {code}. While it answers a server error, crawlers that follow the robots.txt standard (RFC 9309) treat every page on the site as disallowed, and Google pauses crawling the site."));
        assert_eq!(row.manual_fix.as_deref(), Some("Make /robots.txt answer HTTP 200 with the file, or 404 if the site has no crawl rules. Check the server, CDN or framework route that serves it."));
        assert_eq!(row.why_it_matters.as_deref(), Some("Search engines that follow the robots.txt standard stop crawling the site while robots.txt answers a server error, so new and changed pages are not picked up."));
        assert_eq!(
            row.raw_data,
            Some(
                serde_json::json!({"robots_policy_evaluated": false, "status_code": code, "server_error": true})
            )
        );
    }
    let rows = evaluate_robots_txt(&robots_fetch_from_probe(response(
        &format!("{ORIGIN}/robots.txt"),
        429,
        "text/plain",
        "",
    )));
    assert_eq!(rows[0].status, CheckStatus::Skipped);
    assert_eq!(rows[0].title, "Robots.txt policy not evaluated");
}

#[test]
fn a_challenged_server_error_is_skipped_and_adds_no_routes() {
    let ProbeOutcome::Response(mut robots) =
        response(&format!("{ORIGIN}/robots.txt"), 503, "text/html", "")
    else {
        unreachable!()
    };
    robots
        .headers
        .push(("cf-mitigated".into(), "challenge".into()));
    let outcome = ProbeOutcome::Response(robots);
    keeps_planned(outcome.clone());
    let rows = evaluate_robots_txt(&robots_fetch_from_probe(outcome));
    assert_eq!(rows[0].status, CheckStatus::Skipped);
    assert_eq!(rows[0].title, "Robots.txt policy not evaluated");
}

#[test]
fn the_page_corpus_distinguishes_server_errors_and_rate_limiting() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/checks/golden_probes.json")).unwrap();
    for (name, code, status) in [
        ("server_error_robots_endpoint_fails", 503, CheckStatus::Fail),
        (
            "rate_limited_robots_endpoint_is_not_evaluated",
            429,
            CheckStatus::Skipped,
        ),
    ] {
        let case = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let rows =
            evaluate_robots_txt(&sitecmd_engine::checks::seo::robots::RobotsTxtFetch::Status(code));
        assert_eq!(rows[0].status, status);
        assert_eq!(serde_json::to_value(rows).unwrap(), case["expected"]);
    }
}

fn assert_session_case(name: &str) {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/session/golden.json")).unwrap();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    let page = serde_json::from_value(case["pages"][0]["page"].clone()).unwrap();
    let mut session = RouteSession::open(page).unwrap();
    let outcomes: Vec<ExecutedProbe> =
        serde_json::from_value(case["pages"][0]["probe_outcomes"].clone()).unwrap();
    session.record(Some(outcomes));
    let planned: Vec<String> = serde_json::from_value(case["discover"]["planned"].clone()).unwrap();
    assert_eq!(
        session.discover(&planned, LIMIT).routes,
        Some(planned),
        "{name}"
    );
}

#[test]
fn session_corpus_unanswered_robots_keeps_only_planned_routes() {
    assert_session_case("discovery_keeps_only_planned_routes_when_robots_did_not_answer");
}

#[test]
fn session_corpus_first_scan_with_a_503_adopts_no_routes() {
    assert_session_case("discovery_adopts_none_when_robots_answers_503_on_a_first_scan");
}

#[test]
fn session_corpus_429_keeps_only_planned_routes() {
    assert_session_case("discovery_keeps_only_planned_routes_when_robots_answers_429");
}

fn challenged(status: u16, marker: &str) -> ProbeOutcome {
    let ProbeOutcome::Response(mut robots) =
        response(&format!("{ORIGIN}/robots.txt"), status, "text/html", "")
    else {
        unreachable!()
    };
    robots.body = None;
    robots.headers.push(("cf-mitigated".into(), marker.into()));
    ProbeOutcome::Response(robots)
}

#[test]
fn a_challenged_503_keeps_the_sitemap_directive_status_row() {
    let actual = evaluate_sitemap_in_robots(&robots_fetch_from_probe(challenged(503, "challenge")));
    let expected = evaluate_sitemap_in_robots(&RobotsTxtFetch::Status(503));
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}

#[test]
fn a_challenged_503_keeps_the_robots_http_status_evidence() {
    let rows = evaluate_robots_txt(&robots_fetch_from_probe(challenged(503, "challenge")));
    assert_eq!(rows[0].raw_data.as_ref().unwrap()["status_code"], 503);
}

#[test]
fn a_challenged_403_adopts_no_new_routes() {
    keeps_planned(challenged(403, "challenge"));
}

#[test]
fn challenge_markers_ignore_case_and_surrounding_whitespace() {
    for status in [503, 403] {
        let outcome = challenged(status, " \tChAlLeNgE \t");
        let rows = evaluate_robots_txt(&robots_fetch_from_probe(outcome.clone()));
        assert_eq!(rows[0].status, CheckStatus::Skipped);
        assert_eq!(rows[0].raw_data.as_ref().unwrap()["status_code"], status);
        keeps_planned(outcome);
    }
}

#[test]
fn challenged_non_successes_keep_both_checks_status_rows() {
    for status in [301, 403, 404, 410, 429, 500, 503, 599] {
        let outcome = challenged(status, "challenge");
        let fetch = robots_fetch_from_probe(outcome.clone());
        let mut expected = evaluate_robots_txt(&RobotsTxtFetch::Status(if status >= 500 {
            429
        } else {
            status
        }));
        if status >= 500 {
            expected[0].description = expected[0].description.replace("429", &status.to_string());
            expected[0].raw_data.as_mut().unwrap()["status_code"] = status.into();
        }
        assert_eq!(
            serde_json::to_vec(&evaluate_robots_txt(&fetch)).unwrap(),
            serde_json::to_vec(&expected).unwrap(),
            "{status}"
        );
        assert_eq!(
            serde_json::to_vec(&evaluate_sitemap_in_robots(&fetch)).unwrap(),
            serde_json::to_vec(&evaluate_sitemap_in_robots(&RobotsTxtFetch::Status(status)))
                .unwrap(),
            "{status}"
        );
        assert!(fetch.body().is_none());
        keeps_planned(outcome);
    }
}

#[test]
fn a_final_redirect_without_a_destination_adopts_no_new_routes() {
    keeps_planned(response(
        &format!("{ORIGIN}/robots.txt"),
        302,
        "text/plain",
        "",
    ));
}
