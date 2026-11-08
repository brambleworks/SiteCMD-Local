// A hosted route plans a sweep path twice or one per round, grades an unanswered path as exposed, absent or passing, keeps a secret file's content, or plans a request the CLI's shell would not send.

use sitecmd_engine::checks::origin_with_port;
use sitecmd_engine::checks::security::directory_listing::{listing_request, PROBE_DIRS};
use sitecmd_engine::checks::security::exposed_files::{
    sensitive_path_request, source_secrets_result, SENSITIVE_PATHS,
};
use sitecmd_engine::checks::security::security_txt::{
    classify_security_txt_probe, evaluate_well_known, security_txt_request, security_txt_urls,
    SecurityTxtStep, CHECK_ID,
};
use sitecmd_engine::evaluation::ExecutedProbe;
use sitecmd_engine::evaluation::{probe_key, PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::probe::{
    BodyLimit, ProbeBody, ProbeFailure, ProbeFailureClass, ProbeOutcome, ProbeRequest,
    ProbeResponse,
};
use sitecmd_engine::{CheckResult, CheckStatus, Severity};

const ORIGIN: &str = "https://example.com:8443";
const EVALUATION_TIME: &str = "2026-10-30T00:00:00Z";

/// The origin a CLI shell builds its requests from for the route's page.
fn shell_base() -> String {
    origin_with_port(&url::Url::parse(&format!("{ORIGIN}/nested/page")).unwrap())
}

fn route() -> RouteSession {
    route_with("", EVALUATION_TIME)
}

fn route_with(body: &str, evaluation_time: &str) -> RouteSession {
    RouteSession::open(PageArtifact {
        url: format!("{ORIGIN}/nested/page"),
        requested_url: None,
        status_code: 200,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![],
        body: body.into(),
        evaluation_time: evaluation_time.parse().unwrap(),
    })
    .unwrap()
}

fn answer(status: u16, text: &str, content_type: &str) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: format!("{ORIGIN}/.well-known/security.txt"),
        content_type: Some(content_type.into()),
        content_length: Some(text.len() as u64),
        headers: vec![],
        body: Some(ProbeBody {
            text: text.into(),
            bytes: text.len(),
            utf8_valid: true,
        }),
    })
}

fn results(route: &RouteSession) -> Vec<CheckResult> {
    route.evaluate(&RouteFacts::default()).results
}

fn row<'a>(rows: &'a [CheckResult], id: &str) -> &'a CheckResult {
    rows.iter()
        .find(|r| r.check_id == id)
        .unwrap_or_else(|| panic!("missing {id}"))
}

fn record_sweeps(route: &mut RouteSession, outcome: impl Fn(&str) -> ProbeOutcome) {
    let probes = route
        .plan()
        .probes
        .into_iter()
        .filter(|p| p.request.limit == BodyLimit::Sweep)
        .collect::<Vec<_>>();
    assert_eq!(probes.len(), 32);
    for probe in probes {
        route.record(Some(vec![ExecutedProbe::new(
            probe.key,
            outcome(&probe.request.url),
        )]));
    }
}

#[test]
fn every_sweep_path_is_in_the_first_round_with_the_shells_request_key() {
    // Missing paths, wrong policies, repeated keys, or route-relative URLs change the request the shell sends.
    let mut route = route();
    let plan = route.plan();
    let sweep = plan
        .probes
        .iter()
        .filter(|p| p.request.limit == BodyLimit::Sweep)
        .collect::<Vec<_>>();
    assert_eq!(sweep.len(), 32);
    let base = shell_base();
    let shell = SENSITIVE_PATHS
        .iter()
        .map(|(path, _, _)| (*path, sensitive_path_request(&base, path)))
        .chain(
            PROBE_DIRS
                .iter()
                .map(|dir| (*dir, listing_request(&base, dir))),
        );
    for (path, shell_request) in shell {
        let request = ProbeRequest::get(format!("{ORIGIN}{path}")).limit(BodyLimit::Sweep);
        let key = probe_key(&request);
        assert_eq!(probe_key(&shell_request), key, "{path}");
        assert_eq!(sweep.iter().filter(|p| p.key == key).count(), 1, "{path}");
    }
    let (well_url, legacy_url) = security_txt_urls(&base);
    let well = ProbeRequest::get(format!("{ORIGIN}/.well-known/security.txt"));
    let legacy = ProbeRequest::get(format!("{ORIGIN}/security.txt"));
    assert_eq!(
        probe_key(&security_txt_request(&well_url)),
        probe_key(&well)
    );
    assert_eq!(
        probe_key(&security_txt_request(&legacy_url)),
        probe_key(&legacy)
    );
    assert!(plan.probes.iter().any(|p| p.key == probe_key(&well)));
    assert!(!plan.probes.iter().any(|p| p.key == probe_key(&legacy)));
    let recorded = sweep[0].key.clone();
    route.record(Some(vec![ExecutedProbe::new(
        recorded.clone(),
        answer(404, "", "text/plain"),
    )]));
    assert!(!route.plan().probes.iter().any(|p| p.key == recorded));
    route.record(Some(vec![ExecutedProbe::new(
        probe_key(&well),
        answer(404, "", "text/plain"),
    )]));
    assert!(route
        .plan()
        .probes
        .iter()
        .any(|p| p.key == probe_key(&legacy)));
}

#[test]
fn a_large_html_catch_all_is_not_a_file_or_directory_listing() {
    // A SPA shell cannot establish an exposure or silently pass the phpinfo signature mismatch.
    let mut route = route();
    let shell = format!(
        "<html><title>Application</title>{}</html>",
        "x".repeat(400 * 1024)
    );
    record_sweeps(&mut route, |_| answer(200, &shell, "text/html"));
    let rows = results(&route);
    let paths = rows
        .iter()
        .filter(|r| {
            r.check_id.starts_with("security.exposed_files.")
                && r.check_id != "security.exposed_files.summary"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths
            .iter()
            .filter(|r| r.status == CheckStatus::Pass)
            .count(),
        12
    );
    assert_eq!(
        paths
            .iter()
            .filter(|r| r.status == CheckStatus::Skipped)
            .count(),
        1
    );
    let summary = row(&rows, "security.exposed_files.summary");
    assert_eq!(summary.status, CheckStatus::Skipped);
    assert_eq!(summary.raw_data.as_ref().unwrap()["signature_mismatch"], 1);
    assert_eq!(summary.raw_data.as_ref().unwrap()["paths_probed"], 13);
    assert_eq!(
        row(&rows, "security.directory_listing").status,
        CheckStatus::Pass
    );
}

fn assert_no_value(value: &serde_json::Value, secrets: &[String]) {
    match value {
        serde_json::Value::String(text) => {
            for secret in secrets {
                assert!(!text.contains(secret), "secret escaped in a result string");
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                assert_no_value(value, secrets);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                assert_no_value(&serde_json::Value::String(key.clone()), secrets);
                assert_no_value(value, secrets);
            }
        }
        _ => {}
    }
}

#[test]
fn an_env_exposure_keeps_every_value_out_of_every_result_string() {
    // Grading a real configuration file must never retain its values in any result field.
    let mut route = route();
    let values = vec![
        ["unique", "App", "Value", "9462"].concat(),
        ["unique", "Database", "Value", "7831"].concat(),
        ["ghp", "_", "Rq7Lm2Xc9Vb4Nz6Kd1Wf8Hs3Jt5Py0Ug2Ae"].concat(),
    ];
    let body = format!("APP_KEY={}\nDB_PASSWORD={}\n", values[0], values[1]);
    let git_config = format!(
        "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://{}@example.com/repo.git\n",
        values[2]
    );
    record_sweeps(&mut route, |url| {
        if url.ends_with("/.env") {
            answer(200, &body, "text/plain")
        } else if url.ends_with("/.git/config") {
            answer(200, &git_config, "text/plain")
        } else {
            answer(404, "", "text/plain")
        }
    });
    let response = route.evaluate(&RouteFacts::default());
    let env = row(&response.results, "security.exposed_files.env");
    assert_eq!(env.status, CheckStatus::Fail);
    assert_eq!(env.severity, Severity::Critical);
    let config = row(&response.results, "security.exposed_files.gitconfig");
    assert_eq!(config.status, CheckStatus::Fail);
    assert_no_value(&serde_json::to_value(&response).unwrap(), &values);
}

#[test]
fn refused_or_unrecorded_paths_make_both_sweeps_inconclusive() {
    // Budget refusal and missing answers are not negative evidence about exposure.
    for record_refusals in [false, true] {
        let mut route = route();
        let probes = route.plan().probes;
        assert_eq!(
            probes
                .iter()
                .filter(|p| p.request.limit == BodyLimit::Sweep)
                .count(),
            32
        );
        route.record(Some(vec![]));
        for probe in probes
            .into_iter()
            .filter(|p| p.request.limit == BodyLimit::Sweep)
        {
            if probe.request.url.ends_with("/.env") || probe.request.url.ends_with("/images/") {
                if record_refusals {
                    route.record(Some(vec![ExecutedProbe::new(
                        probe.key,
                        ProbeOutcome::Failure(ProbeFailure {
                            class: ProbeFailureClass::Transport,
                            detail: "request budget refused".into(),
                        }),
                    )]));
                }
            } else {
                route.record(Some(vec![ExecutedProbe::new(
                    probe.key,
                    answer(404, "", "text/plain"),
                )]));
            }
        }
        let rows = results(&route);
        assert_eq!(
            row(&rows, "security.exposed_files.env").status,
            CheckStatus::Skipped
        );
        assert_eq!(
            row(&rows, "security.exposed_files.summary").status,
            CheckStatus::Skipped
        );
        let listing = row(&rows, "security.directory_listing");
        assert_eq!(listing.status, CheckStatus::Skipped);
        assert_eq!(listing.title, "Directory listing check incomplete");
        assert_eq!(listing.description, "None of the 18 directories that answered lists its contents, but 1 of the 19 did not answer, so this scan could not rule out a listing there.");
    }
}

#[test]
fn security_txt_uses_the_injected_evaluation_time() {
    // Wall-clock grading or a missing runner would lose the expired RFC 9116 verdict.
    // The file expired before the injected time but is more than a year
    // ahead of the real clock, so the two clocks grade it differently.
    let evaluation_time = "2099-06-01T00:00:00Z";
    let mut route = route_with("", evaluation_time);
    let request = ProbeRequest::get(format!("{ORIGIN}/.well-known/security.txt"));
    assert!(route
        .plan()
        .probes
        .iter()
        .any(|p| p.key == probe_key(&request)));
    let expired = || {
        answer(
            200,
            "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n",
            "text/plain",
        )
    };
    route.record(Some(vec![ExecutedProbe::new(
        probe_key(&request),
        expired(),
    )]));
    let rows = results(&route);
    let result = row(&rows, "security.security_txt");
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.title, "security.txt has expired");
    let SecurityTxtStep::Done(direct) = evaluate_well_known(
        CHECK_ID,
        &shell_base(),
        classify_security_txt_probe(expired()),
        evaluation_time.parse().unwrap(),
    ) else {
        panic!("an answered well-known file needs no legacy probe");
    };
    let planned: Vec<&CheckResult> = rows.iter().filter(|r| r.check_id == CHECK_ID).collect();
    assert_eq!(
        serde_json::to_value(planned).unwrap(),
        serde_json::to_value(&direct).unwrap()
    );
    assert!(!route
        .plan()
        .probes
        .iter()
        .any(|p| p.request.url.ends_with("/security.txt")));
}

#[test]
fn legacy_security_txt_uses_the_injected_evaluation_time() {
    let mut route = route_with("", "2099-06-01T00:00:00Z");
    let (well_known, legacy) = security_txt_urls(ORIGIN);
    let well_known_request = security_txt_request(&well_known);
    let legacy_request = security_txt_request(&legacy);
    assert!(route
        .plan()
        .probes
        .iter()
        .any(|probe| probe.key == probe_key(&well_known_request)));
    route.record(Some(vec![ExecutedProbe::new(
        probe_key(&well_known_request),
        answer(404, "", "text/plain"),
    )]));
    assert!(route
        .plan()
        .probes
        .iter()
        .any(|probe| probe.key == probe_key(&legacy_request)));
    route.record(Some(vec![ExecutedProbe::new(
        probe_key(&legacy_request),
        answer(
            200,
            "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n",
            "text/plain",
        ),
    )]));
    let rows = results(&route);
    let result = row(&rows, "security.security_txt");
    assert_eq!(result.status, CheckStatus::Warn);
    let evidence = result.raw_data.as_ref().expect("security.txt evidence");
    assert_eq!(evidence["location"], "/security.txt");
    assert_eq!(evidence["expired"], true);
    assert!(evidence["validation_issues"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("expired")));
}

#[test]
fn the_hosted_row_reads_secret_names_in_the_page_source() {
    // A row that grades without the page body silently loses the source advisory the hosted count includes.
    let body = "<html><body><script>const conn = config.db_password;</script></body></html>";
    let mut route = route_with(body, EVALUATION_TIME);
    record_sweeps(&mut route, |_| answer(404, "", "text/plain"));
    let rows = results(&route);
    let advisory = rows
        .iter()
        .filter(|r| r.check_id == "security.exposed_files.source_secrets")
        .collect::<Vec<_>>();
    assert_eq!(advisory.len(), 1);
    assert!(!rows
        .iter()
        .any(|r| r.check_id == "security.exposed_files.summary"));
    assert_eq!(
        serde_json::to_value(advisory[0]).unwrap(),
        serde_json::to_value(source_secrets_result(body).expect("an advisory")).unwrap()
    );
}
