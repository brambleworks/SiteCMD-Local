//! Evaluation contract tests.

use super::*;
use crate::checks::Check;
use crate::manifest::CheckScope;
use crate::vocab::CheckStatus;

fn artifact(body: &str) -> PageArtifact {
    PageArtifact {
        url: "https://example.com/".into(),
        // A route requested and answered without a redirect: recorded, and
        // equal to the url the body came from.
        requested_url: Some("https://example.com/".into()),
        status_code: 200,
        http_version: Some("HTTP/2.0".into()),
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: body.into(),
        // Frozen: a verdict that moved with the wall clock would make these
        // tests fail on a calendar boundary rather than on a code change.
        evaluation_time: "2026-08-05T00:00:00Z"
            .parse()
            .expect("static evaluation time"),
    }
}

fn request(body: &str) -> EvaluationRequest {
    EvaluationRequest {
        page: artifact(body),
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    }
}

#[test]
fn the_resolver_plan_gathers_every_selector_an_spf_include_can_derive() {
    // The plan is authored before the apex TXT answer exists, so it must
    // cover both the common defaults and any provider selector the SPF
    // derivation can later ask for. Planning only the common list left every
    // derived selector ungathered on this path.
    use crate::checks::security::dns_email::dkim;

    let plan = external_fact_plan(
        &artifact("<html><body>hi</body></html>")
            .page_context()
            .expect("artifact converts"),
    );
    let resolver = plan.resolver.expect("a public domain has a resolver plan");
    let planned: Vec<&str> = resolver
        .dkim_txt_names
        .iter()
        .map(|question| question.selector.as_str())
        .collect();

    for selector in dkim::COMMON_SELECTORS {
        assert!(planned.contains(&selector), "{selector} is not planned");
    }
    for selector in dkim::all_provider_selectors() {
        assert!(
            planned.contains(&selector),
            "derivable selector {selector} is not planned"
        );
    }
    assert!(
        resolver
            .dkim_txt_names
            .iter()
            .all(|question| question.name.ends_with("._domainkey.example.com")),
        "every planned selector question names the registrable domain"
    );
}

fn browser_facts() -> BrowserFacts {
    BrowserFacts {
        axe_report: crate::browser::AxeReport {
            violations: Vec::new(),
            passes: vec!["document-title".into()],
            incomplete: Vec::new(),
            inapplicable: Vec::new(),
        },
        core_web_vitals: crate::browser::CoreWebVitals {
            lcp_ms: Some(4_200.0),
            cls: Some(0.03),
            fcp_ms: Some(1_100.0),
            ttfb_ms: Some(320.0),
            observed_long_task_blocking_ms: Some(75.0),
            js_errors: Vec::new(),
            js_error_count: Some(0),
        },
    }
}

fn tls_facts() -> TlsFacts {
    use crate::checks::security::tls::{TlsValidation, TrustAuthority};
    TlsFacts {
        not_before: Some("2026-01-01T00:00:00Z".parse().expect("static not_before")),
        not_after: Some("2027-01-01T00:00:00Z".parse().expect("static not_after")),
        issuer: Some("Example CA".into()),
        subject_names: vec!["example.com".into()],
        protocol: Some("TLSv1.3".into()),
        validation: TlsValidation::valid(TrustAuthority::Webpki),
        facts_observed_at: "2026-08-05T00:00:00Z"
            .parse()
            .expect("static facts_observed_at"),
    }
}

#[test]
fn resolver_facts_execute_the_hosted_dns_checks() {
    let mut wire = serde_json::to_value(request("<html></html>")).expect("request serializes");
    wire["resolver_facts"] = serde_json::json!({
        "domain": "example.com",
        "apex_txt": { "answer": "no_records" },
        "apex_mx": { "answer": "no_records" },
        "dmarc_txt": { "answer": "no_records" },
        "dkim_txt": [],
        "dnskey": { "answer": "no_records" },
        "caa": { "answer": "no_records" },
        "www_cname": { "answer": "no_records" },
        "www_target_addresses": null
    });
    let request: EvaluationRequest = serde_json::from_value(wire).expect("wire request parses");
    let response = evaluate(&request).expect("request evaluates");

    assert!(response.facts_present.contains(&RuntimeFact::Resolver));
    assert!(response
        .planned
        .iter()
        .any(|check| check.check == "security.dns.mx"));
    let mx = response
        .results
        .iter()
        .find(|result| result.check_id == "security.dns.mx")
        .expect("the MX verdict runs");
    assert_eq!(mx.status, CheckStatus::Pass);
}

#[test]
fn vulnerability_facts_execute_the_hosted_library_check() {
    let mut wire = serde_json::to_value(request(
        r#"<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>"#,
    ))
    .expect("request serializes");
    wire["vulnerability_facts"] = serde_json::json!({
        "status": "answered",
        "advisories": []
    });
    let request: EvaluationRequest = serde_json::from_value(wire).expect("wire request parses");
    let response = evaluate(&request).expect("request evaluates");

    assert!(response
        .facts_present
        .contains(&RuntimeFact::VulnerabilityCorpus));
    assert!(response
        .planned
        .iter()
        .any(|check| check.check == "security.vulnerable_libraries"));
    let libraries = response
        .results
        .iter()
        .find(|result| result.check_id == "security.vulnerable_libraries")
        .expect("the library verdict runs");
    assert_eq!(libraries.status, CheckStatus::Pass);
}

#[test]
fn evaluation_requests_the_external_facts_needed_for_the_page() {
    let response = evaluate(&request(
        r#"<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>"#,
    ))
    .expect("request evaluates");
    let wire = serde_json::to_value(response).expect("response serializes");

    assert_eq!(
        wire["external_fact_plan"]["resolver"]["domain"],
        "example.com"
    );
    assert_eq!(
        wire["external_fact_plan"]["vulnerability_queries"][0]["name"],
        "jquery"
    );
    assert_eq!(
        wire["external_fact_plan"]["vulnerability_queries"][0]["version"],
        "3.7.1"
    );
}

fn reason_for<'a>(response: &'a EvaluationResponse, check: &str) -> &'a NotEvaluatedReason {
    &response
        .not_evaluated
        .iter()
        .find(|entry| entry.check == check)
        .unwrap_or_else(|| panic!("'{check}' is reported not-evaluated"))
        .reason
}

// Rule 1: every artifact-lane entry is claimed exactly once, or excluded
// with its reason. A check added to the registry without a runner leaves an
// id here, which is the whole point of naming the exclusions in source.
#[test]
fn every_artifact_lane_entry_is_claimed_once_or_excluded() {
    let manifest = capability_manifest();
    let excluded: Vec<&str> = EXCLUDED_ARTIFACT_CHECKS.iter().map(|(id, _)| *id).collect();
    let claimed: Vec<&str> = artifact_runners()
        .flat_map(|runner| runner.covers.iter().copied())
        .collect();

    let mut unclaimed = Vec::new();
    for entry in &manifest.entries {
        // The cross-page analysis produces session verdicts, once per scan.
        if entry.hosted != HostedLane::Artifact || entry.scope == CheckScope::Session {
            continue;
        }
        let is_claimed = claimed.contains(&entry.check.as_str());
        let is_excluded = excluded.contains(&entry.check.as_str());
        if !is_claimed && !is_excluded {
            unclaimed.push(entry.check.clone());
        }
        assert!(
            !(is_claimed && is_excluded),
            "'{}' is both claimed and excluded; one of the two is a lie",
            entry.check
        );
    }
    assert!(
        unclaimed.is_empty(),
        "artifact-lane checks with no runner and no documented exclusion: {unclaimed:?}"
    );

    for (id, reason) in EXCLUDED_ARTIFACT_CHECKS {
        assert!(!reason.is_empty(), "exclusion '{id}' carries no reason");
    }
}

// Every id RUNNERS, SEO_RUNNERS or PROBE_CHECKS claims, in dispatch order. One list because
// `runner_index` is one map: an id in multiple tables would resolve to whichever
// was inserted last and silently retire the other producer.
fn all_claimed_ids() -> Vec<&'static str> {
    artifact_runners()
        .flat_map(|runner| runner.covers.iter().copied())
        .chain(
            PROBE_CHECKS
                .iter()
                .flat_map(|check| check.covers.iter().copied()),
        )
        .collect()
}

// Two claimants would run one check twice and double every row it emits.
#[test]
fn no_manifest_id_is_claimed_by_two_runners() {
    let mut seen: Vec<&str> = Vec::new();
    for check in all_claimed_ids() {
        assert!(
            !seen.contains(&check),
            "'{check}' is claimed twice across the RUNNERS, SEO_RUNNERS and PROBE_CHECKS tables; its rows would be emitted twice"
        );
        seen.push(check);
    }
}

// An id the manifest does not publish is an observation connect quarantines,
// which costs the whole route's evidence rather than just that row.
#[test]
fn no_runner_claims_an_unpublished_id() {
    let manifest = capability_manifest();
    for check in all_claimed_ids() {
        assert!(
            manifest.entries.iter().any(|entry| entry.check == check),
            "a runner claims '{check}', which has no capability-manifest entry"
        );
    }
}

// The totality claim: every manifest entry lands in exactly one of `planned`
// and `not_evaluated`. This is the test that would fail if a future change
// started filtering entries out of the loop instead of naming them.
#[test]
fn every_manifest_entry_is_planned_or_named_not_evaluated() {
    let manifest = capability_manifest();
    let response = evaluate(&request("<html><body>hi</body></html>")).expect("request evaluates");
    for entry in &manifest.entries {
        let planned = response
            .planned
            .iter()
            .any(|check| check.check == entry.check);
        let excepted = response
            .not_evaluated
            .iter()
            .any(|check| check.check == entry.check);
        assert!(
            planned != excepted,
            "'{}' is planned={planned} not_evaluated={excepted}; it must be exactly one",
            entry.check
        );
    }
    assert_eq!(
        response.planned.len() + response.not_evaluated.len(),
        manifest.entries.len(),
        "the response says something about every entry and nothing else"
    );
}

// Both evaluation partitions retain each manifest entry's declared scope.
#[test]
fn the_partition_reports_each_entry_scope_from_the_manifest() {
    let manifest = capability_manifest();
    let declared = |check: &str| {
        manifest
            .entries
            .iter()
            .find(|entry| entry.check == check)
            .unwrap_or_else(|| panic!("'{check}' is a published manifest entry"))
            .scope
    };
    let mut gathered = request("<html></html>");
    gathered.probe_outcomes = Some(Vec::new());
    let response = evaluate(&gathered).expect("request evaluates");

    let mut planned = Vec::new();
    for row in &response.planned {
        assert_eq!(
            row.scope,
            declared(&row.check),
            "planned '{}' reports the manifest's scope",
            row.check
        );
        planned.push(row.scope);
    }
    let mut excepted = Vec::new();
    for row in &response.not_evaluated {
        assert_eq!(
            row.scope,
            declared(&row.check),
            "not-evaluated '{}' reports the manifest's scope",
            row.check
        );
        excepted.push(row.scope);
    }

    // Both scopes on both sides, so neither loop above is comparing one
    // constant against itself.
    for (side, scopes) in [("planned", planned), ("not_evaluated", excepted)] {
        for scope in [CheckScope::Page, CheckScope::Origin] {
            assert!(
                scopes.contains(&scope),
                "{side} covers at least one {scope:?}-scoped entry"
            );
        }
    }
}

// A check no hosted lane can produce is NAMED. Filtering it out would leave
// a consumer unable to tell it from a check that passed.
#[test]
fn unsupported_checks_are_named_rather_than_omitted() {
    let unsupported = crate::manifest::Entry::new("seo.title")
        .unsupported()
        .resolve();
    let named = partition(&unsupported, &[RuntimeFact::PageArtifact], &runner_index())
        .expect_err("an unsupported entry is never planned");
    assert_eq!(named.reason, NotEvaluatedReason::UnsupportedLane);
    // No producing layer, because there is no producer.
    assert_eq!(named.layer, None);
    let response = evaluate(&request("<html></html>")).expect("request evaluates");
    let reported = response
        .not_evaluated
        .iter()
        .filter(|entry| entry.reason == NotEvaluatedReason::UnsupportedLane)
        .count();
    assert_eq!(
        reported,
        capability_manifest()
            .entries
            .iter()
            .filter(|entry| entry.hosted == HostedLane::Unsupported)
            .count()
    );
}

// A fact the caller could not gather is named BY FACT, so the consumer can
// tell an operational gap (no browser slot) from a transport one.
#[test]
fn a_missing_fact_is_named_by_the_fact_that_is_missing() {
    let response = evaluate(&request("<html></html>")).expect("request evaluates");
    assert_eq!(
        reason_for(&response, "security.https_enforcement"),
        &NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::Fetch
        }
    );
    assert_eq!(
        reason_for(&response, "security.dns.spf"),
        &NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::Resolver
        }
    );
    assert_eq!(
        reason_for(&response, "security.domain_expiry"),
        &NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::Rdap
        }
    );
    assert_eq!(
        reason_for(&response, "accessibility.axe."),
        &NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::Browser
        }
    );
    assert_eq!(
        reason_for(&response, "security.ssl.expiry"),
        &NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::TlsFacts
        }
    );
    // The browser family keeps its layer, so a consumer maps it to a browser
    // exception rather than to a probe failure.
    let axe = response
        .not_evaluated
        .iter()
        .find(|entry| entry.check == "accessibility.axe.")
        .expect("axe family reported");
    assert_eq!(axe.layer, Some(CheckLayer::Browser));
}

// `NoRunner` is a defect state, and the only sanctioned occurrences are the
// documented exclusions. Nothing else may reach it on a page-artifact-only
// request.
#[test]
fn the_only_no_runner_reports_are_the_documented_exclusions() {
    let response = evaluate(&request("<html></html>")).expect("request evaluates");
    let mut reported: Vec<&str> = response
        .not_evaluated
        .iter()
        .filter(|entry| entry.reason == NotEvaluatedReason::NoRunner)
        .map(|entry| entry.check.as_str())
        .collect();
    let mut excluded: Vec<&str> = EXCLUDED_ARTIFACT_CHECKS.iter().map(|(id, _)| *id).collect();
    reported.sort_unstable();
    excluded.sort_unstable();
    assert_eq!(reported, excluded);
}

// Gathering a fact is what makes its checks run. Nothing about the artifact
// changes; only the fact set does.
#[test]
fn supplying_certificate_facts_moves_the_tls_checks_into_the_plan() {
    let mut with_tls = request("<html></html>");
    with_tls.tls_facts = Some(tls_facts());
    let response = evaluate(&with_tls).expect("request evaluates");

    assert_eq!(
        response.facts_present,
        vec![RuntimeFact::PageArtifact, RuntimeFact::TlsFacts]
    );
    for id in [
        "security.ssl.chain",
        "security.ssl.expiry",
        "security.ssl.hostname",
        "security.ssl.protocol",
    ] {
        assert!(
            response.planned.iter().any(|check| check.check == id),
            "'{id}' is planned once its facts arrived"
        );
        assert!(
            response.results.iter().any(|row| row.check_id == id),
            "'{id}' produced a verdict row"
        );
    }
    // A valid, unexpired certificate for the scanned host passes expiry.
    let expiry = response
        .results
        .iter()
        .find(|row| row.check_id == "security.ssl.expiry")
        .expect("expiry row");
    assert_eq!(expiry.status, CheckStatus::Pass);
}

#[test]
fn supplying_browser_facts_runs_every_browser_lane_verdict() {
    let mut gathered = request("<html><title>Example</title></html>");
    gathered.browser_facts = Some(browser_facts());
    let response = evaluate(&gathered).expect("request evaluates");

    assert!(response.facts_present.contains(&RuntimeFact::Browser));
    for id in [
        "accessibility.axe.",
        "performance.cls",
        "performance.fcp",
        "performance.lcp",
        "performance.long_task_blocking",
        "polish.js-errors",
    ] {
        assert!(
            response.planned.iter().any(|check| check.check == id),
            "'{id}' is planned once browser facts arrive"
        );
        assert!(
            response.not_evaluated.iter().all(|check| check.check != id),
            "'{id}' is no longer excepted"
        );
    }
    assert_eq!(
        response
            .results
            .iter()
            .find(|row| row.check_id == "performance.lcp")
            .expect("LCP verdict")
            .status,
        CheckStatus::Fail
    );
    assert!(response
        .results
        .iter()
        .any(|row| row.check_id == "polish.js-errors"));

    let samples: std::collections::HashMap<_, _> = response
        .measurement_samples
        .iter()
        .map(|sample| (sample.check.as_str(), (sample.value, sample.unit)))
        .collect();
    assert_eq!(samples.len(), 4);
    assert_eq!(
        samples.get("performance.lcp"),
        Some(&(4_200.0, MeasurementUnit::Milliseconds))
    );
    assert_eq!(
        samples.get("performance.cls"),
        Some(&(0.03, MeasurementUnit::Ratio))
    );
    assert!(!samples.contains_key("performance.ttfb"));

    for check in &response.planned {
        assert_eq!(
            check.measurement_unit.is_some(),
            check.class == CheckClass::Measurement,
            "{} carries its manifest class and unit",
            check.check
        );
    }
    for check in &response.not_evaluated {
        assert_eq!(
            check.measurement_unit.is_some(),
            check.class == CheckClass::Measurement,
            "{} carries its manifest class and unit",
            check.check
        );
    }
}

// The verdicts are the checks' own, unchanged by the dispatch. A page with an
// unlabeled input fails form labels through `evaluate` exactly as it does
// through `Check::run`.
#[test]
fn verdicts_match_the_direct_check_call() {
    let page = artifact("<html><body><input type=\"text\" name=\"q\"></body></html>");
    let context = page.page_context().expect("artifact converts");
    let direct = crate::checks::accessibility::form_labels::FormLabelsCheck.run(&context);
    let response = evaluate(&EvaluationRequest {
        page,
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    })
    .expect("request evaluates");
    let through_evaluate: Vec<&CheckResult> = response
        .results
        .iter()
        .filter(|row| row.check_id == "accessibility.form_labels")
        .collect();
    assert_eq!(through_evaluate.len(), direct.len());
    for (actual, expected) in through_evaluate.iter().zip(&direct) {
        assert_eq!(
            serde_json::to_value(actual).expect("row serializes"),
            serde_json::to_value(expected).expect("row serializes")
        );
    }
    assert_eq!(direct[0].status, CheckStatus::Fail);
}

// A URL that does not parse is refused as a value. The wasm boundary turns a
// panic into a trap with no message, so a malformed request has to come back
// as data an operator can read.
#[test]
fn a_malformed_request_is_refused_as_data() {
    let mut broken = request("<html></html>");
    broken.page.url = "not a url".into();
    assert_eq!(
        evaluate(&broken).expect_err("a malformed url is refused"),
        EvaluationError::Url
    );

    let mut bad_header = request("<html></html>");
    bad_header.page.headers = vec![("not a header name".into(), "value".into())];
    assert!(matches!(
        evaluate(&bad_header),
        Err(EvaluationError::HeaderName { .. })
    ));
}

// A header value is never echoed back: response headers routinely carry
// session cookies, and an error string is the one place they would escape a
// module that otherwise never persists a header.
#[test]
fn a_refusal_never_echoes_a_header_value() {
    let mut secret = request("<html></html>");
    secret.page.headers = vec![("set-cookie".into(), "session=s3cr3t\u{7f}".into())];
    let error = evaluate(&secret).expect_err("an invalid header value is refused");
    let rendered = error.to_string();
    assert!(rendered.contains("set-cookie"));
    assert!(!rendered.contains("s3cr3t"));
}

// Same request, same bytes. The registry order and the manifest's sorted
// entries are what make this hold; a `HashMap` iteration leaking into either
// would break it.
#[test]
fn identical_requests_produce_identical_responses() {
    let body = "<html><body><img src=\"a.png\"><script src=\"x.js\"></script></body></html>";
    let first = serde_json::to_string(&evaluate(&request(body)).expect("evaluates"))
        .expect("response serializes");
    let second = serde_json::to_string(&evaluate(&request(body)).expect("evaluates"))
        .expect("response serializes");
    assert_eq!(first, second);
}

// The response names the manifest it planned against. Comparing two
// observations under different manifests is exactly what connect refuses,
// and it can only refuse what the producer declared.
#[test]
fn the_response_names_the_manifest_it_planned_against() {
    let response = evaluate(&request("<html></html>")).expect("request evaluates");
    assert_eq!(response.manifest_digest, capability_manifest().digest());
    assert!(!response.manifest_digest.is_empty());
}
