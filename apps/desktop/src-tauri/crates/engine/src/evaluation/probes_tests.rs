//! Probe-plan coverage and identity tests.

use super::*;
use crate::evaluation::{evaluate, PageArtifact};
use crate::manifest::{capability_manifest, CheckScope};
use crate::probe::{ProbeBody, ProbeFailure, ProbeFailureClass, ProbeResponse};
use crate::vocab::{CheckResult, CheckStatus};

// These two state nothing until robots.txt answers with a body or the walk
// finds a sitemap, as on the desktop.
const SILENT_WITHOUT_INPUT: [&str; 2] = ["seo.ai_crawler_blocking", "seo.sitemap_freshness"];

// Page fixture that makes two checks request the same relative privacy path.
const PAGE: &str = concat!(
    "<html><head>",
    "<link rel=\"icon\" href=\"/icon.png\">",
    "<link rel=\"manifest\" href=\"/app.webmanifest\">",
    "</head><body>",
    "<a href=\"privacy\">Notice</a>",
    "<a href=\"https://elsewhere.example/doc\">Doc</a>",
    "</body></html>"
);

fn artifact(body: &str) -> PageArtifact {
    PageArtifact {
        url: "https://example.com/".into(),
        requested_url: Some("http://example.com/".into()),
        status_code: 200,
        http_version: Some("HTTP/2.0".into()),
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: body.into(),
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

// Checks that share one bounded redirect walk.
const REDIRECT_WALK_CHECKS: [&str; 2] = ["performance.redirect_chain", "seo.temporary_redirect"];

fn probe_lane_ids() -> Vec<String> {
    capability_manifest()
        .entries
        .iter()
        .filter(|entry| entry.hosted == HostedLane::ProbeAdapter)
        .map(|entry| entry.check.clone())
        .collect()
}

#[test]
fn the_fetch_adapter_plans_the_rdap_domain_expiry_probe() {
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");

    assert!(
        plan.probes.iter().any(|probe| {
            probe.request.url == "https://rdap.org/domain/example.com"
                && probe.checks == ["security.domain_expiry"]
        }),
        "the hosted fetch adapter must gather the RDAP fact it advertises"
    );
    assert!(
        plan.planned
            .iter()
            .any(|check| check.check == "security.domain_expiry"),
        "domain expiry must be part of the executable probe plan"
    );
}

fn response(status: u16, content_type: Option<&str>, body: Option<&str>) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: String::new(),
        content_type: content_type.map(str::to_string),
        content_length: None,
        headers: match status {
            300..=399 => vec![("location".into(), "https://example.com/".into())],
            _ => Vec::new(),
        },
        body: body.map(|text| ProbeBody {
            text: text.to_string(),
            bytes: text.len(),
            utf8_valid: true,
        }),
    })
}

// Canned transport covering every URL produced for [`PAGE`].
fn execute(planned: &PlannedProbe) -> ProbeOutcome {
    match planned.request.url.as_str() {
        "https://example.com/app.webmanifest" => response(
            200,
            Some("application/manifest+json"),
            Some("{\"name\":\"App\",\"icons\":[{\"src\":\"/i.png\"}]}"),
        ),
        "https://example.com/icon.png" => response(200, Some("image/png"), None),
        // Answers the legal sweep's first candidate AND the same-host link's
        // HEAD, because they are one probe.
        "https://example.com/privacy" => response(404, None, None),
        "https://example.com/privacy-policy" => response(200, None, None),
        "https://example.com/terms" => response(200, None, None),
        "https://elsewhere.example/doc" => response(200, Some("text/html"), None),
        "http://example.com/" | "https://www.example.com/" => response(301, None, None),
        url if url.contains("does-not-exist") => response(404, Some("text/html"), Some("gone")),
        _ => response(200, Some("text/html"), None),
    }
}

// Execute requests against any artifact and transport until no requests
// remain. Returns the request the verdicts are graded from and the round count.
fn drive_to_fixpoint(
    mut evaluation: EvaluationRequest,
    transport: impl Fn(&PlannedProbe) -> ProbeOutcome,
) -> (EvaluationRequest, usize) {
    let mut gathered: Vec<ExecutedProbe> = Vec::new();
    for round in 1..=8 {
        evaluation.probe_outcomes = Some(gathered.clone());
        let plan = probe_plan(&evaluation).expect("the plan builds");
        if plan.probes.is_empty() {
            return (evaluation, round);
        }
        for planned in &plan.probes {
            gathered.push(ExecutedProbe {
                key: planned.key.clone(),
                outcome: transport(planned),
            });
        }
    }
    panic!("the plan never reached a fixpoint; a probe is being planned after it was answered");
}

// Every probe-lane check is planned or explicitly declined.
#[test]
fn every_probe_lane_entry_is_planned_or_named_not_planned() {
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");
    let ids = probe_lane_ids();
    assert!(!ids.is_empty(), "the manifest has probe-lane entries");
    for check in &ids {
        let planned = plan.planned.iter().any(|row| &row.check == check);
        let excepted = plan.not_planned.iter().any(|row| &row.check == check);
        assert!(
            planned != excepted,
            "'{check}' is planned={planned} not_planned={excepted}; it must be exactly one"
        );
    }
    assert_eq!(
        plan.planned.len() + plan.not_planned.len(),
        ids.len(),
        "the plan says something about every probe-lane entry and nothing else"
    );
    assert_eq!(plan.manifest_digest, capability_manifest().digest());
}

// Both planned and unplanned entries inherit scope from the manifest so
// callers can avoid repeating origin-scoped probes for every route.
#[test]
fn the_plan_reports_each_entry_scope_from_the_manifest() {
    let manifest = capability_manifest();
    let declared = |check: &str| {
        manifest
            .entries
            .iter()
            .find(|entry| entry.check == check)
            .unwrap_or_else(|| panic!("'{check}' is a published manifest entry"))
            .scope
    };
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");

    let mut planned = Vec::new();
    for row in &plan.planned {
        assert_eq!(
            row.scope,
            declared(&row.check),
            "planned '{}' reports the manifest's scope",
            row.check
        );
        planned.push(row.scope);
    }
    let mut excepted = Vec::new();
    for row in &plan.not_planned {
        assert_eq!(
            row.scope,
            declared(&row.check),
            "not-planned '{}' reports the manifest's scope",
            row.check
        );
        excepted.push(row.scope);
    }

    // Both scopes on both sides, so neither loop above is comparing one
    // constant against itself.
    for (side, scopes) in [("planned", planned), ("not_planned", excepted)] {
        for scope in [CheckScope::Page, CheckScope::Origin] {
            assert!(
                scopes.contains(&scope),
                "{side} covers at least one {scope:?}-scoped entry"
            );
        }
    }
}

// Name external facts instead of pretending the ordinary fetch adapter supplies them.
#[test]
fn a_fact_no_fetch_supplies_is_named_rather_than_probed() {
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");
    let reason_for = |check: &str| {
        plan.not_planned
            .iter()
            .find(|row| row.check == check)
            .unwrap_or_else(|| panic!("'{check}' is named in the plan"))
            .reason
            .clone()
    };
    assert!(plan
        .planned
        .iter()
        .any(|row| row.check == "security.domain_expiry"));
    assert_eq!(
        reason_for("security.dns.spf"),
        NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::Resolver
        }
    );
    assert_eq!(
        reason_for("security.ssl.expiry"),
        NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::TlsFacts
        }
    );
    assert_eq!(
        reason_for("security.vulnerable_libraries"),
        NotEvaluatedReason::MissingFact {
            fact: RuntimeFact::VulnerabilityCorpus
        }
    );
}

// `NoRunner` in the probe lane is a defect state, and the only sanctioned
// occurrences are the documented exclusions. Nothing else may reach it.
#[test]
fn the_only_unplanned_probe_checks_are_the_documented_exclusions() {
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");
    let mut reported: Vec<&str> = plan
        .not_planned
        .iter()
        .filter(|row| row.reason == NotEvaluatedReason::NoRunner)
        .map(|row| row.check.as_str())
        .collect();
    let mut excluded: Vec<&str> = EXCLUDED_PROBE_CHECKS.iter().map(|(id, _)| *id).collect();
    reported.sort_unstable();
    excluded.sort_unstable();
    assert_eq!(reported, excluded);

    for (id, reason) in EXCLUDED_PROBE_CHECKS {
        assert!(!reason.is_empty(), "exclusion '{id}' carries no reason");
    }
    let claimed: Vec<&str> = PROBE_CHECKS
        .iter()
        .flat_map(|check| check.covers.iter().copied())
        .collect();
    for (id, _) in EXCLUDED_PROBE_CHECKS {
        assert!(
            !claimed.contains(id),
            "'{id}' is both planned and excluded; one of the two is a lie"
        );
    }
}

// Every probe check ID must exist in the published manifest.
#[test]
fn no_probe_check_claims_an_unpublished_id() {
    let ids = probe_lane_ids();
    for check in PROBE_CHECKS {
        for id in check.covers {
            assert!(
                ids.iter().any(|published| published == id),
                "probe check claims '{id}', which the manifest does not publish in the probe lane"
            );
        }
    }
}

// Two checks needing one document produce ONE probe carrying both ids.
// Without this the hosted scanner pays twice for every shared document.
#[test]
fn two_checks_needing_one_document_share_a_single_probe() {
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");
    let shared: Vec<&PlannedProbe> = plan
        .probes
        .iter()
        .filter(|probe| probe.request.url == "https://example.com/privacy")
        .collect();
    assert_eq!(
        shared.len(),
        1,
        "the same request must be planned exactly once, not once per claimant"
    );
    assert_eq!(
        shared[0].checks,
        vec![
            "compliance.privacy_policy".to_string(),
            "seo.broken_links".to_string()
        ],
        "the one probe names every check its answer serves"
    );
}

// Transport policy participates in probe identity.
#[test]
fn the_key_separates_requests_that_differ_only_in_policy() {
    use crate::probe::{BodyPolicy, RedirectPolicy};
    let base = ProbeRequest::get("https://example.com/x");
    assert_ne!(
        probe_key(&base),
        probe_key(&ProbeRequest::head("https://example.com/x"))
    );
    assert_ne!(
        probe_key(&base),
        probe_key(&base.clone().body(BodyPolicy::None))
    );
    assert_ne!(
        probe_key(&base),
        probe_key(&base.clone().redirects(RedirectPolicy::None))
    );
    assert_ne!(
        probe_key(&base),
        probe_key(&base.clone().header("Origin", "https://other.example"))
    );
    // Field names are case-insensitive in HTTP, so two spellings of one
    // header must not fetch the same document twice.
    assert_eq!(
        probe_key(&base.clone().header("Origin", "https://other.example")),
        probe_key(&base.clone().header("origin", "https://other.example"))
    );
    assert_eq!(probe_key(&base), probe_key(&base.clone()));
}

// Identical artifacts produce byte-identical plans. The ABI's determinism
// claim rests on it, and a `HashMap` iteration leaking into the probe order
// would break it.
#[test]
fn identical_artifacts_produce_identical_plans() {
    let first = serde_json::to_string(&probe_plan(&request(PAGE)).expect("the plan builds"))
        .expect("plan serializes");
    let second = serde_json::to_string(&probe_plan(&request(PAGE)).expect("the plan builds"))
        .expect("plan serializes");
    assert_eq!(first, second);
}

#[test]
fn a_request_without_probe_outcomes_answers_as_it_did_before() {
    let evaluated = evaluate(&request(PAGE)).expect("request evaluates");
    let manifest = capability_manifest();
    assert_eq!(evaluated.facts_present, vec![RuntimeFact::PageArtifact]);
    for check in PROBE_CHECKS {
        for id in check.covers {
            assert!(
                !evaluated.planned.iter().any(|row| &row.check == id),
                "'{id}' must not be planned without the fetch fact"
            );
            assert!(
                !evaluated.results.iter().any(|row| &row.check_id == id),
                "'{id}' must produce no verdict row without the fetch fact"
            );
            let reason = &evaluated
                .not_evaluated
                .iter()
                .find(|row| &row.check == id)
                .unwrap_or_else(|| panic!("'{id}' is named not-evaluated"))
                .reason;
            let entry = manifest
                .entries
                .iter()
                .find(|entry| entry.check == *id)
                .unwrap_or_else(|| panic!("'{id}' is published"));
            let expected = entry
                .requires
                .iter()
                .find(|fact| **fact != RuntimeFact::PageArtifact)
                .copied()
                .expect("a probe check requires a runtime fact");
            assert_eq!(reason, &NotEvaluatedReason::MissingFact { fact: expected });
        }
    }
}

// Planning reaches a fixpoint and every covered check receives a verdict.
#[test]
fn executing_the_plan_moves_every_covered_check_to_a_verdict() {
    let (evaluated, rounds) = drive_to_fixpoint(request(PAGE), execute);
    assert!(
        rounds > 1,
        "the sample page exercises a multi-round plan, not a single shot"
    );
    let response = evaluate(&evaluated).expect("request evaluates");
    assert_eq!(
        response.facts_present,
        vec![
            RuntimeFact::PageArtifact,
            RuntimeFact::Fetch,
            RuntimeFact::Rdap
        ]
    );
    for check in PROBE_CHECKS {
        for id in check.covers {
            if !response.planned.iter().any(|row| &row.check == id) {
                assert!(matches!(
                    response
                        .not_evaluated
                        .iter()
                        .find(|row| &row.check == id)
                        .map(|row| &row.reason),
                    Some(NotEvaluatedReason::MissingFact {
                        fact: RuntimeFact::Resolver | RuntimeFact::VulnerabilityCorpus
                    })
                ));
                continue;
            }
            if SILENT_WITHOUT_INPUT.contains(id) {
                continue;
            }
            assert!(
                response.results.iter().any(|row| &row.check_id == id),
                "'{id}' produced a verdict row"
            );
        }
    }
}

#[test]
fn one_shared_answer_is_read_by_each_check_in_its_own_terms() {
    let (evaluated, _) = drive_to_fixpoint(request(PAGE), execute);
    let response = evaluate(&evaluated).expect("request evaluates");
    let row = |id: &str| {
        response
            .results
            .iter()
            .find(|row| row.check_id == id)
            .unwrap_or_else(|| panic!("'{id}' produced a row"))
    };
    // The sweep moved past the 404 and reported the second candidate.
    let privacy = row("compliance.privacy_policy");
    assert_eq!(privacy.status, CheckStatus::Pass);
    assert!(privacy.description.contains("/privacy-policy"));
    // The same 404, confirmed by the GET the second round planned.
    let links = row("seo.broken_links");
    assert_eq!(links.status, CheckStatus::Fail);
    assert!(links.description.contains("404"));
    assert_eq!(row("seo.broken_external_links").status, CheckStatus::Pass);
    assert_eq!(row("config.favicon").status, CheckStatus::Pass);
    assert_eq!(row("config.web_manifest").status, CheckStatus::Pass);
}

// Grade redirects from the requested URL, not the final page URL.
#[test]
fn a_recorded_requested_url_is_what_makes_the_walk_real() {
    // A temporary canonicalization, so the pair reaches two different
    // verdicts off one hop rather than agreeing by accident.
    let temporary = |planned: &PlannedProbe| match planned.request.url.as_str() {
        "http://example.com/" => response(302, None, None),
        _ => execute(planned),
    };
    let (evaluated, _) = drive_to_fixpoint(request(PAGE), temporary);
    let response = evaluate(&evaluated).expect("request evaluates");
    let row = |id: &str| {
        response
            .results
            .iter()
            .find(|row| row.check_id == id)
            .unwrap_or_else(|| panic!("'{id}' produced a row"))
    };

    let chain = row("performance.redirect_chain");
    assert_eq!(chain.status, CheckStatus::Pass);
    let walk = chain.raw_data.as_ref().expect("the chain reports its walk");
    assert_eq!(walk["start_url"], "http://example.com/");
    assert_eq!(
        walk["redirect_count"], 1,
        "a walk seeded from the post-redirect url would have counted zero hops"
    );
    assert_eq!(walk["hops"][0]["from"], "http://example.com/");
    assert_eq!(walk["hops"][0]["to"], "https://example.com/");

    let statuses = row("seo.temporary_redirect");
    assert_eq!(statuses.status, CheckStatus::Warn);
    assert!(statuses.description.contains("HTTP 302"));
}

#[test]
fn without_a_requested_url_neither_redirect_check_reports_no_redirects() {
    let mut unrecorded = request(PAGE);
    unrecorded.page.requested_url = None;

    // Nothing is planned to walk: the plan never asks the transport where
    // `page.url` leads, because that answer would not be about the chain.
    let plan = probe_plan(&unrecorded).expect("the plan builds");
    for id in REDIRECT_WALK_CHECKS {
        assert!(
            !plan
                .probes
                .iter()
                .any(|probe| probe.checks.iter().any(|check| check == id)),
            "'{id}' planned a probe with no recorded url to start the walk from"
        );
        assert!(
            plan.planned.iter().any(|row| row.check == id),
            "'{id}' is planned: a planner exists, so this is a verdict question and not a coverage hole"
        );
    }

    let (evaluated, _) = drive_to_fixpoint(unrecorded, execute);
    let response = evaluate(&evaluated).expect("request evaluates");
    for id in REDIRECT_WALK_CHECKS {
        let row = response
            .results
            .iter()
            .find(|row| row.check_id == id)
            .unwrap_or_else(|| panic!("'{id}' still emits a row"));
        assert_eq!(
            row.status,
            CheckStatus::Skipped,
            "'{id}' graded a walk it could not place the start of: {}",
            row.description
        );
        assert!(
            !row.description.contains("No redirects were observed"),
            "'{id}' reported no redirects about a chain nothing walked"
        );
        assert!(
            !row.description.contains("No canonicalizing redirect"),
            "'{id}' cleared the statuses of a chain nothing walked"
        );
    }
}

// A requested page URL proves a completed no-redirect walk, not absence.
#[test]
fn a_route_that_did_not_redirect_passes_rather_than_declining() {
    let mut direct = request(PAGE);
    direct.page.requested_url = Some(direct.page.url.clone());
    let (evaluated, _) = drive_to_fixpoint(direct, execute);
    let response = evaluate(&evaluated).expect("request evaluates");
    let row = |id: &str| {
        response
            .results
            .iter()
            .find(|row| row.check_id == id)
            .unwrap_or_else(|| panic!("'{id}' produced a row"))
    };

    let chain = row("performance.redirect_chain");
    assert_eq!(chain.status, CheckStatus::Pass);
    assert!(chain.description.contains("No redirects were observed"));
    assert_eq!(
        chain.raw_data.as_ref().expect("the chain reports its walk")["redirect_count"],
        0
    );

    let statuses = row("seo.temporary_redirect");
    assert_eq!(statuses.status, CheckStatus::Pass);
    assert!(statuses
        .description
        .contains("No canonicalizing redirect uses a temporary status"));
}

// Keep planned redirect checks out of the exclusion list.
#[test]
fn the_redirect_walk_checks_are_planned_rather_than_excluded() {
    let claimed: Vec<&str> = PROBE_CHECKS
        .iter()
        .flat_map(|check| check.covers.iter().copied())
        .collect();
    for id in REDIRECT_WALK_CHECKS {
        assert!(
            claimed.contains(&id),
            "'{id}' has a probe check that plans it"
        );
        assert!(
            !EXCLUDED_PROBE_CHECKS
                .iter()
                .any(|(excluded, _)| *excluded == id),
            "'{id}' is excluded and planned at once; one of the two is a lie"
        );
    }
}

// Identical no-follow requests share one exchange across claimants.
#[test]
fn both_redirect_checks_share_one_probe_per_hop() {
    let plan = probe_plan(&request(PAGE)).expect("the plan builds");
    // Found by claimant rather than by url, so this stays a statement about
    // the merge and not about which url the walk happens to start at.
    let hops: Vec<&PlannedProbe> = plan
        .probes
        .iter()
        .filter(|probe| {
            probe
                .checks
                .iter()
                .any(|check| check == REDIRECT_WALK_CHECKS[0])
        })
        .collect();
    assert_eq!(hops.len(), 1, "the walk's next hop is planned exactly once");
    for id in REDIRECT_WALK_CHECKS {
        assert!(
            hops[0].checks.iter().any(|check| check == id),
            "the one probe names '{id}', whose verdict its answer serves"
        );
    }
}

// A probe the caller never ran is never read as evidence. An incomplete run
// has to degrade into "not established", because the alternative is a check
// reporting a clean result for a document nobody fetched.
#[test]
fn an_unexecuted_probe_is_never_graded_as_a_clean_result() {
    let mut incomplete = request(PAGE);
    // The fetch fact is claimed, and nothing was actually gathered.
    incomplete.probe_outcomes = Some(Vec::new());
    let response = evaluate(&incomplete).expect("request evaluates");
    let row = |id: &str| {
        response
            .results
            .iter()
            .find(|row| row.check_id == id)
            .unwrap_or_else(|| panic!("'{id}' produced a row"))
    };
    assert_eq!(row("config.favicon").status, CheckStatus::Skipped);
    assert_eq!(row("config.web_manifest").status, CheckStatus::Skipped);
    assert_eq!(
        row("security.https_enforcement").status,
        CheckStatus::Skipped
    );
    assert_eq!(row("seo.broken_links").status, CheckStatus::Skipped);
    assert_eq!(
        row("compliance.privacy_policy").status,
        CheckStatus::Skipped,
        "an unrun path sweep establishes neither a policy nor its absence"
    );
    assert_eq!(row("compliance.terms").status, CheckStatus::Skipped);
    assert_eq!(row("security.open_redirect").status, CheckStatus::Skipped);

    // And the synthesized outcome says so rather than borrowing a
    // transport's error text, since no transport was involved.
    let ProbeOutcome::Failure(ProbeFailure { class, detail }) = unexecuted_probe() else {
        panic!("an unexecuted probe is a failure outcome");
    };
    assert_eq!(class, ProbeFailureClass::Transport);
    assert!(detail.contains("not executed"));
}

// Every other fixture here is an https page, so the hosted lane's
// HTTPS-availability arm is only reachable from a cleartext one. Without this
// the arm that grades it would be dead code in the suite, and pairing it with
// the downgrade grader (which turns an unanswered probe into a skip) would
// silently stop failing a site served entirely over HTTP.
#[test]
fn a_cleartext_hosted_page_grades_the_https_origin_as_availability() {
    let cleartext = || {
        let mut evaluation = request(PAGE);
        evaluation.page.url = "http://example.com/".into();
        evaluation
    };
    let row = |response: &crate::evaluation::EvaluationResponse| {
        response
            .results
            .iter()
            .find(|row| row.check_id == "security.https_enforcement")
            .expect("https_enforcement produced a row")
            .clone()
    };

    let plan = probe_plan(&cleartext()).expect("the plan builds");
    assert!(
        plan.probes.iter().any(|probe| {
            probe.request.url == "https://example.com/"
                && probe
                    .checks
                    .iter()
                    .any(|check| check == "security.https_enforcement")
        }),
        "a cleartext page must plan the HTTPS origin root, not the HTTP one"
    );

    // HTTPS answers: the missing redirect. The downgrade grader produces the
    // same title for a 200, so the evidence keys are what separate them.
    let (answered, _) = drive_to_fixpoint(cleartext(), execute);
    let answered = row(&evaluate(&answered).expect("request evaluates"));
    assert_eq!(answered.status, CheckStatus::Fail);
    let evidence = answered.raw_data.expect("the verdict carries evidence");
    assert!(
        evidence.get("scanned_over_http").is_some() && evidence.get("https_probe_url").is_some(),
        "graded by the availability grader, got {evidence}"
    );
    assert!(
        evidence.get("http_probe_url").is_none(),
        "the downgrade grader's evidence must not appear here, got {evidence}"
    );

    // HTTPS does not answer: still a Fail, because the cleartext delivery
    // came from the page artifact. The downgrade grader would skip instead.
    let unanswered = |_: &PlannedProbe| {
        ProbeOutcome::Failure(ProbeFailure {
            class: ProbeFailureClass::Transport,
            detail: "connection refused".into(),
        })
    };
    let (silent, _) = drive_to_fixpoint(cleartext(), unanswered);
    let silent = row(&evaluate(&silent).expect("request evaluates"));
    assert_eq!(
        silent.status,
        CheckStatus::Fail,
        "an HTTP-served page must not stop failing because its HTTPS probe went unanswered"
    );
    assert_eq!(
        silent.title,
        "No HTTPS response observed; site served over HTTP"
    );
}

// A lane-wide transport failure emits every row without grading any verdict.
#[test]
fn a_lane_wide_transport_failure_produces_no_probe_lane_verdict() {
    let failure = |_: &PlannedProbe| {
        ProbeOutcome::Failure(ProbeFailure {
            class: ProbeFailureClass::Transport,
            detail: "connection refused".into(),
        })
    };
    let (evaluated, _) = drive_to_fixpoint(request(PAGE), failure);
    let response = evaluate(&evaluated).expect("request evaluates");

    let mut graded = 0;
    for check in PROBE_CHECKS {
        for id in check.covers {
            if !response.planned.iter().any(|row| &row.check == id) {
                continue;
            }
            if SILENT_WITHOUT_INPUT.contains(id) {
                continue;
            }
            assert!(
                response.planned.iter().any(|row| &row.check == id),
                "'{id}' is planned: the fetch fact arrived, so this is a verdict question and not a coverage hole"
            );
            let rows: Vec<&CheckResult> = response
                .results
                .iter()
                .filter(|row| &row.check_id == id)
                .collect();
            assert!(!rows.is_empty(), "'{id}' still emits a row");
            for row in rows {
                assert!(
                    !matches!(
                        row.status,
                        CheckStatus::Pass | CheckStatus::Fail | CheckStatus::Warn
                    ),
                    "'{id}' claimed {:?} from probes that never reached the site: {}",
                    row.status,
                    row.description
                );
                graded += 1;
            }
        }
    }
    assert!(graded >= 13, "the probe lane covers every id it publishes");
}

// A malformed artifact is refused as a value here too. The plan crosses the
// same wasm boundary the evaluation does, where a panic is a trap carrying
// no message.
#[test]
fn a_malformed_request_is_refused_as_data() {
    let mut broken = request(PAGE);
    broken.page.url = "not a url".into();
    assert_eq!(
        probe_plan(&broken).expect_err("a malformed url is refused"),
        EvaluationError::Url
    );
}
