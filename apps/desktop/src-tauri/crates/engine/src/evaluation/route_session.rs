//! One route's evaluation as a session: the document read once into a page
//! context, probe outcomes recorded as they arrive, and every later call
//! reading both, so a caller hands the engine each fact once.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::artifact::facts_in_order;
use super::probes::{plan_probes, ExecutedProbe, ProbeContext, ProbeOutcomes, ProbePlan};
use super::session_facts::{page_facts, SessionPageFacts};
use super::{
    artifact_runners, external_fact_plan, partition, runner_index, BrowserFacts, EvaluationError,
    EvaluationInputs, EvaluationResponse, ExternalFactPlan, PageArtifact, MANIFEST, PROBE_CHECKS,
};
use crate::checks::security::tls::TlsFacts;
use crate::checks::security::vulnerable_libraries::AdvisoryLookup;
use crate::checks::seo::links::LinkTargets;
use crate::dns::ResolverFacts;
use crate::header_lines::{split_probe_lines, HeaderLines};
use crate::page::PageContext;
use crate::probe::ProbeOutcome;
use crate::severity_policy::WebSeverityInput;
use crate::stack::detect_stack;

/// The facts a route's evaluation grades beside the outcomes it recorded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteFacts {
    #[serde(default)]
    pub resolver_facts: Option<ResolverFacts>,
    #[serde(default)]
    pub vulnerability_facts: Option<AdvisoryLookup>,
    #[serde(default)]
    pub tls_facts: Option<TlsFacts>,
    #[serde(default)]
    pub browser_facts: Option<BrowserFacts>,
}

/// What opening a route answers: the external facts its evaluation reads,
/// planned from the document alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteOpened {
    pub external_fact_plan: ExternalFactPlan,
}

/// `engine_route_open`'s request: the route's document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteOpenRequest {
    pub page: PageArtifact,
    /// How the runtime handed over its header lines; the desktop's are separate.
    #[serde(default)]
    pub header_lines: HeaderLines,
}

/// A route call's request: the probe outcomes executed since the previous
/// call. Present, even empty, says the fetch lane ran.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteCall {
    #[serde(default)]
    pub probe_outcomes: Option<Vec<ExecutedProbe>>,
}

/// `engine_route_evaluate`'s request: a route call's outcomes, and the facts
/// the evaluation grades beside them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteEvaluationRequest {
    #[serde(default)]
    pub probe_outcomes: Option<Vec<ExecutedProbe>>,
    #[serde(flatten)]
    pub facts: RouteFacts,
}

/// `engine_route_session_page`'s request: the scan's planned routes,
/// absolute and in plan order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSessionPageRequest {
    pub routes: Vec<String>,
}

/// One route's document, read once, and the probe outcomes recorded for it.
pub struct RouteSession {
    page: PageContext,
    header_lines: HeaderLines,
    requested_url: Option<String>,
    outcomes: Vec<ExecutedProbe>,
    /// Set once a call carries outcomes, even none: that is what says the
    /// fetch lane ran.
    fetched: bool,
    external_fact_plan: ExternalFactPlan,
    /// The page's anchor destinations, resolved by the first link planner or
    /// verdict that asks and read by every later call.
    link_targets: OnceLock<LinkTargets>,
    /// The asset sample's addresses, resolved by the first asset planner that
    /// asks and read by every later call.
    asset_sample: OnceLock<Vec<url::Url>>,
}

impl RouteSession {
    /// Read the document. Refuses an artifact no page context can be built
    /// from, as every call on it would.
    pub fn open(page: PageArtifact) -> Result<Self, EvaluationError> {
        Self::open_with(page, HeaderLines::Separate)
    }

    /// Read the document with the runtime's response header line form.
    pub fn open_with(page: PageArtifact, lines: HeaderLines) -> Result<Self, EvaluationError> {
        let requested_url = page.requested_url.clone();
        let page = page.into_page_context_with(lines)?;
        let external_fact_plan = external_fact_plan(&page);
        Ok(Self {
            page,
            header_lines: lines,
            requested_url,
            outcomes: Vec::new(),
            fetched: false,
            external_fact_plan,
            link_targets: OnceLock::new(),
            asset_sample: OnceLock::new(),
        })
    }

    /// What opening answered.
    pub fn opened(&self) -> RouteOpened {
        RouteOpened {
            external_fact_plan: self.external_fact_plan.clone(),
        }
    }

    /// Record the outcomes executed since the previous call. A later answer
    /// for a key already recorded is the one read, as a whole request's index
    /// keeps the last. A joined session restores each response's field lines.
    pub fn record(&mut self, outcomes: Option<Vec<ExecutedProbe>>) {
        if let Some(mut outcomes) = outcomes {
            if self.header_lines == HeaderLines::Joined {
                for executed in &mut outcomes {
                    if let ProbeOutcome::Response(response) = &mut executed.outcome {
                        split_probe_lines(response);
                    }
                }
            }
            self.fetched = true;
            self.outcomes.extend(outcomes);
        }
    }

    /// How the route's lines were handed over.
    pub fn header_lines(&self) -> HeaderLines {
        self.header_lines
    }

    /// What the probe checks still need, given every outcome recorded.
    pub fn plan(&self) -> ProbePlan {
        let outcomes = ProbeOutcomes::index(&self.outcomes);
        plan_probes(&self.context(&outcomes, &RouteFacts::default()))
    }

    /// The route's evaluation over every outcome recorded and these facts.
    /// Every manifest entry lands in `planned` or `not_evaluated`; lane,
    /// scope, fact, and runner checks are applied in that order.
    pub fn evaluate(&self, facts: &RouteFacts) -> EvaluationResponse {
        let inputs = EvaluationInputs {
            page: &self.page,
            tls_facts: facts.tls_facts.as_ref(),
            browser_facts: facts.browser_facts.as_ref(),
            header_lines: self.header_lines,
        };
        let outcomes = ProbeOutcomes::index(&self.outcomes);
        let probe_context = self.context(&outcomes, facts);
        let present = facts_in_order(
            self.fetched,
            facts.resolver_facts.is_some(),
            facts.tls_facts.is_some(),
            facts.browser_facts.is_some(),
            facts.vulnerability_facts.is_some(),
        );

        let claimed_by = runner_index();
        // Execute each runner once in stable table order for deterministic payloads;
        // artifact runner indexes precede probe indexes.
        let artifact_count = artifact_runners().count();
        let mut ran: Vec<bool> = vec![false; artifact_count + PROBE_CHECKS.len()];
        let mut planned = Vec::new();
        let mut not_evaluated = Vec::new();
        for entry in &MANIFEST.entries {
            match partition(entry, &present, &claimed_by) {
                Ok((check, index)) => {
                    ran[index] = true;
                    planned.push(check);
                }
                Err(omitted) => not_evaluated.push(omitted),
            }
        }

        let mut results = Vec::new();
        for (runner, executed) in artifact_runners().zip(&ran) {
            if *executed {
                results.extend((runner.run)(&inputs));
            }
        }
        let probe_rows = results.len();
        for (check, executed) in PROBE_CHECKS.iter().zip(&ran[artifact_count..]) {
            if *executed {
                results.extend((check.grade)(&probe_context));
            }
        }

        let measurement_samples = crate::measurement::route_samples(
            facts
                .browser_facts
                .as_ref()
                .map(|browser| &browser.core_web_vitals),
            &results[probe_rows..],
        );
        let severity_inputs = results.iter().map(WebSeverityInput::of).collect();
        EvaluationResponse {
            manifest_digest: MANIFEST.digest().to_string(),
            external_fact_plan: self.external_fact_plan.clone(),
            facts_present: present,
            planned,
            results,
            severity_inputs,
            measurement_samples,
            not_evaluated,
            stack: detect_stack(
                &self.page.response_headers,
                &self.page.body,
                self.page.body_lower(),
            ),
        }
    }

    /// The route's contribution to its scan's comparison of pages, or `None` when the
    /// page's own address cannot be named without query material or
    /// credentials.
    pub fn session_page(
        &self,
        routes: &[String],
    ) -> Result<Option<SessionPageFacts>, EvaluationError> {
        let outcomes = ProbeOutcomes::index(&self.outcomes);
        page_facts(
            &self.context(&outcomes, &RouteFacts::default()),
            routes,
            self.header_lines,
        )
    }

    fn context<'a>(
        &'a self,
        outcomes: &'a ProbeOutcomes<'a>,
        facts: &'a RouteFacts,
    ) -> ProbeContext<'a> {
        ProbeContext {
            page: &self.page,
            outcomes,
            requested_url: self.requested_url.as_deref(),
            resolver_facts: facts.resolver_facts.as_ref(),
            vulnerability_facts: facts.vulnerability_facts.as_ref(),
            link_targets: &self.link_targets,
            asset_sample: &self.asset_sample,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_plans_ignore_resolver_and_vulnerability_facts() {
        let linked: PageArtifact = serde_json::from_value(serde_json::json!({
            "url": "https://example.com/",
            "requested_url": "https://example.com/",
            "status_code": 200,
            "headers": [["content-type", "text/html; charset=utf-8"]],
            "body": concat!(
                "<html><head><title>Home</title><link rel=\"icon\" href=\"/icon.png\"></head>",
                "<body><a href=\"/about\">About</a><a href=\"/team\">Team</a>",
                "<a href=\"https://elsewhere.example.net/\">Elsewhere</a></body></html>"
            ),
            "evaluation_time": "2026-08-05T00:00:00Z"
        }))
        .expect("a linked page");
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/checks/golden.json"))
                .expect("corpus parses");
        let pages =
            std::iter::once(linked).chain(corpus["cases"].as_array().expect("cases").iter().map(
                |case| serde_json::from_value(case["page"].clone()).expect("a page artifact"),
            ));
        let facts: RouteFacts = serde_json::from_value(serde_json::json!({
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
        }))
        .expect("route facts parse");
        for page in pages {
            let route = RouteSession::open(page).expect("opens");
            let outcomes = ProbeOutcomes::index(&[]);
            assert_eq!(
                serde_json::to_value(plan_probes(&route.context(&outcomes, &facts)))
                    .expect("plan with facts serializes"),
                serde_json::to_value(route.plan()).expect("route plan serializes"),
                "{}",
                route.page.url
            );
        }
    }

    #[test]
    fn every_call_reads_one_resolution_of_the_page_anchors() {
        let page: PageArtifact = serde_json::from_value(serde_json::json!({
            "url": "https://example.com/",
            "status_code": 200,
            "headers": [],
            "body": "<a href=\"/about\">About</a><a href=\"https://elsewhere.example.net/\">Out</a>",
            "evaluation_time": "2026-08-05T00:00:00Z"
        }))
        .expect("a page");
        let mut route = RouteSession::open(page).expect("opens");
        route.record(Some(Vec::new()));
        route.plan();
        let first = route.link_targets.get().map(std::ptr::from_ref);
        assert!(first.is_some(), "a link planner resolved the anchors");
        route.plan();
        route.evaluate(&RouteFacts::default());
        assert_eq!(route.link_targets.get().map(std::ptr::from_ref), first);
    }

    #[test]
    fn every_call_reads_one_resolution_of_the_asset_sample() {
        let page: PageArtifact = serde_json::from_value(serde_json::json!({
            "url": "https://example.com/",
            "status_code": 200,
            "headers": [],
            "body": "<img src=\"/hero.png\" alt=\"Hero\"><script src=\"/app.js\"></script>",
            "evaluation_time": "2026-08-05T00:00:00Z"
        }))
        .expect("a page");
        let mut route = RouteSession::open(page).expect("opens");
        route.record(Some(Vec::new()));
        route.plan();
        let first = route.asset_sample.get().map(std::ptr::from_ref);
        assert!(first.is_some(), "the asset planner resolved the sample");
        route.plan();
        route.evaluate(&RouteFacts::default());
        assert_eq!(route.asset_sample.get().map(std::ptr::from_ref), first);
    }
}
