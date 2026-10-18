//! One route's evaluation as a session: the document read once into a page
//! context, probe outcomes recorded as they arrive, and every later call
//! reading both, so a caller hands the engine each fact once.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::artifact::facts_in_order;
use super::discovery::{discover, DiscoveryResponse};
use super::origin_reads::found_index;
use super::probes::{
    is_sitemap_child_key, is_sitemap_probe_key, plan_probes, ExecutedProbe, ProbeContext,
    ProbeOutcomes, ProbePlan,
};
use super::session_facts::{page_facts, SessionPageFacts};
use super::sitemap_children::ChildSitemaps;
use super::{
    artifact_runners, external_fact_plan, partition, runner_index, BrowserFacts, EvaluationError,
    EvaluationInputs, EvaluationResponse, ExternalFactPlan, PageArtifact, MANIFEST, PROBE_CHECKS,
};
use crate::checks::origin_with_port;
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
    /// How many of an index sitemap's children the route reads; none unless
    /// the runtime names a number.
    #[serde(default)]
    pub sitemap_children: usize,
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

/// `engine_route_discover`'s request: the routes the scan's plan held after
/// its entry route when it started, as canonical paths, which stand in for
/// pages the walk could not read, and how many routes discovery may add.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDiscoverRequest {
    #[serde(default)]
    pub planned: Vec<String>,
    pub limit: usize,
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
    /// An index sitemap's children this route reads, none unless its runtime
    /// names a limit.
    sitemap_children: ChildSitemaps,
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
            sitemap_children: ChildSitemaps::default(),
            asset_sample: OnceLock::new(),
        })
    }

    /// What opening answered.
    pub fn opened(&self) -> RouteOpened {
        RouteOpened {
            external_fact_plan: self.external_fact_plan.clone(),
        }
    }

    /// Read an index sitemap's children, at most `limit` on the page's origin;
    /// a route reads none unless its runtime asks.
    pub fn with_sitemap_children(mut self, limit: usize) -> Self {
        self.sitemap_children = ChildSitemaps::new(limit);
        self
    }

    /// Record the outcomes executed since the previous call. Except for child
    /// sitemap keys, a later answer for a key already recorded is the one read,
    /// as a whole request's index keeps the last. A child sitemap's first answer
    /// is the one read. A joined session restores each response's field lines.
    /// A child sitemap's answer is kept without its body, once its page addresses are read.
    /// Invalid sitemap encodings retain their byte count and validity flag, without text.
    pub fn record(&mut self, outcomes: Option<Vec<ExecutedProbe>>) {
        if let Some(mut outcomes) = outcomes {
            for executed in &mut outcomes {
                if let ProbeOutcome::Response(response) = &mut executed.outcome {
                    if is_sitemap_probe_key(&executed.key) {
                        if let Some(body) = response.body.as_mut().filter(|body| !body.utf8_valid) {
                            body.text = String::new();
                        }
                    }
                    if self.header_lines == HeaderLines::Joined {
                        split_probe_lines(response);
                    }
                }
            }
            self.fetched = true;
            // A child sitemap's answer is read once and kept as its page
            // addresses, after the walk's own answers in the same call, which
            // are what find its index.
            let (children, others): (Vec<_>, Vec<_>) = outcomes
                .into_iter()
                .partition(|probe| is_sitemap_child_key(&probe.key));
            self.outcomes.extend(others);
            if !children.is_empty() && !self.sitemap_children.knows_index() {
                let outcomes = ProbeOutcomes::index(&self.outcomes);
                if let Some(index) = found_index(&self.context(&outcomes, &RouteFacts::default())) {
                    self.sitemap_children
                        .learn_index(&index, &origin_with_port(&self.page.url));
                }
            }
            for child in children {
                let kept = self.sitemap_children.absorb(child);
                self.outcomes.push(kept);
            }
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

    /// The routes this route's reads discover for its scan (`discovery.rs`):
    /// `routes` is `None` when its document did not answer with a success.
    pub fn discover(&self, planned: &[String], limit: usize) -> DiscoveryResponse {
        let outcomes = ProbeOutcomes::index(&self.outcomes);
        discover(
            &self.context(&outcomes, &RouteFacts::default()),
            planned,
            limit,
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
            sitemap_children: &self.sitemap_children,
            asset_sample: &self.asset_sample,
        }
    }
}

#[cfg(test)]
#[path = "route_session_tests.rs"]
mod tests;
