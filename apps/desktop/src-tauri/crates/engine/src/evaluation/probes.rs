//! Deterministic probe planning for portable checks.
//!
//! The manifest drives planning, identical requests are deduplicated, and
//! callers repeat plan and execute rounds until no probes remain.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::probe_checks::PROBE_CHECKS;
use super::{
    CheckLayer, EvaluationError, EvaluationRequest, NotEvaluated, NotEvaluatedReason, PlannedCheck,
    MANIFEST,
};
use crate::checks::seo::links::LinkTargets;
use crate::manifest::{HostedLane, RuntimeFact};
use crate::page::PageContext;
use crate::probe::{
    BodyLimit, BodyPolicy, ContentCoding, ProbeFailure, ProbeFailureClass, ProbeMeasure,
    ProbeMethod, ProbeOutcome, ProbeRequest, RedirectPolicy,
};

/// Non-printable separator for collision-resistant probe keys whose fields may
/// contain any printable character.
const KEY_SEPARATOR: char = '\u{1f}';

/// One probe the caller must execute and every manifest check it serves.
/// Exact comparisons use serialized boundary bytes, so this type intentionally
/// does not implement `PartialEq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedProbe {
    /// The identity the caller returns the outcome under. Derived from the
    /// request, so a caller cannot invent one and a check cannot be handed an
    /// answer to a different question.
    pub key: String,
    pub request: ProbeRequest,
    pub checks: Vec<String>,
}

/// One executed probe, keyed back to the plan that asked for it, with what the
/// runtime measured executing it when the request asked for a measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutedProbe {
    pub key: String,
    pub outcome: ProbeOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measure: Option<ProbeMeasure>,
}

impl ExecutedProbe {
    /// An executed probe that measured nothing beyond its outcome.
    pub fn new(key: String, outcome: ProbeOutcome) -> Self {
        Self {
            key,
            outcome,
            measure: None,
        }
    }
}

/// One route's probe plan: what to fetch, which checks that unlocks, and
/// which probe-lane checks this plan cannot speak to at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbePlan {
    /// Manifest contract used to build this plan.
    pub manifest_digest: String,
    /// Every probe still needed, in a stable order.
    pub probes: Vec<PlannedProbe>,
    /// Probe-lane checks this plan can evaluate, including artifact-only verdicts.
    pub planned: Vec<PlannedCheck>,
    /// Every other probe-lane entry, with the reason it produced nothing.
    pub not_planned: Vec<NotEvaluated>,
}

/// Canonical identity for a complete probe request, including body, redirect,
/// and header policies. Header names are case-insensitive; values are not.
pub fn probe_key(request: &ProbeRequest) -> String {
    let method = match request.method {
        ProbeMethod::Get => "get",
        ProbeMethod::Head => "head",
    };
    let body = match request.body {
        BodyPolicy::SuccessOnly => "body=success_only",
        BodyPolicy::Always => "body=always",
        BodyPolicy::None => "body=none",
        BodyPolicy::Count => "body=count",
    };
    let redirects = match request.redirects {
        RedirectPolicy::Follow => "redirects=follow",
        RedirectPolicy::None => "redirects=none",
    };
    let mut key = String::with_capacity(request.url.len() + 48);
    key.push_str(method);
    for field in [request.url.as_str(), body, redirects] {
        key.push(KEY_SEPARATOR);
        key.push_str(field);
    }
    if request.limit == BodyLimit::Sitemap {
        key.push(KEY_SEPARATOR);
        key.push_str("limit=sitemap");
    }
    if request.coding == ContentCoding::Raw {
        key.push(KEY_SEPARATOR);
        key.push_str("coding=raw");
    }
    if let Some(sample) = request.timed {
        key.push(KEY_SEPARATOR);
        key.push_str(&format!("timed={sample}"));
    }
    for (name, value) in &request.headers {
        key.push(KEY_SEPARATOR);
        key.push_str(&name.to_ascii_lowercase());
        key.push('=');
        key.push_str(value);
    }
    key
}

/// Represent a planned but unexecuted probe as a transport failure.
pub fn unexecuted_probe() -> ProbeOutcome {
    ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::Transport,
        detail: "the planned probe was not executed".into(),
    })
}

/// The executed probes, indexed for lookup by request.
pub struct ProbeOutcomes<'a> {
    by_key: HashMap<&'a str, &'a ExecutedProbe>,
}

impl<'a> ProbeOutcomes<'a> {
    /// Index executed probes, keeping the last outcome for duplicate keys.
    pub fn index(executed: &'a [ExecutedProbe]) -> Self {
        let mut by_key = HashMap::with_capacity(executed.len());
        for entry in executed {
            by_key.insert(entry.key.as_str(), entry);
        }
        Self { by_key }
    }

    /// The outcome for one planned request, or `None` when it was not run.
    pub fn get(&self, request: &ProbeRequest) -> Option<&'a ProbeOutcome> {
        self.by_key
            .get(probe_key(request).as_str())
            .copied()
            .map(|entry| &entry.outcome)
    }

    /// Whether a key already has an answer. The plan's own short-circuit:
    /// a probe that came back is never planned again, which is what makes
    /// the caller's loop terminate rather than re-asking forever.
    pub fn answered(&self, key: &str) -> bool {
        self.by_key.contains_key(key)
    }

    /// The outcome for one planned request, with [`unexecuted_probe`] for a
    /// probe the caller never ran.
    pub fn owned(&self, request: &ProbeRequest) -> ProbeOutcome {
        self.get(request).cloned().unwrap_or_else(unexecuted_probe)
    }

    /// What the runtime measured executing one planned request, if anything.
    pub fn measure(&self, request: &ProbeRequest) -> Option<ProbeMeasure> {
        self.by_key
            .get(probe_key(request).as_str())
            .and_then(|entry| entry.measure)
    }
}

/// Everything a probe-lane plan or verdict may read: the document, the answers gathered so far,
/// what the caller recorded asking for, and the kept anchor resolution and asset sample.
/// No client, no clock.
pub struct ProbeContext<'a> {
    pub page: &'a PageContext,
    pub outcomes: &'a ProbeOutcomes<'a>,
    /// Pre-redirect URL, or `None` when this vantage cannot place the walk's start.
    pub requested_url: Option<&'a str>,
    pub resolver_facts: Option<&'a crate::dns::ResolverFacts>,
    pub vulnerability_facts:
        Option<&'a crate::checks::security::vulnerable_libraries::AdvisoryLookup>,
    /// The page's anchor destinations, resolved by the first link planner or
    /// verdict that asks.
    pub link_targets: &'a OnceLock<LinkTargets>,
    /// The asset sample's addresses, resolved by the first asset planner that
    /// asks.
    pub asset_sample: &'a OnceLock<Vec<url::Url>>,
}

/// Probe entries not yet planned by this crate, paired with the required reason.
pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[
    (
        "security.directory_listing",
        "the candidate-path sweep is still planned by the desktop shell",
    ),
    (
        "security.exposed_files.",
        "the candidate-path sweep is still planned by the desktop shell",
    ),
    (
        "security.exposed_files.source_secrets",
        "the candidate-path sweep is still planned by the desktop shell",
    ),
    (
        "security.exposed_files.summary",
        "the candidate-path sweep is still planned by the desktop shell",
    ),
    (
        "security.security_txt",
        "the well-known path sweep is still planned by the desktop shell",
    ),
];

/// The facts a fetch plan can supply. A probe-lane check declaring anything
/// else needs a supplier this call is not, and says so by name rather than
/// planning a fetch that could never answer it.
fn fetch_plan_supplies(fact: RuntimeFact) -> bool {
    matches!(
        fact,
        RuntimeFact::PageArtifact | RuntimeFact::Fetch | RuntimeFact::Rdap
    )
}

/// Manifest id to the index of the probe check that plans it.
pub(super) fn probe_check_index() -> HashMap<&'static str, usize> {
    let mut index = HashMap::new();
    for (position, check) in PROBE_CHECKS.iter().enumerate() {
        for id in check.covers {
            index.insert(*id, position);
        }
    }
    index
}

/// Plan remaining probes for one route from its whole request. Repeat until
/// the plan is empty before calling [`super::evaluate`].
pub fn probe_plan(request: &EvaluationRequest) -> Result<ProbePlan, EvaluationError> {
    let mut route = super::RouteSession::open(request.page.clone())?;
    route.record(request.probe_outcomes.clone());
    Ok(route.plan())
}

pub(super) fn plan_probes(context: &ProbeContext) -> ProbePlan {
    // Probes in check-table order, then in each check's own order, merged by
    // key. `position` is a lookup only: the output order comes from the walk,
    // never from the map.
    let mut probes: Vec<PlannedProbe> = Vec::new();
    let mut position: HashMap<String, usize> = HashMap::new();
    for check in PROBE_CHECKS {
        for request in (check.plan)(context) {
            let key = probe_key(&request);
            // Deduplicate already-answered requests centrally so individual
            // checks can state their complete needs.
            if context.outcomes.answered(&key) {
                continue;
            }
            match position.get(&key) {
                Some(&at) => attach_checks(&mut probes[at].checks, check.covers),
                None => {
                    position.insert(key.clone(), probes.len());
                    probes.push(PlannedProbe {
                        key,
                        request,
                        checks: check.covers.iter().map(|id| (*id).to_string()).collect(),
                    });
                }
            }
        }
    }

    let claimed = probe_check_index();
    let mut planned = Vec::new();
    let mut not_planned = Vec::new();
    for entry in &MANIFEST.entries {
        if entry.hosted != HostedLane::ProbeAdapter {
            continue;
        }
        // The FIRST fact outside the fetch lane, in the order the manifest
        // declares them, so a check needing two of them always names the same
        // one and the plan stays byte-stable across runs.
        if let Some(missing) = entry
            .requires
            .iter()
            .find(|fact| !fetch_plan_supplies(**fact))
        {
            not_planned.push(NotEvaluated {
                check: entry.check.clone(),
                layer: Some(CheckLayer::Transport),
                class: entry.class,
                measurement_unit: entry.measurement_unit,
                scope: entry.scope,
                reason: NotEvaluatedReason::MissingFact { fact: *missing },
            });
        } else if claimed.contains_key(entry.check.as_str()) {
            planned.push(PlannedCheck {
                check: entry.check.clone(),
                layer: CheckLayer::Transport,
                class: entry.class,
                measurement_unit: entry.measurement_unit,
                // Preserve manifest scope so callers can deduplicate expensive
                // origin probes across routes within the same scan.
                scope: entry.scope,
            });
        } else {
            not_planned.push(NotEvaluated {
                check: entry.check.clone(),
                layer: Some(CheckLayer::Transport),
                class: entry.class,
                measurement_unit: entry.measurement_unit,
                scope: entry.scope,
                reason: NotEvaluatedReason::NoRunner,
            });
        }
    }

    ProbePlan {
        manifest_digest: MANIFEST.digest().to_string(),
        probes,
        planned,
        not_planned,
    }
}

/// Add a second claimant's ids to a probe already planned, without
/// duplicating one that is already there.
fn attach_checks(held: &mut Vec<String>, covers: &[&'static str]) {
    for id in covers {
        if !held.iter().any(|already| already == id) {
            held.push((*id).to_string());
        }
    }
}

#[cfg(test)]
#[path = "probes_tests.rs"]
mod tests;
