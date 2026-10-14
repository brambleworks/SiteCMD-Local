//! Portable evaluation with explicit outcomes for every manifest entry.

mod artifact;
mod inputs;
mod origin_reads;
mod probe_checks;
mod probe_dns;
mod probes;
mod route_session;
mod runners;
mod runners_seo;
mod session_eval;
mod session_facts;

pub use artifact::{EvaluationError, PageArtifact};
pub use inputs::EvaluationInputs;
pub use probe_checks::{ProbeCheck, PROBE_CHECKS};
pub use probes::{
    probe_key, probe_plan, unexecuted_probe, ExecutedProbe, PlannedProbe, ProbeContext,
    ProbeOutcomes, ProbePlan, EXCLUDED_PROBE_CHECKS,
};
pub use route_session::{
    RouteCall, RouteEvaluationRequest, RouteFacts, RouteOpenRequest, RouteOpened, RouteSession,
    RouteSessionPageRequest,
};
pub use runners::{Runner, RUNNERS};
pub use runners_seo::{EXCLUDED_ARTIFACT_CHECKS, SEO_RUNNERS};
pub use session_eval::{evaluate_session, SessionRequest, SessionResponse, SessionVerdictRow};
pub use session_facts::{
    session_page, SessionPageFacts, SessionPageRequest, SessionSitemapCause, SessionSitemapFacts,
    ELSEWHERE,
};

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::browser::{AxeReport, CoreWebVitals};
use crate::checks::security::tls::TlsFacts;
use crate::checks::security::vulnerable_libraries::{
    detect_libraries, AdvisoryLookup, DetectedLibrary,
};
use crate::dns::{DkimSelectorQuestion, ResolverFacts, ResolverPlan};
use crate::manifest::{
    capability_manifest, CapabilityManifest, CheckClass, CheckScope, HostedLane, ManifestEntry,
    MeasurementUnit, RuntimeFact,
};
use crate::page::PageContext;
use crate::severity_policy::WebSeverityInput;
use crate::stack::DetectedStack;
use crate::vocab::CheckResult;

/// Cached because hosted evaluation reuses this digest on every route.
static MANIFEST: LazyLock<CapabilityManifest> = LazyLock::new(capability_manifest);

/// Facts gathered for one route.
/// Optional-field presence is authoritative; the evaluation derives
/// coverage from the payload so callers cannot claim facts they did not send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub page: PageArtifact,
    /// Normalized answers from the runtime's resolver adapter.
    #[serde(default)]
    pub resolver_facts: Option<ResolverFacts>,
    /// Result of querying the runtime's vulnerability corpus for the exact
    /// library versions detected in `page`.
    #[serde(default)]
    pub vulnerability_facts: Option<AdvisoryLookup>,
    /// Certificate facts from whichever adapter captured them (the desktop's
    /// rustls handshake, or CDP during a hosted browser navigation).
    #[serde(default)]
    pub tls_facts: Option<TlsFacts>,
    /// Executed [`probe_plan`] outcomes. `None` means probes were not gathered;
    /// an empty list means the plan ran and required no fetches.
    #[serde(default)]
    pub probe_outcomes: Option<Vec<ExecutedProbe>>,
    /// Facts gathered inside one real browser navigation. Axe and the
    /// performance sample travel together because the hosted runner captures
    /// them from the same isolated page context and the desktop already grades
    /// both from that one navigation.
    #[serde(default)]
    pub browser_facts: Option<BrowserFacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFacts {
    pub axe_report: AxeReport,
    pub core_web_vitals: CoreWebVitals,
}

/// Manifest layer derived from the runner lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckLayer {
    Transport,
    Browser,
}

impl CheckLayer {
    /// The layer a lane produces, or `None` for a check no hosted lane can
    /// produce: an unsupported check has no layer because it has no producer.
    pub fn of(lane: HostedLane) -> Option<Self> {
        match lane {
            HostedLane::Artifact | HostedLane::ProbeAdapter => Some(Self::Transport),
            HostedLane::Browser => Some(Self::Browser),
            HostedLane::Unsupported => None,
        }
    }
}

/// One check this evaluation set out to produce. The caller turns this into
/// its planned set, so an exception can name a pair even when the check
/// emitted no row at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedCheck {
    pub check: String,
    pub layer: CheckLayer,
    /// Whether this entry participates in finding lifecycle. Consumers must
    /// route measurement entries to samples and keep them out of occurrences,
    /// covered pairs, and absence resolution.
    pub class: CheckClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_unit: Option<MeasurementUnit>,
    /// Manifest scope carried with the entry so consumers can deduplicate origin
    /// work without maintaining a second check table.
    pub scope: CheckScope,
}

/// Structured reason a manifest entry produced no evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotEvaluatedReason {
    /// The check declares a runtime fact this request did not carry. The
    /// fact is named so the consumer can distinguish an operational gap
    /// (no browser slot) from a transport one (no probe answer).
    MissingFact { fact: RuntimeFact },
    /// The manifest's own answer: no hosted lane can produce this check.
    /// Reported rather than filtered out, because a consumer that never
    /// hears about the check cannot tell it apart from one that passed.
    UnsupportedLane,
    /// A cross-page check: no single route's evaluation can produce it, and
    /// [`evaluate_session`] grades it once over the scan's pages.
    SessionScope,
    /// The lane and the facts both check out and no runner claims the check.
    /// A defect unless the id appears in `EXCLUDED_ARTIFACT_CHECKS` or
    /// `EXCLUDED_PROBE_CHECKS` with its reason; the registry tests fail on
    /// any other occurrence.
    NoRunner,
}

/// One manifest entry that produced no evaluation, with why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotEvaluated {
    pub check: String,
    /// `None` for an unsupported check, which has no producing layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<CheckLayer>,
    pub class: CheckClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_unit: Option<MeasurementUnit>,
    /// Required manifest scope, even when no execution layer supports the check.
    pub scope: CheckScope,
    #[serde(flatten)]
    pub reason: NotEvaluatedReason,
}

/// Engine-owned measurement and unit before runtime route attribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationMeasurement {
    pub check: String,
    pub value: f64,
    pub unit: MeasurementUnit,
}

/// One route's verdicts, execution claims, and omissions. Exact comparisons
/// use serialized boundary bytes, so this type intentionally lacks `PartialEq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResponse {
    /// Manifest this evaluation was planned against.
    pub manifest_digest: String,
    /// Runtime work that cannot be expressed as an ordinary HTTP page probe.
    /// The engine authors every queried name and package so adapters never
    /// duplicate registrable-domain or library-detection logic.
    pub external_fact_plan: ExternalFactPlan,
    /// The facts the request carried, derived from the request itself.
    pub facts_present: Vec<RuntimeFact>,
    /// Every check whose facts were present and whose runner executed.
    pub planned: Vec<PlannedCheck>,
    /// Runner-ordered verdicts; skipped results remain coverage exceptions.
    pub results: Vec<CheckResult>,
    /// Severity inputs aligned with `results`, so consumers apply the policy
    /// without reading a verdict's raw data.
    pub severity_inputs: Vec<WebSeverityInput>,
    /// Measurement-class observations. These never imply a lifecycle verdict,
    /// even though the same engine may also grade the value for a local UI.
    #[serde(default)]
    pub measurement_samples: Vec<EvaluationMeasurement>,
    /// Every other manifest entry, with the reason it produced nothing.
    pub not_evaluated: Vec<NotEvaluated>,
    /// The stack this document shows, from the detector the desktop runs.
    pub stack: DetectedStack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalFactPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<ResolverPlan>,
    #[serde(default)]
    pub vulnerability_queries: Vec<DetectedLibrary>,
}

fn external_fact_plan(page: &PageContext) -> ExternalFactPlan {
    use crate::checks::security::dns_email::{
        dangling_cname, dkim, dmarc, registrable_domain_for_url, DomainTarget,
    };

    let resolver = match registrable_domain_for_url(&page.url) {
        DomainTarget::LocalOrIp => None,
        DomainTarget::Registrable(domain) => Some(ResolverPlan {
            apex_address_name: domain.clone(),
            apex_txt_name: domain.clone(),
            apex_mx_name: domain.clone(),
            dmarc_txt_name: dmarc::dmarc_lookup_name(&domain),
            // This plan is authored before any DNS answer exists, so it
            // cannot know which provider the domain's SPF record names. It
            // gathers the common defaults plus every selector an SPF include
            // could derive, so the sweep that runs after the apex TXT answer
            // resolves against facts that were actually fetched. Planning only
            // the common list would make each derived selector come back as
            // "not gathered", which reads as a failed probe and leaves the
            // false warn this derivation exists to remove.
            dkim_txt_names: dkim::COMMON_SELECTORS
                .iter()
                .copied()
                .chain(dkim::all_provider_selectors())
                .map(|selector| DkimSelectorQuestion {
                    selector: selector.to_string(),
                    name: dkim::selector_lookup_name(selector, &domain),
                })
                .collect(),
            dnskey_name: domain.clone(),
            caa_name: domain.clone(),
            www_cname_name: dangling_cname::www_lookup_name(&domain),
            domain,
        }),
    };
    ExternalFactPlan {
        resolver,
        vulnerability_queries: detect_libraries(&page.body),
    }
}

fn browser_measurement_samples(facts: Option<&BrowserFacts>) -> Vec<EvaluationMeasurement> {
    let Some(facts) = facts else {
        return Vec::new();
    };
    crate::measurement::from_browser_vitals(&facts.core_web_vitals)
        .into_iter()
        .map(|sample| EvaluationMeasurement {
            check: sample.check.to_string(),
            value: sample.value,
            unit: sample.unit,
        })
        .collect()
}

/// Evaluate one route from its whole request: a route session opened on its
/// page, with every outcome recorded at once.
pub fn evaluate(request: &EvaluationRequest) -> Result<EvaluationResponse, EvaluationError> {
    let mut route = RouteSession::open(request.page.clone())?;
    route.record(request.probe_outcomes.clone());
    Ok(route.evaluate(&RouteFacts {
        resolver_facts: request.resolver_facts.clone(),
        vulnerability_facts: request.vulnerability_facts.clone(),
        tls_facts: request.tls_facts.clone(),
        browser_facts: request.browser_facts.clone(),
    }))
}

/// Where one manifest entry lands: planned, with the runner index that
/// produces it, or named with the reason it produced nothing. Lane, scope, fact, and
/// runner checks are applied in that order.
fn partition(
    entry: &ManifestEntry,
    facts: &[RuntimeFact],
    claimed_by: &HashMap<&'static str, usize>,
) -> Result<(PlannedCheck, usize), NotEvaluated> {
    let layer = CheckLayer::of(entry.hosted);
    // Preserve manifest scope directly through every partition branch.
    let omitted = |reason| NotEvaluated {
        check: entry.check.clone(),
        layer,
        class: entry.class,
        measurement_unit: entry.measurement_unit,
        scope: entry.scope,
        reason,
    };
    if entry.hosted == HostedLane::Unsupported {
        return Err(omitted(NotEvaluatedReason::UnsupportedLane));
    }
    if entry.scope == CheckScope::Session {
        return Err(omitted(NotEvaluatedReason::SessionScope));
    }
    // The FIRST missing fact, in the order the manifest declares them, so a
    // check needing two absent facts always names the same one and the
    // response stays byte-stable across runs.
    if let Some(missing) = entry.requires.iter().find(|fact| !facts.contains(*fact)) {
        return Err(omitted(NotEvaluatedReason::MissingFact { fact: *missing }));
    }
    let Some(&index) = claimed_by.get(entry.check.as_str()) else {
        return Err(omitted(NotEvaluatedReason::NoRunner));
    };
    Ok((
        PlannedCheck {
            check: entry.check.clone(),
            // A planned check always has a producing layer: the only lane
            // without one is Unsupported, which returned above.
            layer: layer.unwrap_or(CheckLayer::Transport),
            class: entry.class,
            measurement_unit: entry.measurement_unit,
            scope: entry.scope,
        },
        index,
    ))
}

/// Every artifact runner in response order: the shared table, then the SEO
/// table beside it.
fn artifact_runners() -> impl Iterator<Item = &'static Runner> {
    RUNNERS.iter().chain(SEO_RUNNERS)
}

/// Maps manifest ids to the runner indexes used by `ran`, with artifact
/// runners followed by probe runners.
fn runner_index() -> HashMap<&'static str, usize> {
    let mut index = HashMap::new();
    for (position, runner) in artifact_runners().enumerate() {
        for check in runner.covers {
            index.insert(*check, position);
        }
    }
    let artifact_count = artifact_runners().count();
    for (position, check) in PROBE_CHECKS.iter().enumerate() {
        for id in check.covers {
            index.insert(*id, artifact_count + position);
        }
    }
    index
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
