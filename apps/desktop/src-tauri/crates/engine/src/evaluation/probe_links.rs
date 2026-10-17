//! The broken-link rows' planning and grading: the sampled anchors, HEAD first,
//! and a GET confirmation where the HEAD needs one.

use url::Url;

use crate::checks::seo::links::{
    head_needs_get, link_get_request, link_head_request, link_probe_result, no_link_targets_result,
    observe_link, resolve_link_targets, summarize_link_probes, LinkScope, LinkTargets,
    BROKEN_LINK_EXTERNAL_SAMPLE, BROKEN_LINK_INTERNAL_SAMPLE,
};
use crate::evaluation::ProbeContext;
use crate::probe::ProbeRequest;
use crate::vocab::{CheckResult, Severity};

/// Resolve anchor targets once per route without transport policy; refused
/// targets return as failed probes so every runtime plans the same work.
fn link_targets<'a>(ctx: &ProbeContext<'a>) -> &'a LinkTargets {
    ctx.link_targets
        .get_or_init(|| resolve_link_targets(ctx.page, |_| true))
}

/// The sampled destinations for one scope, with the eligible count and the
/// cap the verdict reports.
fn link_sample(targets: &LinkTargets, scope: LinkScope) -> (Vec<Url>, usize, usize) {
    let (eligible, limit) = match scope {
        LinkScope::Internal => (&targets.internal, BROKEN_LINK_INTERNAL_SAMPLE),
        LinkScope::External => (&targets.external, BROKEN_LINK_EXTERNAL_SAMPLE),
    };
    (
        eligible.iter().take(limit).cloned().collect(),
        eligible.len(),
        limit,
    )
}

/// Probe links with HEAD, adding GET only when HEAD needs confirmation.
pub(super) fn links_plan(ctx: &ProbeContext, scope: LinkScope) -> Vec<ProbeRequest> {
    let (sample, _, _) = link_sample(link_targets(ctx), scope);
    let mut requests = Vec::new();
    for url in &sample {
        let head = link_head_request(url);
        let Some(observed) = ctx.outcomes.get(&head) else {
            requests.push(head);
            continue;
        };
        if head_needs_get(observed) {
            let get = link_get_request(url);
            if ctx.outcomes.get(&get).is_none() {
                requests.push(get);
            }
        }
    }
    requests
}

pub(super) fn links_grade(
    ctx: &ProbeContext,
    scope: LinkScope,
    check_id: &str,
    severity: Severity,
) -> Vec<CheckResult> {
    let targets = link_targets(ctx);
    let (sample, eligible, limit) = link_sample(targets, scope);
    if sample.is_empty() {
        return vec![no_link_targets_result(
            check_id, severity, scope, targets, limit,
        )];
    }
    let observations = sample
        .iter()
        .map(|url| {
            let head = ctx.outcomes.owned(&link_head_request(url));
            let get = head_needs_get(&head).then(|| ctx.outcomes.owned(&link_get_request(url)));
            observe_link(url, &head, get.as_ref())
        })
        .collect();
    let summary = summarize_link_probes(sample.len(), observations);
    vec![link_probe_result(
        check_id,
        severity,
        scope,
        targets,
        eligible,
        sample.len(),
        limit,
        summary,
    )]
}
