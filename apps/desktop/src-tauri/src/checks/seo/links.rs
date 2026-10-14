//! Desktop transport for portable broken-link probes.
//!
//! This layer owns concurrency, timeouts, and network policy; the engine owns
//! target selection and verdicts.

use crate::checks::{probe_with_timeout, AsyncCheck, CheckContext, CheckResult, ScanCategory};
use futures_util::{stream, StreamExt};
use sitecmd_engine::checks::seo::links::{
    head_needs_get, link_get_request, link_head_request, link_probe_result, no_link_targets_result,
    observe_link, resolve_link_targets, summarize_link_probes, LinkObservation, LinkScope,
    LinkTargets, BROKEN_LINK_EXTERNAL_CONCURRENCY, BROKEN_LINK_EXTERNAL_SAMPLE,
    BROKEN_LINK_INTERNAL_CONCURRENCY, BROKEN_LINK_INTERNAL_SAMPLE, EXTERNAL_CHECK_ID,
    INTERNAL_CHECK_ID,
};
use sitecmd_engine::Severity;
use std::time::Duration;
use url::Url;

// The sync URL-structure check lives in the engine; re-export it so the
// `links::UrlStructureCheck` registration path keeps resolving.
pub use sitecmd_engine::checks::seo::url_structure::UrlStructureCheck;

/// This page's anchor destinations under the desktop's page-subresource
/// network policy, resolved once for both link checks.
fn targets_for(ctx: &CheckContext) -> &LinkTargets {
    ctx.probe_cache.link_targets.get_or_init(|| {
        resolve_link_targets(&ctx.page, |resolved| {
            crate::network_policy::validate_page_subresource_target(
                resolved,
                ctx.subordinate_policy(),
            )
            .is_ok()
        })
    })
}

/// Probe one destination: HEAD first, then a GET confirmation only when the
/// HEAD failed or returned an error status.
async fn probe_one_link(client: reqwest::Client, url: Url, timeout: Duration) -> LinkObservation {
    let head = probe_with_timeout(&client, link_head_request(&url), Some(timeout)).await;
    let get = if head_needs_get(&head) {
        Some(probe_with_timeout(&client, link_get_request(&url), Some(timeout)).await)
    } else {
        None
    };
    observe_link(&url, &head, get.as_ref())
}

/// Probe a sampled destination list concurrently.
async fn probe_links(
    client: &reqwest::Client,
    links: &[Url],
    concurrency: usize,
    timeout: Duration,
) -> sitecmd_engine::checks::seo::links::ProbeSummary {
    let observations: Vec<LinkObservation> = stream::iter(links.iter().cloned())
        .map(|url| probe_one_link(client.clone(), url, timeout))
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    summarize_link_probes(links.len(), observations)
}

pub struct BrokenLinksCheck;

#[async_trait::async_trait]
impl AsyncCheck for BrokenLinksCheck {
    fn id(&self) -> &str {
        INTERNAL_CHECK_ID
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let targets = targets_for(ctx);
        let eligible_candidate_count = targets.internal.len();
        let sample_limit = BROKEN_LINK_INTERNAL_SAMPLE;
        let sampled: Vec<Url> = targets
            .internal
            .iter()
            .take(sample_limit)
            .cloned()
            .collect();
        if sampled.is_empty() {
            return vec![no_link_targets_result(
                self.id(),
                Severity::High,
                LinkScope::Internal,
                targets,
                sample_limit,
            )];
        }
        let summary = probe_links(
            &ctx.client,
            &sampled,
            BROKEN_LINK_INTERNAL_CONCURRENCY,
            crate::constants::CHECK_PROBE_TIMEOUT,
        )
        .await;
        vec![link_probe_result(
            self.id(),
            Severity::High,
            LinkScope::Internal,
            targets,
            eligible_candidate_count,
            sampled.len(),
            sample_limit,
            summary,
        )]
    }
}

/// Check for broken external links (sample bounded by
/// BROKEN_LINK_EXTERNAL_SAMPLE)
pub struct BrokenExternalLinksCheck;

#[async_trait::async_trait]
impl AsyncCheck for BrokenExternalLinksCheck {
    fn id(&self) -> &str {
        EXTERNAL_CHECK_ID
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let targets = targets_for(ctx);
        let eligible_candidate_count = targets.external.len();
        let sample_limit = BROKEN_LINK_EXTERNAL_SAMPLE;
        let sampled: Vec<Url> = targets
            .external
            .iter()
            .take(sample_limit)
            .cloned()
            .collect();
        if sampled.is_empty() {
            return vec![no_link_targets_result(
                self.id(),
                Severity::Medium,
                LinkScope::External,
                targets,
                sample_limit,
            )];
        }
        let summary = probe_links(
            &ctx.client,
            &sampled,
            BROKEN_LINK_EXTERNAL_CONCURRENCY,
            crate::constants::CHECK_LINK_TIMEOUT,
        )
        .await;
        vec![link_probe_result(
            self.id(),
            Severity::Medium,
            LinkScope::External,
            targets,
            eligible_candidate_count,
            sampled.len(),
            sample_limit,
            summary,
        )]
    }
}

#[cfg(test)]
#[path = "links/tests.rs"]
mod tests;
