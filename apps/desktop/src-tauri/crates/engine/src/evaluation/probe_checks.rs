//! Registry pairing each probe plan with its grader.
//!
//! Plans are rederived from current outcomes. A grader requires at least one
//! answered probe; transport failures are not observations about the site.

use url::Url;

use super::probes::ProbeContext;
use super::{origin_reads, probe_dns};
use crate::checks::compliance::legal_documents::{
    evaluate_privacy_policy, evaluate_terms, has_terms_link, legal_path_request,
    page_links_privacy_policy, LegalPathSweep, LegalPathWalk, PRIVACY_PATHS, TERMS_PATHS,
};
use crate::checks::config::alt_host::{alt_host_probe_request, alternate_host, evaluate_alt_host};
use crate::checks::config::favicon::{
    evaluate_declared, evaluate_fallback, favicon_probe_request, plan_favicon, FaviconProbeSkip,
    FaviconStep,
};
use crate::checks::config::missing_page::{
    evaluate_missing_page, localhost_skip_result, missing_page_probe_request,
};
use crate::checks::config::web_manifest::{
    evaluate_web_manifest, manifest_request, plan_web_manifest, WebManifestStep,
};
use crate::checks::performance::redirects::{
    evaluate_redirect_chain, redirect_chain_unrecorded_start, RedirectWalk, RedirectWalkStep,
    RedirectWalker,
};
use crate::checks::security::cors::{
    evaluate_reflection, reflection_localhost_skip_result, reflection_probe_request,
};
use crate::checks::security::dns_email::{
    domain_expiry, registrable_domain_for_url, skipped_local_result, DomainTarget,
};
use crate::checks::security::https_enforcement::{
    evaluate_http_downgrade, evaluate_https_availability, origin_root_request,
    plan_https_enforcement, HttpsEnforcementStep,
};
use crate::checks::security::open_redirect::{
    evaluate_open_redirect, open_redirect_probes, probe_origin, OpenRedirectSweep,
};
use crate::checks::security::vulnerable_libraries::{
    detect_libraries, evaluate_vulnerable_libraries,
};
use crate::checks::seo::geo::{
    ai_crawlers::evaluate_ai_crawler_blocking, sitemap_freshness::evaluate_sitemap_freshness,
};
use crate::checks::seo::links::{
    head_needs_get, link_get_request, link_head_request, link_probe_result, no_link_targets_result,
    observe_link, resolve_link_targets, summarize_link_probes, LinkScope, LinkTargets,
    BROKEN_LINK_EXTERNAL_SAMPLE, BROKEN_LINK_INTERNAL_SAMPLE, EXTERNAL_CHECK_ID, INTERNAL_CHECK_ID,
};
use crate::checks::seo::redirects::{
    evaluate_temporary_redirect, temporary_redirect_unrecorded_start,
};
use crate::checks::seo::robots::{evaluate_robots_txt, RobotsTxtFetch};
use crate::checks::seo::robots_directives::evaluate_sitemap_in_robots;
use crate::checks::seo::sitemap::{evaluate_sitemap, SitemapProbe};
use crate::page::origin_with_port;
use crate::probe::ProbeRequest;
use crate::vocab::{CheckResult, Severity};

/// One probe-lane check: the ids it produces, the probes it still needs, and
/// the verdict it grades once they arrive.
pub struct ProbeCheck {
    /// The manifest ids this row is the sole producer of.
    pub covers: &'static [&'static str],
    /// The probes still needed given the artifact and the outcomes so far.
    /// Empty means the check can grade now.
    pub plan: fn(&ProbeContext) -> Vec<ProbeRequest>,
    /// The verdict rows. Called only when the manifest says the check's facts
    /// are present, so it never has to decide whether the fetch lane ran.
    pub grade: fn(&ProbeContext) -> Vec<CheckResult>,
}

/// Every probe check, in the order their rows appear in a response. Sorted by
/// manifest id: the order is part of the ABI's determinism claim, and an
/// alphabetical rule is one nobody has to remember.
pub const PROBE_CHECKS: &[ProbeCheck] = &[
    ProbeCheck {
        covers: &["compliance.privacy_policy"],
        plan: |ctx| {
            legal_plan(
                ctx,
                page_links_privacy_policy(ctx.page.body_lower()),
                PRIVACY_PATHS,
            )
        },
        grade: |ctx| {
            let linked = page_links_privacy_policy(ctx.page.body_lower());
            evaluate_privacy_policy(linked, &legal_sweep(ctx, linked, PRIVACY_PATHS))
        },
    },
    ProbeCheck {
        covers: &["compliance.terms"],
        plan: |ctx| legal_plan(ctx, has_terms_link(ctx.page.body_lower()), TERMS_PATHS),
        grade: |ctx| {
            let linked = has_terms_link(ctx.page.body_lower());
            evaluate_terms(linked, &legal_sweep(ctx, linked, TERMS_PATHS))
        },
    },
    ProbeCheck {
        covers: &["config.custom_404"],
        plan: |ctx| match missing_page_probe(ctx) {
            Some(request) => vec![request],
            None => Vec::new(),
        },
        grade: |ctx| match missing_page_probe(ctx) {
            Some(request) => evaluate_missing_page(ctx.outcomes.owned(&request)),
            None => vec![localhost_skip_result()],
        },
    },
    ProbeCheck {
        covers: &["config.favicon"],
        plan: |ctx| match favicon_step(ctx) {
            FaviconStep::Done(_) => Vec::new(),
            FaviconStep::ProbeDeclared { url, .. } | FaviconStep::ProbeFallback { url } => {
                vec![favicon_probe_request(&url)]
            }
        },
        grade: |ctx| match favicon_step(ctx) {
            FaviconStep::Done(results) => results,
            FaviconStep::ProbeDeclared { url, safe_href } => {
                evaluate_declared(&safe_href, &url, favicon_outcome(ctx, &url))
            }
            FaviconStep::ProbeFallback { url } => evaluate_fallback(favicon_outcome(ctx, &url)),
        },
    },
    ProbeCheck {
        covers: &["config.sitemap_in_robots"],
        plan: |ctx| vec![origin_reads::robots_request(ctx)],
        grade: |ctx| evaluate_sitemap_in_robots(&origin_reads::robots_fetch(ctx)),
    },
    ProbeCheck {
        covers: &["config.web_manifest"],
        plan: |ctx| match plan_web_manifest(&ctx.page.body, &ctx.page.url) {
            WebManifestStep::Done(_) => Vec::new(),
            WebManifestStep::Probe { url, .. } => vec![manifest_request(&url)],
        },
        grade: |ctx| match plan_web_manifest(&ctx.page.body, &ctx.page.url) {
            WebManifestStep::Done(results) => results,
            // `Ok` rather than a skip: the network-policy refusal the skip
            // variant describes is the RUNTIME's decision, and a plan that
            // reached this point never made it.
            WebManifestStep::Probe { safe_href, url } => {
                evaluate_web_manifest(&safe_href, Ok(ctx.outcomes.owned(&manifest_request(&url))))
            }
        },
    },
    ProbeCheck {
        covers: &["config.www_redirect"],
        plan: |ctx| vec![alt_host_probe(ctx).1],
        grade: |ctx| {
            let (alternate, request) = alt_host_probe(ctx);
            evaluate_alt_host(&alternate, ctx.outcomes.owned(&request))
        },
    },
    ProbeCheck {
        covers: &["performance.redirect_chain"],
        plan: redirect_plan,
        grade: |ctx| match redirect_walk(ctx) {
            Some((start, walk)) => vec![evaluate_redirect_chain(&start, &walk)],
            None => vec![redirect_chain_unrecorded_start()],
        },
    },
    ProbeCheck {
        covers: &["security.cors_reflection"],
        plan: |ctx| match reflection_probe(ctx) {
            Some(request) => vec![request],
            None => Vec::new(),
        },
        grade: |ctx| match reflection_probe(ctx) {
            Some(request) => evaluate_reflection(ctx.outcomes.owned(&request)),
            None => reflection_localhost_skip_result(),
        },
    },
    ProbeCheck {
        covers: &[
            "security.dns.caa",
            "security.dns.dangling_cname",
            "security.dns.dkim",
            "security.dns.dmarc",
            "security.dns.dnssec",
            "security.dns.mx",
            "security.dns.spf",
        ],
        plan: |_| Vec::new(),
        grade: probe_dns::resolver_grade,
    },
    ProbeCheck {
        covers: &["security.domain_expiry"],
        plan: |ctx| match registrable_domain_for_url(&ctx.page.url) {
            DomainTarget::Registrable(domain) => vec![domain_expiry::rdap_probe(&domain)],
            DomainTarget::LocalOrIp => Vec::new(),
        },
        grade: |ctx| match registrable_domain_for_url(&ctx.page.url) {
            DomainTarget::Registrable(domain) => {
                let request = domain_expiry::rdap_probe(&domain);
                domain_expiry::evaluate_rdap(
                    &domain,
                    &ctx.outcomes.owned(&request),
                    ctx.page.evaluation_time,
                )
            }
            DomainTarget::LocalOrIp => vec![skipped_local_result(
                domain_expiry::CHECK_ID,
                domain_expiry::TITLE,
            )],
        },
    },
    ProbeCheck {
        covers: &["security.https_enforcement"],
        plan: |ctx| match plan_https_enforcement(&ctx.page.url, ctx.page.is_localhost) {
            HttpsEnforcementStep::Done(_) => Vec::new(),
            HttpsEnforcementStep::ProbeHttpOrigin { url }
            | HttpsEnforcementStep::ProbeHttpsOrigin { url } => vec![origin_root_request(&url)],
        },
        grade: |ctx| match plan_https_enforcement(&ctx.page.url, ctx.page.is_localhost) {
            HttpsEnforcementStep::Done(results) => results,
            HttpsEnforcementStep::ProbeHttpOrigin { url } => {
                let request = origin_root_request(&url);
                evaluate_http_downgrade(url.as_str(), ctx.outcomes.owned(&request))
            }
            HttpsEnforcementStep::ProbeHttpsOrigin { url } => {
                let request = origin_root_request(&url);
                evaluate_https_availability(url.as_str(), ctx.outcomes.owned(&request))
            }
        },
    },
    ProbeCheck {
        covers: &["security.open_redirect"],
        plan: |ctx| {
            open_redirect_probes(&probe_origin(&ctx.page.url))
                .iter()
                .map(|probe| probe.request())
                .collect()
        },
        grade: |ctx| {
            // Every planned probe is folded in, answered or not: the sweep
            // counts what it asked for as well as what came back, which is
            // what lets the verdict tell "nothing vulnerable" from "nothing
            // answered".
            let mut sweep = OpenRedirectSweep::default();
            for probe in open_redirect_probes(&probe_origin(&ctx.page.url)) {
                sweep.observe(&probe, &ctx.outcomes.owned(&probe.request()));
            }
            evaluate_open_redirect(sweep)
        },
    },
    ProbeCheck {
        covers: &["security.vulnerable_libraries"],
        plan: |_| Vec::new(),
        grade: |ctx| {
            let detected = detect_libraries(&ctx.page.body);
            let Some(lookup) = ctx.vulnerability_facts else {
                return Vec::new();
            };
            evaluate_vulnerable_libraries(&detected, lookup.clone())
        },
    },
    // Literal ids keep the registry test independent from their constants.
    ProbeCheck {
        covers: &["seo.ai_crawler_blocking"],
        plan: |ctx| vec![origin_reads::robots_request(ctx)],
        // The desktop's own rule: a crawler policy is read only from a
        // robots.txt that answered with one, and anything else states nothing.
        grade: |ctx| match origin_reads::robots_fetch(ctx) {
            RobotsTxtFetch::Found { body } => evaluate_ai_crawler_blocking(&body),
            _ => Vec::new(),
        },
    },
    ProbeCheck {
        covers: &["seo.broken_external_links"],
        plan: |ctx| links_plan(ctx, LinkScope::External),
        grade: |ctx| {
            links_grade(
                ctx,
                LinkScope::External,
                EXTERNAL_CHECK_ID,
                Severity::Medium,
            )
        },
    },
    ProbeCheck {
        covers: &["seo.broken_links"],
        plan: |ctx| links_plan(ctx, LinkScope::Internal),
        grade: |ctx| links_grade(ctx, LinkScope::Internal, INTERNAL_CHECK_ID, Severity::High),
    },
    ProbeCheck {
        covers: &["seo.llms_txt"],
        plan: |ctx| vec![origin_reads::llms_request(ctx)],
        grade: origin_reads::llms_grade,
    },
    ProbeCheck {
        covers: &["seo.og_image_status"],
        plan: origin_reads::og_image_plan,
        grade: origin_reads::og_image_grade,
    },
    ProbeCheck {
        covers: &["seo.robots_txt"],
        plan: |ctx| vec![origin_reads::robots_request(ctx)],
        grade: |ctx| evaluate_robots_txt(&origin_reads::robots_fetch(ctx)),
    },
    ProbeCheck {
        covers: &["seo.sitemap"],
        plan: origin_reads::sitemap_plan,
        grade: |ctx| {
            let robots = origin_reads::robots_fetch(ctx);
            evaluate_sitemap(
                ctx.page,
                &robots,
                &origin_reads::sitemap_probe(ctx, &robots),
            )
        },
    },
    ProbeCheck {
        covers: &["seo.sitemap_freshness"],
        plan: origin_reads::sitemap_plan,
        // As on the desktop: freshness is read only from a sitemap the walk found.
        grade: |ctx| match origin_reads::sitemap_probe(ctx, &origin_reads::robots_fetch(ctx)) {
            SitemapProbe::Found(found) => evaluate_sitemap_freshness(&found),
            _ => Vec::new(),
        },
    },
    ProbeCheck {
        covers: &["seo.temporary_redirect"],
        // The same walk `performance.redirect_chain` counts, read for its
        // statuses instead of its length. Both rows plan it identically, so
        // the key dedups them into one exchange per hop rather than two.
        plan: redirect_plan,
        grade: |ctx| match redirect_walk(ctx) {
            Some((_, walk)) => vec![evaluate_temporary_redirect(&walk)],
            None => vec![temporary_redirect_unrecorded_start()],
        },
    },
];

/// State of the ordered, short-circuiting legal-path sweep.
enum LegalStep {
    Served(&'static str),
    /// The next candidate and all evidence collected so far.
    Probe(ProbeRequest, LegalPathWalk),
    /// Every candidate path has an outcome and none served the document.
    Exhausted(LegalPathWalk),
}

fn legal_step(ctx: &ProbeContext, paths: &'static [&'static str]) -> LegalStep {
    let origin = origin_with_port(&ctx.page.url);
    let mut walk = LegalPathWalk::default();
    for path in paths {
        let request = legal_path_request(&origin, path);
        let Some(outcome) = ctx.outcomes.get(&request) else {
            return LegalStep::Probe(request, walk);
        };
        if walk.observe(path, outcome) {
            return LegalStep::Served(path);
        }
    }
    LegalStep::Exhausted(walk)
}

fn legal_plan(
    ctx: &ProbeContext,
    link_in_page: bool,
    paths: &'static [&'static str],
) -> Vec<ProbeRequest> {
    if link_in_page {
        return Vec::new();
    }
    match legal_step(ctx, paths) {
        LegalStep::Probe(request, _) => vec![request],
        LegalStep::Served(_) | LegalStep::Exhausted(_) => Vec::new(),
    }
}

/// Grade only answered candidate paths; unanswered probes are not absence evidence.
fn legal_sweep(
    ctx: &ProbeContext,
    link_in_page: bool,
    paths: &'static [&'static str],
) -> LegalPathSweep {
    if link_in_page {
        // Both verdicts short-circuit when the page already links the document.
        return LegalPathSweep::Unanswered;
    }
    match legal_step(ctx, paths) {
        LegalStep::Served(path) => LegalPathSweep::Served(path),
        LegalStep::Probe(_, walk) | LegalStep::Exhausted(walk) => walk.finish(),
    }
}

/// `None` on a localhost preview, where the verdict is a skip and no request
/// is made: local preview servers answer unknown paths with their own generic
/// page, so the probe would grade the dev server rather than the site.
fn missing_page_probe(ctx: &ProbeContext) -> Option<ProbeRequest> {
    (!ctx.page.is_localhost).then(|| missing_page_probe_request(&origin_with_port(&ctx.page.url)))
}

fn favicon_step(ctx: &ProbeContext) -> FaviconStep {
    plan_favicon(&ctx.page.body, &origin_with_port(&ctx.page.url), |href| {
        ctx.page.url.join(href).ok().map(|url| url.to_string())
    })
}

/// A probe the caller never ran reads as [`FaviconProbeSkip::Failed`], the
/// same as a transport that returned nothing. The `Disallowed` variant is the
/// runtime's own network-policy refusal and is never synthesized here.
fn favicon_outcome(
    ctx: &ProbeContext,
    url: &str,
) -> Result<crate::probe::ProbeOutcome, FaviconProbeSkip> {
    ctx.outcomes
        .get(&favicon_probe_request(url))
        .cloned()
        .ok_or(FaviconProbeSkip::Failed)
}

fn alt_host_probe(ctx: &ProbeContext) -> (String, ProbeRequest) {
    let alternate = alternate_host(ctx.page.url.host_str().unwrap_or(""));
    let request = alt_host_probe_request(ctx.page.url.scheme(), &alternate);
    (alternate, request)
}

/// Seeds a redirect walk from the requested URL. `page.url` is the response's
/// final URL and would incorrectly erase already-followed redirects.
fn redirect_start<'a>(ctx: &ProbeContext<'a>) -> Option<(&'a str, RedirectWalker)> {
    let requested = ctx.requested_url?;
    let start = Url::parse(requested).ok()?;
    Some((requested, RedirectWalker::new(&start)))
}

/// The next hop with no answer yet, one at a time. A chain cannot be planned
/// ahead: each hop's 3xx answer is what names the position after it.
fn redirect_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    let Some((_, mut walker)) = redirect_start(ctx) else {
        return Vec::new();
    };
    loop {
        let request = walker.request();
        let Some(outcome) = ctx.outcomes.get(&request) else {
            return vec![request];
        };
        match walker.observe(outcome) {
            RedirectWalkStep::Continue(next) => walker = next,
            RedirectWalkStep::Done(_) => return Vec::new(),
        }
    }
}

/// Walks only the available probe outcomes. A missing hop becomes a network
/// failure so incomplete execution remains inconclusive.
fn redirect_walk(ctx: &ProbeContext) -> Option<(String, RedirectWalk)> {
    let (requested, mut walker) = redirect_start(ctx)?;
    let start = requested.to_string();
    loop {
        let outcome = ctx.outcomes.owned(&walker.request());
        match walker.observe(&outcome) {
            RedirectWalkStep::Continue(next) => walker = next,
            RedirectWalkStep::Done(walk) => return Some((start, walk)),
        }
    }
}

/// `None` on a localhost preview: dev servers are deliberately permissive
/// about origins, so a reflection verdict there describes the dev server.
fn reflection_probe(ctx: &ProbeContext) -> Option<ProbeRequest> {
    (!ctx.page.is_localhost).then(|| reflection_probe_request(ctx.page.url.as_str()))
}

/// Resolve anchor targets without transport policy; refused targets return as
/// failed probes so every runtime plans the same work.
fn link_targets(ctx: &ProbeContext) -> LinkTargets {
    resolve_link_targets(ctx.page, |_| true)
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
fn links_plan(ctx: &ProbeContext, scope: LinkScope) -> Vec<ProbeRequest> {
    let targets = link_targets(ctx);
    let (sample, _, _) = link_sample(&targets, scope);
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

fn links_grade(
    ctx: &ProbeContext,
    scope: LinkScope,
    check_id: &str,
    severity: Severity,
) -> Vec<CheckResult> {
    let targets = link_targets(ctx);
    let (sample, eligible, limit) = link_sample(&targets, scope);
    if sample.is_empty() {
        return vec![no_link_targets_result(
            check_id, severity, scope, &targets, limit,
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
        &targets,
        eligible,
        sample.len(),
        limit,
        summary,
    )]
}
