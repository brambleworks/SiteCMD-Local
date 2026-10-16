//! The origin reads for the page's own site (robots.txt,
//! the bounded sitemap candidate walk and llms.txt) and the og:image the page
//! names, wherever it lives. Each verdict is the one the desktop's shells
//! grade, from the same request.

use super::probes::{unexecuted_probe, ProbeContext};
use crate::checks::origin_with_port;
use crate::checks::seo::geo::llms_txt::{evaluate_llms_txt, llms_txt_url};
use crate::checks::seo::og_image::{evaluate_og_image, plan_og_image, OgImageStep};
use crate::checks::seo::robots::{robots_fetch_from_probe, robots_txt_url, RobotsTxtFetch};
use crate::checks::seo::sitemap::{sitemap_candidate_urls, SitemapFetch, SitemapProbe};
use crate::checks::seo::sitemap_walk::{
    robots_was_read, sitemap_candidates, sitemap_request, walk_sitemap_candidates,
};
use crate::probe::{BodyPolicy, ProbeRequest};
use crate::vocab::CheckResult;

pub(super) fn robots_request(ctx: &ProbeContext) -> ProbeRequest {
    ProbeRequest::get(robots_txt_url(&ctx.page.url))
}

/// robots.txt as the engine classifies it. A request nobody answered reads as
/// the transport failure `unexecuted_probe` describes.
pub(super) fn robots_fetch(ctx: &ProbeContext) -> RobotsTxtFetch {
    robots_fetch_from_probe(ctx.outcomes.owned(&robots_request(ctx)))
}

/// Whether robots.txt was read and every earlier candidate was conclusively missing.
pub(super) fn sitemap_sources_read(
    context: &ProbeContext,
    robots: &RobotsTxtFetch,
    found: &SitemapFetch,
) -> bool {
    let candidates = sitemap_candidates(&origin_with_port(&context.page.url), robots);
    let ahead = candidates
        .iter()
        .position(|url| *url == found.url)
        .unwrap_or(candidates.len());
    context
        .outcomes
        .get(&robots_request(context))
        .is_some_and(robots_was_read)
        && matches!(
            walk_sitemap_candidates(&candidates[..ahead], |request| context
                .outcomes
                .get(request)),
            Ok(SitemapProbe::Missing { .. })
        )
}

/// What the sitemap walk still needs. Until robots.txt answers, that is
/// robots.txt and the conventional paths, which every walk that finds no
/// well-formed declaration reads anyway, so asking for them now saves rounds;
/// after it, the first candidate in walk order with no answer, and once the
/// walk has found an index, the index's children this route still reads
/// (`sitemap_children.rs`).
pub(super) fn sitemap_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    let origin = origin_with_port(&ctx.page.url);
    let robots = robots_request(ctx);
    let Some(answer) = ctx.outcomes.get(&robots) else {
        let mut requests = vec![robots];
        requests.extend(
            sitemap_candidate_urls(&origin)
                .iter()
                .map(|url| sitemap_request(url)),
        );
        return requests;
    };
    let candidates = sitemap_candidates(&origin, &robots_fetch_from_probe(answer.clone()));
    match walk_sitemap_candidates(&candidates, |request| ctx.outcomes.get(request)) {
        // The comparison reads an index's pages from its children.
        Ok(SitemapProbe::Found(found)) if found.kind.lists_child_sitemaps() => {
            ctx.sitemap_children.wanted(&found, &origin)
        }
        Ok(_) => Vec::new(),
        Err(next) => vec![next],
    }
}

/// The walk's answer when grading. A candidate nobody answered reads as the
/// transport failure `unexecuted_probe` describes, so the walk always ends.
pub(super) fn sitemap_probe(ctx: &ProbeContext, robots: &RobotsTxtFetch) -> SitemapProbe {
    let unanswered = unexecuted_probe();
    let candidates = sitemap_candidates(&origin_with_port(&ctx.page.url), robots);
    walk_sitemap_candidates(&candidates, |request| {
        Some(ctx.outcomes.get(request).unwrap_or(&unanswered))
    })
    // Every candidate has an answer, so the walk cannot ask for another.
    .unwrap_or(SitemapProbe::Inconclusive {
        observations: Vec::new(),
    })
}

/// The index the walk found over the answers in hand, when what it found is one.
pub(super) fn found_index(ctx: &ProbeContext) -> Option<SitemapFetch> {
    let robots = robots_fetch_from_probe(ctx.outcomes.get(&robots_request(ctx))?.clone());
    match sitemap_probe(ctx, &robots) {
        SitemapProbe::Found(found) if found.kind.lists_child_sitemaps() => Some(found),
        _ => None,
    }
}

pub(super) fn llms_request(ctx: &ProbeContext) -> ProbeRequest {
    ProbeRequest::get(llms_txt_url(&ctx.page.url))
}

pub(super) fn llms_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    evaluate_llms_txt(ctx.outcomes.owned(&llms_request(ctx)))
}

/// The og:image's status, asked of the host the page names without reading
/// the image. A host the runtime's network policy refuses comes back as a
/// transport failure.
fn og_image_request(url: &url::Url) -> ProbeRequest {
    ProbeRequest::get(url.as_str()).body(BodyPolicy::None)
}

pub(super) fn og_image_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    match plan_og_image(&ctx.page.body) {
        OgImageStep::Done(_) => Vec::new(),
        OgImageStep::Probe { url, .. } => vec![og_image_request(&url)],
    }
}

pub(super) fn og_image_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    match plan_og_image(&ctx.page.body) {
        OgImageStep::Done(results) => results,
        // `Ok` rather than the policy skip: the network policy is the
        // runtime's, applied when the request is made, and a plan that reached
        // this point never decided it.
        OgImageStep::Probe { value, url } => {
            evaluate_og_image(&value, Ok(ctx.outcomes.owned(&og_image_request(&url))))
        }
    }
}
