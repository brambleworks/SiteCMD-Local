//! The performance reads a probe plan makes for one page, each graded by the
//! verdict the desktop's shells grade; the asset and compression shells send
//! these same requests.

use url::Url;

use crate::checks::performance::assets::{self, ASSET_SAMPLE_LIMIT};
use crate::checks::performance::compression::{self, CompressionStep};
use crate::checks::performance::ttfb;
use crate::evaluation::ProbeContext;
use crate::probe::ProbeRequest;
use crate::vocab::CheckResult;

/// Every web-scheme asset the markup names is requested, whatever its host:
/// the runtime's network policy refuses what it refuses, and a refusal comes
/// back as an unanswered request, so the sample does not depend on which
/// runtime executes it.
fn web_scheme(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

/// The sample's addresses, from a scan of the page that stops once the sample
/// is full: resolved by the first planning call that asks and read by every
/// later one.
fn sample<'a>(ctx: &ProbeContext<'a>) -> &'a [Url] {
    ctx.asset_sample.get_or_init(|| {
        assets::asset_sample(
            &ctx.page.body,
            ctx.page.body_lower(),
            &ctx.page.url,
            web_scheme,
            ASSET_SAMPLE_LIMIT,
        )
    })
}

/// The sample's requests.
pub(super) fn asset_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    sample(ctx).iter().map(assets::asset_request).collect()
}

pub(super) fn asset_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    let collection = assets::collect_assets(
        &ctx.page.body,
        ctx.page.body_lower(),
        &ctx.page.url,
        web_scheme,
        ASSET_SAMPLE_LIMIT,
    );
    let measured: Vec<_> = collection
        .sampled
        .iter()
        .map(|asset| {
            let request = assets::asset_request(&asset.url);
            assets::measured_asset(
                asset,
                &ctx.outcomes.owned(&request),
                ctx.outcomes.measure(&request),
            )
        })
        .collect();
    assets::evaluate_asset_sample(ctx.page.body.len() as u64, &collection, &measured)
}

/// The HEAD, then the GET only when the HEAD's answer proves nothing.
pub(super) fn compression_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    if ctx.page.is_localhost {
        return Vec::new();
    }
    let head = compression::head_request(&ctx.page.url);
    let Some(answer) = ctx.outcomes.get(&head) else {
        return vec![head];
    };
    match compression::evaluate_compression_head(compression::encoding_probe(answer).as_ref()) {
        CompressionStep::Done(_) => Vec::new(),
        CompressionStep::NeedsGet => vec![compression::get_request(&ctx.page.url)],
    }
}

pub(super) fn compression_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    if ctx.page.is_localhost {
        return vec![compression::localhost_skip_result()];
    }
    let head = ctx
        .outcomes
        .owned(&compression::head_request(&ctx.page.url));
    match compression::evaluate_compression_head(compression::encoding_probe(&head).as_ref()) {
        CompressionStep::Done(results) => results,
        CompressionStep::NeedsGet => {
            let get = ctx.outcomes.owned(&compression::get_request(&ctx.page.url));
            compression::evaluate_compression_get(compression::encoding_probe(&get), ctx.page)
        }
    }
}

pub(super) fn ttfb_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    ttfb::timing_requests(&ctx.page.url)
}

pub(super) fn ttfb_grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    let answers: Vec<_> = ttfb::timing_requests(&ctx.page.url)
        .iter()
        .map(|request| (ctx.outcomes.owned(request), ctx.outcomes.measure(request)))
        .collect();
    ttfb::evaluate_timing_answers(&answers)
}
