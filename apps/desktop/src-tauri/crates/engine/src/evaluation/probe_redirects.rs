//! The redirect walk `performance.redirect_chain` and `seo.temporary_redirect`
//! both read, planned one hop at a time from the requested URL.

use url::Url;

use crate::checks::performance::redirects::{RedirectWalk, RedirectWalkStep, RedirectWalker};
use crate::evaluation::ProbeContext;
use crate::probe::ProbeRequest;

/// Seeds a redirect walk from the requested URL. `page.url` is the response's
/// final URL and would incorrectly erase already-followed redirects.
fn redirect_start<'a>(ctx: &ProbeContext<'a>) -> Option<(&'a str, RedirectWalker)> {
    let requested = ctx.requested_url?;
    let start = Url::parse(requested).ok()?;
    Some((requested, RedirectWalker::new(&start)))
}

/// The next hop with no answer yet, one at a time. A chain cannot be planned
/// ahead: each hop's 3xx answer is what names the position after it.
pub(super) fn redirect_plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
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
pub(super) fn redirect_walk(ctx: &ProbeContext) -> Option<(String, RedirectWalk)> {
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
