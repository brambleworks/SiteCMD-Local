//! The ordered legal-path sweep the privacy policy and terms rows read, one
//! candidate path at a time until one serves the document.

use crate::checks::compliance::legal_documents::{
    legal_path_request, LegalPathSweep, LegalPathWalk,
};
use crate::evaluation::ProbeContext;
use crate::page::origin_with_port;
use crate::probe::ProbeRequest;

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

pub(super) fn legal_plan(
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
pub(super) fn legal_sweep(
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
