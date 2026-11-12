//! Entry-page stylesheets sampled in one round and graded from compact readings.

use super::super::ProbeContext;
use crate::checks::polish::{
    extract_stylesheet_urls, grade_stylesheet_signals, stylesheet_request, CssSignalCounts,
    PolishContext, STYLESHEET_SAMPLE_LIMIT,
};
use crate::probe::ProbeRequest;
use crate::vocab::CheckResult;

pub(super) fn plan(ctx: &ProbeContext) -> Vec<ProbeRequest> {
    extract_stylesheet_urls(&ctx.page.body, &ctx.page.url)
        .iter()
        .take(STYLESHEET_SAMPLE_LIMIT)
        .map(|url| stylesheet_request(url))
        .collect()
}

pub(super) fn grade(ctx: &ProbeContext) -> Vec<CheckResult> {
    let urls = extract_stylesheet_urls(&ctx.page.body, &ctx.page.url);
    let mut fetched = 0;
    let counts = urls
        .iter()
        .take(STYLESHEET_SAMPLE_LIMIT)
        .filter_map(|url| ctx.readings.stylesheet(&stylesheet_request(url)))
        .fold(CssSignalCounts::default(), |sum, counts| {
            fetched += 1;
            sum + *counts
        });
    let polish = PolishContext::new(
        ctx.page.url.clone(),
        std::borrow::Cow::Borrowed(&ctx.page.body),
        counts,
    );
    grade_stylesheet_signals(&polish, urls.len(), fetched)
}
