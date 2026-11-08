//! Shared stylesheet grades and incomplete-coverage handling.

use super::{polish_check_result, PolishContext, POLISH_SIGNALS};
use crate::vocab::{CheckResult, CheckStatus};

/// Grade the stylesheet signals from the page's combined counts and facts.
pub fn grade_stylesheet_signals(
    ctx: &PolishContext,
    discovered: usize,
    fetched: usize,
) -> Vec<CheckResult> {
    let mut results = POLISH_SIGNALS
        .iter()
        .filter(|signal| signal.reads_stylesheets)
        .map(|signal| polish_check_result(&(signal.run)(ctx)))
        .collect::<Vec<_>>();
    grade_stylesheet_coverage(&mut results, discovered, fetched);
    results
}

/// CSS-dependent Polish signals can still prove a finding from inline HTML or
/// the stylesheets that were fetched. They cannot prove a clean result when a
/// linked stylesheet was unavailable, so preserve that distinction as Skipped.
pub fn grade_stylesheet_coverage(
    results: &mut [CheckResult],
    stylesheets_discovered: usize,
    stylesheets_fetched: usize,
) {
    if stylesheets_fetched >= stylesheets_discovered {
        return;
    }
    for result in results.iter_mut().filter(|result| {
        result.status == CheckStatus::Pass
            && POLISH_SIGNALS.iter().any(|signal| {
                signal.reads_stylesheets
                    && result.check_id.strip_prefix("polish.") == Some(signal.id)
            })
    }) {
        result.status = CheckStatus::Skipped;
        result.description = format!(
            "This signal could not be cleared because SiteCMD fetched {} of {} linked stylesheets. The unavailable stylesheet may contain matching CSS.",
            stylesheets_fetched, stylesheets_discovered
        );
        result.raw_data = Some(serde_json::json!({
            "stylesheets_discovered": stylesheets_discovered,
            "stylesheets_fetched": stylesheets_fetched,
            "coverage_complete": false,
        }));
        result.confidence = crate::vocab::IssueConfidence::NeedsReview;
        result.confidence_reason = Some(
            "Linked stylesheet coverage was incomplete, so absence of the CSS pattern was not established."
                .to_string(),
        );
    }
}
