//! Cross-page analysis over collected page signals. The analyzers are the
//! engine's (`sitecmd_engine::session`); this wrapper hands them the
//! desktop's signals and omits declines accompanying site-level findings.

use crate::checks::{CheckResult, CheckStatus};
use crate::core::page_signals::PageSignals;
use std::collections::HashSet;

pub use sitecmd_engine::session::{SessionSitemap, SESSION_CHECK_IDS};

// The session suite reads these through `use super::*`.
#[cfg(test)]
use crate::checks::IssueConfidence;
#[cfg(test)]
use crate::core::page_signals::normalize_page_url;

/// Run every cross-page analyzer over the scan's page signals. Pure and
/// synchronous: the caller does any fetching.
pub fn analyze_session(
    pages: &[PageSignals],
    sitemap: Option<SessionSitemap<'_>>,
) -> Vec<CheckResult> {
    let compared: Vec<_> = pages.iter().map(PageSignals::session_page).collect();
    let analysis = sitecmd_engine::session::analyze_session(&compared, sitemap);
    let findings: HashSet<String> = analysis
        .verdicts
        .iter()
        .filter(|verdict| matches!(verdict.result.status, CheckStatus::Fail | CheckStatus::Warn))
        .map(|verdict| verdict.result.check_id.clone())
        .collect();
    analysis
        .verdicts
        .into_iter()
        .filter(|verdict| {
            verdict.result.status != CheckStatus::Skipped
                || !findings.contains(&verdict.result.check_id)
        })
        .map(|verdict| verdict.result)
        .collect()
}

#[cfg(test)]
#[path = "session_analysis_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_analysis_decline_tests.rs"]
mod decline_tests;
