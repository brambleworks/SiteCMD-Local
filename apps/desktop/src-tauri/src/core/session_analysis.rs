//! Cross-page analysis over collected page signals. The analyzers are the
//! engine's (`sitecmd_engine::session`); this wrapper hands them the
//! desktop's signals and keeps the verdict rows, as the scan loop reads them.

use crate::checks::CheckResult;
use crate::core::page_signals::PageSignals;

pub use sitecmd_engine::session::{SessionSitemap, SESSION_CHECK_IDS};

// The session suite reads these through `use super::*`.
#[cfg(test)]
use crate::checks::{CheckStatus, IssueConfidence};
#[cfg(test)]
use crate::core::page_signals::normalize_page_url;

/// Run every cross-page analyzer over the scan's page signals. Pure and
/// synchronous: the caller does any fetching.
pub fn analyze_session(
    pages: &[PageSignals],
    sitemap: Option<SessionSitemap<'_>>,
) -> Vec<CheckResult> {
    let compared: Vec<_> = pages.iter().map(PageSignals::session_page).collect();
    sitecmd_engine::session::analyze_session(&compared, sitemap)
        .verdicts
        .into_iter()
        .map(|verdict| verdict.result)
        .collect()
}

#[cfg(test)]
#[path = "session_analysis_tests.rs"]
mod tests;
