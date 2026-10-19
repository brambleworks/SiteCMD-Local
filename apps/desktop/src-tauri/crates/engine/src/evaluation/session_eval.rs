//! A scan's comparison of its pages, from the facts each page step kept.

use serde::{Deserialize, Serialize};

use super::session_facts::{SessionPageFacts, SessionSitemapFacts, ELSEWHERE};
use super::{CheckLayer, PlannedCheck, MANIFEST};
use crate::manifest::CheckScope;
use crate::session::{analyze_session, SessionPage, SessionSitemap};
use crate::vocab::{CheckStatus, Severity};

/// Every page the scan compared, one per completed route, in route order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub pages: Vec<SessionPageFacts>,
}

/// One verdict, and the pages it names by their position in the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVerdictRow {
    pub check_id: String,
    pub status: CheckStatus,
    pub severity: Severity,
    pub pages: Vec<usize>,
}

/// The comparison's answer. Verdicts carry no title or description: the
/// analysis's words name keys here, not pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Manifest contract the comparison ran under.
    pub manifest_digest: String,
    /// Every cross-page check, with the layer its pairs carry.
    pub checks: Vec<PlannedCheck>,
    /// The positions of the pages the comparison used.
    pub compared: Vec<usize>,
    pub verdicts: Vec<SessionVerdictRow>,
}

/// Run the cross-page analysis over a scan's page facts.
pub fn evaluate_session(request: &SessionRequest) -> SessionResponse {
    let pages: Vec<SessionPage> = request
        .pages
        .iter()
        .enumerate()
        .map(|(position, facts)| compared_page(position, facts))
        .collect();
    let sitemap = request
        .pages
        .iter()
        .find_map(|facts| facts.sitemap.as_ref());
    let partial = sitemap.and_then(SessionSitemapFacts::partial_because);
    let analysis = analyze_session(
        &pages,
        sitemap.map(|found| SessionSitemap {
            urls: &found.entries,
            partial_because: partial.as_deref(),
        }),
    );
    SessionResponse {
        manifest_digest: MANIFEST.digest().to_string(),
        checks: MANIFEST
            .entries
            .iter()
            .filter(|entry| entry.scope == CheckScope::Session)
            .map(|entry| PlannedCheck {
                check: entry.check.clone(),
                layer: CheckLayer::of(entry.hosted).unwrap_or(CheckLayer::Transport),
                class: entry.class,
                measurement_unit: entry.measurement_unit,
                scope: entry.scope,
            })
            .collect(),
        compared: analysis.compared,
        verdicts: analysis
            .verdicts
            .into_iter()
            .map(|verdict| SessionVerdictRow {
                check_id: verdict.result.check_id,
                status: verdict.result.status,
                severity: verdict.result.severity,
                pages: verdict.pages,
            })
            .collect(),
    }
}

/// A page as the analysis compares it. Unknown requested and canonical keys
/// become unique to the input position so they cannot identify another page.
fn compared_page(position: usize, facts: &SessionPageFacts) -> SessionPage {
    SessionPage {
        url: facts.page.clone(),
        requested_url: if facts.requested == ELSEWHERE {
            format!("{ELSEWHERE}{position}")
        } else {
            facts.requested.clone()
        },
        status_code: facts.status_code,
        title: facts.title.clone(),
        meta_description: facts.description.clone(),
        h1: facts.h1.clone(),
        canonical: facts.canonical.as_deref().map(|key| {
            if key == ELSEWHERE {
                format!("{ELSEWHERE}{position}")
            } else {
                key.to_string()
            }
        }),
        noindex: facts.noindex,
        hreflang: facts.hreflang.clone(),
        hreflang_truncated: facts.hreflang_truncated,
        internal_links: facts.links.clone(),
        internal_links_truncated: facts.links_truncated,
    }
}
