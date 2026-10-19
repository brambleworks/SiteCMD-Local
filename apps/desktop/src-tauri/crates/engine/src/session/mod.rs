//! Cross-page analysis over the pages one scan compared, for every runtime that compares them.

use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};
use compared::ComparedPages;
use std::collections::HashSet;

mod canonical;
mod compared;
mod duplicates;
mod graph;
mod hreflang;
pub mod signals;
use duplicates::duplicate_field;

/// Minimum scanned pages before orphan analysis says anything. On tiny scan
/// sets "no other scanned page links here" is noise, not signal.
const ORPHAN_MIN_PAGES: usize = 5;
const NOINDEX_PARTIAL_CONSEQUENCE: &str =
    "a noindex page listed in the part it did not read would not have been seen";

/// Session evidence needs the path so a user can identify the page, but URL
/// credentials, query values, fragments, and token-looking path segments must
/// not be persisted in issue descriptions/raw data.
fn safe_page_url(raw: &str) -> String {
    crate::log_sanitizer::evidence_safe_page_url(raw)
}

/// Ordered session checks used to prove complete outcome coverage.
pub const SESSION_CHECK_IDS: &[&str] = &[
    "seo.duplicate_title_across_pages",
    "seo.duplicate_description_across_pages",
    "seo.duplicate_h1",
    "seo.orphan_pages",
    "seo.noindex_in_sitemap",
    "seo.canonical_loop",
    "seo.hreflang_reciprocity",
];

/// The sitemap URL set handed to session analysis, plus whether SiteCMD can
/// claim it read all of it.
#[derive(Debug, Clone, Copy)]
pub struct SessionSitemap<'a> {
    pub urls: &'a [String],
    /// Set when the URL set is known to be partial, naming why. A check that
    /// found nothing in a partial set has not established a clean verdict.
    pub partial_because: Option<&'a str>,
}

/// A page's comparison signals. URL fields are identity keys, equal exactly
/// when they name one page.
/// A title, description or H1 holding U+FFFD is not compared at all.
#[derive(Debug, Clone)]
pub struct SessionPage {
    pub url: String,
    pub requested_url: String,
    pub status_code: u16,
    /// Compared after `trim().to_ascii_lowercase()`.
    pub title: Option<String>,
    /// Compared after `trim().to_ascii_lowercase()`.
    pub meta_description: Option<String>,
    /// Compared after `trim().to_ascii_lowercase()`.
    pub h1: Option<String>,
    pub canonical: Option<String>,
    /// `None` when where a joined X-Robots-Tag line ended decides it; a check that it decides declines.
    pub noindex: Option<bool>,
    /// Alternate targets; a target's declared language never decides whether
    /// it returns the link.
    pub hreflang: Vec<String>,
    pub hreflang_truncated: bool,
    pub internal_links: Vec<String>,
    pub internal_links_truncated: bool,
}

/// An outcome and the input positions of the pages it names.
#[derive(Debug)]
pub struct SessionVerdict {
    pub result: CheckResult,
    pub pages: Vec<usize>,
}

/// Cross-page outcomes and the input positions actually compared.
#[derive(Debug)]
pub struct SessionAnalysis {
    pub verdicts: Vec<SessionVerdict>,
    pub compared: Vec<usize>,
}

/// Run all session-level analyzers. `sitemap` should be the discovered sitemap
/// URL set when available, for orphan coverage and noindex contradictions.
/// Pure and synchronous: the caller does any fetching.
pub fn analyze_session(
    pages: &[SessionPage],
    sitemap: Option<SessionSitemap<'_>>,
) -> SessionAnalysis {
    let compared = ComparedPages::from_pages(pages);
    if pages.len() < 2 {
        return SessionAnalysis {
            verdicts: Vec::new(),
            compared: compared.positions.clone(),
        };
    }
    let comparable = compared.pages.as_slice();

    let mut found = Vec::new();
    found.extend(duplicate_field(
        comparable,
        &compared,
        "seo.duplicate_title_across_pages",
        "title",
        |p| p.title.as_deref(),
    ));
    found.extend(duplicate_field(
        comparable,
        &compared,
        "seo.duplicate_description_across_pages",
        "meta description",
        |p| p.meta_description.as_deref(),
    ));
    found.extend(duplicate_field(
        comparable,
        &compared,
        "seo.duplicate_h1",
        "H1 heading",
        |p| p.h1.as_deref(),
    ));
    found.extend(graph::orphan_pages(comparable, &compared, sitemap));
    if let Some(sitemap) = sitemap {
        found.extend(graph::noindex_in_sitemap(comparable, &compared, sitemap));
    }
    found.extend(canonical::canonical_loops(comparable, &compared));
    found.extend(hreflang::hreflang_reciprocity(comparable, &compared));
    let reported: HashSet<String> = found
        .iter()
        .map(|(result, _)| result.check_id.clone())
        .collect();
    let unreported = unreported_outcomes(&reported, &compared, sitemap);
    let mut verdicts: Vec<SessionVerdict> = found
        .into_iter()
        .map(|(result, named)| SessionVerdict {
            pages: compared.positions_of(&named),
            result,
        })
        .collect();
    verdicts.extend(unreported.into_iter().map(|result| SessionVerdict {
        result,
        pages: Vec::new(),
    }));
    SessionAnalysis {
        verdicts,
        compared: compared.positions.clone(),
    }
}

/// Produces `Pass` only when the full set was evaluated; missing inputs produce
/// `Skipped` so coverage cannot resolve an earlier finding.
fn unreported_outcomes(
    reported: &HashSet<String>,
    compared: &ComparedPages<'_>,
    sitemap: Option<SessionSitemap<'_>>,
) -> Vec<CheckResult> {
    let comparable = compared.pages.len();
    let note = compared.exclusion_note();
    let phrase = compared.compared_phrase();
    SESSION_CHECK_IDS
        .iter()
        .filter(|check_id| !reported.contains(**check_id))
        .map(|check_id| {
            let subject = session_check_subject(check_id);
            // Too few comparable pages is a missing input for every check, so
            // it is decided before the per-check reasons.
            let skipped_because = if comparable < 2 {
                Some(format!(
                    "A cross-page comparison needs at least two comparable pages; this scan produced {comparable}.{note}"
                ))
            } else {
                match *check_id {
                "seo.orphan_pages" if compared.entry_page.is_none() => Some(
                    "The page this scan started from did not return a successful page response, so the links it publishes are missing from the graph and every page it links to would look unreachable.".to_string(),
                ),
                "seo.orphan_pages" if comparable < ORPHAN_MIN_PAGES => Some(format!(
                    "This check needs at least {ORPHAN_MIN_PAGES} scanned pages to tell an unlinked page from a small scan; this scan compared {comparable}.{note}"
                )),
                "seo.orphan_pages" => graph::orphan_sitemap_skip_reason(compared, sitemap),
                "seo.noindex_in_sitemap" if sitemap.is_none() => Some(
                    "No sitemap was found for this site, so no page could be compared against one."
                        .to_string(),
                ),
                "seo.noindex_in_sitemap" => sitemap
                    .and_then(|sitemap| sitemap.partial_because)
                    .map(|reason| partial_sitemap_reason(reason, NOINDEX_PARTIAL_CONSEQUENCE)),
                "seo.hreflang_reciprocity" if compared.hreflang_truncated => Some(
                    "A compared page declares more hreflang alternates than SiteCMD keeps for one page, so a missing return link could not be told apart from one it did not keep."
                        .to_string(),
                ),
                _ => None,
                }
            };
            match skipped_because {
                Some(reason) => not_checked(check_id, reason),
                None => {
                    let mut result = base_result(
                        check_id,
                        format!("No {subject} across the scanned pages"),
                        format!("SiteCMD compared {phrase} and found no {subject}.{note}"),
                    );
                    result.status = CheckStatus::Pass;
                    result
                }
            }
        })
        .collect()
}

fn partial_sitemap_reason(reason: &str, consequence: &str) -> String {
    format!("SiteCMD read only part of this site's sitemap ({reason}), so {consequence}.")
}

/// The row of a check that reached no verdict, saying why.
fn not_checked(check_id: &str, reason: String) -> CheckResult {
    let subject = session_check_subject(check_id);
    let mut result = base_result(check_id, format!("{subject} were not checked"), reason);
    result.status = CheckStatus::Skipped;
    result
}

/// What each session check is about, in the words a person reads. A row that
/// named its check id would put a developer's identifier in front of the
/// people who see these results.
fn session_check_subject(check_id: &str) -> &str {
    match check_id {
        "seo.duplicate_title_across_pages" => "shared page titles",
        "seo.duplicate_description_across_pages" => "shared meta descriptions",
        "seo.duplicate_h1" => "shared H1 headings",
        "seo.orphan_pages" => "pages without an inbound link",
        "seo.noindex_in_sitemap" => "noindex pages listed in the sitemap",
        "seo.canonical_loop" => "canonical loops",
        "seo.hreflang_reciprocity" => "one-way hreflang pairs",
        other => other,
    }
}

fn base_result(check_id: &str, title: String, description: String) -> CheckResult {
    CheckResult {
        check_id: check_id.to_string(),
        category: ScanCategory::Seo,
        title,
        description,
        status: CheckStatus::Warn,
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        let cut = crate::checks::floor_char_boundary(text, max);
        format!("{}...", &text[..cut])
    }
}
