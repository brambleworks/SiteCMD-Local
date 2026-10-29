//! The document's title and meta description, each graded by length as an editorial heuristic and kept as bounded evidence.

use super::extract_meta;
use crate::checks::seo::parsing::extract_document_title;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

/// The metadata check's character-length classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthOutcome {
    Missing,
    Short,
    Long,
    Ok,
}

/// The non-empty, trimmed document title the title check grades.
pub(crate) fn title_value(body: &str) -> Option<String> {
    extract_document_title(body).filter(|value| !value.trim().is_empty())
}

/// The first non-blank description attribute, preserving its whitespace.
pub(crate) fn description_value(body: &str) -> Option<String> {
    extract_meta(body, "description").filter(|value| !value.trim().is_empty())
}

/// Grade an extracted title's character count, with `None` classified as missing.
pub(crate) fn title_outcome(title: Option<&str>) -> LengthOutcome {
    length_outcome(title, 20, 70)
}

/// Grade an extracted description's character count, with `None` classified as missing.
pub(crate) fn description_outcome(description: Option<&str>) -> LengthOutcome {
    length_outcome(description, 50, 170)
}

fn length_outcome(value: Option<&str>, minimum: usize, maximum: usize) -> LengthOutcome {
    let Some(value) = value else {
        return LengthOutcome::Missing;
    };
    match value.chars().count() {
        length if length < minimum => LengthOutcome::Short,
        length if length > maximum => LengthOutcome::Long,
        _ => LengthOutcome::Ok,
    }
}

fn bounded_metadata_evidence(value: &str, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value.to_string(), false);
    }
    let cut = crate::checks::floor_char_boundary(value, max_bytes);
    (format!("{}...", &value[..cut]), true)
}

pub struct TitleTagCheck;

impl Check for TitleTagCheck {
    fn id(&self) -> &str {
        "seo.title"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let title = title_value(&ctx.body);
        let outcome = title_outcome(title.as_deref());
        match title {
            Some(t) => {
                // Character count, not byte length: a 30-character CJK title is
                // ~90 bytes, which `.len` reported as "exceeds 70 characters"
                // on every non-Latin-script site.
                let len = t.chars().count();
                // Search displays render by width and may rewrite title
                // links. Character count is therefore only an extreme-value
                // review heuristic, not proof of quality or truncation.
                let (status, result_title, desc) = if outcome == LengthOutcome::Short {
                    (CheckStatus::Warn, "Short title tag needs review", format!("The title contains {} characters. Length alone does not establish quality, but a very short title may be too generic or fail to distinguish this page. Review the rendered title and page intent rather than padding it to a quota.", len))
                } else if outcome == LengthOutcome::Long {
                    (CheckStatus::Warn, "Long title tag needs review", format!("The title contains {} characters. Search title links render by width and may be rewritten, so this extreme count is a review signal; it does not prove truncation or that a particular query will display the supplied title unchanged.", len))
                } else {
                    (CheckStatus::Pass, "Title tag", format!("A non-empty title is present ({} characters) and did not trigger the extreme-length heuristic. This check does not assess relevance, uniqueness across pages, rendered width, or search-engine rewrites.", len))
                };
                let (title_evidence, title_evidence_truncated) =
                    bounded_metadata_evidence(&t, 500);
                vec![CheckResult {
                    check_id: "seo.title".into(), category: ScanCategory::Seo,
                    title: result_title.into(), description: desc,
                    status, severity: Severity::High,
                    fix_prompt: None, manual_fix: if status == CheckStatus::Pass {
                        None
                    } else if outcome == LengthOutcome::Short {
                        Some("Review the page intent and the title shown in the rendered document. If the wording is generic or ambiguous, replace it with a concise, page-specific label; include the brand only when it helps users distinguish the result. Do not add filler solely to reach a character target.".into())
                    } else {
                        Some("Review the title's wording, rendered width, and representative search contexts. Remove redundant or low-value text while preserving the page-specific topic; do not force a character quota or assume that shortening guarantees a particular search display.".into())
                    },
                    raw_data: Some(serde_json::json!({
                        "title": title_evidence,
                        "length": len,
                        "title_evidence_truncated": title_evidence_truncated,
                        "source": "initial_html",
                        "rendered_title_inspected": false,
                    })),
                    confidence: if status == CheckStatus::Pass { crate::checks::IssueConfidence::High } else { crate::checks::IssueConfidence::NeedsReview },
                    confidence_reason: if status == CheckStatus::Pass { None } else { Some("Character count is directly observed, but rendered width, query context, title-link rewriting, and whether the wording is sufficiently descriptive require review.".into()) },
                    why_it_matters: if status != CheckStatus::Pass { Some("If the title is generic or too wide in the actual search/browser context, users may receive a less useful or rewritten label. The count alone does not establish that outcome.".into()) } else { None },
                }]
            }
            None => vec![CheckResult {
                check_id: "seo.title".into(), category: ScanCategory::Seo,
                title: "Missing title tag".into(),
                description: "No non-empty document <title> was found in the fetched HTML. Browsers use this element for tabs and bookmarks, and search systems commonly use it as one input when generating a title link, although they may derive or rewrite that label.".into(),
                status: CheckStatus::Fail, severity: Severity::High,
                fix_prompt: None, manual_fix: Some("Add one real `<title>` tag in `<head>` that states what this page is for and, if helpful, includes the brand. Keep it specific to the page instead of reusing the site-wide name everywhere.".into()),
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: Some("Pages without titles are harder to understand in browser tabs, bookmarks, and search result snippets.".into()),
            }],
        }
    }
}

pub struct MetaDescriptionCheck;

impl Check for MetaDescriptionCheck {
    fn id(&self) -> &str {
        "seo.meta_description"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let desc = description_value(&ctx.body);
        let outcome = description_outcome(desc.as_deref());
        match desc {
            Some(d) => {
                // Character count, not byte length (see seo.title): a CJK
                // description measured in bytes over-reports length ~3x.
                let len = d.chars().count();
                // Snippet length varies by query, device, and search system,
                // and the supplied description may be rewritten. Character
                // count is an editorial review heuristic only.
                let (status, result_title, msg) = if outcome == LengthOutcome::Short {
                    (CheckStatus::Warn, "Short meta description needs review", format!("The meta description contains {} characters. It may be intentionally concise, but review whether it gives a useful, page-specific summary; do not pad it solely to meet a character target.", len))
                } else if outcome == LengthOutcome::Long {
                    (CheckStatus::Warn, "Long meta description needs review", format!("The meta description contains {} characters. Search snippets vary by query and device and may be rewritten, so the tail may not be shown; this count does not prove truncation.", len))
                } else {
                    (CheckStatus::Pass, "Meta description", format!("A non-empty meta description is present ({} characters) and did not trigger the extreme-length heuristic. This check does not assess relevance, uniqueness, displayed snippet length, or whether a search system will use it.", len))
                };
                let (description_evidence, description_evidence_truncated) =
                    bounded_metadata_evidence(&d, 1_000);
                vec![CheckResult {
                    check_id: "seo.meta_description".into(), category: ScanCategory::Seo,
                    title: result_title.into(), description: msg,
                    status, severity: Severity::Medium,
                    fix_prompt: None, manual_fix: if status == CheckStatus::Pass {
                        None
                    } else if outcome == LengthOutcome::Short {
                        Some("Review the page intent and representative search contexts. If this description is too generic to explain the page, replace it with a specific plain-language summary of what the visitor will find; add substance, not filler, and do not target a character quota.".into())
                    } else {
                        Some("Review the description in representative search contexts. Move the most useful page-specific information earlier and remove redundant wording that may not add value when a snippet is shortened; do not assume a fixed character limit or that a search system will use the supplied text.".into())
                    },
                    raw_data: Some(serde_json::json!({
                        "description": description_evidence,
                        "length": len,
                        "description_evidence_truncated": description_evidence_truncated,
                        "source": "initial_html",
                        "rendered_head_inspected": false,
                    })),
                    confidence: if status == CheckStatus::Pass { crate::checks::IssueConfidence::High } else { crate::checks::IssueConfidence::NeedsReview },
                    confidence_reason: if status == CheckStatus::Pass { None } else { Some("The length is directly observed, but usefulness, query fit, device rendering, and search-engine snippet selection are contextual.".into()) },
                    why_it_matters: if status == CheckStatus::Pass {
                        None
                    } else if outcome == LengthOutcome::Short {
                        Some("An underspecified authored summary can give a consumer little page-specific context, but usefulness and click-through impact cannot be inferred from character count alone.".into())
                    } else {
                        Some("A consumer may omit the tail of a long authored summary, but displayed length, usefulness, and click-through impact cannot be inferred from character count alone.".into())
                    },
                }]
            }
            None => vec![CheckResult {
                check_id: "seo.meta_description".into(), category: ScanCategory::Seo,
                title: "Missing meta description".into(),
                description: "No non-empty meta description was found in the fetched HTML. Search systems may use a supplied description or may generate a query-dependent snippet from visible page content; absence does not mean the result has no snippet.".into(),
                status: CheckStatus::Fail, severity: Severity::Medium,
                fix_prompt: None, manual_fix: Some("Add one `<meta name=\"description\">` tag with a concise, page-specific summary when an authored default would help. Inspect the deployed HTML and representative search queries; search systems may still choose visible page text instead.".into()),
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: Some("Without an authored default, link/search consumers may derive a summary from page content. That can be appropriate, but it gives the site less control over the fallback wording.".into()),
            }],
        }
    }
}
