//! Repeated document title and meta description elements on one page.

use super::extract_attr_value;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct DuplicateMetaCheck;

impl Check for DuplicateMetaCheck {
    fn id(&self) -> &str {
        "seo.duplicate_meta"
    }
    fn emitted_ids(&self) -> Vec<String> {
        vec![
            "seo.duplicate_meta".to_string(),
            "seo.duplicate_title".to_string(),
            "seo.duplicate_description".to_string(),
        ]
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let lower = ctx.body_lower();
        let mut results = Vec::new();

        // Ignore non-content blocks and SVG titles, which label icons rather than documents.
        let scannable = crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(lower, " ");
        let without_svg = crate::checks::seo::parsing::SVG_BLOCK_RE.replace_all(&scannable, " ");
        let title_count =
            crate::checks::html_attrs::tag_slices(&without_svg, &without_svg, "title").len();
        if title_count > 1 {
            results.push(CheckResult {
                check_id: "seo.duplicate_title".into(),
                category: ScanCategory::Seo,
                title: "Multiple document title elements observed".into(),
                description: format!(
                    "Found {} document <title> elements in the scannable initial HTML after excluding comments, scripts, styles, and inline SVG title elements. HTML documents have one document title; SiteCMD did not execute client-side head management or determine which value a browser/search consumer ultimately uses.",
                    title_count
                ),
                status: CheckStatus::Fail,
                severity: Severity::Medium,
                fix_prompt: None,
                manual_fix: Some("Trace every framework, layout, CMS/plugin, template, and client head-management source, then emit one coherent document <title> for the route. Inspect both the production response and rendered head across navigation, fallback, locale, and error states.".into()),
                raw_data: Some(serde_json::json!({
                    "document_title_element_count": title_count,
                    "source": "initial_html",
                    "rendered_head_inspected": false,
                })),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: Some("Conflicting document-title declarations make the intended title ambiguous to browsers, assistive technology, and crawlers; downstream consumers can apply their own selection or rewriting behavior.".into()),
            });
        }

        if title_count <= 1 {
            results.push(single_element_pass(
                "seo.duplicate_title",
                "No repeated document title element",
                "No more than one document <title> element was found in the scannable initial HTML after excluding comments, scripts, styles, and inline SVG title elements. This pass does not inspect client-side head changes or compare titles across pages.",
            ));
        }

        // Count only description meta tags, not unrelated elements with that name.
        let desc_count = crate::checks::html_attrs::tag_slices(&scannable, &scannable, "meta")
            .into_iter()
            .filter(|tag| {
                extract_attr_value(tag, "name")
                    .is_some_and(|value| value.eq_ignore_ascii_case("description"))
            })
            .count();
        if desc_count > 1 {
            results.push(CheckResult {
                check_id: "seo.duplicate_description".into(),
                category: ScanCategory::Seo,
                title: "Duplicate meta descriptions".into(),
                description: format!(
                    "Found {} <meta name=\"description\"> elements in the scannable initial HTML. The intended summary is ambiguous; parsers and search engines can select, ignore, or rewrite these declarations, and SiteCMD did not inspect client-side head changes.",
                    desc_count
                ),
                status: CheckStatus::Fail,
                severity: Severity::Medium,
                fix_prompt: None,
                manual_fix: Some("Trace framework, layout, CMS/plugin, template, and client head-management sources, then emit one coherent meta description when the page needs one. Inspect the production response and rendered head across navigation, fallback, locale, and error states.".into()),
                raw_data: Some(serde_json::json!({
                    "meta_description_element_count": desc_count,
                    "source": "initial_html",
                    "rendered_head_inspected": false,
                })),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: Some("Conflicting description declarations make the page's intended summary ambiguous to crawlers and link-preview consumers; actual search snippets are selected by the search engine.".into()),
            });
        }

        if desc_count <= 1 {
            results.push(single_element_pass(
                "seo.duplicate_description",
                "No repeated meta description element",
                "No more than one <meta name=\"description\"> element was found in the scannable initial HTML. This pass does not inspect client-side head changes or compare descriptions across pages.",
            ));
        }

        if title_count <= 1 && desc_count <= 1 {
            results.push(CheckResult {
                check_id: "seo.duplicate_meta".into(),
                category: ScanCategory::Seo,
                title: "Duplicate meta tags".into(),
                description: "No repeated document <title> or <meta name=\"description\"> elements were found in the scannable initial HTML. This pass does not inspect client-side head changes or compare values across pages.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            });
        }

        results
    }
}

/// A passing verdict for one sub-check, so a run that found the element once or
/// not at all covers that id and a fixed duplicate can be verified fixed.
fn single_element_pass(check_id: &str, title: &str, description: &str) -> CheckResult {
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Seo,
        title: title.into(),
        description: description.into(),
        status: CheckStatus::Pass,
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}
