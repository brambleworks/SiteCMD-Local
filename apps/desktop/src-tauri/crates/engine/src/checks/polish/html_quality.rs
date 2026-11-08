//! Structural HTML quality signals for Polish Scan.

use super::{PolishContext, PolishResult, SignalCategory, SignalWeight};
use crate::checks::accessibility::form_labels::{
    captured_value, is_inert_hidden_control, is_wrapped_by_label, label_spans,
};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

const CATEGORY: SignalCategory = SignalCategory::HtmlQuality;
/// Matches opening tags of semantic HTML elements.
static SEMANTIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<(main|section|article|aside|nav|header|footer|figure|figcaption|details|summary|time|mark|address)(?-u:\b)")
        .expect("semantic regex")
});

/// Matches opening `<div` tags.
static DIV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<div(?-u:\b)").expect("div regex"));

/// Matches heading tags, capturing the level number.
static HEADING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<h([1-6])(?-u:\b)").expect("heading regex"));

/// Matches form input elements (input, select, textarea).
static INPUT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<(input|select|textarea)(?-u:\b)[^>]*>"#).expect("input regex")
});

/// Matches `id=...` attribute (quoted or not), capturing the id value.
static ID_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\s"']id\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#).expect("id attr regex")
});

/// Matches `type=...` attribute (quoted or not), capturing the type value.
static TYPE_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\s"']type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#)
        .expect("type attr regex")
});

/// Matches `<label for=...>` tags (quoted or not), capturing the target id.
static LABEL_FOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<label\b[^>]*[\s"']for\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#)
        .expect("label for regex")
});

/// Matches `onclick` attributes on elements, capturing the tag name.
/// The attribute boundary is `[\s"']`, not `\b` - a word boundary
/// matched `data-onclick=` at the hyphen.
static ONCLICK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<([a-z][a-z0-9]*)(?-u:\b)[^>]*[\s"']onclick\s*="#).expect("onclick regex")
});

/// Matches a `role=button` attribute inside a tag's attribute text.
static ROLE_BUTTON_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\s"']role\s*=\s*["']?button(?-u:\b)"#).expect("role button regex")
});

/// Flag pages whose generic-container ratio exceeds 85% (High, 15).
pub fn div_soup_ratio(ctx: &PolishContext) -> PolishResult {
    let div_count = DIV_RE.find_iter(&ctx.html).count();
    let semantic_count = SEMANTIC_RE.find_iter(&ctx.html).count();
    let total = div_count + semantic_count;

    if total < 5 {
        return PolishResult::clear(
            "div-soup-ratio",
            "High Div Element Density",
            SignalWeight::High,
            CATEGORY,
        );
    }

    let div_ratio = div_count as f64 / total as f64;

    if div_ratio > 0.85 {
        PolishResult::fired(
            "div-soup-ratio",
            "High Div Element Density",
            SignalWeight::High,
            CATEGORY,
            format!(
                "{}% of container elements are <div> tags ({} divs, {} semantic)",
                (div_ratio * 100.0).round() as u32,
                div_count,
                semantic_count
            ),
            serde_json::json!({
                "div_count": div_count,
                "semantic_count": semantic_count,
                "ratio": (div_ratio * 1000.0).round() / 1000.0,
            }),
        )
    } else {
        PolishResult::clear(
            "div-soup-ratio",
            "High Div Element Density",
            SignalWeight::High,
            CATEGORY,
        )
    }
}

/// Flag multiple H1s or heading-level gaps as a medium review signal.
pub fn heading_hierarchy(ctx: &PolishContext) -> PolishResult {
    // Ignore non-content blocks.
    let content =
        crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(ctx.html_lower(), " ");
    let headings: Vec<u32> = HEADING_RE
        .captures_iter(&content)
        .filter_map(|cap| cap[1].parse::<u32>().ok())
        .collect();

    // No early return on an empty list: a page with no headings at all has no
    // h1 either, and `seo.headings.h1` already says so.
    let h1_count = headings.iter().filter(|&&h| h == 1).count();
    let mut issues: Vec<String> = Vec::new();

    // Multiple h1 tags
    if h1_count > 1 {
        issues.push(format!(
            "{} h1 elements in fetched HTML; confirm one unambiguous page-level heading and review whether the others represent independently scoped content",
            h1_count
        ));
    }

    // No h1 at all
    if h1_count == 0 {
        issues.push(
            "No h1 element in fetched HTML; confirm the page has a clear top-level heading"
                .to_string(),
        );
    }

    // Level gaps > 1
    for window in headings.windows(2) {
        let (prev, next) = (window[0], window[1]);
        if next > prev + 1 {
            issues.push(format!(
                "Heading level moves from h{} to h{}; review whether an intermediate section label is missing",
                prev, next
            ));
        }
    }

    if !issues.is_empty() {
        PolishResult::fired(
            "heading-hierarchy",
            "Heading Order Issues",
            SignalWeight::Medium,
            CATEGORY,
            issues.join("; "),
            serde_json::json!({
                "h1_count": h1_count,
                "heading_sequence": headings,
                "issues": issues,
            }),
        )
    } else {
        PolishResult::clear(
            "heading-hierarchy",
            "Heading Order Issues",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Flag forms where more than half of the inputs lack labels (Medium, 8).
pub fn form_accessibility(ctx: &PolishContext) -> PolishResult {
    // Collect all label `for` attribute values
    let label_fors: HashSet<String> = LABEL_FOR_RE
        .captures_iter(&ctx.html)
        .filter_map(|cap| captured_value(&cap))
        .collect();

    // Match form-label semantics by treating wrapping labels as valid.
    let wrapping_spans = label_spans(&ctx.html);

    // Collect all input elements, filtering out hidden and submit
    let mut total_inputs = 0usize;
    let mut unlabeled = 0usize;

    for cap in INPUT_RE.captures_iter(&ctx.html) {
        let tag = &cap[0];
        if is_inert_hidden_control(tag) {
            continue;
        }

        // Skip hidden inputs and submit buttons
        if let Some(type_cap) = TYPE_ATTR_RE.captures(tag) {
            if let Some(input_type) = captured_value(&type_cap) {
                // technical vocabulary: https://html.spec.whatwg.org/multipage/input.html#attr-input-type
                if matches!(input_type.as_str(), "hidden" | "submit" | "button") {
                    continue;
                }
            }
        }

        total_inputs += 1;

        // Check if this input has a matching label
        let has_label = ID_ATTR_RE
            .captures(tag)
            .and_then(|c| captured_value(&c))
            .map(|id| label_fors.contains(&id))
            .unwrap_or(false);

        let has_aria_label = tag.to_lowercase().contains("aria-label");

        let tag_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        if !has_label && !has_aria_label && !is_wrapped_by_label(&wrapping_spans, tag_start) {
            unlabeled += 1;
        }
    }

    if total_inputs == 0 {
        return PolishResult::clear(
            "form-accessibility",
            "Form Inputs Missing Labels",
            SignalWeight::Medium,
            CATEGORY,
        );
    }

    let unlabeled_ratio = unlabeled as f64 / total_inputs as f64;

    if unlabeled_ratio > 0.50 {
        PolishResult::fired(
            "form-accessibility",
            "Form Inputs Missing Labels",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{}% of form inputs lack labels ({} of {} inputs)",
                (unlabeled_ratio * 100.0).round() as u32,
                unlabeled,
                total_inputs
            ),
            serde_json::json!({
                "total_inputs": total_inputs,
                "unlabeled": unlabeled,
                "ratio": (unlabeled_ratio * 1000.0).round() / 1000.0,
            }),
        )
    } else {
        PolishResult::clear(
            "form-accessibility",
            "Form Inputs Missing Labels",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}
/// Detect click handlers on non-interactive elements without `role="button"`.
pub fn button_vs_clickable_div(ctx: &PolishContext) -> PolishResult {
    // technical vocabulary: https://html.spec.whatwg.org/multipage/dom.html#interactive-content
    let interactive_tags = ["button", "a", "input", "select", "textarea"];
    // technical vocabulary: https://html.spec.whatwg.org/multipage/interactive-elements.html#the-summary-element
    const SUMMARY_TAG: &str = "summary";
    let mut violations = 0usize;

    for cap in ONCLICK_RE.captures_iter(&ctx.html) {
        let tag_name = cap[1].to_lowercase();
        if interactive_tags.contains(&tag_name.as_str()) || tag_name == SUMMARY_TAG {
            continue;
        }
        // role= can sit after onclick= in the tag, so check the whole
        // open tag, not just the regex match.
        let start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let tag_end = ctx.html[start..]
            .find('>')
            .map(|i| start + i)
            .unwrap_or(ctx.html.len());
        if ROLE_BUTTON_ATTR_RE.is_match(&ctx.html[start..tag_end]) {
            continue;
        }
        violations += 1;
    }

    if violations > 0 {
        PolishResult::fired(
            "button-vs-clickable-div",
            "Non-Accessible Click Targets",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{} non-button element{} with click handlers and no button role",
                violations,
                if violations != 1 { "s" } else { "" }
            ),
            serde_json::json!({ "violations": violations }),
        )
    } else {
        PolishResult::clear(
            "button-vs-clickable-div",
            "Non-Accessible Click Targets",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Flag a missing document-language declaration (Low, 3).
pub fn missing_lang(ctx: &PolishContext) -> PolishResult {
    // Shared with `accessibility.lang` so the two never disagree about one
    // attribute; the quote-agnostic form accepts `<html lang=en>`.
    if crate::checks::accessibility::html_checks::declares_document_language(&ctx.html) {
        PolishResult::clear(
            "missing-lang",
            "Missing Language Tag",
            SignalWeight::Low,
            CATEGORY,
        )
    } else {
        PolishResult::fired(
            "missing-lang",
            "Missing Language Tag",
            SignalWeight::Low,
            CATEGORY,
            "No lang attribute on <html> element".to_string(),
            serde_json::json!({}),
        )
    }
}

#[cfg(test)]
mod tests;
