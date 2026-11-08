//! Form control accessible-name checks.
//!
//! Each control is evaluated against ARIA naming, a matching `label[for]`, or
//! a wrapping label; unrelated labels do not count.

use crate::checks::html_attrs::{attr_value, has_attr};
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use std::sync::LazyLock;

pub struct FormLabelsCheck;

static FORM_FIELD_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)<(?:input|select|textarea)\b([^>]*)>"#)
        .expect("static form field regex") // allow-expect: compile-time literal regex
});
static FOR_ATTR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)[\s"']id\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))"#)
        .expect("static id attr regex")
    // allow-expect: compile-time literal regex
});
static HIDDEN_OR_BUTTON_TYPE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)[\s"']type\s*=\s*["']?(?:hidden|submit|reset|button|image)\b"#)
        .expect("static input-type regex") // allow-expect: compile-time literal regex
});
// Nested labels are invalid HTML, so a non-greedy element matcher is enough
// for the source-level association check and lets us reject empty labels.
static LABEL_ELEMENT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?is)<label\b([^>]*)>(.*?)</label\s*>").expect("static label element regex")
    // allow-expect: compile-time literal regex
});
static LABEL_CONTENT_TAG_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?is)<[^>]+>").expect("static label content tag regex")
    // allow-expect: compile-time literal regex
});

pub fn label_spans(body: &str) -> Vec<(usize, usize)> {
    LABEL_ELEMENT_RE
        .captures_iter(body)
        .filter(|capture| {
            capture
                .get(2)
                .is_some_and(|content| label_content_has_name(content.as_str()))
        })
        .filter_map(|capture| {
            capture
                .get(0)
                .map(|matched| (matched.start(), matched.end()))
        })
        .collect()
}

/// Look up a control in the ordered, non-overlapping spans returned by `label_spans`.
pub fn is_wrapped_by_label(spans: &[(usize, usize)], tag_start: usize) -> bool {
    spans
        .partition_point(|(start, _)| *start < tag_start)
        .checked_sub(1)
        .is_some_and(|index| tag_start < spans[index].1)
}

fn label_content_has_name(content: &str) -> bool {
    let text = LABEL_CONTENT_TAG_RE.replace_all(content, " ");
    let normalized = text
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&#xA0;", " ")
        .replace("&#xa0;", " ");
    !normalized.trim().is_empty()
}

pub fn captured_value(caps: &regex::Captures) -> Option<String> {
    caps.get(1)
        .or_else(|| caps.get(2))
        .or_else(|| caps.get(3))
        .map(|m| m.as_str().to_lowercase())
}

/// Whether a control is disabled and explicitly hidden from assistive technology.
pub fn is_inert_hidden_control(tag: &str) -> bool {
    has_attr(tag, "disabled")
        && attr_value(tag, "aria-hidden").is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

impl Check for FormLabelsCheck {
    fn id(&self) -> &str {
        "accessibility.form_labels"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Accessibility
    }
    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        // Ignore form-like text outside rendered markup.
        let scannable =
            crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(&ctx.body, " ");
        let labeled_ids: std::collections::HashSet<String> = LABEL_ELEMENT_RE
            .captures_iter(&scannable)
            .filter(|capture| {
                capture
                    .get(2)
                    .is_some_and(|content| label_content_has_name(content.as_str()))
            })
            .filter_map(|capture| {
                capture
                    .get(1)
                    .and_then(|attrs| attr_value(attrs.as_str(), "for"))
                    .map(|id| id.to_lowercase())
            })
            .collect();

        let spans = label_spans(&scannable);
        let document_ids = FOR_ATTR_RE
            .captures_iter(&scannable)
            .filter_map(|capture| captured_value(&capture))
            .collect::<std::collections::HashSet<_>>();

        let mut input_count = 0usize;
        let mut unlabeled_count = 0usize;
        let mut aria_named_count = 0usize;
        let mut title_named_count = 0usize;
        let mut for_labeled_count = 0usize;
        let mut wrapped_count = 0usize;
        for cap in FORM_FIELD_RE.captures_iter(&scannable) {
            let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let tag = cap.get(0).map(|matched| matched.as_str()).unwrap_or("");
            if HIDDEN_OR_BUTTON_TYPE_RE.is_match(attrs) || is_inert_hidden_control(tag) {
                continue;
            }
            input_count += 1;
            let has_aria_label =
                attr_value(tag, "aria-label").is_some_and(|value| !value.trim().is_empty());
            let has_valid_aria_reference =
                attr_value(tag, "aria-labelledby").is_some_and(|value| {
                    value
                        .split_whitespace()
                        .map(str::to_lowercase)
                        .any(|id| document_ids.contains(&id))
                });
            let has_aria_name = has_aria_label || has_valid_aria_reference;
            let has_title_name =
                attr_value(tag, "title").is_some_and(|value| !value.trim().is_empty());
            let has_id_label = FOR_ATTR_RE
                .captures(attrs)
                .and_then(|c| captured_value(&c))
                .map(|id| labeled_ids.contains(&id))
                .unwrap_or(false);
            let tag_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
            if has_aria_name {
                aria_named_count += 1;
            } else if has_title_name {
                title_named_count += 1;
            } else if has_id_label {
                for_labeled_count += 1;
            } else if is_wrapped_by_label(&spans, tag_start) {
                wrapped_count += 1;
            } else {
                unlabeled_count += 1;
            }
        }

        if input_count == 0 {
            return vec![CheckResult {
                check_id: "accessibility.form_labels".into(),
                category: ScanCategory::Accessibility,
                title: "Form labels".into(),
                description: "No form inputs found on this page.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }];
        }
        let possibly_unlabeled = unlabeled_count;
        let labeled = input_count - unlabeled_count;
        vec![CheckResult {
            check_id: "accessibility.form_labels".into(),
            category: ScanCategory::Accessibility,
            title: if possibly_unlabeled == 0 {
                "Form labels".into()
            } else {
                "Form inputs missing labels".into()
            },
            description: if possibly_unlabeled == 0 {
                if input_count == 1 {
                    "The form input appears to have a visible label or an accessible name.".into()
                } else {
                    format!(
                        "All {} form inputs appear to have a visible label or an accessible name.",
                        input_count
                    )
                }
            } else {
                format!(
                    "{} of {} form input{} {} no associated label or recognized accessible-name marker in the fetched HTML ({} appear named). If these controls render without a runtime-provided name, they fail WCAG 2.2 SC 4.1.2 (Name, Role, Value). WCAG 2.2 SC 3.3.2 (Labels or Instructions) separately requires a label or instructions when content requires user input; confirm that visible context in the rendered form.",
                    possibly_unlabeled,
                    input_count,
                    if input_count == 1 { "" } else { "s" },
                    if possibly_unlabeled == 1 { "has" } else { "have" },
                    labeled
                )
            },
            status: if possibly_unlabeled == 0 {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            severity: Severity::High,
            fix_prompt: None,
            manual_fix: if possibly_unlabeled > 0 {
                Some("Inspect each surfaced control in the rendered accessibility tree first. Prefer a visible <label for=\"input-id\">Caption</label> paired with a unique input id, or wrap the control in its label. Use aria-labelledby when existing visible text should provide the name and aria-label only when no visible label is practical. Give related checkbox or radio groups a fieldset and legend, then verify keyboard and screen-reader output.".into())
            } else {
                None
            },
            raw_data: Some(serde_json::json!({
                "inputs": input_count,
                "labeled_via_for": for_labeled_count,
                "labeled_via_aria": aria_named_count,
                "labeled_via_title": title_named_count,
                "labeled_via_wrapping": wrapped_count,
                "unlabeled": possibly_unlabeled,
            })),
            confidence: if possibly_unlabeled > 0 {
                crate::checks::IssueConfidence::NeedsReview
            } else {
                crate::checks::IssueConfidence::High
            },
            confidence_reason: (possibly_unlabeled > 0).then(|| "This static HTML check recognizes labels, non-empty aria-label, aria-labelledby references to an observed id, and non-empty title fallbacks. Client rendering or a more complex accessible-name relationship can change the final accessibility tree.".into()),
            why_it_matters: if possibly_unlabeled > 0 {
                Some("A rendered control without an accessible name is difficult to identify with a screen reader or voice control. The static source finding must be confirmed against the rendered accessibility tree.".into())
            } else {
                None
            },
        }]
    }
}
