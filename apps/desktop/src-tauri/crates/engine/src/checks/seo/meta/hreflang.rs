//! hreflang alternates as one page's initial HTML declares them.

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct HreflangCheck;

impl Check for HreflangCheck {
    fn id(&self) -> &str {
        "seo.hreflang"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let scannable =
            crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(&ctx.body, " ");
        let lower = scannable.to_ascii_lowercase();
        let annotations: Vec<(String, Option<String>)> =
            crate::checks::html_attrs::tag_slices(&scannable, &lower, "link")
                .into_iter()
                .filter(|tag| {
                    crate::checks::html_attrs::attr_value(tag, "rel").is_some_and(|rel| {
                        rel.split_ascii_whitespace()
                            .any(|token| token.eq_ignore_ascii_case("alternate"))
                    })
                })
                .filter_map(|tag| {
                    crate::checks::html_attrs::attr_value(tag, "hreflang").map(|language| {
                        (
                            language.trim().to_ascii_lowercase(),
                            crate::checks::html_attrs::attr_value(tag, "href"),
                        )
                    })
                })
                .collect();

        let has_default = annotations
            .iter()
            .any(|(language, _)| language == "x-default");
        let mut incomplete_count = 0usize;
        let mut non_absolute_count = 0usize;
        let mut has_language_self_reference = false;
        for (language, href) in &annotations {
            let Some(href) = href
                .as_deref()
                .map(str::trim)
                .filter(|href| !href.is_empty())
            else {
                incomplete_count += 1;
                continue;
            };
            let Ok(target) = url::Url::parse(href) else {
                non_absolute_count += 1;
                continue;
            };
            if !matches!(target.scheme(), "http" | "https") {
                non_absolute_count += 1;
                continue;
            }
            if language != "x-default" {
                let mut target_without_fragment = target;
                target_without_fragment.set_fragment(None);
                let mut current_without_fragment = ctx.url.clone();
                current_without_fragment.set_fragment(None);
                if target_without_fragment == current_without_fragment {
                    has_language_self_reference = true;
                }
            }
        }

        let has_issue = !annotations.is_empty()
            && (incomplete_count > 0 || non_absolute_count > 0 || !has_language_self_reference);
        let description = if annotations.is_empty() {
            "No HTML link annotation with rel=alternate and hreflang was observed. That is fine when this page has no localized equivalent. This source check does not inspect hreflang delivered through HTTP headers or sitemaps."
                .into()
        } else if has_issue {
            let mut concerns = Vec::new();
            if incomplete_count > 0 {
                concerns.push(format!(
                    "{} annotation{} ha{} an empty language or missing/empty href",
                    incomplete_count,
                    if incomplete_count == 1 { "" } else { "s" },
                    if incomplete_count == 1 { "s" } else { "ve" },
                ));
            }
            if non_absolute_count > 0 {
                concerns.push(format!(
                    "{} href{} not a fully qualified HTTP(S) URL",
                    non_absolute_count,
                    if non_absolute_count == 1 {
                        " is"
                    } else {
                        "s are"
                    },
                ));
            }
            if !has_language_self_reference {
                concerns.push("the HTML set has no language-specific self-reference".into());
            }
            format!(
                "Observed {} HTML hreflang annotation{}; {}. Google Search documents fully qualified alternate URLs and a self-reference in each HTML language set. x-default is optional and is not the reason for this finding. This check did not validate BCP 47 meaning, target responses/canonicals, return links, HTTP-header annotations, or sitemap annotations.",
                annotations.len(),
                if annotations.len() == 1 { "" } else { "s" },
                concerns.join("; "),
            )
        } else {
            format!(
                "Observed {} HTML hreflang annotation{} with a language-specific self-reference. {} This source check does not validate BCP 47 meaning, target responses/canonicals, return links, HTTP-header annotations, or sitemap annotations.",
                annotations.len(),
                if annotations.len() == 1 { "" } else { "s" },
                if has_default {
                    "An x-default fallback is also present; its target and suitability were not evaluated."
                } else {
                    "No x-default fallback is present; x-default is optional and is most useful when an unmatched-language fallback is intentional."
                },
            )
        };

        vec![CheckResult {
            check_id: "seo.hreflang".into(),
            category: ScanCategory::Seo,
            title: if has_issue {
                "Hreflang HTML annotations need review".into()
            } else {
                "Hreflang HTML annotations".into()
            },
            description,
            status: if has_issue {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: has_issue.then(|| "Review the emitted HTML alternate set for this exact page. Give every annotation a supported BCP 47 language/region value (or x-default), a fully qualified canonical final HTTP(S) URL, and include the current page under its own language value. Generate corresponding return annotations from one locale map, then verify the production HTML, target responses, canonicals, and the target search engine's current requirements. Do not add x-default solely to clear this finding.".into()),
            raw_data: Some(serde_json::json!({
                "html_annotation_count": annotations.len(),
                "languages": annotations.iter().map(|(language, _)| language).collect::<Vec<_>>(),
                "x_default_present": has_default,
                "incomplete_annotation_count": incomplete_count,
                "non_absolute_href_count": non_absolute_count,
                "language_self_reference_present": has_language_self_reference,
                "http_header_annotations_inspected": false,
                "sitemap_annotations_inspected": false,
                "target_responses_inspected": false,
                "return_links_inspected_here": false,
            })),
            confidence: if has_issue {
                crate::checks::IssueConfidence::NeedsReview
            } else {
                crate::checks::IssueConfidence::High
            },
            confidence_reason: has_issue.then(|| "The HTML attributes are directly observed, but SiteCMD did not validate the language values, alternate targets, equivalent content, other annotation channels, or target-consumer processing.".into()),
            why_it_matters: has_issue.then(|| "A malformed or incomplete HTML alternate set may be ignored or misinterpreted by consumers that process hreflang. The actual effect depends on the target consumer and any annotations delivered through other supported channels.".into()),
        }]
    }
}
