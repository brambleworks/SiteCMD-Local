//! The canonical link and the viewport declaration.

use super::extract_attr_value;
use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};

pub struct CanonicalCheck;

impl Check for CanonicalCheck {
    fn id(&self) -> &str {
        "seo.canonical"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        // Token-aware attributes handle minified/unquoted markup without
        // accepting data-rel="canonical" or a rel token with no href.
        let scannable =
            crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(&ctx.body, " ");
        let lower = scannable.to_ascii_lowercase();
        let has_canonical = crate::checks::html_attrs::tag_slices(&scannable, &lower, "link")
            .into_iter()
            .any(|tag| {
                crate::checks::html_attrs::attr_value(tag, "rel").is_some_and(|rel| {
                    rel.split_whitespace()
                        .any(|token| token.eq_ignore_ascii_case("canonical"))
                }) && crate::checks::html_attrs::has_attr(tag, "href")
            });
        vec![CheckResult {
            check_id: "seo.canonical".into(),
            category: ScanCategory::Seo,
            title: if has_canonical {
                "Canonical URL".into()
            } else {
                "Missing canonical URL".into()
            },
            description: if has_canonical {
                "A rel=canonical declaration is present. This presence check does not validate its href, resolve redirects, compare it with the scanned URL, or prove that a search engine will select it.".into()
            } else {
                "No rel=canonical declaration was found in the fetched HTML. Search engines can infer a canonical without the tag; an explicit declaration is most useful when this content is reachable through duplicate or parameterized URLs.".into()
            },
            status: if has_canonical {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            // A missing canonical is hygiene risk, not an indexing block.
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if has_canonical {
                None
            } else {
                Some(
                    "If this page has duplicate, parameterized, or alternate URL variants, add one canonical link in `<head>` that points to the final public URL you prefer for indexing. Verify the absolute/relative URL resolves correctly in production and is itself crawlable and suitable for indexing; do not add a self-canonical solely to silence the check when it adds no value."
                        .into(),
                )
            },
            raw_data: None,
            confidence: if has_canonical {
                crate::checks::IssueConfidence::High
            } else {
                crate::checks::IssueConfidence::NeedsReview
            },
            confidence_reason: if has_canonical {
                None
            } else {
                Some("Absence in the fetched HTML is direct, but duplicate URL exposure, HTTP-header canonicals, framework/runtime injection, and search-engine canonical selection are outside this presence check.".into())
            },
            why_it_matters: if has_canonical {
                None
            } else {
                Some("Duplicate URL variants make it harder for crawlers to understand which page should be treated as the preferred version.".into())
            },
        }]
    }
}

pub struct ViewportCheck;

impl Check for ViewportCheck {
    fn id(&self) -> &str {
        "seo.viewport"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        // Parse tag attributes so quoted and unquoted minified forms agree.
        let scannable =
            crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(&ctx.body, " ");
        let scannable_lower = scannable.to_ascii_lowercase();
        let viewport_contents: Vec<String> =
            crate::checks::html_attrs::tag_slices(&scannable, &scannable_lower, "meta")
                .into_iter()
                .filter_map(|tag| {
                    extract_attr_value(tag, "name")
                        .filter(|value| value.eq_ignore_ascii_case("viewport"))
                        .map(|_| extract_attr_value(tag, "content").unwrap_or_default())
                })
                .collect();
        let viewport_content = viewport_contents.first().cloned();
        let viewport_tag_count = viewport_contents.len();
        let has_viewport = viewport_tag_count > 0;
        let has_device_width = viewport_contents.iter().any(|content| {
            content
                .split(',')
                .map(str::trim)
                .filter_map(|directive| directive.split_once('='))
                .any(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("width")
                        && value.trim().eq_ignore_ascii_case("device-width")
                })
        });
        let duplicate_viewports = viewport_tag_count > 1;
        let pass = has_device_width && !duplicate_viewports;
        vec![CheckResult {
            check_id: "seo.viewport".into(),
            category: ScanCategory::Seo,
            title: if duplicate_viewports {
                "Multiple viewport meta tags need review".into()
            } else if has_device_width {
                "Mobile viewport".into()
            } else if has_viewport {
                "Viewport configuration needs review".into()
            } else {
                "Missing viewport meta tag".into()
            },
            description: if duplicate_viewports && has_device_width {
                format!("Found {} viewport meta tags. At least one includes width=device-width, but multiple declarations can interact differently across clients and maintenance paths; consolidate to one intentional directive and test the rendered page. Presence still does not prove that the layout is mobile-friendly.", viewport_tag_count)
            } else if duplicate_viewports {
                format!("Found {} viewport meta tags, and neither includes width=device-width. Multiple declarations can interact differently across clients and maintenance paths; consolidate to one intentional directive that matches the target devices, then test the rendered page. Source markup alone does not prove that the layout is mobile-friendly or broken.", viewport_tag_count)
            } else if has_device_width {
                "A viewport declaration with width=device-width is present. This confirms the baseline device-width instruction only; it does not prove that the layout, text, controls, or responsive breakpoints are mobile-friendly.".into()
            } else if has_viewport {
                "A viewport meta tag is present, but its content does not include width=device-width. Fixed, empty, or unusual viewport rules may be intentional for a specialized document, so verify the target devices and rendered layout before changing it.".into()
            } else {
                "No viewport meta tag was observed in the initial HTML outside comments, scripts, and styles. Ordinary mobile browsers may use a wider default layout viewport, but this source observation does not prove that the rendered page is broken or that a specialized client requires the standard directive.".into()
            },
            status: if pass {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Medium,
            fix_prompt: None,
            manual_fix: if pass {
                None
            } else {
                Some("For an ordinary responsive web page, keep exactly one `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">` in `<head>`, remove conflicting duplicates, then test representative narrow, zoomed, large-text, and orientation states. Preserve a specialized fixed viewport only when the product explicitly requires it and the target clients are documented.".into())
            },
            raw_data: Some(serde_json::json!({
                "viewport_content": viewport_content,
                "viewport_contents": viewport_contents,
                "viewport_tag_count": viewport_tag_count,
                "has_device_width": has_device_width,
                "responsive_layout_verified": false,
            })),
            confidence: if pass {
                crate::checks::IssueConfidence::High
            } else {
                crate::checks::IssueConfidence::NeedsReview
            },
            confidence_reason: if pass {
                None
            } else {
                Some("Viewport declaration state is directly observed in the initial HTML, but specialized client intent, runtime changes, and rendered behavior were not measured by this source check.".into())
            },
            why_it_matters: if pass {
                None
            } else {
                Some("Without an appropriate viewport for the target devices, a page can render at an unintended virtual width and require horizontal panning or excessive zoom. Actual impact must be confirmed in the rendered layout.".into())
            },
        }]
    }
}
