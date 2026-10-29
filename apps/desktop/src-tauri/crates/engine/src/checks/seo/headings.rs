//! Static heading-outline review for the initial HTML response.
//! Multiple H1s and level jumps remain low-confidence review signals.

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use regex::Regex;
use std::sync::LazyLock;

/// Heading open tag with a real tag boundary, capturing the level.
static HEADING_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<h([1-6])[\s/>]").expect("valid heading regex"));

/// Remove comments, scripts, and styles before finding heading tags.
pub static NON_CONTENT_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<!--.*?-->|<script\b.*?</script>|<style\b.*?</style>")
        .expect("valid non-content regex")
});

/// Remove comments and scripts while keeping `<style>` blocks, for checks that
/// grade the page's CSS but must not read a comment as a stylesheet rule.
///
/// This and `NON_CONTENT_BLOCK_RE` are markup helpers rather than heading
/// helpers, and belong in a shared markup module. They live here because that
/// is where the first one landed and because callers across every category
/// already reach for `seo::headings::NON_CONTENT_BLOCK_RE`; moving both is a
/// rename for whichever change owns `checks/html_attrs.rs` next.
pub static COMMENT_AND_SCRIPT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<!--.*?-->|<script\b.*?</script>").expect("valid comment/script regex")
});

/// Heading levels in document order from comment/script/style-stripped markup.
pub(crate) fn heading_levels(ctx: &PageContext) -> Vec<u8> {
    let scannable = NON_CONTENT_BLOCK_RE.replace_all(ctx.body_lower(), " ");
    HEADING_TAG_RE
        .captures_iter(&scannable)
        .filter_map(|caps| caps[1].parse().ok())
        .collect()
}

/// The `seo.headings.h1` verdict from the ordered heading levels.
fn h1_result(levels: &[u8]) -> CheckResult {
    let h1_count = levels.iter().filter(|&&level| level == 1).count();
    CheckResult {
            check_id: "seo.headings.h1".into(),
            category: ScanCategory::Seo,
            title: match h1_count {
                0 => "No H1 element detected in initial HTML".into(),
                1 => "H1 element detected".into(),
                _ => "Multiple H1 elements detected in initial HTML".into(),
            },
            description: match h1_count {
                0 => "No H1 element was found in the initial HTML response. Many content pages benefit from a clear page-level heading, but a client-rendered heading or a document whose structure does not require H1 cannot be ruled out by this static response check."
                    .into(),
                1 => "One H1 element was found in the initial HTML response.".into(),
                n => format!(
                    "{} H1 elements were found in the initial HTML response. Multiple H1 elements are not automatically an SEO or accessibility failure; review whether each one labels a distinct top-level section and whether the rendered outline makes the page's primary topic clear.",
                    n
                ),
            },
            status: if h1_count == 1 {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if h1_count == 0 {
                Some("Inspect the rendered accessibility tree and heading list first. If the page has a primary content topic but no page-level heading, mark that visible heading with the level that correctly represents the outline. Do not add an empty or visually hidden H1 solely to satisfy the scanner.".into())
            } else if h1_count > 1 {
                Some("Review the rendered heading outline and the content sections each H1 labels. Keep multiple H1 elements when they accurately represent distinct top-level sections; otherwise change only the elements whose semantic level does not match their content role. Use CSS, not heading level, for visual sizing.".into())
            } else {
                None
            },
            raw_data: Some(serde_json::json!({"h1_count": h1_count})),
            confidence: if h1_count == 1 {
                crate::checks::IssueConfidence::High
            } else {
                crate::checks::IssueConfidence::NeedsReview
            },
            confidence_reason: if h1_count == 1 {
                None
            } else {
                Some("Static initial-HTML count; rendered headings and document context require review.".into())
            },
            why_it_matters: match h1_count {
                0 => Some(
                    "A well-chosen page-level heading can make the primary content easier to identify and navigate, but its applicability depends on the rendered document structure.".into(),
                ),
                1 => None,
                _ => Some(
                    "An unclear heading outline can make content harder to scan and navigate. The count alone does not establish that the outline is unclear or that search visibility is harmed.".into(),
                ),
            },
    }
}

/// H1-count authority for the SEO category. Heading-order signals stay with
/// `accessibility.headings`.
pub struct H1Check;

impl Check for H1Check {
    fn id(&self) -> &str {
        "seo.headings.h1"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        vec![h1_result(&heading_levels(ctx))]
    }
}

pub struct HeadingCheck;

impl Check for HeadingCheck {
    fn id(&self) -> &str {
        "seo.headings"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        let levels = heading_levels(ctx);
        let mut results = vec![h1_result(&levels)];

        // Evaluate hierarchy in document order, not by the set of levels present.
        let mut last_level = 0u8;
        let mut skips: Vec<String> = Vec::new();
        for &level in &levels {
            if last_level > 0 && level > last_level + 1 {
                let skip = format!("H{} → H{}", last_level, level);
                if !skips.contains(&skip) {
                    skips.push(skip);
                }
            }
            last_level = level;
        }

        results.push(CheckResult {
            check_id: "seo.headings.hierarchy".into(), category: ScanCategory::Seo,
            title: if skips.is_empty() {
                "Heading hierarchy".into()
            } else {
                "Heading levels jump in initial HTML".into()
            },
            description: if skips.is_empty() {
                "No upward heading-level jumps were found in the initial HTML response.".into()
            } else {
                format!("The initial HTML response contains these upward heading-level jumps: {}. A jump can reveal that visual size rather than content structure selected the tag, but it is not automatically a WCAG or SEO failure and may be valid in context.", skips.join(", "))
            },
            status: if skips.is_empty() { CheckStatus::Pass } else { CheckStatus::Warn },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: if skips.is_empty() { None } else { Some("Inspect the rendered heading list and the content relationship at each surfaced jump. If a heading is a subsection, change it to the level that reflects its real parent; if the jump is intentional and the outline remains clear, no mechanical placeholder heading is needed. Use CSS for appearance.".into()) },
            raw_data: Some(serde_json::json!({"skips": skips})),
                confidence: if skips.is_empty() { crate::checks::IssueConfidence::High } else { crate::checks::IssueConfidence::NeedsReview },
                confidence_reason: if skips.is_empty() { None } else { Some("Static heading-sequence signal; rendered component and section context require review.".into()) },
                why_it_matters: if skips.is_empty() { None } else { Some("Unexpected heading jumps can make a document outline harder to understand for people scanning headings, including screen reader users. The sequence alone does not prove a barrier.".into()) },
        });

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Check, CheckStatus, PageContext};
    use http::header::HeaderMap;

    fn ctx(body: &str) -> PageContext {
        PageContext {
            evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: HeaderMap::new(),
            status_code: 200,
            body: body.to_string(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: Some("HTTP/2.0".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn test_headings_single_h1_pass() {
        let html = "<html><body><h1>Main Title</h1><h2>Section</h2></body></html>";
        let check = HeadingCheck;
        let results = check.run(&ctx(html));
        let h1 = results
            .iter()
            .find(|r| r.check_id == "seo.headings.h1")
            .unwrap();
        assert_eq!(h1.status, CheckStatus::Pass);
    }

    #[test]
    fn test_headings_no_h1_warns_for_review() {
        let html = "<html><body><h2>Subsection</h2><h3>Detail</h3></body></html>";
        let check = HeadingCheck;
        let results = check.run(&ctx(html));
        let h1 = results
            .iter()
            .find(|r| r.check_id == "seo.headings.h1")
            .unwrap();
        assert_eq!(h1.status, CheckStatus::Warn);
        assert_eq!(h1.severity, Severity::Low);
        assert_eq!(h1.confidence, crate::checks::IssueConfidence::NeedsReview);
        assert!(h1.description.contains("initial HTML response"));
        assert!(!h1.description.contains("exactly one"));
    }

    #[test]
    fn test_headings_multiple_h1_warns_for_review() {
        let html = "<html><body><h1>Title One</h1><h1>Title Two</h1></body></html>";
        let check = HeadingCheck;
        let results = check.run(&ctx(html));
        let h1 = results
            .iter()
            .find(|r| r.check_id == "seo.headings.h1")
            .unwrap();
        assert_eq!(h1.status, CheckStatus::Warn);
        assert_eq!(h1.severity, Severity::Low);
        assert_eq!(h1.confidence, crate::checks::IssueConfidence::NeedsReview);
        // Multiple H1s are not automatically an SEO or accessibility failure.
        assert!(
            h1.description.contains("not automatically"),
            "{}",
            h1.description
        );
        assert!(
            !h1.description.contains("exactly one"),
            "no exactly-one dogma: {}",
            h1.description
        );
        assert!(
            !h1.manual_fix
                .as_deref()
                .unwrap_or_default()
                .contains("Demote all but one"),
            "the fix must ask for a content-outline review, not a bulk rewrite: {:?}",
            h1.manual_fix
        );
    }

    #[test]
    fn hierarchy_copy_does_not_claim_crawler_confusion() {
        let html = "<html><body><h1>Title</h1><h3>Skipped</h3></body></html>";
        let results = HeadingCheck.run(&ctx(html));
        let hier = results
            .iter()
            .find(|r| r.check_id == "seo.headings.hierarchy")
            .unwrap();
        let why = hier.why_it_matters.as_deref().unwrap_or("");
        assert!(
            !why.contains("confuse crawlers"),
            "folklore claim must stay removed: {why}"
        );
    }

    #[test]
    fn test_headings_hierarchy_skip_warn() {
        let html = "<html><body><h1>Title</h1><h3>Skipped H2</h3></body></html>";
        let check = HeadingCheck;
        let results = check.run(&ctx(html));
        let hier = results
            .iter()
            .find(|r| r.check_id == "seo.headings.hierarchy")
            .unwrap();
        assert_eq!(hier.status, CheckStatus::Warn);
        assert_eq!(hier.severity, Severity::Low);
        assert_eq!(hier.confidence, crate::checks::IssueConfidence::NeedsReview);
        assert!(hier.description.contains("initial HTML response"));
        assert!(!hier
            .manual_fix
            .as_deref()
            .unwrap_or_default()
            .contains("Don't skip levels"));
    }

    #[test]
    fn test_headings_proper_hierarchy_pass() {
        let html = "<html><body><h1>Title</h1><h2>Sub</h2><h3>Detail</h3></body></html>";
        let check = HeadingCheck;
        let results = check.run(&ctx(html));
        let hier = results
            .iter()
            .find(|r| r.check_id == "seo.headings.hierarchy")
            .unwrap();
        assert_eq!(hier.status, CheckStatus::Pass);
        assert_eq!(hier.confidence, crate::checks::IssueConfidence::High);
    }

    #[test]
    fn test_headings_document_order_skip_detected_despite_level_presence() {
        let html = "<h1>T</h1><h2>A</h2><h4>Deep</h4><h3>Later</h3>";
        let results = HeadingCheck.run(&ctx(html));
        let hier = results
            .iter()
            .find(|r| r.check_id == "seo.headings.hierarchy")
            .unwrap();
        assert_eq!(hier.status, CheckStatus::Warn);
        assert!(hier.description.contains("H2 → H4"));
    }

    #[test]
    fn test_headings_ignore_comments_scripts_and_custom_elements() {
        let html = r#"
            <!-- <h1>old hero</h1> -->
            <script>var tpl = "<h1>{{title}}</h1>";</script>
            <h1-widget></h1-widget>
            <h1>Real Title</h1>
        "#;
        let results = HeadingCheck.run(&ctx(html));
        let h1 = results
            .iter()
            .find(|r| r.check_id == "seo.headings.h1")
            .unwrap();
        assert_eq!(h1.status, CheckStatus::Pass, "{}", h1.description);
    }

    #[test]
    fn h1_check_owns_the_h1_count_signal_under_seo() {
        let html = "<html><body><h1>One</h1><h1>Two</h1><h2>Sub</h2></body></html>";
        let results = H1Check.run(&ctx(html));
        assert_eq!(results.len(), 1, "H1Check reports only the H1-count signal");
        let h1 = &results[0];
        assert_eq!(h1.check_id, "seo.headings.h1");
        assert_eq!(h1.category, crate::checks::ScanCategory::Seo);
        assert_eq!(h1.status, CheckStatus::Warn);
        assert_eq!(h1.severity, Severity::Low);
        assert_eq!(h1.confidence, crate::checks::IssueConfidence::NeedsReview);
        assert_eq!(h1.raw_data.as_ref().unwrap()["h1_count"], 2);
    }

    #[test]
    fn h1_check_passes_a_single_h1() {
        let html = "<html><body><h1>Main</h1><h2>Sub</h2></body></html>";
        let results = H1Check.run(&ctx(html));
        assert_eq!(results[0].status, CheckStatus::Pass);
        assert_eq!(results[0].confidence, crate::checks::IssueConfidence::High);
    }

    #[test]
    fn h1_check_matches_the_heading_check_h1_result() {
        let html = "<html><body><h2>Only subheads</h2></body></html>";
        let from_h1_check = &H1Check.run(&ctx(html))[0];
        let shell = HeadingCheck.run(&ctx(html));
        let from_shell = shell
            .iter()
            .find(|r| r.check_id == "seo.headings.h1")
            .unwrap();
        assert_eq!(from_h1_check.status, from_shell.status);
        assert_eq!(from_h1_check.description, from_shell.description);
    }

    #[test]
    fn test_headings_returning_to_higher_level_is_not_a_skip() {
        let html = "<h1>T</h1><h2>A</h2><h3>B</h3><h2>C</h2><h3>D</h3>";
        let results = HeadingCheck.run(&ctx(html));
        let hier = results
            .iter()
            .find(|r| r.check_id == "seo.headings.hierarchy")
            .unwrap();
        assert_eq!(hier.status, CheckStatus::Pass);
    }
}
