//! Point-impact and fix-applicability classification for CLI output.

use crate::core::scan_types::{actionable, CheckResult};

/// Where a fix needs to happen - narrows the actionable surface for each issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability {
    /// The fix lives in source code (framework config, middleware, component).
    Code,
    /// The fix lives in server / hosting / infra configuration.
    Config,
    /// The fix requires changing copy, images, or page content.
    Content,
}

impl Applicability {
    /// Short bracketed tag for inline CLI output, e.g. `"{code}"`.
    pub fn tag(&self) -> &'static str {
        match self {
            Applicability::Code => "{code}",
            Applicability::Config => "{config}",
            Applicability::Content => "{content}",
        }
    }

    /// Plain label, e.g. `"code"`.
    pub fn label(&self) -> &'static str {
        match self {
            Applicability::Code => "code",
            Applicability::Config => "config",
            Applicability::Content => "content",
        }
    }
}

/// A `CheckResult` annotated with its rank and
/// applicability classification.
pub struct RankedIssue<'a> {
    pub issue: &'a CheckResult,
    /// 1-indexed rank (1 = highest impact).
    pub rank: usize,
    /// Position among actionable findings before sorting.
    pub actionable_index: usize,
    /// Where the fix needs to happen.
    pub applicability: Applicability,
}

/// Frameworks that support file-based security header configuration.
const FRAMEWORK_CONFIG_HEADERS: &[&str] =
    &["Next.js", "Nuxt", "Astro", "Remix", "SvelteKit", "Gatsby"];

/// Locate the likely fix surface for a check and detected stack.
pub fn classify_applicability(
    check_id: &str,
    detected_stack: Option<&serde_json::Value>,
) -> Applicability {
    let stack_field = |field: &str| -> Option<&str> {
        detected_stack
            .and_then(|v| v.get(field))
            .and_then(|v| v.as_str())
    };

    if check_id.contains("security_header") || check_id.contains("headers.") {
        // If the project uses a framework that handles headers via config files,
        // the fix is a code/config-file change in that framework.
        let framework = stack_field("framework")
            .or_else(|| stack_field("js_framework"))
            .unwrap_or("");
        let has_framework_config = FRAMEWORK_CONFIG_HEADERS
            .iter()
            .any(|f| framework.contains(f));
        return if has_framework_config {
            Applicability::Code
        } else {
            Applicability::Config
        };
    }

    if check_id.starts_with("security.https")
        || check_id.starts_with("security.tls")
        || check_id.contains("https")
        || check_id.contains("tls")
        || check_id.contains("ssl")
        || check_id.contains("hsts")
    {
        return Applicability::Config;
    }

    if check_id.starts_with("security.") {
        return Applicability::Code;
    }

    if check_id == "performance.ttfb" || check_id.contains("ttfb") {
        return Applicability::Config;
    }

    if check_id.starts_with("performance.") {
        return Applicability::Code;
    }

    if check_id.starts_with("seo.") {
        return Applicability::Code;
    }

    if check_id.contains("alt_text")
        || check_id.contains("image_alt")
        || check_id.contains("alt-text")
    {
        return Applicability::Content;
    }

    if check_id.starts_with("accessibility.") {
        return Applicability::Code;
    }

    if check_id.contains("privacy")
        || check_id.contains("cookie")
        || check_id.contains("gdpr")
        || check_id.contains("ccpa")
    {
        return Applicability::Content;
    }

    if check_id.starts_with("compliance.") {
        return Applicability::Code;
    }

    if check_id.contains("copy")
        || check_id.contains("content")
        || check_id.contains("text")
        || check_id.starts_with("polish.copy_content")
    {
        return Applicability::Content;
    }

    if check_id.starts_with("polish.") {
        return Applicability::Code;
    }

    Applicability::Code
}

/// Rank by severity and verdict, preserving scan order for ties.
pub fn rank_issues<'a>(
    issues: &'a [CheckResult],
    detected_stack: Option<&serde_json::Value>,
) -> Vec<RankedIssue<'a>> {
    let mut ranked: Vec<_> = actionable(issues)
        .filter_map(|issue| Some((issue.status.fix_priority(issue.severity)?, issue)))
        .enumerate()
        .collect();
    ranked.sort_by_key(|(_, (priority, _))| *priority);

    ranked
        .into_iter()
        .enumerate()
        .map(|(i, (actionable_index, (_, r)))| RankedIssue {
            issue: r,
            rank: i + 1,
            actionable_index,
            applicability: classify_applicability(&r.check_id, detected_stack),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan_types::{CheckResult, CheckStatus, Severity};

    fn make_result(check_id: &str, severity: Severity, status: CheckStatus) -> CheckResult {
        CheckResult {
            covered: false,
            check_id: check_id.to_string(),
            category: None,
            title: check_id.to_string(),
            description: String::new(),
            status,
            severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::core::scan_types::IssueConfidence::High,
            confidence_reason: None,
            skip_reason: None,
            why_it_matters: None,
        }
    }

    #[test]
    fn a_critical_outranks_a_high_whatever_its_category() {
        // A critical finding ranks below a high one because of its category.
        let issues = [
            make_result(
                "config.placeholder_content",
                Severity::Critical,
                CheckStatus::Fail,
            ),
            make_result("security.csp", Severity::High, CheckStatus::Fail),
        ];
        assert_eq!(
            rank_issues(&issues, None)[0].issue.check_id,
            "config.placeholder_content"
        );
    }

    #[test]
    fn applicability_security_headers_with_nextjs() {
        let stack = serde_json::json!({ "framework": "Next.js", "js_framework": "React" });
        let result = classify_applicability("security_headers.x_frame_options", Some(&stack));
        assert_eq!(result, Applicability::Code);
    }

    #[test]
    fn applicability_security_headers_without_framework() {
        let stack = serde_json::json!({ "server": "nginx" });
        let result = classify_applicability("security_headers.x_frame_options", Some(&stack));
        assert_eq!(result, Applicability::Config);
    }

    #[test]
    fn applicability_alt_text_is_content() {
        let result = classify_applicability("accessibility.alt_text", None);
        assert_eq!(result, Applicability::Content);
    }

    #[test]
    fn applicability_ttfb_is_config() {
        let result = classify_applicability("performance.ttfb", None);
        assert_eq!(result, Applicability::Config);
    }

    #[test]
    fn rank_issues_sorted_by_severity() {
        let issues = vec![
            make_result("performance.ttfb", Severity::Low, CheckStatus::Fail),
            make_result(
                "security.missing_csp",
                Severity::Critical,
                CheckStatus::Fail,
            ),
            make_result("seo.meta_description", Severity::Medium, CheckStatus::Warn),
        ];

        let ranked = rank_issues(&issues, None);

        assert_eq!(ranked.len(), 3);
        // Critical security should be rank 1 (highest impact)
        assert_eq!(ranked[0].issue.check_id, "security.missing_csp");
        assert_eq!(ranked[0].rank, 1);
        // Low performance (ttfb) should be lowest
        assert_eq!(ranked[2].issue.check_id, "performance.ttfb");
        assert_eq!(ranked[2].rank, 3);
    }
}
