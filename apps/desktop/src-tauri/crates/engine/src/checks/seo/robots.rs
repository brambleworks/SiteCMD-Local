//! Portable robots.txt parsing and `seo.robots_txt` verdicts.
//! Runtimes own fetching; this module owns classification and grading.

use crate::checks::seo::robots_directives::has_sitemap_directive;
use crate::checks::seo::robots_document::records;
use crate::checks::{
    looks_like_html_shell, CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity,
};
use crate::probe::{ProbeOutcome, ProbeResponse};

/// Outcome of the shared per-scan robots.txt fetch. Several checks inspect
/// robots.txt with different semantics (content, missing, unreachable), so
/// the memo keeps the full outcome rather than just a body.
#[derive(Debug)]
pub enum RobotsTxtFetch {
    /// 2xx response with a readable non-HTML-shell body.
    Found { body: String },
    /// A readable robots.txt body served as text/html instead of text/plain.
    FoundWithHtmlType { body: String },
    /// Reachable but non-2xx.
    Status(u16),
    /// A non-2xx response intercepted by a bot challenge.
    Challenged(u16),
    /// A 2xx response whose body is an HTML page rather than a robots.txt: a
    /// catch-all route answered for the path. The endpoint responded, so this
    /// is not a network failure and re-running will not change it.
    HtmlShell,
    /// Network-level failure or an unreadable body.
    Error(String),
}

impl RobotsTxtFetch {
    /// The readable policy body, including one sent with an HTML media type.
    pub fn body(&self) -> Option<&str> {
        match self {
            Self::Found { body } | Self::FoundWithHtmlType { body } => Some(body),
            _ => None,
        }
    }
}

/// The canonical robots.txt probe URL for a scanned page.
pub fn robots_txt_url(page_url: &url::Url) -> String {
    format!("{}/robots.txt", crate::checks::origin_with_port(page_url))
}

/// Whether a non-success response was intercepted before robots.txt answered.
pub(super) fn robots_response_is_challenged(response: &ProbeResponse) -> bool {
    !(200..300).contains(&response.status)
        && response
            .header("cf-mitigated")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("challenge"))
}

/// Classify a completed robots.txt probe. A read failure (timeout mid-body
/// or exceeding the probe size cap) must not collapse into an empty `Found`.
/// A genuinely empty 2xx body still resolves to `Found`.
pub fn robots_fetch_from_probe(outcome: ProbeOutcome) -> RobotsTxtFetch {
    match outcome {
        ProbeOutcome::Response(response) if (200..300).contains(&response.status) => {
            let content_type = response
                .content_type
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase();
            match response.body {
                Some(body) => {
                    let html_type =
                        content_type.split(';').next().unwrap_or_default().trim() == "text/html";
                    let html_body = body.text.trim_start_matches('\u{feff}').trim_start();
                    if looks_like_html_shell("", &body.text)
                        || (html_type && html_body.starts_with('<'))
                    {
                        RobotsTxtFetch::HtmlShell
                    } else if html_type {
                        RobotsTxtFetch::FoundWithHtmlType { body: body.text }
                    } else {
                        RobotsTxtFetch::Found { body: body.text }
                    }
                }
                None => RobotsTxtFetch::Error(
                    "could not read /robots.txt (the response body was unavailable)".into(),
                ),
            }
        }
        ProbeOutcome::Response(response) if robots_response_is_challenged(&response) => {
            RobotsTxtFetch::Challenged(response.status)
        }
        ProbeOutcome::Response(response) => RobotsTxtFetch::Status(response.status),
        ProbeOutcome::Failure(failure) => RobotsTxtFetch::Error(failure.detail),
    }
}

/// One robots.txt group: the user agents naming it and whether its own
/// rules disallow the site root (with no same-group `Allow: /` re-opening
/// it). Agents are lowercased.
pub struct RobotsGroup {
    pub agents: Vec<String>,
    pub root_disallow: bool,
    pub has_allow_rule: bool,
    pub blocks_root: bool,
}

/// Parse crawler groups, including consecutive `User-agent:` lines that share
/// the following rule block.
pub fn robots_groups(body: &str) -> Vec<RobotsGroup> {
    let mut groups: Vec<RobotsGroup> = Vec::new();
    let mut current_agents: Vec<String> = Vec::new();
    let mut seen_rule = false;
    let mut disallow_root = false;
    let mut has_allow_rule = false;

    for (directive, value) in records(body) {
        let directive = directive.to_ascii_lowercase();
        if directive == "user-agent" {
            // A user-agent line after a rule line begins a new group;
            // close out the group we are leaving first.
            if seen_rule {
                groups.push(RobotsGroup {
                    agents: std::mem::take(&mut current_agents),
                    root_disallow: disallow_root,
                    has_allow_rule,
                    blocks_root: disallow_root && !has_allow_rule,
                });
                seen_rule = false;
                disallow_root = false;
                has_allow_rule = false;
            }
            if !value.is_empty() {
                current_agents.push(value.to_ascii_lowercase());
            }
            continue;
        }
        if current_agents.is_empty() {
            continue;
        }
        seen_rule = true;
        if directive == "disallow" {
            if matches!(value, "/" | "/*") {
                disallow_root = true;
            }
        } else if directive == "allow" && !value.is_empty() {
            // Any explicit exception means `Disallow: /` is not a
            // literal whole-site block. This conservative summary does
            // not attempt a full path-pattern crawl simulation.
            has_allow_rule = true;
        }
    }
    if !current_agents.is_empty() {
        groups.push(RobotsGroup {
            agents: current_agents,
            root_disallow: disallow_root,
            has_allow_rule,
            blocks_root: disallow_root && !has_allow_rule,
        });
    }
    groups
}

/// Whether the `User-agent: *` group itself disallows the entire site.
pub fn wildcard_blocks_entire_site(body: &str) -> bool {
    let groups = robots_groups(body);
    let wildcard_groups: Vec<_> = groups
        .iter()
        .filter(|group| group.agents.iter().any(|agent| agent == "*"))
        .collect();
    wildcard_groups.iter().any(|group| group.root_disallow)
        && !wildcard_groups.iter().any(|group| group.has_allow_rule)
}

/// Grade the `seo.robots_txt` outcome from the shared fetch. Missing files
/// and Sitemap directives are optional and are not treated as defects; a
/// root-wide wildcard block with no `Allow` exception or an HTML media type warns.
pub fn evaluate_robots_txt(fetch: &RobotsTxtFetch) -> Vec<CheckResult> {
    let mut rows = match fetch {
        RobotsTxtFetch::Found { body } | RobotsTxtFetch::FoundWithHtmlType { body } => {
            // A wildcard group is a fallback. More-specific user-agent
            // groups can override it, so do not call this "all crawlers."
            let wildcard_default_block = wildcard_blocks_entire_site(body);

            // Check for sitemap reference
            let has_sitemap = has_sitemap_directive(body);

            vec![CheckResult {
                check_id: "seo.robots_txt".into(),
                category: ScanCategory::Seo,
                title: if wildcard_default_block {
                    "robots.txt broadly blocks crawling by default".into()
                } else {
                    "Robots.txt policy observed".into()
                },
                description: if wildcard_default_block {
                    "The `User-agent: *` fallback group has `Disallow: /` (or `/*`) and no nonempty `Allow` exception. Compliant crawlers that select this wildcard group are instructed not to crawl the site. A crawler with a more-specific matching group may use that group instead, so this check does not claim every crawler is blocked.".into()
                } else if has_sitemap {
                    "robots.txt is present, includes a Sitemap directive, and has no root-wide wildcard block without an Allow exception. This bounded check does not validate every path pattern, crawler-specific group, sitemap target, robots syntax edge case, CDN policy, or actual crawler behavior.".into()
                } else {
                    "robots.txt is present with no root-wide wildcard block without an Allow exception. No Sitemap directive was observed, but that directive is an optional discovery hint and its absence does not block crawling or indexing.".into()
                },
                status: if wildcard_default_block {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Pass
                },
                severity: if wildcard_default_block {
                    Severity::High
                } else {
                    Severity::Low
                },
                fix_prompt: None,
                manual_fix: if wildcard_default_block {
                    Some("Confirm whether the wildcard block is intentional for this environment. If public crawling is intended, remove the root-wide `Disallow: /`/`/*`, narrow it to the sensitive paths that should not be crawled, or add explicit crawler groups only when policy requires them. Preserve authentication for private data because robots.txt is not access control. Test representative important URLs with the crawler groups and edge controls that matter.".into())
                } else {
                    None
                },
                raw_data: Some(serde_json::json!({
                    "has_sitemap_directive": has_sitemap,
                    "wildcard_default_block": wildcard_default_block,
                    "specific_user_agent_overrides_evaluated": false,
                })),
                confidence: if wildcard_default_block {
                    IssueConfidence::NeedsReview
                } else {
                    IssueConfidence::High
                },
                confidence_reason: if wildcard_default_block {
                    Some("The wildcard rule is directly observed, but specific crawler groups, path-pattern precedence beyond this conservative summary, and edge-level access can change the effective result for a given crawler.".into())
                } else {
                    None
                },
                why_it_matters: if wildcard_default_block {
                    Some("For crawlers that fall back to the wildcard group, a root-wide disallow prevents normal crawling and can impair discovery or refresh. Intentional staging/private-site policies may make that the desired outcome.".into())
                } else {
                    None
                },
            }]
        }
        RobotsTxtFetch::Status(code) | RobotsTxtFetch::Challenged(code)
            if matches!(*code, 404 | 410) =>
        {
            let mut result = missing_robots_result();
            result.raw_data = Some(serde_json::json!({
                "robots_policy_evaluated": false,
                "status_code": code,
                "confirmed_missing": true,
            }));
            result.confidence = IssueConfidence::High;
            result.confidence_reason = None;
            vec![result]
        }
        RobotsTxtFetch::Status(code) if (500..600).contains(code) => {
            vec![robots_server_error_result(*code)]
        }
        RobotsTxtFetch::Status(code) | RobotsTxtFetch::Challenged(code) => {
            vec![robots_unavailable_result(
                Some(*code),
                "robots.txt returned a non-success response",
            )]
        }
        RobotsTxtFetch::HtmlShell => vec![robots_html_shell_result()],
        RobotsTxtFetch::Error(_) => vec![robots_unavailable_result(
            None,
            "the robots.txt request failed",
        )],
    };
    if matches!(fetch, RobotsTxtFetch::FoundWithHtmlType { .. }) {
        for row in &mut rows {
            if row.status == CheckStatus::Pass {
                row.status = CheckStatus::Warn;
                row.title = "Robots.txt is served as text/html".into();
            }
            row.description
                .push_str(" robots.txt is served as text/html; text/plain is expected.");
            let fix = "Serve robots.txt with a Content-Type header of text/plain.";
            row.manual_fix = Some(match row.manual_fix.take() {
                Some(existing) => format!("{existing} {fix}"),
                None => fix.into(),
            });
        }
    }
    rows
}

/// Result for a robots.txt path answered by an HTML catch-all route. The
/// endpoint responded, so the copy must not call this a failed request or ask
/// for a re-run.
pub fn robots_html_shell_result() -> CheckResult {
    CheckResult {
        check_id: "seo.robots_txt".into(),
        category: ScanCategory::Seo,
        title: "Robots.txt policy not evaluated".into(),
        description: "robots.txt answered with an HTML page (catch-all rewrite), not a robots.txt file, so no rules could be parsed and no robots policy conclusion was made. Serve the file as text/plain from that path if crawl rules are intended.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({
            "robots_policy_evaluated": false,
            "html_catch_all": true,
            "probe_conclusive": false,
        })),
        confidence: IssueConfidence::High,
        confidence_reason: Some(
            "The response body is an HTML document, so the endpoint served a page rather than a robots.txt."
                .into(),
        ),
        why_it_matters: None,
    }
}

/// Result for a confirmed missing robots.txt response.
fn missing_robots_result() -> CheckResult {
    CheckResult {
        check_id: "seo.robots_txt".into(),
        category: ScanCategory::Seo,
        title: "No robots.txt file".into(),
        description: "robots.txt is absent. Under the standard missing-file behavior, that means no robots crawl restrictions; publishing the optional file is useful only when the operator needs crawl rules or a Sitemap discovery hint.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"robots_policy_evaluated": false, "confirmed_missing": true})),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

fn robots_unavailable_result(status_code: Option<u16>, observation: &str) -> CheckResult {
    CheckResult {
        check_id: "seo.robots_txt".into(),
        category: ScanCategory::Seo,
        title: "Robots.txt policy not evaluated".into(),
        description: format!(
            "{}{}; no robots policy conclusion was made. Re-run when the endpoint is readable.",
            observation,
            status_code
                .map(|code| format!(" (HTTP {code})"))
                .unwrap_or_default()
        ),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({
            "robots_policy_evaluated": false,
            "status_code": status_code,
            "probe_conclusive": false,
        })),
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: Some(
            "The endpoint did not return a readable robots.txt body, so rules could not be parsed."
                .into(),
        ),
        why_it_matters: None,
    }
}

fn robots_server_error_result(code: u16) -> CheckResult {
    CheckResult {
        check_id: "seo.robots_txt".into(),
        category: ScanCategory::Seo,
        title: "robots.txt answers a server error".into(),
        description: format!("robots.txt answered HTTP {code}. While it answers a server error, crawlers that follow the robots.txt standard (RFC 9309) treat every page on the site as disallowed, and Google pauses crawling the site."),
        status: CheckStatus::Fail,
        severity: Severity::High,
        fix_prompt: None,
        manual_fix: Some("Make /robots.txt answer HTTP 200 with the file, or 404 if the site has no crawl rules. Check the server, CDN or framework route that serves it.".into()),
        raw_data: Some(serde_json::json!({
            "robots_policy_evaluated": false, "status_code": code, "server_error": true,
        })),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: Some("Search engines that follow the robots.txt standard stop crawling the site while robots.txt answers a server error, so new and changed pages are not picked up.".into()),
    }
}

#[cfg(test)]
#[path = "robots_tests.rs"]
mod tests;
