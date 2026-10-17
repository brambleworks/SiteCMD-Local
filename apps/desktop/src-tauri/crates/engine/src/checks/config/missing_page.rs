//! Portable custom-404 probe plan and verdicts.

use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};
use crate::probe::{BodyPolicy, ProbeOutcome, ProbeRequest, BROWSER_PAGE_ACCEPT};

/// Reproducible path that is deliberately unlikely to be a real route.
pub const MISSING_PAGE_PATH: &str = "/this-page-definitely-does-not-exist-shk-test";

/// The probe request: the status line is the primary evidence and the body
/// only refines it (404-page substance), so the body is read regardless of
/// status and its absence degrades rather than reclassifying.
///
/// The browser `Accept` is load-bearing rather than cosmetic: this check
/// grades the response a visitor would land on, and origins that
/// content-negotiate serve a terse machine body to a `*/*` client and the
/// branded page to a browser.
pub fn missing_page_probe_request(origin_with_port: &str) -> ProbeRequest {
    ProbeRequest::get(format!("{origin_with_port}{MISSING_PAGE_PATH}"))
        .body(BodyPolicy::Always)
        .header("Accept", BROWSER_PAGE_ACCEPT)
}

/// The localhost-preview result: local preview servers often return their
/// own generic 404 page, so the deployed target is what matters.
pub fn localhost_skip_result() -> CheckResult {
    CheckResult {
        check_id: "config.custom_404".into(),
        category: ScanCategory::Polish,
        title: "Custom 404 page".into(),
        description: "Skipped on localhost preview. Local preview servers often return their own generic 404 page, so this is worth checking on a deployed preview or staging URL instead.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"reason": "localhost_preview_server"})),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// Classification of a probe for a definitely missing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingPageKind {
    /// 404 with a body long enough to look like a branded page.
    CustomPage,
    /// 404 with a short body: a bare server-default error page.
    ServerDefault,
    /// 2xx for the generated missing-looking path: a likely soft 404.
    Soft404,
    /// Some other non-404 status (301, 410,...).
    WrongStatus,
    /// The origin throttled, challenged, or failed the probe (429, 403, 5xx),
    /// so it never answered the question this check asks.
    Blocked,
}

/// Statuses that say the origin declined to serve this request rather than
/// that missing paths behave this way. A throttled or challenged probe is the
/// scanner's own traffic pattern coming back, and a 5xx is the origin failing;
/// none of them observed the site's handling of an absent path.
fn probe_was_refused(status_code: u16) -> bool {
    matches!(status_code, 403 | 429) || (500..600).contains(&status_code)
}

pub fn missing_page_kind(status_code: u16, body_len: usize) -> MissingPageKind {
    if status_code == 404 {
        if body_len > 500 {
            MissingPageKind::CustomPage
        } else {
            MissingPageKind::ServerDefault
        }
    } else if (200..300).contains(&status_code) {
        MissingPageKind::Soft404
    } else if probe_was_refused(status_code) {
        MissingPageKind::Blocked
    } else {
        MissingPageKind::WrongStatus
    }
}

/// The verdict for a probe the origin refused to answer. Reported as skipped
/// with the observed status rather than graded, because no missing-path
/// behavior was seen.
fn blocked_probe_result(status_code: u16) -> CheckResult {
    CheckResult {
        check_id: "config.custom_404".into(),
        category: ScanCategory::Polish,
        title: "Custom 404 page".into(),
        description: format!(
            "The probe was rate-limited or blocked: the generated missing-looking path returned HTTP {status_code}, which is the origin declining this request rather than its handling of a missing page. No 404 behavior was observed, so this scan produced no verdict."
        ),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({
            "status_code": status_code,
            "reason": "probe_rate_limited_or_blocked",
        })),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// Grade a confirmed 404 without inferring the size of an unread body.
fn unread_404_result() -> CheckResult {
    CheckResult {
        check_id: "config.custom_404".into(),
        category: ScanCategory::Polish,
        title: "404 status; response body not read".into(),
        description: "The generated missing-looking path returned HTTP 404. The response body was not read, so its size and content were not evaluated and it is not treated as a short body.".into(),
        status: CheckStatus::Pass,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"status_code": 404, "body_read": false})),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// Grade the missing-page probe outcome.
pub fn evaluate_missing_page(outcome: ProbeOutcome) -> Vec<CheckResult> {
    let ProbeOutcome::Response(response) = outcome else {
        return vec![CheckResult {
            check_id: "config.custom_404".into(),
            category: ScanCategory::Polish,
            title: "Custom 404 page".into(),
            description: "Could not test 404 page.".into(),
            status: CheckStatus::Skipped,
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }];
    };

    let status_code = response.status;
    if status_code == 404 && response.body.is_none() {
        return vec![unread_404_result()];
    }
    let body_len = response.body.as_ref().map_or(0, |body| body.text.len());
    let kind = missing_page_kind(status_code, body_len);
    if kind == MissingPageKind::Blocked {
        return vec![blocked_probe_result(status_code)];
    }
    let is_custom = kind == MissingPageKind::CustomPage;
    // A 2xx for the generated missing-looking path is a likely soft 404. One
    // probe cannot establish how every unknown URL behaves or whether an
    // unusual wildcard route is intentional.
    let is_soft_404 = kind == MissingPageKind::Soft404;
    let title = if is_custom {
        // Deliberately a measurement, not a characterization: plenty of sites
        // serve their homepage body under a 404 status, and calling that an
        // error page would be a claim this probe cannot support.
        format!("404 status with a {body_len}-byte body")
    } else if status_code == 404 {
        "404 response body is minimal".to_string()
    } else if is_soft_404 {
        format!(
            "Missing pages return HTTP {} (soft 404) instead of 404",
            status_code
        )
    } else {
        format!("Missing page returns HTTP {} instead of 404", status_code)
    };
    vec![CheckResult {
        check_id: "config.custom_404".into(),
        category: ScanCategory::Polish,
        title,
        description: if is_custom {
            "The generated missing-looking path returned HTTP 404 with a response body over 500 bytes. That confirms the status and the size of what came back, and nothing more: body length does not establish that the response is a purpose-built error page rather than the homepage served under a 404, nor that it is branded, accessible, useful, or consistent with the rest of the site.".into()
        } else if status_code == 404 {
            "The generated missing-looking path returned HTTP 404 with a short response body. It may be an intentional minimal API response or a generic server page; inspect it in a browser before deciding that a richer recovery experience is appropriate.".into()
        } else if is_soft_404 {
            format!(
                "The generated missing-looking path returned HTTP {} instead of 404, which is a likely soft-404 signal. This one probe does not establish that every unknown URL behaves this way or that search engines will classify the response as a soft 404. If the path is genuinely absent, a success status can confuse users and automated link/crawl handling and may cause search engines to exclude the response or spend crawl capacity on non-existent URLs.",
                status_code
            )
        } else {
            format!(
                "A page that does not exist returned HTTP {} instead of a 404.",
                status_code
            )
        },
        status: if is_custom {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: if is_custom {
            None
        } else if is_soft_404 {
            Some("Make unknown paths return a real HTTP 404 (or 410) status, then style that 404 response as a branded page. On SPA hosts, configure the platform's 404 handling instead of a blanket 200 catch-all: Netlify/Vercel/Cloudflare Pages all support a real 404 for unmatched routes.".into())
        } else {
            Some("Add a real 404 page with your normal navigation, a short explanation, and one or two clear ways back to working content.".into())
        },
        raw_data: Some(serde_json::json!({
            "status_code": status_code,
            "body_length": body_len,
            "soft_404": is_soft_404,
        })),
        confidence: if is_soft_404 {
            crate::checks::IssueConfidence::NeedsReview
        } else {
            crate::checks::IssueConfidence::High
        },
        confidence_reason: if is_soft_404 {
            Some("One generated missing-looking path returned a 2xx response; wildcard routing intent, response meaning, and other unknown paths were not evaluated.".into())
        } else {
            None
        },
        why_it_matters: if is_custom {
            None
        } else if is_soft_404 {
            Some("For genuinely absent content, an accurate 404 or 410 status helps users, crawlers, caches, and link checkers distinguish missing resources from successful pages.".into())
        } else {
            Some("A minimal 404 can be correct for an API, while a user-facing site may benefit from clear recovery links; the right treatment depends on the route and audience.".into())
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_hundred_on_missing_path_is_a_soft_404() {
        // The soft-404 case  called out: a catch-all 200
        // means broken-link checks never see a failure.
        assert_eq!(missing_page_kind(200, 4000), MissingPageKind::Soft404);
        assert_eq!(missing_page_kind(204, 0), MissingPageKind::Soft404);
    }

    #[test]
    fn real_404s_are_classified_by_body_length_not_as_soft() {
        assert_eq!(missing_page_kind(404, 1200), MissingPageKind::CustomPage);
        assert_eq!(missing_page_kind(404, 80), MissingPageKind::ServerDefault);
    }

    #[test]
    fn other_statuses_are_wrong_status_not_soft() {
        assert_eq!(missing_page_kind(301, 0), MissingPageKind::WrongStatus);
        assert_eq!(missing_page_kind(410, 0), MissingPageKind::WrongStatus);
    }

    #[test]
    fn a_throttled_or_challenged_probe_is_not_a_verdict_about_missing_pages() {
        for status in [403u16, 429, 500, 502, 503, 504] {
            assert_eq!(
                missing_page_kind(status, 0),
                MissingPageKind::Blocked,
                "HTTP {status} is the origin declining the probe, not its 404 behavior"
            );
        }
    }

    fn graded(status: u16, body: &str) -> CheckResult {
        let outcome = ProbeOutcome::Response(crate::probe::ProbeResponse {
            status,
            final_url: "https://example.com/x".into(),
            content_type: Some("text/html".into()),
            content_length: None,
            headers: Vec::new(),
            body: Some(crate::probe::ProbeBody {
                text: body.to_string(),
                bytes: body.len(),
                utf8_valid: true,
            }),
        });
        evaluate_missing_page(outcome).remove(0)
    }

    #[test]
    fn a_rate_limited_probe_reports_no_verdict_instead_of_a_wrong_status_warning() {
        for status in [429u16, 503] {
            let result = graded(status, "");
            assert_eq!(
                result.status,
                CheckStatus::Skipped,
                "HTTP {status} must not be graded"
            );
            assert!(
                result.description.contains("rate-limited or blocked"),
                "got {}",
                result.description
            );
            assert!(
                !result.title.contains("instead of a 404"),
                "a refused probe must not claim the site returns {status} for missing pages"
            );
        }
    }

    #[test]
    fn a_substantial_body_is_reported_as_a_measurement_not_as_an_error_page() {
        // example.com serves its homepage body under a 404 status.
        let homepage_under_404 = "x".repeat(559);
        let result = graded(404, &homepage_under_404);
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.title, "404 status with a 559-byte body");
        assert!(
            !result.title.contains("error page"),
            "body length does not establish that the response is an error page"
        );
    }

    #[test]
    fn an_unread_404_body_is_neither_minimal_nor_measured() {
        let outcome = ProbeOutcome::Response(crate::probe::ProbeResponse {
            status: 404,
            final_url: "https://example.com/x".into(),
            content_type: Some("text/html".into()),
            content_length: Some(524_289),
            headers: Vec::new(),
            body: None,
        });
        let result = evaluate_missing_page(outcome).remove(0);
        assert_ne!(result.title, "404 response body is minimal");
        assert_eq!(result.status, CheckStatus::Pass);
        assert_eq!(result.title, "404 status; response body not read");
        assert!(result.description.contains("body was not read"));
        assert!(result.description.contains("not treated as a short body"));
        assert!(!result.title.contains("byte"));
        assert!(!result.description.contains("byte"));
        assert_eq!(
            result.raw_data,
            Some(serde_json::json!({"status_code": 404, "body_read": false}))
        );
        assert!(result.manual_fix.is_none());
    }

    #[test]
    fn the_probe_asks_for_a_page_the_way_a_browser_does() {
        // Content-negotiating origins serve a terse machine body to `*/*`
        // clients, which is not the response this check is meant to grade.
        let request = missing_page_probe_request("https://example.com");
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("accept")
                    && value == crate::probe::BROWSER_PAGE_ACCEPT),
            "got {:?}",
            request.headers
        );
    }
}
