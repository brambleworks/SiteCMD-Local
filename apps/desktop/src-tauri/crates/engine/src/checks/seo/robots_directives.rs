//! Portable robots.txt parsing and sitemap-directive verdicts.

use crate::checks::seo::robots_document::records;
use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};

/// Return whether robots.txt contains a nonempty, uncommented `Sitemap:` directive.
pub fn has_sitemap_directive(body: &str) -> bool {
    records(body).any(|(name, value)| name.eq_ignore_ascii_case("sitemap") && !value.is_empty())
}

use crate::checks::seo::robots::RobotsTxtFetch;

/// Grade sitemap directives while keeping missing files and network failures
/// distinct. The optional directive does not affect the score.
pub fn evaluate_sitemap_in_robots(outcome: &RobotsTxtFetch) -> Vec<CheckResult> {
    enum RobotsFetch {
        HasSitemap,
        NoSitemap,
        Status(u16),
        HtmlShell,
        NetworkError,
    }
    let fetch = match outcome {
        RobotsTxtFetch::Found { body } | RobotsTxtFetch::FoundWithHtmlType { body } => {
            if has_sitemap_directive(body) {
                RobotsFetch::HasSitemap
            } else {
                RobotsFetch::NoSitemap
            }
        }
        RobotsTxtFetch::Status(code) | RobotsTxtFetch::Challenged(code) => {
            RobotsFetch::Status(*code)
        }
        RobotsTxtFetch::HtmlShell => RobotsFetch::HtmlShell,
        RobotsTxtFetch::Error(_) => RobotsFetch::NetworkError,
    };

    let (status, title, description, manual_fix, why, confidence, confidence_reason, raw) = match &fetch {
        RobotsFetch::HasSitemap => (
            CheckStatus::Pass,
            "Sitemap in Robots.txt",
            "robots.txt includes a nonempty Sitemap directive. This confirms directive presence only; the target URL, sitemap syntax/content, canonical host, and crawler use are evaluated separately or require manual review.".to_string(),
            None,
            None,
            crate::checks::IssueConfidence::High,
            None,
            None,
        ),
        RobotsFetch::NoSitemap => (
            CheckStatus::Skipped,
            "No Sitemap directive in robots.txt",
            "robots.txt exists without a Sitemap directive. The directive is an optional discovery hint; absence does not block crawling, indexing, direct sitemap submission, or sitemap discovery through other channels, so no defect is inferred.".to_string(),
            None,
            None,
            crate::checks::IssueConfidence::High,
            None,
            Some(serde_json::json!({"robots_present": true, "has_sitemap_directive": false, "directive_optional": true})),
        ),
        RobotsFetch::Status(code) if matches!(code, 404 | 410) => (
            CheckStatus::Skipped,
            "No robots.txt file to inspect",
            format!("robots.txt returned HTTP {code}, confirming that no file was served at that endpoint. A missing robots file cannot contain a Sitemap directive, but both the file and directive are optional; the sitemap itself can still exist or be submitted elsewhere."),
            None,
            None,
            crate::checks::IssueConfidence::High,
            None,
            Some(serde_json::json!({"robots_status_code": code, "confirmed_missing": true, "has_sitemap_directive": false, "directive_optional": true})),
        ),
        RobotsFetch::Status(code) => (
            CheckStatus::Skipped,
            "Sitemap directive not evaluated",
            format!("robots.txt returned HTTP {code}. This non-success response does not establish that the endpoint is missing, so Sitemap directive presence was not evaluated; the optional directive is not scored from this inconclusive probe."),
            None,
            None,
            crate::checks::IssueConfidence::NeedsReview,
            Some("A non-success response other than a confirmed 404 or 410 leaves the endpoint state and body unavailable to this check.".to_string()),
            Some(serde_json::json!({"robots_status_code": code, "confirmed_missing": false, "probe_conclusive": false, "directive_optional": true})),
        ),
        RobotsFetch::HtmlShell => (
            CheckStatus::Skipped,
            "Sitemap directive not evaluated",
            "robots.txt answered with an HTML page (catch-all rewrite), so no directives could be read. The endpoint responded, so this is not a network failure; the optional directive is not scored as missing.".to_string(),
            None,
            None,
            crate::checks::IssueConfidence::High,
            Some("The response body is an HTML document, so the endpoint served a page rather than a robots.txt.".to_string()),
            Some(serde_json::json!({"robots_present": false, "html_catch_all": true, "probe_conclusive": false, "directive_optional": true})),
        ),
        RobotsFetch::NetworkError => (
            CheckStatus::Skipped,
            "Sitemap directive not evaluated",
            "The robots.txt request failed, so Sitemap directive presence was not evaluated. Re-run when the endpoint is reachable; the optional directive is not scored as missing from this inconclusive probe.".to_string(),
            None,
            None,
            crate::checks::IssueConfidence::NeedsReview,
            Some("robots.txt fetch failed; the check has no input.".to_string()),
            Some(serde_json::json!({"probe_conclusive": false, "directive_optional": true})),
        ),
    };

    vec![CheckResult {
        check_id: "config.sitemap_in_robots".into(),
        category: ScanCategory::Seo,
        title: title.into(),
        description,
        status,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix,
        raw_data: raw,
        confidence,
        confidence_reason,
        why_it_matters: why,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonempty_sitemap_directive_is_detected() {
        assert!(has_sitemap_directive(
            "User-agent: *\nAllow: /\nSitemap: https://sitecmd.com/sitemap-index.xml\n"
        ));
    }

    #[test]
    fn absence_is_detected_without_calling_it_a_warning() {
        assert!(!has_sitemap_directive("User-agent: *\nAllow: /\n"));
        let rows = evaluate_sitemap_in_robots(&RobotsTxtFetch::Found {
            body: "User-agent: *\nAllow: /\n".into(),
        });
        assert_eq!(rows[0].status, CheckStatus::Skipped);
    }

    #[test]
    fn sitemap_file_words_outside_a_directive_do_not_count() {
        assert!(!has_sitemap_directive(
            "# Sitemap: https://example.com/sitemap.xml\nUser-agent: *\nDisallow: /sitemap.xml\n"
        ));
    }

    #[test]
    fn confirmed_missing_robots_is_distinct_from_an_unavailable_probe() {
        let missing = evaluate_sitemap_in_robots(&RobotsTxtFetch::Status(404));
        assert_eq!(missing[0].status, CheckStatus::Skipped);
        assert_eq!(missing[0].title, "No robots.txt file to inspect");
        assert_eq!(
            missing[0].raw_data.as_ref().unwrap()["confirmed_missing"],
            true
        );

        let unavailable = evaluate_sitemap_in_robots(&RobotsTxtFetch::Status(503));
        assert_eq!(unavailable[0].status, CheckStatus::Skipped);
        assert_eq!(unavailable[0].title, "Sitemap directive not evaluated");
        assert!(unavailable[0]
            .description
            .contains("does not establish that the endpoint is missing"));
        assert_eq!(
            unavailable[0].confidence,
            crate::checks::IssueConfidence::NeedsReview
        );
    }

    #[test]
    fn an_html_catch_all_is_not_described_as_a_failed_request() {
        let rows = evaluate_sitemap_in_robots(&RobotsTxtFetch::HtmlShell);
        assert_eq!(rows[0].status, CheckStatus::Skipped);
        assert!(
            !rows[0].description.contains("request failed"),
            "{}",
            rows[0].description
        );
        assert!(
            rows[0].description.contains("catch-all rewrite"),
            "{}",
            rows[0].description
        );
        assert_eq!(rows[0].raw_data.as_ref().unwrap()["html_catch_all"], true);

        // A genuine transport failure keeps the network wording.
        let failed = evaluate_sitemap_in_robots(&RobotsTxtFetch::Error("timed out".into()));
        assert!(
            failed[0].description.contains("request failed"),
            "{}",
            failed[0].description
        );
    }
}
