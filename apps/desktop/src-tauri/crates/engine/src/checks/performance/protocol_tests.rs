use super::*;
use crate::checks::{Check, CheckStatus, PageContext};

fn ctx(is_localhost: bool, version: &str) -> PageContext {
    PageContext {
        evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        url: url::Url::parse(if is_localhost {
            "http://localhost:3000"
        } else {
            "https://example.com"
        })
        .unwrap(),
        response_headers: http::header::HeaderMap::new(),
        status_code: 200,
        body: String::new(),
        is_localhost,
        is_strict_localhost: is_localhost,
        http_version: Some(version.to_string()),
        body_lower_cache: std::sync::OnceLock::new(),
    }
}

#[test]
fn http2_check_skips_when_protocol_was_not_observed() {
    let mut page = ctx(false, "HTTP/2.0");
    page.http_version = None;
    let results = Http2Check.run(&page);
    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.status, CheckStatus::Skipped, "{result:?}");
    assert_eq!(result.check_id, "performance.http2");
    assert_eq!(result.severity, Severity::Low);
    assert!(result.description.contains("protocol was not observed"));
    assert!(result.description.contains("did not grade"));
    assert_eq!(
        result.raw_data,
        Some(serde_json::json!({"reason": "protocol_not_observed"}))
    );
    assert!(result.fix_prompt.is_none());
    assert!(result.manual_fix.is_none());
}

#[test]
fn http2_check_skips_on_localhost_preview() {
    let results = Http2Check.run(&ctx(true, "HTTP/1.1"));
    assert_eq!(results[0].status, CheckStatus::Skipped);
}

#[test]
fn http2_check_still_warns_on_production_http1() {
    let results = Http2Check.run(&ctx(false, "HTTP/1.1"));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(results[0].title.contains("HTTP/1"));
    assert!(results[0].description.contains("depends on"));
    assert!(!results[0].description.contains("significant performance"));
    assert!(results[0]
        .manual_fix
        .as_deref()
        .is_some_and(|fix| fix.contains("browser-facing") && fix.contains("Re-test")));
}

#[test]
fn a_plain_http_page_is_told_https_is_the_prerequisite() {
    // neverssl.com is HTTP-only, so h2/h3 advice names a setting the site
    // cannot reach: ALPN happens inside the TLS handshake.
    let mut page = ctx(false, "HTTP/1.1");
    page.url = url::Url::parse("http://neverssl.com/").unwrap();
    let results = Http2Check.run(&page);

    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(
        results[0].description.contains("served over HTTPS"),
        "{}",
        results[0].description
    );
    assert!(
        results[0]
            .manual_fix
            .as_deref()
            .is_some_and(|fix| fix.contains("Serve this hostname over HTTPS first")),
        "{:?}",
        results[0].manual_fix
    );
    assert_eq!(results[0].raw_data.as_ref().unwrap()["scheme"], "http");
}

#[test]
fn http3_check_still_passes_on_production() {
    for version in ["HTTP/3", "HTTP/3.0"] {
        let results = Http2Check.run(&ctx(false, version));
        assert_eq!(results[0].status, CheckStatus::Pass);
        assert_eq!(results[0].title, "Modern HTTP protocol detected");
        assert_eq!(
            results[0].raw_data.as_ref().unwrap()["http_version"],
            version
        );
    }
}

#[test]
fn http2_pass_copy_does_not_turn_optional_http3_into_a_defect() {
    let results = Http2Check.run(&ctx(false, "HTTP/2.0"));
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert!(results[0].description.contains("not a defect"));
    assert!(!results[0].description.contains("noticeably helps"));
}

fn inline_css_ctx(css_bytes: usize) -> PageContext {
    let mut c = ctx(false, "HTTP/2.0");
    c.body = format!(
        "<html><head><style>{}</style></head></html>",
        "a".repeat(css_bytes)
    );
    c
}

#[test]
fn inline_css_tiers_reserve_high_for_over_200kb() {
    use crate::checks::Severity;

    let pass = InlineCssSizeCheck.run(&inline_css_ctx(40_000));
    assert_eq!(pass[0].status, CheckStatus::Pass);

    let warn = InlineCssSizeCheck.run(&inline_css_ctx(60_000));
    assert_eq!(warn[0].status, CheckStatus::Warn);
    assert_eq!(warn[0].severity, Severity::Medium);
    assert_eq!(
        warn[0].confidence,
        crate::checks::IssueConfidence::NeedsReview
    );
    assert!(!warn[0]
        .why_it_matters
        .as_deref()
        .unwrap_or("")
        .contains("every page load"));

    let fail_medium = InlineCssSizeCheck.run(&inline_css_ctx(150_000));
    assert_eq!(fail_medium[0].status, CheckStatus::Fail);
    assert_eq!(fail_medium[0].severity, Severity::Medium);
    assert!(fail_medium[0].title.contains("100KB"));

    let fail_high = InlineCssSizeCheck.run(&inline_css_ctx(250_000));
    assert_eq!(fail_high[0].status, CheckStatus::Fail);
    assert_eq!(fail_high[0].severity, Severity::High);
    assert!(fail_high[0].title.contains("200KB"));
}

#[test]
fn inline_css_uses_decimal_kb_consistently() {
    let results = InlineCssSizeCheck.run(&inline_css_ctx(52_000));
    assert_eq!(results[0].status, CheckStatus::Warn);
    assert!(
        results[0].description.contains("52KB")
            && results[0].description.contains("Large blocks: 52KB"),
        "decimal display must match the threshold basis: {}",
        results[0].description
    );
    // Singular block grammar.
    assert!(results[0].description.contains("1 block."));
}
