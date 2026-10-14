use super::*;
use crate::checks::CheckStatus;
use http::header::HeaderMap;

fn ctx(body: &str) -> PageContext {
    PageContext {
        evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        url: url::Url::parse("https://example.com/page").unwrap(),
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
fn meta_robots_index_and_noindex_conflict_fails() {
    let body = r#"<meta name="robots" content="index, noindex">"#;
    let results = MetaRobotsConflictCheck.run(&ctx(body));
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert_eq!(results[0].severity, Severity::Medium);
}

#[test]
fn meta_robots_follow_and_nofollow_conflict_fails() {
    let body = r#"<meta name="robots" content="follow, nofollow">"#;
    let results = MetaRobotsConflictCheck.run(&ctx(body));
    assert_eq!(results[0].status, CheckStatus::Fail);
}

#[test]
fn meta_robots_multiple_consistent_tags_pass() {
    let body = r#"<meta name="robots" content="index"><meta name="robots" content="follow">"#;
    let results = MetaRobotsConflictCheck.run(&ctx(body));
    assert_eq!(results[0].status, CheckStatus::Pass);
    assert!(
        !results[0].title.contains("Conflicting"),
        "consistent tags must not be titled Conflicting: {}",
        results[0].title
    );
    assert!(results[0].description.contains("combine"));
}

#[test]
fn meta_robots_conflict_across_multiple_tags_still_fails() {
    let body = r#"<meta name="robots" content="index"><meta name="robots" content="noindex">"#;
    let results = MetaRobotsConflictCheck.run(&ctx(body));
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert!(results[0].title.contains("Contradictory"));
}

#[test]
fn meta_robots_single_directive_passes() {
    let body = r#"<meta name="robots" content="noindex">"#;
    let results = MetaRobotsConflictCheck.run(&ctx(body));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn meta_robots_absent_passes_default() {
    let results = MetaRobotsConflictCheck.run(&ctx("<html></html>"));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn meta_robots_x_robots_tag_header_is_read() {
    // Directives can arrive via the X-Robots-Tag header, not just the tag.
    let mut c = ctx("<html></html>");
    c.response_headers
        .insert("x-robots-tag", "index, noindex".parse().unwrap());
    let results = MetaRobotsConflictCheck.run(&c);
    assert_eq!(results[0].status, CheckStatus::Fail);
}

#[test]
fn robots_markup_examples_in_inert_content_are_ignored() {
    let body = r#"<!-- <meta name=robots content="index,noindex"> -->
        <script>const example = '<meta name=robots content="follow,nofollow">';</script>"#;
    let result = &MetaRobotsConflictCheck.run(&ctx(body))[0];
    assert_eq!(result.status, CheckStatus::Pass);
    assert!(result.description.contains("No supported page-level"));
    assert!(!result.description.contains("default crawling behavior"));
}

#[test]
fn none_shorthand_conflicts_with_index_in_the_same_scope() {
    let result = &MetaRobotsConflictCheck.run(&ctx(r#"<meta name=robots content="all, none">"#))[0];
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.description.contains("index and noindex"));
    assert!(result.description.contains("follow and nofollow"));
}

#[test]
fn different_crawler_scopes_are_not_merged_into_a_false_conflict() {
    let mut c = ctx(r#"<meta name=robots content=index>"#);
    c.response_headers
        .append("x-robots-tag", "googlebot: noindex".parse().unwrap());
    c.response_headers
        .append("x-robots-tag", "bingbot: follow".parse().unwrap());
    let result = &MetaRobotsConflictCheck.run(&c)[0];
    assert_eq!(result.status, CheckStatus::Pass);
    assert!(result.description.contains("same crawler scope"));
}

#[test]
fn repeated_header_values_are_all_compared_within_their_scope() {
    let mut c = ctx("<html></html>");
    c.response_headers
        .append("x-robots-tag", "googlebot: index".parse().unwrap());
    c.response_headers
        .append("x-robots-tag", "googlebot: noindex".parse().unwrap());
    let result = &MetaRobotsConflictCheck.run(&c)[0];
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.description.contains("Googlebot scope"));
    assert_eq!(result.raw_data.as_ref().unwrap()["header_value_count"], 2);
}
