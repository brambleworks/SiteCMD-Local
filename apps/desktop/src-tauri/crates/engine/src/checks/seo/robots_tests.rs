use super::*;
use crate::probe::{ProbeBody, ProbeFailure, ProbeFailureClass, ProbeResponse};

fn response(status: u16, content_type: &str, body: Option<&str>) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: "https://example.com/robots.txt".into(),
        content_type: Some(content_type.to_string()),
        content_length: None,
        headers: Vec::new(),
        body: body.map(|text| ProbeBody {
            text: text.to_string(),
            bytes: text.len(),
            utf8_valid: true,
        }),
    })
}

#[test]
fn ai_bot_block_is_not_a_site_wide_block() {
    let robots = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow:\n";
    assert!(!wildcard_blocks_entire_site(robots));
}

#[test]
fn wildcard_disallow_root_is_a_site_wide_block() {
    assert!(wildcard_blocks_entire_site("User-agent: *\nDisallow: /\n"));
    // Grouped agents sharing the rule still count.
    assert!(wildcard_blocks_entire_site(
        "User-agent: GPTBot\nUser-agent: *\nDisallow: /\n"
    ));
}

#[test]
fn allow_root_in_same_group_reopens_the_site() {
    assert!(!wildcard_blocks_entire_site(
        "User-agent: *\nDisallow: /\nAllow: /\n"
    ));
}

#[test]
fn allow_exception_means_the_entire_site_is_not_blocked() {
    assert!(!wildcard_blocks_entire_site(
        "User-agent: *\nDisallow: /\nAllow: /public/\n"
    ));
}

#[test]
fn repeated_wildcard_groups_are_combined_before_classifying_a_total_block() {
    assert!(!wildcard_blocks_entire_site(
        "User-agent: *\nDisallow: /\n\nUser-agent: *\nAllow: /public/\n"
    ));
}

#[test]
fn parser_accepts_whitespace_around_directive_colons() {
    assert!(wildcard_blocks_entire_site(
        "User-agent : *\nDisallow : /\n"
    ));
}

#[test]
fn wildcard_path_form_is_recognized_as_a_root_wide_block() {
    assert!(wildcard_blocks_entire_site("User-agent: *\nDisallow: /*\n"));
}

#[test]
fn robots_groups_share_rules_across_consecutive_user_agents() {
    let robots = "User-agent: GPTBot\nUser-agent: CCBot\nDisallow: /\n\nUser-agent: *\nDisallow:\n";
    let groups = robots_groups(robots);
    let blocked: Vec<&str> = groups
        .iter()
        .filter(|g| g.blocks_root)
        .flat_map(|g| g.agents.iter().map(String::as_str))
        .collect();
    assert_eq!(blocked, vec!["gptbot", "ccbot"]);
}

#[test]
fn robots_groups_folder_disallow_does_not_block_root() {
    let robots = "User-agent: GPTBot\nDisallow: /private/\n";
    let groups = robots_groups(robots);
    assert!(groups.iter().all(|g| !g.blocks_root));
}

#[test]
fn missing_robots_txt_is_not_scored_as_a_defect() {
    let result = missing_robots_result();
    assert_eq!(result.status, CheckStatus::Skipped);
    assert_eq!(result.severity, Severity::Low);
    assert!(result.description.contains("no robots crawl restrictions"));
}

#[test]
fn folder_scoped_disallow_is_not_a_site_wide_block() {
    assert!(!wildcard_blocks_entire_site(
        "User-agent: *\nDisallow: /admin/\nDisallow: /private/\n"
    ));
}

#[test]
fn blocks_all_fix_names_the_disallow_line() {
    let results = evaluate_robots_txt(&RobotsTxtFetch::Found {
        body: "User-agent: *\nDisallow: /\n".into(),
    });
    assert_eq!(results[0].status, CheckStatus::Warn);
    let fix = results[0].manual_fix.as_deref().unwrap_or("");
    assert!(
        fix.contains("Disallow: /") && fix.to_ascii_lowercase().contains("remove"),
        "fix must name the offending line: {fix}"
    );
}

#[test]
fn missing_sitemap_directive_is_not_described_as_a_crawl_block() {
    let result = evaluate_robots_txt(&RobotsTxtFetch::Found {
        body: "User-agent: *\nAllow: /\n".into(),
    })
    .remove(0);
    assert_eq!(result.status, CheckStatus::Pass);
    assert!(result.manual_fix.is_none());
    assert!(result.description.contains("optional discovery hint"));
    assert!(!result.description.contains("entire site"));
}

#[test]
fn successful_probe_with_a_text_body_classifies_as_found() {
    let outcome = response(200, "text/plain", Some("User-agent: *\nDisallow:\n"));
    let RobotsTxtFetch::Found { body } = robots_fetch_from_probe(outcome) else {
        panic!("expected Found for a normal robots.txt body");
    };
    assert!(body.contains("User-agent"));
    // A genuinely empty robots.txt (complete read, empty body) stays
    // Found; only failed reads are inconclusive.
    assert!(matches!(
        robots_fetch_from_probe(response(200, "text/plain", Some(""))),
        RobotsTxtFetch::Found { .. }
    ));
}

#[test]
fn html_catch_all_rewrite_is_its_own_outcome_not_an_empty_robots() {
    let outcome = response(200, "text/html; charset=utf-8", Some("<!doctype html>"));
    assert!(matches!(
        robots_fetch_from_probe(outcome),
        RobotsTxtFetch::HtmlShell
    ));
}

#[test]
fn an_html_catch_all_robots_policy_row_does_not_claim_a_failed_request() {
    let rows = evaluate_robots_txt(&RobotsTxtFetch::HtmlShell);
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
}

#[test]
fn non_success_status_classifies_as_status() {
    assert!(matches!(
        robots_fetch_from_probe(response(404, "text/html", None)),
        RobotsTxtFetch::Status(404)
    ));
}

#[test]
fn probe_failure_classifies_as_error_never_found() {
    // A timed-out or capped body read must not become Found { "" }.
    let outcome = ProbeOutcome::Failure(ProbeFailure {
        class: ProbeFailureClass::BodyCapExceeded,
        detail: "body exceeded cap".into(),
    });
    assert!(matches!(
        robots_fetch_from_probe(outcome),
        RobotsTxtFetch::Error(_)
    ));
}

#[test]
fn robots_url_preserves_non_default_ports() {
    let url = url::Url::parse("http://localhost:8080/deep/page").unwrap();
    assert_eq!(robots_txt_url(&url), "http://localhost:8080/robots.txt");
}
