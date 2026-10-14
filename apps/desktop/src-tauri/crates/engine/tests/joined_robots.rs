//! An X-Robots-Tag value whose lines arrived joined: any of its commas may
//! have been where a line ended, after which no crawler name carries. A
//! verdict that turns on where a line ended declines, a verdict every split
//! gives stands, and the comparison's noindex fact is unknown exactly when a
//! split decides it.

use sitecmd_engine::evaluation::{PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::header_lines::HeaderLines::{self, Joined, Separate};
use sitecmd_engine::session::{analyze_session, SessionAnalysis, SessionPage, SessionSitemap};
use sitecmd_engine::{CheckStatus, Severity};

const BODY: &str =
    "<html><head><title>Example</title></head><body><main>Example</main></body></html>";
const PAGE: &str = "https://example.com/a";
const ENTRY: &str = "https://example.com/";

fn route(url: &str, body: &str, x_robots_tag: &[&str], lines: HeaderLines) -> RouteSession {
    let page = PageArtifact {
        url: url.into(),
        requested_url: Some(url.into()),
        status_code: 200,
        http_version: Some("HTTP/2.0".into()),
        is_localhost: false,
        is_strict_localhost: false,
        headers: x_robots_tag
            .iter()
            .map(|value| ("x-robots-tag".to_string(), value.to_string()))
            .collect(),
        body: body.into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    };
    RouteSession::open_with(page, lines).expect("opens")
}

/// The status and severity one check answers for the page.
fn verdict(
    url: &str,
    x_robots_tag: &[&str],
    lines: HeaderLines,
    check: &str,
) -> (CheckStatus, Severity) {
    let row = route(url, BODY, x_robots_tag, lines)
        .evaluate(&RouteFacts::default())
        .results
        .into_iter()
        .find(|row| row.check_id == check)
        .expect("the check answers");
    (row.status, row.severity)
}

/// The page's noindex fact in its scan's comparison.
fn noindex_fact(body: &str, x_robots_tag: &[&str], lines: HeaderLines) -> Option<bool> {
    route(PAGE, body, x_robots_tag, lines)
        .session_page(&[PAGE.to_string()])
        .expect("facts")
        .expect("named")
        .noindex
}

#[test]
fn a_noindex_after_another_crawlers_name_is_not_established_when_joined() {
    // The joined value is what either of these sent, and they grade apart.
    assert_eq!(
        verdict(
            PAGE,
            &["bingbot: noarchive, noindex"],
            Separate,
            "seo.noindex"
        ),
        (CheckStatus::Warn, Severity::Low)
    );
    assert_eq!(
        verdict(
            PAGE,
            &["bingbot: noarchive", "noindex"],
            Separate,
            "seo.noindex"
        ),
        (CheckStatus::Warn, Severity::Medium)
    );
    assert_eq!(
        verdict(
            PAGE,
            &["bingbot: noarchive, noindex"],
            Joined,
            "seo.noindex"
        )
        .0,
        CheckStatus::Skipped
    );
    assert_eq!(
        noindex_fact(BODY, &["bingbot: noarchive, noindex"], Joined),
        None
    );
    let marked = r#"<html><head><meta name="robots" content="noindex"></head></html>"#;
    assert_eq!(
        noindex_fact(marked, &["bingbot: noarchive, noindex"], Joined),
        Some(true)
    );
}

#[test]
fn a_verdict_every_split_gives_stands_when_joined() {
    // Googlebot's scope and every crawler's grade alike.
    assert_eq!(
        verdict(
            PAGE,
            &["googlebot: noarchive, noindex"],
            Joined,
            "seo.noindex"
        ),
        (CheckStatus::Warn, Severity::Medium)
    );
    // Nothing carries to a clause before any name.
    assert_eq!(
        verdict(
            PAGE,
            &["noindex, bingbot: noarchive"],
            Joined,
            "seo.noindex"
        ),
        (CheckStatus::Warn, Severity::Medium)
    );
    assert_eq!(
        noindex_fact(BODY, &["noindex, bingbot: noarchive"], Joined),
        Some(true)
    );
    assert_eq!(
        noindex_fact(BODY, &["bingbot: noarchive, nofollow"], Joined),
        Some(false)
    );
    assert_eq!(
        verdict(ENTRY, &["noindex, nofollow"], Joined, "seo.noindex"),
        (CheckStatus::Warn, Severity::High)
    );
    // Each clause names its own crawler, so the conflict holds in every split.
    assert_eq!(
        verdict(
            PAGE,
            &["googlebot: index, googlebot: noindex"],
            Joined,
            "seo.meta_conflicts"
        ),
        (CheckStatus::Fail, Severity::Medium)
    );
}

#[test]
fn a_conflict_that_turns_on_where_a_line_ended_is_not_established_when_joined() {
    assert_eq!(
        verdict(
            PAGE,
            &["bingbot: noindex, index"],
            Separate,
            "seo.meta_conflicts"
        )
        .0,
        CheckStatus::Fail
    );
    assert_eq!(
        verdict(
            PAGE,
            &["bingbot: noindex", "index"],
            Separate,
            "seo.meta_conflicts"
        )
        .0,
        CheckStatus::Pass
    );
    assert_eq!(
        verdict(
            PAGE,
            &["bingbot: noindex, index"],
            Joined,
            "seo.meta_conflicts"
        )
        .0,
        CheckStatus::Skipped
    );
    // Read as one line it conflicts in Bingbot's scope, and one line per
    // clause in every crawler's, yet this split of it conflicts nowhere.
    let value = "follow, bingbot: index, noindex, googlebot: noarchive, nofollow";
    assert_eq!(
        verdict(
            PAGE,
            &[
                "follow, bingbot: index",
                "noindex, googlebot: noarchive, nofollow"
            ],
            Separate,
            "seo.meta_conflicts"
        )
        .0,
        CheckStatus::Pass
    );
    assert_eq!(
        verdict(PAGE, &[value], Joined, "seo.meta_conflicts").0,
        CheckStatus::Skipped
    );
}

#[test]
fn a_valued_directive_before_noindex_names_no_crawler() {
    for lines in [Separate, Joined] {
        let header = ["max-snippet: 20, noindex"];
        assert_eq!(
            verdict(PAGE, &header, lines, "seo.noindex"),
            (CheckStatus::Warn, Severity::Medium),
            "{lines:?}"
        );
        assert_eq!(
            verdict(ENTRY, &header, lines, "seo.noindex"),
            (CheckStatus::Warn, Severity::High),
            "{lines:?}"
        );
        assert_eq!(noindex_fact(BODY, &header, lines), Some(true), "{lines:?}");
    }
    // A valued directive must not hide fixed conflicts by becoming a crawler name.
    assert_eq!(
        verdict(
            PAGE,
            &["max-snippet: 20, index, noindex"],
            Joined,
            "seo.meta_conflicts"
        ),
        (CheckStatus::Fail, Severity::Medium)
    );
}

fn robots_reading(
    value: &str,
    lines: HeaderLines,
) -> ((CheckStatus, Severity), Option<bool>, CheckStatus) {
    (
        verdict(PAGE, &[value], lines, "seo.noindex"),
        noindex_fact(BODY, &[value], lines),
        verdict(PAGE, &[value], lines, "seo.meta_conflicts").0,
    )
}

fn date_directives(lines: HeaderLines, scoped: ((CheckStatus, Severity), Option<bool>)) {
    let reading = |value| robots_reading(value, lines);
    assert_eq!(
        reading("unavailable_after: Fri, 25 Jun 2010 15:00:00 GMT, noindex"),
        (
            (CheckStatus::Warn, Severity::Medium),
            Some(true),
            CheckStatus::Pass
        )
    );
    assert_eq!(
        reading("bingbot: noarchive, unavailable_after: Fri, 25 Jun 2010 15:00:00 GMT, noindex"),
        (scoped.0, scoped.1, CheckStatus::Pass)
    );
    assert_eq!(
        reading("unavailable_after: Fri, 25 Jun 2010 15:00:00 GMT, index, noindex"),
        (
            (CheckStatus::Warn, Severity::Medium),
            Some(true),
            CheckStatus::Fail
        )
    );
}

#[test]
fn an_unavailable_after_date_does_not_name_a_crawler_on_separate_lines() {
    // A date's colon must not reset Bingbot's scope or hide a general noindex fact.
    date_directives(Separate, ((CheckStatus::Warn, Severity::Low), Some(false)));
}

#[test]
fn an_unavailable_after_date_does_not_name_a_crawler_on_joined_lines() {
    // A date's colon must not make a fixed conflict or general noindex uncertain.
    date_directives(Joined, ((CheckStatus::Skipped, Severity::Low), None));
}

#[test]
fn a_non_token_crawler_name_is_skipped_on_both_lanes() {
    // Invalid crawler names must not establish scope or hide a later general noindex.
    for lines in [Separate, Joined] {
        for value in ["googlebot news: noindex", "googlebot.news: noindex"] {
            assert_eq!(
                robots_reading(value, lines),
                (
                    (CheckStatus::Pass, Severity::Low),
                    Some(false),
                    CheckStatus::Pass
                )
            );
        }
        assert_eq!(
            robots_reading("my bot: index, noindex", lines),
            (
                (CheckStatus::Warn, Severity::Medium),
                Some(true),
                CheckStatus::Pass
            )
        );
    }
}

#[test]
fn a_non_ascii_robots_line_keeps_noindex_on_both_lanes() {
    // An unreadable robots line must not erase a joined line's noindex directive.
    for lines in [Separate, Joined] {
        let headers = match lines {
            Separate => vec!["noindex", "\u{e9}"],
            Joined => vec!["noindex, \u{e9}"],
        };
        assert_eq!(
            verdict(PAGE, &headers, lines, "seo.noindex"),
            (CheckStatus::Warn, Severity::Medium),
            "{lines:?}"
        );
        assert_eq!(noindex_fact(BODY, &headers, lines), Some(true), "{lines:?}");
    }
}

fn page(path: &str, noindex: Option<bool>, title: &str) -> SessionPage {
    let url = format!("https://example.com{path}");
    SessionPage {
        url: url.clone(),
        requested_url: url,
        status_code: 200,
        title: Some(title.into()),
        meta_description: None,
        h1: None,
        canonical: None,
        noindex,
        hreflang: Vec::new(),
        hreflang_truncated: false,
        internal_links: Vec::new(),
        internal_links_truncated: false,
    }
}

fn outcome(analysis: &SessionAnalysis, check: &str) -> (CheckStatus, Vec<usize>) {
    let found = analysis
        .verdicts
        .iter()
        .find(|verdict| verdict.result.check_id == check)
        .expect("the check answers");
    (found.result.status, found.pages.clone())
}

#[test]
fn a_sitemap_listing_a_page_whose_noindex_is_unknown() {
    let pages = [
        page("/", Some(false), "Home"),
        page("/known", Some(true), "Known"),
        page("/unknown", None, "Unknown"),
    ];
    let listing = |positions: &[usize]| -> (CheckStatus, Vec<usize>) {
        let urls: Vec<String> = positions.iter().map(|&at| pages[at].url.clone()).collect();
        let sitemap = SessionSitemap {
            urls: &urls,
            partial_because: None,
        };
        outcome(
            &analyze_session(&pages, Some(sitemap)),
            "seo.noindex_in_sitemap",
        )
    };
    assert_eq!(listing(&[1, 2]), (CheckStatus::Warn, vec![1]));
    assert_eq!(listing(&[2]).0, CheckStatus::Skipped);
    assert_eq!(listing(&[0]).0, CheckStatus::Pass);
}

#[test]
fn a_shared_title_on_a_page_whose_noindex_is_unknown() {
    let titles = |pages: &[SessionPage]| {
        outcome(
            &analyze_session(pages, None),
            "seo.duplicate_title_across_pages",
        )
    };
    let shared = [
        page("/", Some(false), "Shared"),
        page("/a", Some(false), "Shared"),
        page("/u", None, "Shared"),
    ];
    assert_eq!(titles(&shared), (CheckStatus::Warn, vec![0, 1]));
    let undecided = [
        page("/", Some(false), "Home"),
        page("/a", Some(false), "Shared"),
        page("/u", None, "Shared"),
    ];
    assert_eq!(titles(&undecided).0, CheckStatus::Skipped);
    let alone = [
        page("/", Some(false), "Home"),
        page("/a", Some(false), "Shared"),
        page("/u", None, "Mine"),
    ];
    assert_eq!(titles(&alone).0, CheckStatus::Pass);
}
