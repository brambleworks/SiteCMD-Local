use super::*;
use crate::probe::{decode_probe_body, ProbeFailure, ProbeResponse};

const ORIGIN: &str = "https://example.com";
const URLSET: &str = concat!(
    "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
    "<url><loc>https://example.com/</loc></url></urlset>"
);

fn answered(status: u16, content_type: &str, body: &str) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: String::new(),
        content_type: Some(content_type.into()),
        content_length: None,
        headers: Vec::new(),
        body: Some(decode_probe_body(body.as_bytes().to_vec())),
    })
}

fn failed(class: crate::probe::ProbeFailureClass) -> ProbeOutcome {
    ProbeOutcome::Failure(ProbeFailure {
        class,
        detail: "x".into(),
    })
}

fn robots(body: &str) -> RobotsTxtFetch {
    RobotsTxtFetch::Found { body: body.into() }
}

#[test]
fn declarations_come_first_once_each_and_only_from_the_same_origin() {
    let declared = robots(concat!(
        "Sitemap: https://example.com/sitemaps/main.xml\n",
        "Sitemap: https://example.com/sitemaps/main.xml\n",
        "Sitemap: https://cdn.example.net/sitemap.xml\n",
        "Sitemap: https://example.com/sitemap.xml\n",
    ));
    let candidates = sitemap_candidates(ORIGIN, &declared);
    assert_eq!(candidates[0], "https://example.com/sitemaps/main.xml");
    assert_eq!(candidates[1], "https://example.com/sitemap.xml");
    assert_eq!(
        candidates.len(),
        7,
        "one declaration, then the six conventional paths"
    );
    assert!(candidates.iter().all(|url| url.starts_with(ORIGIN)));
}

#[test]
fn no_more_declarations_are_read_than_the_limit() {
    let mut body = "Sitemap: https://cdn.example.net/sitemap.xml\n".to_string();
    body.extend(
        (0..=SITEMAP_DECLARATION_PROBE_LIMIT)
            .map(|index| format!("Sitemap: https://example.com/s{index}.xml\n")),
    );
    let candidates = sitemap_candidates(ORIGIN, &robots(&body));
    assert_eq!(candidates.len(), SITEMAP_DECLARATION_PROBE_LIMIT + 6);
}

#[test]
fn the_walk_asks_for_the_first_candidate_with_no_answer() {
    let candidates = sitemap_candidates(ORIGIN, &RobotsTxtFetch::Status(404));
    let next = walk_sitemap_candidates(&candidates, |_| None).expect_err("needs a request");
    assert_eq!(next.url, "https://example.com/sitemap.xml");
    assert_eq!(next.limit, BodyLimit::Sitemap);
}

#[test]
fn the_first_well_formed_document_in_walk_order_wins() {
    let candidates = sitemap_candidates(ORIGIN, &RobotsTxtFetch::Status(404));
    let missing = answered(404, "text/html", "");
    let found = answered(200, "application/xml", URLSET);
    let probe = walk_sitemap_candidates(&candidates, |request| {
        Some(
            if request.url.ends_with("/sitemap_index.xml") || request.url.ends_with("/sitemap.txt")
            {
                &found
            } else {
                &missing
            },
        )
    })
    .expect("every candidate answered");
    let SitemapProbe::Found(fetch) = probe else {
        panic!("a sitemap was found")
    };
    assert_eq!(fetch.url, "https://example.com/sitemap_index.xml");
}

#[test]
fn not_found_everywhere_is_missing_and_one_server_error_is_inconclusive() {
    let candidates = sitemap_candidates(ORIGIN, &RobotsTxtFetch::Status(404));
    let missing = answered(404, "text/html", "");
    let refused = answered(503, "text/html", "");
    let gone = answered(410, "text/html", "");
    let all_missing = walk_sitemap_candidates(&candidates, |request| {
        Some(if request.url.ends_with("/wp-sitemap.xml") {
            &gone
        } else {
            &missing
        })
    })
    .expect("answered");
    assert!(
        matches!(all_missing, SitemapProbe::Missing { ref observations } if observations[0].outcome == "HTTP 404" && observations.iter().any(|observation| observation.outcome == "HTTP 410"))
    );
    let one_refused = walk_sitemap_candidates(&candidates, |request| {
        Some(if request.url.ends_with("/wp-sitemap.xml") {
            &refused
        } else {
            &missing
        })
    })
    .expect("answered");
    assert!(matches!(one_refused, SitemapProbe::Inconclusive { .. }));
}

#[test]
fn each_unread_answer_says_why_in_the_desktop_words() {
    let candidates = vec!["https://example.com/sitemap.xml".to_string()];
    let words = |outcome: ProbeOutcome, expected_inconclusive: bool| {
        let probe = walk_sitemap_candidates(&candidates, |_| Some(&outcome)).expect("answered");
        assert_eq!(
            matches!(&probe, SitemapProbe::Inconclusive { .. }),
            expected_inconclusive
        );
        match probe {
            SitemapProbe::Missing { observations }
            | SitemapProbe::Inconclusive { observations } => observations[0].outcome.clone(),
            SitemapProbe::Found(_) => panic!("no sitemap here"),
        }
    };
    use crate::probe::ProbeFailureClass::{BodyCapExceeded, Timeout, Transport};
    assert_eq!(
        words(failed(BodyCapExceeded), true),
        "response body could not be read within probe limits"
    );
    assert_eq!(words(failed(Timeout), true), "request failed");
    assert_eq!(words(failed(Transport), true), "request failed");
    assert!(words(
        answered(200, "text/html", "<!doctype html><html></html>"),
        false
    )
    .starts_with("HTTP 200 but "));
}
