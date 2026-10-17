//! The asset sample's size and cache readings and the compression probes' coding
//! and Vary readings grade identically with separate or joined response headers.

use sitecmd_engine::evaluation::{ExecutedProbe, PageArtifact, RouteFacts, RouteSession};
use sitecmd_engine::header_lines::HeaderLines;
use sitecmd_engine::probe::{ProbeOutcome, ProbeRequest, ProbeResponse};

/// The pairs as a runtime hands them over: every line separate, or each
/// repeated name's lines joined with ", " as the Fetch standard combines them.
fn handed(lines: HeaderLines, pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut handed: Vec<(String, String)> = Vec::new();
    for (name, value) in pairs {
        let joined = match lines {
            HeaderLines::Joined => handed.iter_mut().find(|(seen, _)| seen == name),
            HeaderLines::Separate => None,
        };
        match joined {
            Some((_, line)) => {
                line.push_str(", ");
                line.push_str(value);
            }
            None => handed.push((name.to_string(), value.to_string())),
        }
    }
    handed
}

/// The rows of `checks` for a page with `body`, once every probe they plan is
/// answered by `respond`, round after round, in one header line form.
fn graded(
    lines: HeaderLines,
    body: &str,
    checks: &[&str],
    respond: impl Fn(&ProbeRequest) -> ProbeResponse,
) -> serde_json::Value {
    let page = PageArtifact {
        url: "https://example.com/".into(),
        requested_url: Some("https://example.com/".into()),
        status_code: 200,
        http_version: Some("HTTP/2.0".into()),
        is_localhost: false,
        is_strict_localhost: false,
        headers: Vec::new(),
        body: body.into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    };
    let mut route = RouteSession::open_with(page, lines).expect("opens");
    route.record(Some(Vec::new()));
    loop {
        let answered: Vec<ExecutedProbe> = route
            .plan()
            .probes
            .into_iter()
            .filter(|probe| probe.checks.iter().any(|id| checks.contains(&id.as_str())))
            .map(|probe| {
                let response = respond(&probe.request);
                ExecutedProbe::new(probe.key, ProbeOutcome::Response(response))
            })
            .collect();
        if answered.is_empty() {
            break;
        }
        route.record(Some(answered));
    }
    let rows = serde_json::to_value(route.evaluate(&RouteFacts::default()).results).expect("rows");
    rows.as_array()
        .expect("rows")
        .iter()
        .filter(|row| checks.iter().any(|check| row["checkId"] == *check))
        .cloned()
        .collect()
}

fn status<'a>(rows: &'a serde_json::Value, check: &str) -> &'a str {
    rows.as_array()
        .expect("rows")
        .iter()
        .find(|row| row["checkId"] == check)
        .and_then(|row| row["status"].as_str())
        .expect("check row")
}

const ASSET_CHECKS: &[&str] = &[
    "performance.asset_caching",
    "performance.asset_weight",
    "performance.broken_images",
    "performance.images.heavy",
];

#[test]
fn an_asset_answer_handed_over_joined_grades_as_its_separate_lines() {
    // Joined, the image's two Content-Range lines would parse as the second
    // line's total, sizing it at 1 KB where its first line says 900 KB.
    let page = concat!(
        "<img src=\"/hero.jpg\" alt=\"Hero\">",
        "<link rel=\"stylesheet\" href=\"/assets/site-3f9a8c2b1e.css\">"
    );
    let assets = |lines: HeaderLines| {
        graded(lines, page, ASSET_CHECKS, move |request| {
            let image = request.url.ends_with(".jpg");
            let pairs: &[(&str, &str)] = if image {
                &[
                    ("content-range", "bytes 0-0/900000"),
                    ("content-range", "bytes 0-0/1000"),
                ]
            } else {
                &[
                    ("cache-control", "public"),
                    ("cache-control", "max-age=31536000"),
                ]
            };
            ProbeResponse {
                status: if image { 206 } else { 200 },
                final_url: request.url.clone(),
                content_type: Some(if image { "image/jpeg" } else { "text/css" }.into()),
                content_length: Some(if image { 1 } else { 2000 }),
                headers: handed(lines, pairs),
                body: None,
            }
        })
    };
    let separate = assets(HeaderLines::Separate);
    assert_eq!(assets(HeaderLines::Joined), separate);
    // The first Content-Range line sizes the image, and the whole
    // Cache-Control value keeps the fingerprinted stylesheet for a year.
    assert_eq!(status(&separate, "performance.images.heavy"), "warn");
    assert_eq!(status(&separate, "performance.asset_caching"), "pass");
}

#[test]
fn a_compression_answer_handed_over_joined_grades_as_its_separate_lines() {
    // Read by their first lines, the coding would be identity and the Vary
    // would name no coding, so the separate lines would grade a compressed
    // page as uncompressed.
    let compression = |lines: HeaderLines| {
        graded(
            lines,
            "<html></html>",
            &["performance.compression"],
            move |request| ProbeResponse {
                status: 200,
                final_url: request.url.clone(),
                content_type: Some("text/html".into()),
                content_length: None,
                headers: handed(
                    lines,
                    &[
                        ("content-encoding", "identity"),
                        ("content-encoding", "gzip"),
                        ("vary", "Cookie"),
                        ("vary", "Accept-Encoding"),
                    ],
                ),
                body: None,
            },
        )
    };
    let separate = compression(HeaderLines::Separate);
    assert_eq!(compression(HeaderLines::Joined), separate);
    assert_eq!(status(&separate, "performance.compression"), "pass");
}
