//! Release measurements for bounded discovery on long, hostile paths.

use crate::checks::seo::sitemap_walk::{sitemap_request, SITEMAP_URL_LIMIT};
use crate::evaluation::{probe_key, ExecutedProbe, PageArtifact, RouteSession};
use crate::log_sanitizer::ISSUE_EVIDENCE_URL_MAX_CHARS;
use crate::probe::{decode_probe_body, ProbeOutcome, ProbeRequest, ProbeResponse};

const ORIGIN: &str = "https://example.com";
const PAGE_START: &str = "<!doctype html><html><body>";
const PAGE_END: &str = "</body></html>";
const LINK_START: &str = "<a href='";
const LINK_END: &str = "'>Page</a>";

pub(super) fn body_limit(key: &str) -> usize {
    let facts: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../../../product-facts.json"))
            .expect("product facts");
    facts["scannerIdentity"]["limits"][key]
        .as_u64()
        .expect("body cap") as usize
}

pub(super) fn link_count() -> usize {
    let route_bytes = ISSUE_EVIDENCE_URL_MAX_CHARS - ORIGIN.len();
    (body_limit("pageBodyMaxBytes") - PAGE_START.len() - PAGE_END.len())
        / (LINK_START.len() + route_bytes + LINK_END.len())
}

fn response(url: &str, content_type: &str, body: Vec<u8>) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status: 200,
        final_url: url.into(),
        content_type: Some(content_type.into()),
        content_length: None,
        headers: Vec::new(),
        body: Some(decode_probe_body(body)),
    })
}

pub(super) fn paths() -> Vec<String> {
    (0..link_count() + SITEMAP_URL_LIMIT)
        .map(|mut number| {
            let suffix: String = (0..6)
                .map(|_| {
                    let letter = b'a' + (number % 26) as u8;
                    number /= 26;
                    letter as char
                })
                .collect();
            let route = format!(
                "/{}/{suffix}",
                "a".repeat(ISSUE_EVIDENCE_URL_MAX_CHARS - ORIGIN.len() - 8)
            );
            assert_eq!(ORIGIN.len() + route.len(), ISSUE_EVIDENCE_URL_MAX_CHARS);
            route
        })
        .collect()
}

pub(super) fn session(paths: &[String], robots: Vec<u8>) -> RouteSession {
    let links: String = paths[..link_count()]
        .iter()
        .map(|path| format!("{LINK_START}{path}{LINK_END}"))
        .collect();
    let locations: String = paths[link_count()..]
        .iter()
        .map(|path| format!("<url><loc>{ORIGIN}{path}</loc></url>"))
        .collect();
    let sitemap = format!("<urlset>{locations}</urlset>");
    assert!(sitemap.len() <= body_limit("sitemapBodyMaxBytes"));
    let body = format!("{PAGE_START}{links}{PAGE_END}");
    let next_link_bytes = LINK_START.len() + paths[0].len() + LINK_END.len();
    assert!(body.len() <= body_limit("pageBodyMaxBytes"));
    assert!(body.len() + next_link_bytes > body_limit("pageBodyMaxBytes"));
    let page = PageArtifact {
        url: format!("{ORIGIN}/"),
        requested_url: None,
        status_code: 200,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html".into())],
        body,
        evaluation_time: "2026-10-15T00:00:00Z".parse().expect("static time"),
    };
    let mut session = RouteSession::open(page).expect("opens");
    let robots_url = format!("{ORIGIN}/robots.txt");
    let sitemap_url = format!("{ORIGIN}/sitemap.xml");
    session.record(Some(vec![
        ExecutedProbe::new(
            probe_key(&ProbeRequest::get(&robots_url)),
            response(&robots_url, "text/plain", robots),
        ),
        ExecutedProbe::new(
            probe_key(&sitemap_request(&sitemap_url)),
            response(&sitemap_url, "application/xml", sitemap.into_bytes()),
        ),
    ]));
    session
}

// A controlling harness releases each sample only when the machine is quiet.
pub(super) fn measurement_start() {
    if std::env::var_os("SITECMD_CAPACITY_CONTROLLED").is_some() {
        println!("MEASUREMENT_READY");
        let mut line = String::new();
        assert!(std::io::stdin().read_line(&mut line).expect("sample gate") > 0);
    }
}
