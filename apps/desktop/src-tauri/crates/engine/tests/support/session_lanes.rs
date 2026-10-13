//! Page signals and keyed facts from the same supplied responses.

use sitecmd_engine::checks::seo::sitemap::{
    parse_sitemap_document, sitemap_urls_from_robots, unread_sitemaps_reason,
};
use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
use sitecmd_engine::evaluation::{
    evaluate_session, probe_key, session_page, ExecutedProbe, PageArtifact, SessionPageFacts,
    SessionPageRequest, SessionRequest,
};
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeRequest, ProbeResponse};
use sitecmd_engine::session::signals::extract_page_signals_with_headers;
use sitecmd_engine::session::{analyze_session, SessionSitemap};
use sitecmd_engine::{CheckStatus, Severity};

/// One scan: its planned routes, and each route's (final address, status, body).
/// The first sitemap is the one the entry route's walk reads, if the site has one.
pub(super) struct Scan {
    pub(super) routes: Vec<&'static str>,
    pub(super) pages: Vec<(&'static str, u16, String)>,
    pub(super) robots: Option<&'static str>,
    pub(super) sitemaps: Vec<(&'static str, &'static str)>,
}

pub(super) type Verdicts = Vec<(String, CheckStatus, Severity, Vec<usize>)>;

pub(super) fn desktop(scan: &Scan) -> Verdicts {
    let pages: Vec<_> = scan
        .routes
        .iter()
        .zip(&scan.pages)
        .map(|(route, (url, status, body))| {
            let page = url::Url::parse(url).expect("static url");
            let requested = url::Url::parse(route).expect("static url");
            extract_page_signals_with_headers(
                &page,
                &requested,
                *status,
                body,
                &http::HeaderMap::new(),
            )
            .session_page()
        })
        .collect();
    let locs: Vec<String> = scan
        .sitemaps
        .first()
        .map(|(_, body)| parse_sitemap_document(body).locs().to_vec())
        .unwrap_or_default();
    let partial = desktop_reason(scan);
    let sitemap = scan.sitemaps.first().map(|_| SessionSitemap {
        urls: &locs,
        partial_because: partial.as_deref(),
    });
    let mut found: Verdicts = analyze_session(&pages, sitemap)
        .verdicts
        .into_iter()
        .map(|verdict| {
            (
                verdict.result.check_id,
                verdict.result.status,
                verdict.result.severity,
                verdict.pages,
            )
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

pub(super) fn desktop_reason(scan: &Scan) -> Option<String> {
    let declared = scan
        .robots
        .map(sitemap_urls_from_robots)
        .unwrap_or_default();
    unread_sitemaps_reason(&declared, scan.sitemaps.first().map(|(url, _)| *url))
}

pub(super) fn hosted_facts(scan: &Scan) -> Vec<SessionPageFacts> {
    let routes: Vec<String> = scan.routes.iter().map(|route| route.to_string()).collect();
    scan.routes
        .iter()
        .zip(&scan.pages)
        .enumerate()
        .map(|(position, (route, (url, status, body)))| {
            session_page(&SessionPageRequest {
                page: PageArtifact {
                    url: url.to_string(),
                    requested_url: Some(route.to_string()),
                    status_code: *status,
                    http_version: None,
                    is_localhost: false,
                    is_strict_localhost: false,
                    headers: Vec::new(),
                    body: body.clone(),
                    evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
                },
                probe_outcomes: if position == 0 {
                    walked(scan)
                } else {
                    Vec::new()
                },
                routes: routes.clone(),
            })
            .expect("facts build")
            .expect("every page here can be named")
        })
        .collect()
}

pub(super) fn hosted(scan: &Scan) -> Verdicts {
    let pages = hosted_facts(scan);
    let mut found: Verdicts = evaluate_session(&SessionRequest { pages })
        .verdicts
        .into_iter()
        .map(|verdict| {
            (
                verdict.check_id,
                verdict.status,
                verdict.severity,
                verdict.pages,
            )
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The entry route's sitemap walk, answered as the hosted transport would:
/// robots.txt names the declared documents or is not found, so the walk reads
/// the first available sitemap, which answers the scan's sitemap.
fn walked(scan: &Scan) -> Vec<ExecutedProbe> {
    let answer =
        |url: &str, status: u16, content_type: &str, body: Option<&str>, request: ProbeRequest| {
            ExecutedProbe {
                key: probe_key(&request),
                outcome: ProbeOutcome::Response(ProbeResponse {
                    status,
                    final_url: url.into(),
                    content_type: Some(content_type.into()),
                    content_length: None,
                    headers: Vec::new(),
                    body: body.map(|text| decode_probe_body(text.as_bytes().to_vec())),
                }),
            }
        };
    let robots = "https://example.com/robots.txt";
    let mut outcomes = vec![answer(
        robots,
        if scan.robots.is_some() { 200 } else { 404 },
        "text/plain",
        scan.robots,
        ProbeRequest::get(robots),
    )];
    outcomes.extend(scan.sitemaps.iter().map(|(url, body)| {
        answer(
            url,
            200,
            "application/xml",
            Some(body),
            sitemap_request(url),
        )
    }));
    outcomes
}

pub(super) fn page(title: &str, h1: &str, head: &str, body: &str) -> String {
    format!(
        "<html><head><title>{title}</title>{head}</head><body><h1>{h1}</h1>{body}</body></html>"
    )
}

pub(super) const NOINDEX: &str = "<meta name=\"robots\" content=\"noindex\">";
