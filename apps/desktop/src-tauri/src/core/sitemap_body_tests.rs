use super::*;
use sitecmd_engine::checks::seo::sitemap_walk::sitemap_request;
use sitecmd_engine::evaluation::{
    evaluate_session, probe_key, session_page, ExecutedProbe, PageArtifact, SessionPageRequest,
    SessionRequest,
};
use sitecmd_engine::probe::{ProbeFailureClass, ProbeOutcome, ProbeRequest};
use sitecmd_engine::session::signals::extract_page_signals_with_headers;
use sitecmd_engine::session::{analyze_session, SessionSitemap};
use sitecmd_engine::CheckStatus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Reply = (&'static str, &'static str, &'static str, String);

struct TestSite {
    origin: String,
    server: tokio::task::JoinHandle<()>,
}

impl TestSite {
    async fn new(answers: impl FnOnce(&str) -> Vec<Reply>) -> Self {
        Self::with_robots_headers(answers, "").await
    }

    async fn with_robots_headers(
        answers: impl FnOnce(&str) -> Vec<Reply>,
        robots_headers: &'static str,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let origin = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let answers = answers(&origin);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0; 4096];
                let read = stream.read(&mut request).await.expect("read request");
                let request = String::from_utf8_lossy(&request[..read]);
                let path = request.split_whitespace().nth(1).expect("request path");
                let (status, content_type, body) = answers
                    .iter()
                    .find(|(route, _, _, _)| *route == path)
                    .map(|(_, status, content_type, body)| (*status, *content_type, body.as_str()))
                    .unwrap_or(("404 Not Found", "text/plain", ""));
                let extra_headers = if path == "/robots.txt" {
                    robots_headers
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self { origin, server }
    }

    async fn discover(&self) -> SitemapResult {
        discover_sitemap(
            crate::http_client::for_url(true),
            &self.origin,
            crate::network_policy::LocalOrigin::Loopback,
        )
        .await
    }
}

impl Drop for TestSite {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn urlset(origin: &str, path: &str) -> String {
    format!("<urlset><url><loc>{origin}{path}</loc></url></urlset>")
}

async fn compare(site: &TestSite, expected: CheckStatus) -> (SitemapResult, Vec<ExecutedProbe>) {
    let routes = vec![
        format!("{}/", site.origin),
        format!("{}/private", site.origin),
    ];
    let discovered = site.discover().await;
    let mut outcomes = Vec::new();
    let requests = std::iter::once(ProbeRequest::get(format!("{}/robots.txt", site.origin))).chain(
        sitemap_candidate_urls(&site.origin)
            .iter()
            .map(|url| sitemap_request(url))
            .collect::<Vec<_>>(),
    );
    for request in requests {
        outcomes.push(ExecutedProbe::new(
            probe_key(&request),
            crate::checks::probe(crate::http_client::for_url(true), request).await,
        ));
    }
    if let Some(source) = &discovered.source_url {
        let request = sitemap_request(source);
        let key = probe_key(&request);
        if !outcomes.iter().any(|outcome| outcome.key == key) {
            outcomes.push(ExecutedProbe::new(
                key,
                crate::checks::probe(crate::http_client::for_url(true), request).await,
            ));
        }
    }
    assert_eq!(discovered.status, SitemapStatus::Found);
    assert_eq!(discovered.urls, vec![routes[0].clone()]);
    let mut native = Vec::new();
    let mut hosted = Vec::new();
    for (position, route) in routes.iter().enumerate() {
        let body = if position == 1 {
            "<html><head><meta name=\"robots\" content=\"noindex\"></head></html>"
        } else {
            "<html><head></head></html>"
        };
        let url = url::Url::parse(route).expect("page URL");
        native.push(
            extract_page_signals_with_headers(
                &url,
                &url,
                200,
                body,
                &reqwest::header::HeaderMap::new(),
            )
            .session_page(),
        );
        hosted.push(
            session_page(&SessionPageRequest {
                page: PageArtifact {
                    url: route.clone(),
                    requested_url: Some(route.clone()),
                    status_code: 200,
                    http_version: None,
                    is_localhost: true,
                    is_strict_localhost: true,
                    headers: Vec::new(),
                    body: body.into(),
                    evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
                },
                probe_outcomes: if position == 0 {
                    outcomes.clone()
                } else {
                    Vec::new()
                },
                routes: routes.clone(),
            })
            .expect("facts build")
            .expect("named page"),
        );
    }
    let native = analyze_session(
        &native,
        Some(SessionSitemap {
            urls: &discovered.urls,
            partial_because: discovered.partial_because.as_deref(),
        }),
    );
    let native = native
        .verdicts
        .iter()
        .find(|verdict| verdict.result.check_id == "seo.noindex_in_sitemap")
        .expect("native verdict");
    let hosted = evaluate_session(&SessionRequest { pages: hosted });
    let hosted = hosted
        .verdicts
        .iter()
        .find(|verdict| verdict.check_id == "seo.noindex_in_sitemap")
        .expect("hosted verdict");
    assert_eq!(native.result.status, expected);
    assert_eq!(hosted.status, native.result.status);
    assert_eq!(hosted.pages, native.pages);
    (discovered, outcomes)
}

#[tokio::test]
async fn oversized_robots_declarations_leave_both_sitemap_comparisons_complete() {
    let site = TestSite::new(|origin| {
        let mut robots = format!(
            "# {}",
            ".".repeat(crate::constants::MAX_PROBE_BODY_SIZE as usize)
        );
        robots.push_str(&format!(
            "\nSitemap: {origin}/sitemap.xml\nSitemap: {origin}/posts.xml\n"
        ));
        assert!(robots.len() as u64 > crate::constants::MAX_PROBE_BODY_SIZE);
        assert!((robots.len() as u64) < crate::constants::MAX_SITEMAP_SIZE);
        vec![
            ("/robots.txt", "200 OK", "text/plain", robots),
            (
                "/sitemap.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/"),
            ),
            (
                "/posts.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/private"),
            ),
        ]
    })
    .await;
    let (discovered, outcomes) = compare(&site, CheckStatus::Pass).await;
    assert_eq!(discovered.partial_because, None);
    assert!(matches!(&outcomes[0].outcome,
        ProbeOutcome::Failure(failure) if failure.class == ProbeFailureClass::BodyCapExceeded));
}

#[tokio::test]
async fn transient_robots_failures_leave_both_sitemap_comparisons_partial() {
    let site = TestSite::new(|origin| {
        vec![
            (
                "/robots.txt",
                "503 Service Unavailable",
                "text/plain",
                String::new(),
            ),
            (
                "/sitemap.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/"),
            ),
        ]
    })
    .await;
    compare(&site, CheckStatus::Skipped).await;
}

#[tokio::test]
async fn html_robots_declarations_find_a_custom_sitemap() {
    let site = TestSite::new(|origin| {
        vec![
            (
                "/robots.txt",
                "200 OK",
                "text/html; charset=utf-8",
                format!("Sitemap: {origin}/custom.xml"),
            ),
            (
                "/custom.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/"),
            ),
        ]
    })
    .await;
    let discovered = site.discover().await;
    assert_eq!(discovered.status, SitemapStatus::Found);
    assert_eq!(discovered.urls, vec![format!("{}/", site.origin)]);
    assert_eq!(
        discovered.source_url,
        Some(format!("{}/custom.xml", site.origin))
    );
    assert_eq!(discovered.partial_because, None);
}

#[tokio::test]
async fn html_robots_declarations_keep_a_second_sitemap_partial() {
    let site = TestSite::new(|origin| {
        vec![
            (
                "/robots.txt",
                "200 OK",
                "text/html; charset=utf-8",
                format!("Sitemap: {origin}/posts.xml"),
            ),
            (
                "/sitemap.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/"),
            ),
        ]
    })
    .await;
    let discovered = site.discover().await;
    assert_eq!(discovered.status, SitemapStatus::Found);
    assert_eq!(discovered.urls, vec![format!("{}/", site.origin)]);
    assert_eq!(
        discovered.partial_because.as_deref(),
        Some("robots.txt declares 1 further sitemap that was not read")
    );
}

#[tokio::test]
async fn an_unanswered_earlier_candidate_leaves_both_sitemap_comparisons_partial() {
    let site = TestSite::new(|origin| {
        vec![
            (
                "/sitemap.xml",
                "503 Service Unavailable",
                "text/plain",
                String::new(),
            ),
            (
                "/sitemap-index.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/"),
            ),
        ]
    })
    .await;
    compare(&site, CheckStatus::Skipped).await;
}

#[tokio::test]
async fn html_typed_robots_declarations_agree_in_both_sitemap_comparisons() {
    let site = TestSite::new(|origin| {
        vec![
            (
                "/robots.txt",
                "200 OK",
                "text/html; charset=utf-8",
                format!("User-agent: *\nAllow: /\nSitemap: {origin}/custom.xml"),
            ),
            (
                "/custom.xml",
                "200 OK",
                "application/xml",
                urlset(origin, "/"),
            ),
        ]
    })
    .await;
    compare(&site, CheckStatus::Pass).await;
}

#[tokio::test]
async fn robots_line_endings_agree_in_both_sitemap_comparisons() {
    for ending in ["\n", "\r", "\r\n"] {
        let site = TestSite::new(|origin| {
            vec![
                (
                    "/robots.txt",
                    "200 OK",
                    "text/plain",
                    format!(
                        "User-agent: *{ending}Allow: /{ending}Sitemap: {origin}/custom.xml{ending}"
                    ),
                ),
                (
                    "/custom.xml",
                    "200 OK",
                    "application/xml",
                    urlset(origin, "/"),
                ),
            ]
        })
        .await;
        compare(&site, CheckStatus::Pass).await;
    }
}

#[path = "sitemap_challenge_tests.rs"]
mod challenge_tests;
