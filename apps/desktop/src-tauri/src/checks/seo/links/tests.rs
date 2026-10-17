//! Transport-sequencing tests for the link probe shell: the HEAD-then-GET
//! two-step against a real local server, plus checks of the shared resolution.
//! The collection, resolution, and verdict tests live with the engine module.

use super::*;
use sitecmd_engine::checks::seo::links::ProbeOutcomeKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn link_context(body: &str) -> CheckContext {
    CheckContext::new(
        crate::checks::PageContext {
            url: url::Url::parse("https://example.com/").expect("static url"),
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: body.into(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: None,
            body_lower_cache: std::sync::OnceLock::new(),
            evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
                .expect("static time")
                .with_timezone(&chrono::Utc),
        },
        crate::http_client::for_url(false).clone(),
    )
}

#[test]
fn both_link_checks_read_one_resolution_of_the_page() {
    let ctx = link_context(
        "<a href=\"/about\">About</a><a href=\"https://elsewhere.example.net/\">Out</a>",
    );
    assert!(std::ptr::eq(targets_for(&ctx), targets_for(&ctx)));
    assert_eq!(targets_for(&ctx).internal.len(), 1);
}

#[tokio::test]
async fn internal_link_check_reads_the_memoized_resolution() {
    let ctx = link_context("<a href=\"#top\">Top</a>");
    BrokenLinksCheck.run(&ctx).await;
    assert!(ctx.probe_cache.link_targets.get().is_some());
}

#[tokio::test]
async fn external_link_check_reads_the_memoized_resolution() {
    let ctx = link_context("<a href=\"#top\">Top</a>");
    BrokenExternalLinksCheck.run(&ctx).await;
    assert!(ctx.probe_cache.link_targets.get().is_some());
}

async fn method_status_server(
    head_status: u16,
    get_status: u16,
) -> (url::Url, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind link probe server");
    let address = listener.local_addr().expect("test server address");
    let handle = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept probe");
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).await.expect("read probe");
            let method = String::from_utf8_lossy(&request[..read])
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            let status = if method == "HEAD" {
                head_status
            } else {
                get_status
            };
            let reason = match status {
                200 => "OK",
                404 => "Not Found",
                410 => "Gone",
                500 => "Internal Server Error",
                _ => "Response",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write probe response");
        }
    });
    (
        url::Url::parse(&format!("http://{address}/target")).unwrap(),
        handle,
    )
}

async fn observe(head_status: u16, get_status: u16) -> LinkObservation {
    let (url, server) = method_status_server(head_status, get_status).await;
    let observation = probe_one_link(
        crate::http_client::for_url(true).clone(),
        url,
        crate::constants::CHECK_PROBE_TIMEOUT,
    )
    .await;
    server.await.expect("server task");
    observation
}

#[tokio::test]
async fn get_success_overrides_a_head_404() {
    // Some frameworks do not implement HEAD faithfully, so an error HEAD
    // always earns one GET confirmation before anything is called broken.
    assert_eq!(observe(404, 200).await.kind(), ProbeOutcomeKind::Responded);
}

#[tokio::test]
async fn get_404_confirms_a_missing_destination() {
    assert_eq!(observe(404, 404).await.kind(), ProbeOutcomeKind::Missing);
}

#[tokio::test]
async fn get_500_remains_inconclusive() {
    assert_eq!(
        observe(500, 500).await.kind(),
        ProbeOutcomeKind::Inconclusive
    );
}
