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

#[tokio::test]
async fn oversized_robots_declarations_leave_both_sitemap_comparisons_complete() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let origin = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let routes = vec![format!("{origin}/"), format!("{origin}/private")];
    let sitemap = format!("<urlset><url><loc>{origin}/</loc></url></urlset>");
    let declarations = format!("\nSitemap: {origin}/sitemap.xml\nSitemap: {origin}/posts.xml\n");
    let mut robots = format!(
        "# {}",
        ".".repeat(crate::constants::MAX_PROBE_BODY_SIZE as usize)
    );
    robots.push_str(&declarations);
    assert!(robots.len() as u64 > crate::constants::MAX_PROBE_BODY_SIZE);
    assert!((robots.len() as u64) < crate::constants::MAX_SITEMAP_SIZE);
    let posts = format!("<urlset><url><loc>{origin}/private</loc></url></urlset>");
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let read = stream.read(&mut request).await.expect("read request");
            let request = String::from_utf8_lossy(&request[..read]);
            let (content_type, body) = if request.starts_with("GET /robots.txt ") {
                ("text/plain", &robots)
            } else if request.starts_with("GET /posts.xml ") {
                ("application/xml", &posts)
            } else {
                ("application/xml", &sitemap)
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    let client = crate::http_client::for_url(true);
    let discovered = discover_sitemap(
        client,
        &origin,
        crate::network_policy::LocalOrigin::Loopback,
    )
    .await;
    let mut outcomes = Vec::new();
    for request in [
        ProbeRequest::get(format!("{origin}/robots.txt")),
        sitemap_request(&format!("{origin}/sitemap.xml")),
    ] {
        outcomes.push(ExecutedProbe {
            key: probe_key(&request),
            outcome: crate::checks::probe(client, request).await,
        });
    }
    server.abort();
    assert!(matches!(
        &outcomes[0].outcome,
        ProbeOutcome::Failure(failure) if failure.class == ProbeFailureClass::BodyCapExceeded
    ));
    assert_eq!(discovered.status, SitemapStatus::Found);
    assert_eq!(discovered.urls, vec![routes[0].clone()]);
    assert_eq!(discovered.partial_because, None);

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
    assert_eq!(native.result.status, CheckStatus::Pass);
    assert_eq!(hosted.status, native.result.status);
    assert_eq!(hosted.pages, native.pages);
}
