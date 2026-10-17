use super::*;
use sitecmd_engine::checks::config::missing_page;
use sitecmd_engine::CheckStatus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn an_over_cap_404_keeps_its_status_without_measuring_the_unread_body() {
    let body = "x".repeat(crate::constants::MAX_PROBE_BODY_SIZE as usize + 1);
    let answer = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).await;
        let _ = stream.write_all(answer.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    let outcome = probe(
        crate::http_client::for_url(true),
        missing_page::missing_page_probe_request(&origin),
    )
    .await;
    server.abort();
    let ProbeOutcome::Response(response) = &outcome else {
        panic!("a body-cap overrun must preserve the response status");
    };
    assert_eq!(response.status, 404);
    assert!(response.body.is_none());
    let result = missing_page::evaluate_missing_page(outcome).remove(0);
    assert_ne!(result.title, "404 response body is minimal");
    assert_eq!(result.status, CheckStatus::Pass);
    assert_eq!(result.title, "404 status; response body not read");
    assert!(result.description.contains("body was not read"));
    assert_eq!(
        result.raw_data,
        Some(serde_json::json!({"status_code": 404, "body_read": false}))
    );
}
