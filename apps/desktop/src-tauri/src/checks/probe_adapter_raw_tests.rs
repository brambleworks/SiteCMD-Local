//! The raw seam: a response read as the server sent it, through the client
//! that decodes nothing, and a body its headers do not size counted, never
//! kept.

use super::testing::CountingOrigin;
use super::*;
use sitecmd_engine::probe::{ContentCoding, ProbeMeasure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn counted(origin: &str) -> ProbeRequest {
    ProbeRequest::get(format!("{origin}/asset"))
        .body(BodyPolicy::Count)
        .coding(ContentCoding::Raw)
}

#[tokio::test]
async fn a_body_no_header_sizes_is_counted_and_not_kept() {
    let origin = CountingOrigin::serve(
        "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        1,
    )
    .await;
    let (outcome, measure) = probe_raw(true, counted(&origin.url)).await;
    let ProbeOutcome::Response(response) = outcome else {
        panic!("the origin answered");
    };
    assert!(response.body.is_none(), "a counted body is never kept");
    assert_eq!(measure, Some(ProbeMeasure::counted(5, false)));
}

#[tokio::test]
async fn an_answer_its_headers_size_is_not_read() {
    for answer in [
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/12345\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
        "HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ngone\r\n0\r\n\r\n",
    ] {
        let origin = CountingOrigin::serve(answer, 1).await;
        let (_, measure) = probe_raw(true, counted(&origin.url)).await;
        assert_eq!(measure, None, "{answer}");
    }
}

#[tokio::test]
async fn a_count_past_the_probe_cap_is_a_floor() {
    let body = "a".repeat(crate::constants::MAX_PROBE_BODY_SIZE as usize + 64 * 1024);
    let answer: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
        .into_boxed_str(),
    );
    let origin = CountingOrigin::serve(answer, 1).await;
    let (_, measure) = probe_raw(true, counted(&origin.url)).await;
    let measure = measure.expect("the body was counted");
    assert!(measure.count_capped);
    assert!(measure.counted_bytes.expect("a count") > crate::constants::MAX_PROBE_BODY_SIZE);
}

/// Serve one raw answer, including field bytes that are not valid UTF-8.
async fn raw_origin(answer: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw origin");
    let addr = listener.local_addr().expect("raw origin address");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read request head");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        stream.write_all(&answer).await.expect("answer");
        stream.shutdown().await.expect("close");
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_raw_read_keeps_the_coding_and_the_wire_length() {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all("body { color: rebeccapurple; }\n".repeat(400).as_bytes())
        .expect("gzip payload");
    let compressed = encoder.finish().expect("finish gzip stream");
    let mut answer = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    answer.extend_from_slice(&compressed);
    let origin = raw_origin(answer).await;
    let (outcome, _) = probe_raw(true, counted(&origin)).await;
    let ProbeOutcome::Response(response) = outcome else {
        panic!("the origin answered");
    };
    assert_eq!(response.content_length, Some(compressed.len() as u64));
    assert_eq!(response.header("content-encoding"), Some("gzip"));
}

#[tokio::test]
async fn a_non_ascii_cache_line_keeps_its_readable_directives() {
    // `to_str` rejects the second line and would hide its readable `no-store` directive.
    let origin = raw_origin(
        b"HTTP/1.1 200 OK\r\nCache-Control: max-age=31536000\r\nCache-Control: no-store, x=\"\xE9\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    )
    .await;
    let (outcome, _) = probe_raw(true, counted(&origin)).await;
    let ProbeOutcome::Response(response) = outcome else {
        panic!("the origin answered");
    };
    let cache = sitecmd_engine::header_lines::probe_field_value(&response, "cache-control")
        .expect("cache header");
    assert!(cache.contains("no-store"), "{cache}");
}

#[tokio::test]
async fn a_raw_read_that_may_not_follow_redirects_is_refused_unsent() {
    let origin = CountingOrigin::serve(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        1,
    )
    .await;
    let request = ProbeRequest::head(&origin.url)
        .coding(ContentCoding::Raw)
        .redirects(RedirectPolicy::None);
    let (outcome, measure) = probe_raw(true, request).await;
    assert!(matches!(outcome, ProbeOutcome::Failure(_)));
    assert_eq!(measure, None);
    assert_eq!(origin.answered(), 0, "nothing was sent");
}
