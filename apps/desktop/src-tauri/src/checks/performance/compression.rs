//! HTTP-compression transport using the shared no-decompress, SSRF-guarded client.

use crate::checks::{AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::performance::compression;

pub struct CompressionCheck;

#[async_trait::async_trait]
impl AsyncCheck for CompressionCheck {
    fn id(&self) -> &str {
        "performance.compression"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Performance
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        if ctx.is_localhost {
            return vec![compression::localhost_skip_result()];
        }

        let client = crate::http_client::no_decompress_client(ctx.is_strict_localhost);

        let head = send_probe(client.head(ctx.url.as_str())).await;
        match compression::evaluate_compression_head(head.as_ref()) {
            compression::CompressionStep::Done(results) => results,
            compression::CompressionStep::NeedsGet => {
                let get = send_probe(client.get(ctx.url.as_str())).await;
                compression::evaluate_compression_get(get, &ctx.page)
            }
        }
    }
}

async fn send_probe(builder: reqwest::RequestBuilder) -> Option<compression::EncodingProbe> {
    let resp = builder
        .header("Accept-Encoding", "gzip, deflate, br, zstd")
        .timeout(crate::constants::CHECK_PROBE_TIMEOUT)
        .send()
        .await
        .ok()?;
    Some(compression::EncodingProbe {
        http_status: resp.status().as_u16(),
        encoding: sitecmd_engine::header_lines::field_value(resp.headers(), "content-encoding")
            .map(|value| value.to_lowercase()),
        vary: sitecmd_engine::header_lines::field_value(resp.headers(), "vary")
            .map(|value| value.to_lowercase())
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CheckStatus;

    async fn repeated_headers_probe() -> compression::EncodingProbe {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind probe server");
        let address = listener.local_addr().expect("probe address");
        let served = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept probe");
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("read probe");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nVary: Cookie\r\nVary: Accept-Encoding\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await.expect("write probe response");
            stream.shutdown().await.expect("close probe response");
        });
        let probe = send_probe(
            crate::http_client::no_decompress_client(true).head(format!("http://{address}/")),
        )
        .await
        .expect("probe response");
        served.await.expect("probe server");
        probe
    }

    #[tokio::test]
    async fn compression_probe_keeps_every_content_encoding_line() {
        // Reading only the first encoding line misses the gzip evidence on the second.
        let probe = repeated_headers_probe().await;
        assert_eq!(probe.encoding.as_deref(), Some("identity, gzip"));
    }

    #[tokio::test]
    async fn compression_probe_keeps_every_vary_line() {
        // Reading only the first Vary line hides the Accept-Encoding declaration.
        let probe = repeated_headers_probe().await;
        assert_eq!(probe.vary, "cookie, accept-encoding");
    }

    #[tokio::test]
    async fn localhost_previews_skip_without_probing() {
        let ctx = crate::checks::CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse("http://localhost:4321/").expect("static test url"),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: String::new(),
                is_localhost: true,
                is_strict_localhost: true,
                http_version: Some("HTTP/1.1".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(true).clone(),
            probe_cache: Default::default(),
        };
        let results = CompressionCheck.run(&ctx).await;
        assert_eq!(results[0].check_id, CompressionCheck.id());
        assert_eq!(results[0].status, CheckStatus::Skipped);
    }
}
