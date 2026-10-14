//! Compression shell: the engine's HEAD and, when it proves nothing, its GET,
//! sent through the raw probe seam so `Content-Encoding` stays in evidence.

use crate::checks::{probe_raw, AsyncCheck, CheckContext, CheckResult, ScanCategory};
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
        let strict_local = ctx.is_strict_localhost;
        let (head, _) = probe_raw(strict_local, compression::head_request(&ctx.url)).await;
        match compression::evaluate_compression_head(compression::encoding_probe(&head).as_ref()) {
            compression::CompressionStep::Done(results) => results,
            compression::CompressionStep::NeedsGet => {
                let (get, _) = probe_raw(strict_local, compression::get_request(&ctx.url)).await;
                compression::evaluate_compression_get(compression::encoding_probe(&get), &ctx.page)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CheckStatus;

    fn context(url: url::Url, is_localhost: bool) -> CheckContext {
        let page = crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url,
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: String::new(),
            is_localhost,
            is_strict_localhost: true,
            http_version: Some("HTTP/1.1".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        };
        CheckContext::new(page, crate::http_client::for_url(true).clone())
    }

    /// The engine's HEAD, sent through the raw seam to an origin that splits
    /// both list fields across two lines.
    async fn repeated_headers_probe() -> compression::EncodingProbe {
        let origin = crate::checks::probe_adapter::testing::CountingOrigin::serve(
            "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nVary: Cookie\r\nVary: Accept-Encoding\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        )
        .await;
        let url = url::Url::parse(&format!("{}/", origin.url)).expect("origin url");
        let (head, _) = probe_raw(true, compression::head_request(&url)).await;
        compression::encoding_probe(&head).expect("probe response")
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
        let url = url::Url::parse("http://localhost:4321/").expect("static test url");
        let results = CompressionCheck.run(&context(url, true)).await;
        assert_eq!(results[0].check_id, CompressionCheck.id());
        assert_eq!(results[0].status, CheckStatus::Skipped);
    }

    #[tokio::test]
    async fn a_head_that_shows_compression_passes_without_a_get() {
        let origin = crate::checks::probe_adapter::testing::CountingOrigin::serve(
            "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        )
        .await;
        let url = url::Url::parse(&format!("{}/", origin.url)).expect("origin url");
        let results = CompressionCheck.run(&context(url, false)).await;
        assert_eq!(results[0].status, CheckStatus::Pass);
        assert_eq!(origin.answered(), 1, "the HEAD settled it");
    }

    #[tokio::test]
    async fn a_vary_only_head_needs_the_raw_get_to_fail() {
        // A refused or missing GET hides the uncompressed response behind a skip.
        let origin = crate::checks::probe_adapter::testing::CountingOrigin::serve(
            "HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        )
        .await;
        let url = url::Url::parse(&format!("{}/", origin.url)).expect("origin url");
        let results = CompressionCheck.run(&context(url, false)).await;
        assert_eq!(results[0].status, CheckStatus::Fail);
        assert!(results[0].description.contains("only signals capability"));
        assert_eq!(origin.answered(), 2, "the GET decides after the HEAD");
    }
}
