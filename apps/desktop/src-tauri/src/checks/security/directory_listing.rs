//! Desktop transport for portable directory-listing probes.

use crate::checks::{probe, AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::security::directory_listing::{
    grade_listing_probes, listing_request, localhost_skip_result, PROBE_DIRS,
};
use sitecmd_engine::evaluation::sweep_reading;

pub struct DirectoryListingCheck;

#[async_trait::async_trait]
impl AsyncCheck for DirectoryListingCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "security.directory_listing"
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        if ctx.is_localhost {
            return vec![localhost_skip_result()];
        }

        let base = crate::checks::origin_with_port(&ctx.url);

        let mut futures = Vec::new();
        for dir in PROBE_DIRS {
            let request = listing_request(&base, dir);
            let client = ctx.client.clone();
            let dir_path = dir.to_string();
            futures.push(tokio::spawn(async move {
                (dir_path, sweep_reading(&probe(&client, request).await))
            }));
        }

        let mut readings = Vec::new();
        for future in futures {
            if let Ok(reading) = future.await {
                readings.push(reading);
            }
        }

        vec![grade_listing_probes(
            readings
                .iter()
                .map(|(dir, reading)| (dir.clone(), reading))
                .collect(),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CheckStatus;

    fn ctx(url: &str, is_localhost: bool) -> CheckContext {
        CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse(url).unwrap(),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: String::new(),
                is_localhost,
                is_strict_localhost: is_localhost,
                http_version: Some("HTTP/2.0".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(false).clone(),
            probe_cache: Default::default(),
        }
    }

    #[tokio::test]
    async fn localhost_preview_is_skipped() {
        let results = DirectoryListingCheck
            .run(&ctx("http://localhost:3000", true))
            .await;
        assert_eq!(results[0].status, CheckStatus::Skipped);
    }

    #[tokio::test]
    async fn unreachable_origin_reads_inconclusive() {
        // A refused request cannot rule out a directory listing.
        let results = DirectoryListingCheck
            .run(&ctx("http://127.0.0.1:1", false))
            .await;
        assert_eq!(results[0].status, CheckStatus::Skipped);
        assert_eq!(results[0].title, "Directory listing check incomplete");
        assert_eq!(
            results[0].description,
            "None of the 19 directories answered, so this scan could not rule out a listing there."
        );
    }
}
