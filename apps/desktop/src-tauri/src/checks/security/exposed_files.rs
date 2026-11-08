//! Desktop transport for exposed-file probes and inline source-secret grading.
//! The engine owns paths, classification, and summary assembly.

use crate::checks::{probe, AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::security::exposed_files::{
    grade_path_probe, sensitive_path_request, source_secrets_result, summarize_exposed_files,
    SENSITIVE_PATHS,
};
use sitecmd_engine::evaluation::sweep_reading;

/// Probes for exposed sensitive files via HTTP requests
pub struct ExposedFilesCheck;

#[async_trait::async_trait]
impl AsyncCheck for ExposedFilesCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "security.exposed_files"
    }

    /// Never emits its own id. `security.exposed_files.<path>` sub-ids are
    /// dynamic (one per `SENSITIVE_PATHS` entry) and covered by the
    /// manifest's family row instead of enumeration here.
    fn emitted_ids(&self) -> Vec<String> {
        vec![
            "security.exposed_files.source_secrets".to_string(),
            "security.exposed_files.summary".to_string(),
        ]
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let base = crate::checks::origin_with_port(&ctx.url);

        // Secret-named identifiers in inline scripts, from the page body.
        let source_advisory = source_secrets_result(&ctx.body);

        // Probe sensitive file paths concurrently, grading each outcome.
        let mut probe_futures = Vec::new();
        for (path, desc, severity) in SENSITIVE_PATHS {
            let request = sensitive_path_request(&base, path);
            let client = ctx.client.clone();
            let path_str = path.to_string();
            let desc_str = desc.to_string();
            let sev = *severity;
            probe_futures.push(tokio::spawn(async move {
                let outcome = probe(&client, request).await;
                grade_path_probe(&path_str, &desc_str, &sev, &sweep_reading(&outcome))
            }));
        }

        let mut path_rows = Vec::new();
        let mut unjoined_probes = 0;
        for future in probe_futures {
            match future.await {
                Ok(row) => path_rows.push(row),
                Err(_) => unjoined_probes += 1,
            }
        }

        summarize_exposed_files(source_advisory, path_rows, unjoined_probes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CheckStatus;

    fn ctx(url: &str, body: &str) -> CheckContext {
        CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse(url).unwrap(),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: body.to_string(),
                is_localhost: false,
                is_strict_localhost: false,
                http_version: Some("HTTP/2.0".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(false).clone(),
            probe_cache: Default::default(),
        }
    }

    #[tokio::test]
    async fn unreachable_origin_yields_an_inconclusive_summary() {
        let results = ExposedFilesCheck.run(&ctx("http://127.0.0.1:1", "")).await;
        let summary = results
            .iter()
            .find(|r| r.check_id == "security.exposed_files.summary")
            .expect("summary row present");
        assert_eq!(summary.status, CheckStatus::Skipped);
        assert!(summary.description.contains("inconclusive"));
    }

    #[tokio::test]
    async fn inline_script_secret_names_surface_as_a_source_advisory() {
        let html = r#"<script>const conn = config.db_password;</script>"#;
        let results = ExposedFilesCheck
            .run(&ctx("http://127.0.0.1:1", html))
            .await;
        assert!(results
            .iter()
            .any(|r| r.check_id == "security.exposed_files.source_secrets"));
    }
}
