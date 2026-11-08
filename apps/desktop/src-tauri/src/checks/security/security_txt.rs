//! Desktop transport shell for the engine's RFC 9116 security.txt check.

use crate::checks::{probe, AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::security::security_txt::{
    classify_security_txt_probe, evaluate_legacy, evaluate_well_known, security_txt_request,
    security_txt_urls, SecurityTxtStep, CHECK_ID,
};

pub struct SecurityTxtCheck;

#[async_trait::async_trait]
impl AsyncCheck for SecurityTxtCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        CHECK_ID
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let base = crate::checks::origin_with_port(&ctx.url);
        let (well_known, legacy) = security_txt_urls(&base);
        let fetch = classify_security_txt_probe(
            probe(&ctx.client, security_txt_request(&well_known)).await,
        );
        match evaluate_well_known(self.id(), &base, fetch, ctx.evaluation_time) {
            SecurityTxtStep::Done(results) => results,
            SecurityTxtStep::ProbeLegacy { well_known_status } => {
                let fetch = classify_security_txt_probe(
                    probe(&ctx.client, security_txt_request(&legacy)).await,
                );
                evaluate_legacy(
                    self.id(),
                    &base,
                    well_known_status,
                    fetch,
                    ctx.evaluation_time,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::CheckStatus;

    #[tokio::test]
    async fn unreachable_origin_makes_no_presence_claim() {
        let ctx = CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse("http://127.0.0.1:1").unwrap(),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: String::new(),
                is_localhost: false,
                is_strict_localhost: false,
                http_version: Some("HTTP/1.1".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(false).clone(),
            probe_cache: Default::default(),
        };
        let results = SecurityTxtCheck.run(&ctx).await;
        assert_eq!(results[0].status, CheckStatus::Skipped);
        assert!(results[0].title.contains("did not complete"));
    }
}
