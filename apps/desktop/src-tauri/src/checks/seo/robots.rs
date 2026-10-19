//! Desktop transport shell for the engine's robots.txt verdict.

use crate::checks::{AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::seo::robots::evaluate_robots_txt;

pub struct RobotsTxtCheck;

#[async_trait::async_trait]
impl AsyncCheck for RobotsTxtCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "seo.robots_txt"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        evaluate_robots_txt(ctx.robots_txt().await)
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::{AsyncCheck, CheckContext, CheckStatus, RobotsTxtFetch};

    fn ctx_with_robots(fetch: RobotsTxtFetch) -> CheckContext {
        let ctx = CheckContext {
            page: crate::checks::PageContext {
                evaluation_time: chrono::Utc::now(),
                url: url::Url::parse("https://example.com").unwrap(),
                response_headers: reqwest::header::HeaderMap::new(),
                status_code: 200,
                body: String::new(),
                is_localhost: false,
                is_strict_localhost: false,
                http_version: Some("HTTP/2.0".to_string()),
                body_lower_cache: std::sync::OnceLock::new(),
            },
            client: crate::http_client::for_url(false).clone(),
            probe_cache: Default::default(),
        };
        assert!(ctx.probe_cache.robots_txt.set(fetch).is_ok());
        ctx
    }

    #[tokio::test]
    async fn shell_grades_the_seeded_fetch_through_the_engine() {
        let results = super::RobotsTxtCheck
            .run(&ctx_with_robots(RobotsTxtFetch::Found {
                body: "User-agent: *\nDisallow: /\n".into(),
            }))
            .await;
        assert_eq!(results[0].status, CheckStatus::Warn);
        assert!(results[0].title.contains("broadly blocks"));
    }

    #[tokio::test]
    async fn confirmed_missing_robots_is_a_skip_not_a_defect() {
        let results = super::RobotsTxtCheck
            .run(&ctx_with_robots(RobotsTxtFetch::Status(404)))
            .await;
        assert_eq!(results[0].status, CheckStatus::Skipped);
        assert!(results[0].title.contains("No robots.txt"));
    }
    #[tokio::test]
    async fn server_errors_fail_while_rate_limiting_stays_skipped() {
        for (code, expected) in [(503, CheckStatus::Fail), (429, CheckStatus::Skipped)] {
            let results = super::RobotsTxtCheck
                .run(&ctx_with_robots(RobotsTxtFetch::Status(code)))
                .await;
            assert_eq!(results[0].status, expected, "{code}");
        }
    }
}
