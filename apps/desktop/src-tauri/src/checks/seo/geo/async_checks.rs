//! Probe-driven GEO check shells. Each verdict lives in the engine
//! (`sitecmd_engine::checks::seo::geo`); these shells supply the shared
//! per-scan fetches (robots.txt, sitemap) or run the llms.txt probe through
//! the seam.

use crate::checks::{probe, AsyncCheck, CheckContext, CheckResult, ScanCategory};
use sitecmd_engine::checks::seo::geo::ai_crawlers::evaluate_ai_crawler_blocking;
use sitecmd_engine::checks::seo::geo::llms_txt::{evaluate_llms_txt, llms_txt_url};
use sitecmd_engine::checks::seo::geo::sitemap_freshness::evaluate_sitemap_freshness;
use sitecmd_engine::probe::ProbeRequest;

pub struct LlmsTxtCheck;

#[async_trait::async_trait]
impl AsyncCheck for LlmsTxtCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "seo.llms_txt"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let request = ProbeRequest::get(llms_txt_url(&ctx.url));
        evaluate_llms_txt(probe(&ctx.client, request).await)
    }
}

pub struct AiCrawlerBlockingCheck;

#[async_trait::async_trait]
impl AsyncCheck for AiCrawlerBlockingCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "seo.ai_crawler_blocking"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        ctx.robots_txt()
            .await
            .body()
            .map_or_else(Vec::new, evaluate_ai_crawler_blocking)
    }
}

pub struct SitemapFreshnessCheck;

#[async_trait::async_trait]
impl AsyncCheck for SitemapFreshnessCheck {
    fn origin_scoped(&self) -> bool {
        true
    }
    fn id(&self) -> &str {
        "seo.sitemap_freshness"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, ctx: &CheckContext) -> Vec<CheckResult> {
        let crate::checks::SitemapProbe::Found(found) = ctx.sitemap().await else {
            return vec![];
        };
        evaluate_sitemap_freshness(found)
    }
}

#[cfg(test)]
#[path = "async_checks_tests.rs"]
mod tests;
