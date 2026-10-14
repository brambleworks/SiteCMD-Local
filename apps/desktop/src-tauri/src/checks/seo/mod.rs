//! SEO checks: meta tags, headings, canonical URLs, robots.txt, sitemap, structured data, links,
//! and GEO (Generative Engine Optimization) for AI visibility.

pub use sitecmd_engine::checks::seo::canonical_meta;
pub use sitecmd_engine::checks::seo::content;
pub use sitecmd_engine::checks::seo::robots_conflicts;
pub mod geo;
pub use sitecmd_engine::checks::seo::headings;
pub use sitecmd_engine::checks::seo::link_count;
pub mod links;
pub use sitecmd_engine::checks::seo::meta_refresh;
pub mod meta;
pub mod redirects;
pub mod robots;
pub mod sitemap;
pub use sitecmd_engine::checks::seo::speed_hints;
pub use sitecmd_engine::checks::seo::structured_data;

use super::{AsyncCheck, Check};

/// All synchronous SEO checks (HTML parsing)
pub fn sync_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(meta::TitleTagCheck),
        Box::new(meta::MetaDescriptionCheck),
        Box::new(meta::CanonicalCheck),
        Box::new(meta::ViewportCheck),
        Box::new(meta::OpenGraphCheck),
        Box::new(meta::OgImageAbsoluteCheck),
        Box::new(meta::MetaCharsetCheck),
        Box::new(meta::TwitterCardCheck),
        Box::new(meta::NoindexCheck),
        Box::new(meta::HreflangCheck),
        Box::new(meta::DuplicateMetaCheck),
        // The HeadingCheck shell remains for history compatibility but is
        // unregistered: the H1 count runs as the SEO-owned seo.headings.h1,
        // and HeadingOrderCheck owns heading order under accessibility.
        Box::new(headings::H1Check),
        Box::new(meta_refresh::MetaRefreshCheck),
        Box::new(link_count::LinkCountCheck),
        Box::new(links::UrlStructureCheck),
        Box::new(structured_data::StructuredDataCheck),
        Box::new(content::ThinContentCheck),
        Box::new(canonical_meta::CanonicalMismatchCheck),
        Box::new(robots_conflicts::MetaRobotsConflictCheck),
        Box::new(speed_hints::PageSpeedHintsCheck),
        Box::new(geo::CitationMetaCheck),
        Box::new(geo::ContentFreshnessCheck),
        Box::new(geo::OrganizationIdentityCheck),
        Box::new(geo::FaqSchemaCheck),
        Box::new(geo::SemanticHtmlCheck),
        Box::new(geo::SourceCitationsCheck),
        Box::new(geo::JsOnlyContentCheck),
    ]
}

/// All async SEO checks (HTTP probes)
pub fn async_checks() -> Vec<Box<dyn AsyncCheck>> {
    vec![
        Box::new(robots::RobotsTxtCheck),
        Box::new(sitemap::SitemapCheck),
        Box::new(links::BrokenLinksCheck),
        Box::new(links::BrokenExternalLinksCheck),
        Box::new(meta::OgImageResolvableCheck),
        Box::new(redirects::TemporaryRedirectCheck),
        Box::new(geo::LlmsTxtCheck),
        Box::new(geo::AiCrawlerBlockingCheck),
        Box::new(geo::SitemapFreshnessCheck),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn seo_registration_does_not_duplicate_the_accessibility_image_alt_check() {
        let checks = super::sync_checks();
        let ids: Vec<&str> = checks.iter().map(|check| check.id()).collect();
        assert!(
            !ids.contains(&"seo.image_alt"),
            "image alt attributes have one authority: accessibility.image_alt"
        );
    }

    #[test]
    fn h1_count_is_an_seo_check_and_heading_order_stays_with_accessibility() {
        let checks = super::sync_checks();
        let ids: Vec<&str> = checks.iter().map(|check| check.id()).collect();
        assert!(
            ids.contains(&"seo.headings.h1"),
            "the H1 count is an SEO signal with its own registered check"
        );
        assert!(
            !ids.contains(&"seo.headings"),
            "the HeadingCheck shell stays unregistered"
        );
        assert!(
            !ids.contains(&"seo.headings.hierarchy"),
            "heading order has one authority: accessibility.headings"
        );
    }

    #[test]
    fn meta_refresh_and_link_count_are_registered_seo_checks() {
        let checks = super::sync_checks();
        let ids: Vec<&str> = checks.iter().map(|check| check.id()).collect();
        assert!(ids.contains(&"seo.meta_refresh"), "{ids:?}");
        assert!(ids.contains(&"seo.link_count"), "{ids:?}");
    }
}
