//! Sitemap guidance from the detected document stack.

use crate::checks::PageContext;

/// Infer a short stack hint from response headers or generator metadata.
pub fn detect_stack_hint(page: &PageContext) -> Option<&'static str> {
    let powered_by = page
        .response_headers
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let server = page
        .response_headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body_lower = page.body_lower();

    if powered_by.contains("next.js")
        || server.contains("vercel")
        || body_lower.contains("__next") && body_lower.contains("_next/static")
    {
        return Some("Next.js");
    }
    if powered_by.contains("nuxt") || body_lower.contains("__nuxt") {
        return Some("Nuxt");
    }
    if body_lower.contains("astro-island")
        || body_lower.contains("name=\"generator\" content=\"astro")
    {
        return Some("Astro");
    }
    if body_lower.contains("wp-content/") || body_lower.contains("wp-includes/") {
        return Some("WordPress");
    }
    if server.contains("shopify") || body_lower.contains("cdn.shopify.com") {
        return Some("Shopify");
    }
    if body_lower.contains("name=\"generator\" content=\"hugo") {
        return Some("Hugo");
    }
    if body_lower.contains("name=\"generator\" content=\"jekyll") {
        return Some("Jekyll");
    }
    if body_lower.contains("name=\"generator\" content=\"webflow") {
        return Some("Webflow");
    }
    None
}

pub(super) fn framework_specific_sitemap_fix(stack: Option<&'static str>) -> String {
    match stack {
        Some("Next.js") => "For an App Router project, use the installed Next.js version's `sitemap.(xml|js|ts)` metadata-file convention (commonly `app/sitemap.ts`) and generate canonical public URLs from the authoritative route/content source. For other routers or versions, use their documented route mechanism. Deploy, fetch the final XML logged out, validate representative URLs, and advertise the absolute URL from robots.txt when useful.".into(),
        Some("Nuxt") => "Use a sitemap module or server route that supports the installed Nuxt version, and generate canonical public URLs from the authoritative route/content source. Review the module's current configuration instead of copying a version-specific snippet blindly. Deploy, fetch the final XML logged out, validate representative URLs, and advertise its absolute URL from robots.txt when useful.".into(),
        Some("Astro") => "For statically generated Astro routes, configure the current official `@astrojs/sitemap` integration and the canonical `site` origin; account separately for dynamic SSR routes the integration cannot discover at build time. Build and deploy, then fetch the generated sitemap or index logged out and validate representative canonical URLs.".into(),
        Some("WordPress") => "Check the deployed WordPress core sitemap (commonly `/wp-sitemap.xml`) and any SEO-plugin replacement before changing settings. Keep one authoritative generator, confirm it is enabled for the intended public content, fetch the sitemap/index and representative child sitemaps logged out, and advertise the actual absolute URL from robots.txt when useful.".into(),
        Some("Shopify") => "Shopify documents an automatically generated `/sitemap.xml`; verify it on the storefront's canonical public domain while logged out and check for password/access, domain, or platform-support issues if it is unavailable. Do not try to replace the platform sitemap from theme code. Submit the verified canonical-domain sitemap in the search consoles the store uses.".into(),
        Some("Hugo") => "Review the installed Hugo version's sitemap output and configuration, including the canonical `baseURL` and any sitemap-disable or output-format settings. Rebuild and deploy, fetch the final sitemap/index logged out, and validate representative canonical URLs rather than assuming local generation reached production.".into(),
        Some("Jekyll") => "Use a sitemap generator compatible with the installed Jekyll and hosting versions, such as the currently supported `jekyll-sitemap` plugin where that environment permits it. Generate from canonical public pages, rebuild and deploy, then fetch the final XML logged out and validate representative URLs and exclusions.".into(),
        Some("Webflow") => "Review the current Webflow project SEO/sitemap setting and publish to the canonical custom domain. Fetch `/sitemap.xml` logged out after publishing, verify its canonical URLs and exclusions, and advertise or submit the actual deployed URL where useful. Account for workspace/site-plan behavior instead of assuming an editor toggle reached production.".into(),
        _ => "First decide whether a sitemap materially helps this site (for example, it is large, new, frequently changing, or weakly linked). If so, enable the generator supported by the installed framework, CMS, or host, or emit a static sitemap from the authoritative route/content source. Deploy it at a stable public URL, include only canonical indexable pages, fetch and validate the XML plus representative URLs, then advertise its absolute URL in robots.txt and submit it to relevant search consoles where useful.".into(),
    }
}
