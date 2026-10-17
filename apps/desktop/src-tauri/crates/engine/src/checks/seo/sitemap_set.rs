//! Sitemap set identity, bounds and incomplete-read reasons.

/// Which bound cut a sitemap read short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitemapBound {
    /// URLs listed by a single sitemap document.
    Urls,
    /// Child sitemaps listed by a sitemap index.
    ChildSitemaps,
    /// URLs collected while walking a sitemap index. The walk stops as soon as
    /// it holds `cap` URLs, so reaching the cap exactly still means it stopped
    /// with children left unread.
    IndexUrls,
}

/// Why a URL set is known to be shorter than what the document offered, or
/// `None` when the whole document was read. `observed` is what the document
/// offered (for `IndexUrls`, what the walk had collected when it stopped).
pub fn partial_reason(bound: SitemapBound, observed: usize, cap: usize) -> Option<String> {
    let truncated = match bound {
        SitemapBound::IndexUrls => observed >= cap,
        SitemapBound::Urls | SitemapBound::ChildSitemaps => observed > cap,
    };
    if !truncated {
        return None;
    }
    Some(sitemap_bound_description(bound, observed, cap))
}

/// Describe the observed sitemap bound and the portion read.
pub fn sitemap_bound_description(bound: SitemapBound, observed: usize, cap: usize) -> String {
    match bound {
        SitemapBound::Urls => {
            format!("the sitemap lists {observed} URLs and SiteCMD read the first {cap}")
        }
        SitemapBound::ChildSitemaps => format!(
            "the sitemap index lists {observed} child sitemaps and SiteCMD read the first {cap}"
        ),
        SitemapBound::IndexUrls => format!(
            "the sitemap index yielded more than {cap} URLs and SiteCMD read the first {cap}"
        ),
    }
}

/// A sitemap URL reduced to the identity two references to the same document
/// share. robots.txt directives are raw text written by the site: a site
/// scanned at its www host can declare the sitemap on its apex host, a site on
/// https can declare it as http, and a robots.txt can list the same URL twice.
/// None of those is a further sitemap, so none may mark a set partial.
pub fn sitemap_identity(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url.trim()) else {
        return url.trim().trim_end_matches('/').to_ascii_lowercase();
    };
    parsed.set_fragment(None);
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = parsed.path().trim_end_matches('/');
    let query = parsed.query().map(|q| format!("?{q}")).unwrap_or_default();
    format!("{host}{port}{path}{query}")
}

/// Why the set is partial because the site declares sitemaps that were not the
/// one read, or `None` when everything declared was covered by the one read.
pub fn unread_sitemaps_reason(declared: &[String], read: Option<&str>) -> Option<String> {
    let count = unread_sitemaps_count(declared, read);
    (count > 0).then(|| unread_sitemaps_description(count))
}

/// Count distinct declared sitemaps other than the one whose set was read.
pub fn unread_sitemaps_count(declared: &[String], read: Option<&str>) -> usize {
    let read = read.map(sitemap_identity);
    let unread: std::collections::HashSet<String> = declared
        .iter()
        .map(|url| sitemap_identity(url))
        .filter(|identity| Some(identity) != read.as_ref())
        .collect();
    unread.len()
}

/// Why further declared sitemaps make a URL set incomplete.
pub fn unread_sitemaps_description(unread: usize) -> String {
    format!(
        "robots.txt declares {unread} further sitemap{} that {} not read",
        if unread == 1 { "" } else { "s" },
        if unread == 1 { "was" } else { "were" },
    )
}
