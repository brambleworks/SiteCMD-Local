//! A challenge hides declarations and withholds sitemap-based session grading.

use super::*;
use sitecmd_engine::checks::seo::sitemap_walk::SITEMAP_WALK_INCOMPLETE_REASON;

#[tokio::test]
async fn only_challenged_non_successes_withhold_sitemap_session_grading() {
    for (status, headers, expected) in [
        (
            "403 Forbidden",
            "cf-mitigated: \tChAlLeNgE \r\n",
            CheckStatus::Skipped,
        ),
        (
            "503 Service Unavailable",
            "cf-mitigated: challenge\r\n",
            CheckStatus::Skipped,
        ),
        ("200 OK", "cf-mitigated: challenge\r\n", CheckStatus::Warn),
        ("403 Forbidden", "", CheckStatus::Warn),
    ] {
        let paths = ["/", "/a", "/b", "/c", "/d"];
        let site = TestSite::with_robots_headers(
            |origin| {
                let entries: String = paths
                    .iter()
                    .map(|path| format!("<url><loc>{origin}{path}</loc></url>"))
                    .collect();
                vec![
                    ("/robots.txt", status, "text/plain", String::new()),
                    (
                        "/sitemap.xml",
                        "200 OK",
                        "application/xml",
                        format!("<urlset>{entries}</urlset>"),
                    ),
                ]
            },
            headers,
        )
        .await;
        let sitemap = site.discover().await;
        assert_eq!(sitemap.status, SitemapStatus::Found);
        assert_eq!(sitemap.urls.len(), paths.len());
        let pages: Vec<_> = paths.iter().map(|path| {
            let url = url::Url::parse(&format!("{}{path}", site.origin)).expect("page URL");
            let body = match *path {
                "/" => "<html><body><a href='/a'>A</a><a href='/b'>B</a><a href='/c'>C</a></body></html>",
                _ => "<html></html>",
            };
            extract_page_signals_with_headers(&url, &url, 200, body, &reqwest::header::HeaderMap::new()).session_page()
        }).collect();
        let analysis = analyze_session(
            &pages,
            Some(SessionSitemap {
                urls: &sitemap.urls,
                partial_because: sitemap.partial_because.as_deref(),
            }),
        );
        let status_for = |id| {
            analysis
                .verdicts
                .iter()
                .find(|verdict| verdict.result.check_id == id)
                .expect("session verdict")
                .result
                .status
        };
        let reason = (expected == CheckStatus::Skipped).then_some(SITEMAP_WALK_INCOMPLETE_REASON);
        let noindex_status = if expected == CheckStatus::Skipped {
            CheckStatus::Skipped
        } else {
            CheckStatus::Pass
        };
        assert_eq!(
            (
                sitemap.partial_because.as_deref(),
                status_for("seo.orphan_pages"),
                status_for("seo.noindex_in_sitemap")
            ),
            (reason, expected, noindex_status),
            "{status} {headers:?}",
        );
    }
}
