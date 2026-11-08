use super::{verify_checks, ScanType};
use crate::checks::polish::{PolishResult, SignalCategory, SignalWeight};
use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};
use crate::scoring::calculator;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
struct TestResponse {
    status: u16,
    content_type: &'static str,
    body: String,
    location: Option<String>,
}

impl TestResponse {
    fn ok(content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status: 200,
            content_type,
            body: body.into(),
            location: None,
        }
    }

    fn redirect(location: impl Into<String>) -> Self {
        Self {
            status: 302,
            content_type: "text/plain; charset=utf-8",
            body: String::new(),
            location: Some(location.into()),
        }
    }
}

struct TestServer {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_test_server<F>(build_routes: F) -> TestServer
where
    F: FnOnce(&str) -> HashMap<String, TestResponse>,
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let base_url = format!("http://{}", addr);
    let routes = Arc::new(build_routes(&base_url));

    let handle = tokio::spawn({
        let routes = routes.clone();
        async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 8192];
                    let read = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let request_line = request.lines().next().unwrap_or_default();
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("GET");
                    let raw_path = parts.next().unwrap_or("/");
                    let path = raw_path.split('?').next().unwrap_or(raw_path);

                    let response = routes.get(path).cloned().unwrap_or(TestResponse {
                        status: 404,
                        content_type: "text/plain; charset=utf-8",
                        body: "Not found".into(),
                        location: None,
                    });

                    let status_text = match response.status {
                        200 => "OK",
                        302 => "Found",
                        404 => "Not Found",
                        _ => "OK",
                    };
                    let content_length = response.body.len();
                    let location = response
                        .location
                        .as_deref()
                        .map(|value| format!("Location: {value}\r\n"))
                        .unwrap_or_default();
                    let head = format!(
                        "HTTP/1.1 {} {}\r\n{}Content-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.status,
                        status_text,
                        location,
                        response.content_type,
                        content_length
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    if method != "HEAD" {
                        let _ = stream.write_all(response.body.as_bytes()).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        }
    });

    TestServer { base_url, handle }
}

async fn verify_slice(url: &str, check_ids: &[&str]) -> Vec<CheckResult> {
    let ids = check_ids
        .iter()
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();
    verify_checks::<fn() -> bool>(url, &ids, None)
        .await
        .expect("verify checks")
        .results
}

fn score_for_category(results: &[CheckResult], category: ScanCategory) -> u32 {
    let (_, categories) = calculator::calculate_scores(results);
    categories
        .iter()
        .find(|entry| entry.category == category)
        .map(|entry| entry.score)
        .unwrap_or(0)
}

fn status_for(results: &[CheckResult], check_id: &str) -> CheckStatus {
    results
        .iter()
        .find(|result| result.check_id == check_id)
        .unwrap_or_else(|| panic!("missing check result for {}", check_id))
        .status
}

fn fired_polish_result(id: &str, category: SignalCategory, weight: SignalWeight) -> PolishResult {
    PolishResult::fired(
        id,
        id,
        weight,
        category,
        "test detail".to_string(),
        serde_json::json!({}),
    )
}

#[test]
fn polish_copy_signals_do_not_become_critical_issues() {
    let result = fired_polish_result(
        "ai-buzzword-dictionary",
        SignalCategory::CopyContent,
        SignalWeight::High,
    );
    let check = crate::checks::polish::polish_check_result(&result);

    assert_eq!(check.check_id, "polish.ai-buzzword-dictionary");
    assert_eq!(
        crate::core::severity_policy::normalized_web_issue_severity(&check),
        Severity::Low
    );
}

#[test]
fn polish_structure_heuristics_stay_at_editorial_review_severity() {
    let result = fired_polish_result(
        "div-soup-ratio",
        SignalCategory::HtmlQuality,
        SignalWeight::High,
    );
    let check = crate::checks::polish::polish_check_result(&result);

    assert_eq!(check.check_id, "polish.div-soup-ratio");
    assert_eq!(
        crate::core::severity_policy::normalized_web_issue_severity(&check),
        Severity::Low
    );
}

#[test]
fn polish_source_map_reference_is_review_level_until_access_is_confirmed() {
    let result = fired_polish_result(
        "source-maps-production",
        SignalCategory::MetaInfrastructure,
        SignalWeight::Medium,
    );
    let check = crate::checks::polish::polish_check_result(&result);

    assert_eq!(check.check_id, "polish.source-maps-production");
    assert_eq!(
        crate::core::severity_policy::normalized_web_issue_severity(&check),
        Severity::Medium
    );
}

#[tokio::test]
async fn verify_results_arrive_severity_policy_normalized() {
    let server = spawn_test_server(|_| {
        HashMap::from([(
            "/".into(),
            TestResponse::ok(
                "text/html; charset=utf-8",
                "<html><head><title>Home</title></head><body>Home</body></html>",
            ),
        )])
    })
    .await;

    let results = verify_slice(&server.base_url, &["seo.sitemap"]).await;
    let sitemap = results
        .iter()
        .find(|result| result.check_id == "seo.sitemap")
        .expect("seo.sitemap result");

    assert_eq!(sitemap.status, CheckStatus::Warn);
    assert_eq!(sitemap.severity, Severity::Low);
}

#[tokio::test]
async fn sitecmd_landing_preview_golden_slice_matches_expected_statuses() {
    let server = spawn_test_server(|base_url| {
        HashMap::from([
            (
                "/".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    r#"<!doctype html>
                            <html lang="en">
                              <head>
                                <title>SiteCMD | Launch checks for indie devs</title>
                                <meta name="description" content="Catch launch blockers, follow clear fixes, and verify the result before you ship.">
                                <meta name="viewport" content="width=device-width, initial-scale=1">
                                <link rel="canonical" href="https://sitecmd.com/">
                              </head>
                              <body>
                                <main>
                                  <h1>Ship with fewer surprises</h1>
                                  <p>SiteCMD helps indie developers catch real issues before launch.</p>
                                  <a href="/docs">Docs</a>
                                </main>
                              </body>
                            </html>"#.to_string(),
                ),
            ),
            (
                "/docs".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    "<html><head><title>Docs</title></head><body>Docs</body></html>",
                ),
            ),
            (
                "/robots.txt".into(),
                TestResponse::ok(
                    "text/plain; charset=utf-8",
                    format!(
                        "User-agent: *\nAllow: /\nSitemap: {}/sitemap-index.xml\n",
                        base_url
                    ),
                ),
            ),
            (
                "/sitemap-index.xml".into(),
                TestResponse::ok(
                    "application/xml; charset=utf-8",
                    format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
                            <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                              <sitemap><loc>{}/sitemap-pages.xml</loc></sitemap>
                            </sitemapindex>"#,
                        base_url
                    ),
                ),
            ),
            (
                "/llms.txt".into(),
                TestResponse::ok(
                    "text/plain; charset=utf-8",
                    "SiteCMD helps indie developers and vibe coders find launch blockers quickly.",
                ),
            ),
        ])
    })
    .await;

    let check_ids = [
        "seo.meta_description",
        "seo.noindex",
        "seo.robots_txt",
        "seo.sitemap",
        "config.sitemap_in_robots",
        "seo.llms_txt",
        "seo.sitemap_freshness",
        "seo.broken_links",
    ];
    let results = verify_slice(&server.base_url, &check_ids).await;

    assert_eq!(
        status_for(&results, "seo.meta_description"),
        CheckStatus::Pass
    );
    assert_eq!(status_for(&results, "seo.noindex"), CheckStatus::Pass);
    assert_eq!(status_for(&results, "seo.robots_txt"), CheckStatus::Pass);
    assert_eq!(status_for(&results, "seo.sitemap"), CheckStatus::Pass);
    assert_eq!(
        status_for(&results, "config.sitemap_in_robots"),
        CheckStatus::Pass
    );
    assert_eq!(status_for(&results, "seo.llms_txt"), CheckStatus::Pass);
    assert_eq!(
        status_for(&results, "seo.sitemap_freshness"),
        CheckStatus::Pass
    );
    assert_eq!(status_for(&results, "seo.broken_links"), CheckStatus::Pass);

    assert_eq!(score_for_category(&results, ScanCategory::Seo), 100);
}

#[tokio::test]
async fn sitecmd_landing_slice_score_recovers_when_preview_discovery_is_healthy() {
    let healthy = spawn_test_server(|base_url| {
        HashMap::from([
            (
                "/".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    r#"<!doctype html>
                        <html lang="en">
                          <head>
                            <title>SiteCMD</title>
                            <meta name="description" content="Catch launch blockers before you ship.">
                          </head>
                          <body><a href="/docs">Docs</a></body>
                        </html>"#,
                ),
            ),
            (
                "/docs".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    "<html><body>Docs</body></html>",
                ),
            ),
            (
                "/robots.txt".into(),
                TestResponse::ok(
                    "text/plain; charset=utf-8",
                    format!(
                        "User-agent: *\nAllow: /\nSitemap: {}/sitemap-index.xml\n",
                        base_url
                    ),
                ),
            ),
            (
                "/sitemap-index.xml".into(),
                TestResponse::ok(
                    "application/xml; charset=utf-8",
                    format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
                            <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                              <sitemap><loc>{}/sitemap-pages.xml</loc></sitemap>
                            </sitemapindex>"#,
                        base_url
                    ),
                ),
            ),
            (
                "/llms.txt".into(),
                TestResponse::ok(
                    "text/plain; charset=utf-8",
                    "SiteCMD helps indie developers find and fix launch issues.",
                ),
            ),
        ])
    })
    .await;

    let regressed = spawn_test_server(|_base_url| {
        HashMap::from([
            (
                "/".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    r#"<!doctype html>
                        <html lang="en">
                          <head>
                            <title>SiteCMD</title>
                            <meta name="robots" content="noindex,nofollow">
                          </head>
                          <body><a href="/docs">Docs</a></body>
                        </html>"#,
                ),
            ),
            (
                "/robots.txt".into(),
                TestResponse::ok("text/plain; charset=utf-8", "User-agent: *\nAllow: /\n"),
            ),
        ])
    })
    .await;

    let check_ids = [
        "seo.meta_description",
        "seo.noindex",
        "seo.robots_txt",
        "seo.sitemap",
        "config.sitemap_in_robots",
        "seo.llms_txt",
        "seo.broken_links",
    ];
    let healthy_results = verify_slice(&healthy.base_url, &check_ids).await;
    let regressed_results = verify_slice(&regressed.base_url, &check_ids).await;

    let healthy_score = score_for_category(&healthy_results, ScanCategory::Seo);
    let regressed_score = score_for_category(&regressed_results, ScanCategory::Seo);

    assert_eq!(healthy_score, 99);
    assert_eq!(regressed_score, 90);
    assert!(
        healthy_score > regressed_score,
        "expected healthy score {} to beat regressed score {}",
        healthy_score,
        regressed_score
    );
}

#[tokio::test]
async fn projectcostcalc_content_discovery_slice_shows_real_score_movement() {
    let healthy = spawn_test_server(|base_url| {
        HashMap::from([
            (
                "/bathroom-remodel".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    r#"<!doctype html>
                        <html lang="en">
                          <head>
                            <title>Bathroom Remodel Cost Calculator | ProjectCostCalc</title>
                            <meta name="description" content="Estimate bathroom remodel costs with clear pricing ranges, related guides, and next-step planning help.">
                            <meta name="viewport" content="width=device-width, initial-scale=1">
                            <link rel="canonical" href="https://projectcostcalc.com/bathroom-remodel">
                          </head>
                          <body>
                            <main>
                              <h1>Bathroom Remodel Cost Calculator</h1>
                              <p>Use this guide to compare realistic remodel costs.</p>
                              <a href="/guides/costs">Cost guides</a>
                            </main>
                          </body>
                        </html>"#,
                ),
            ),
            (
                "/guides/costs".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    "<html><body>Cost guides</body></html>",
                ),
            ),
            (
                "/robots.txt".into(),
                TestResponse::ok(
                    "text/plain; charset=utf-8",
                    format!("User-agent: *\nAllow: /\nSitemap: {}/sitemap.xml\n", base_url),
                ),
            ),
            (
                "/sitemap.xml".into(),
                TestResponse::ok(
                    "application/xml; charset=utf-8",
                    format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
                            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                              <url>
                                <loc>{}/bathroom-remodel</loc>
                                <lastmod>2026-04-10</lastmod>
                              </url>
                            </urlset>"#,
                        base_url
                    ),
                ),
            ),
        ])
    })
    .await;

    let regressed = spawn_test_server(|base_url| {
        HashMap::from([
            (
                "/bathroom-remodel".into(),
                TestResponse::ok(
                    "text/html; charset=utf-8",
                    r#"<!doctype html>
                        <html lang="en">
                          <head>
                            <title>Bathroom Remodel Cost Calculator | ProjectCostCalc</title>
                            <meta name="description" content="This description is far too long for a clean search snippet because it keeps talking past the point where a search result would normally truncate and starts sounding padded instead of useful to the person deciding whether to click.">
                            <meta name="viewport" content="width=device-width, initial-scale=1">
                          </head>
                          <body>
                            <main>
                              <h1>Bathroom Remodel Cost Calculator</h1>
                              <p>Use this guide to compare realistic remodel costs.</p>
                            </main>
                          </body>
                        </html>"#,
                ),
            ),
            (
                "/robots.txt".into(),
                TestResponse::ok("text/plain; charset=utf-8", "User-agent: *\nAllow: /\n"),
            ),
            (
                "/sitemap.xml".into(),
                TestResponse::ok(
                    "application/xml; charset=utf-8",
                    format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
                            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                              <url><loc>{}/bathroom-remodel</loc></url>
                            </urlset>"#,
                        base_url
                    ),
                ),
            ),
        ])
    })
    .await;

    let check_ids = [
        "seo.title",
        "seo.meta_description",
        "seo.canonical",
        "seo.robots_txt",
        "seo.sitemap",
        "config.sitemap_in_robots",
        "seo.sitemap_freshness",
    ];
    let healthy_results = verify_slice(
        &format!("{}/bathroom-remodel", healthy.base_url),
        &check_ids,
    )
    .await;
    let regressed_results = verify_slice(
        &format!("{}/bathroom-remodel", regressed.base_url),
        &check_ids,
    )
    .await;

    assert_eq!(score_for_category(&healthy_results, ScanCategory::Seo), 100);
    // Pin the aggregate weight of the remaining contextual advisories.
    assert_eq!(
        score_for_category(&regressed_results, ScanCategory::Seo),
        99
    );
}

#[tokio::test]
async fn visityourteam_public_route_slice_does_not_false_positive_on_client_auth() {
    let clean_public_route = spawn_test_server(|_base_url| {
        HashMap::from([(
            "/".into(),
            TestResponse::ok(
                "text/html; charset=utf-8",
                r#"<!doctype html>
                    <html lang="en">
                      <head>
                        <title>VisitYourTeam | Every stadium trip in one place</title>
                        <meta name="description" content="Plan game-day trips with stadium prices, fan tips, and team guides across every major league.">
                      </head>
                      <body>
                        <main>
                          <h1>Plan your next sports trip</h1>
                          <p>Compare costs, parking, and seating before you go.</p>
                        </main>
                      </body>
                    </html>"#,
            ),
        )])
    })
    .await;

    let regressed_public_route = spawn_test_server(|_base_url| {
        HashMap::from([(
            "/".into(),
            TestResponse::ok(
                "text/html; charset=utf-8",
                r#"<!doctype html>
                    <html lang="en">
                      <head>
                        <title>VisitYourTeam | Every stadium trip in one place</title>
                        <meta name="description" content="Plan game-day trips with stadium prices, fan tips, and team guides across every major league.">
                      </head>
                      <body>
                        <script>
                          if (user.role === "admin") { renderAdminPanel(); }
                        </script>
                      </body>
                    </html>"#,
            ),
        )])
    })
    .await;

    let check_ids = [
        "security.vibe.client_auth",
        "seo.title",
        "seo.meta_description",
    ];
    let clean_results = verify_slice(&clean_public_route.base_url, &check_ids).await;
    let regressed_results = verify_slice(&regressed_public_route.base_url, &check_ids).await;

    assert_eq!(
        status_for(&clean_results, "security.vibe.client_auth"),
        CheckStatus::Pass
    );
    assert_eq!(
        status_for(&regressed_results, "security.vibe.client_auth"),
        CheckStatus::Warn
    );
    assert_eq!(
        score_for_category(&clean_results, ScanCategory::Security),
        100
    );
    assert!(
        score_for_category(&regressed_results, ScanCategory::Security) < 100,
        "expected security score to drop after browser-only auth regression, got {}",
        score_for_category(&regressed_results, ScanCategory::Security)
    );
}

#[tokio::test]
async fn localhost_preview_canonical_mismatch_is_skipped_when_pointing_to_production() {
    let preview = spawn_test_server(|_base_url| {
        HashMap::from([(
            "/".into(),
            TestResponse::ok(
                "text/html; charset=utf-8",
                r#"<!doctype html>
                    <html lang="en">
                      <head>
                        <title>SiteCMD</title>
                        <meta name="description" content="Catch launch blockers before you ship.">
                        <link rel="canonical" href="https://sitecmd.com/">
                      </head>
                      <body><h1>Preview build</h1></body>
                    </html>"#,
            ),
        )])
    })
    .await;

    let results = verify_slice(&preview.base_url, &["seo.canonical_mismatch"]).await;
    assert_eq!(
        status_for(&results, "seo.canonical_mismatch"),
        CheckStatus::Skipped
    );
}

#[tokio::test]
async fn run_polish_phase_moves_body_instead_of_cloning() {
    let mut ctx = crate::checks::CheckContext {
        page: crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: "<html><head><title>Test</title></head><body><p>Hi</p></body></html>".to_string(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: None,
            body_lower_cache: std::sync::OnceLock::new(),
        },
        client: crate::http_client::for_url(false).clone(),
        probe_cache: Default::default(),
    };
    let mut results = Vec::new();
    super::run_polish_phase(
        &mut ctx,
        crate::network_policy::LocalOrigin::Public,
        None,
        &mut results,
        None::<&dyn Fn() -> bool>,
        false,
    )
    .await
    .expect("polish phase should succeed for a stylesheet-free body");

    assert!(
        ctx.body.is_empty(),
        "run_polish_phase must move the body out of CheckContext, not clone it"
    );
    assert!(
        !results.is_empty(),
        "polish signals should still produce results from the moved body"
    );
}

#[test]
fn origin_scoped_async_checks_match_expected_set() {
    let (_sync, async_checks) = super::collect_checks(&None);
    let mut origin_scoped: Vec<&str> = async_checks
        .iter()
        .filter(|check| check.origin_scoped())
        .map(|check| check.id())
        .collect();
    origin_scoped.sort_unstable();
    assert_eq!(
        origin_scoped,
        vec![
            "config.custom_404",
            "config.sitemap_in_robots",
            "config.www_redirect",
            "security.directory_listing",
            "security.dns.caa",
            "security.dns.dangling_cname",
            "security.dns.dkim",
            "security.dns.dmarc",
            "security.dns.dnssec",
            "security.dns.mx",
            "security.dns.spf",
            "security.domain_expiry",
            "security.exposed_files",
            "security.https_enforcement",
            "security.open_redirect",
            "security.security_txt",
            "security.ssl",
            "seo.ai_crawler_blocking",
            "seo.llms_txt",
            "seo.robots_txt",
            "seo.sitemap",
            "seo.sitemap_freshness",
        ]
    );
}

#[tokio::test]
async fn probe_cache_fetches_robots_and_sitemap_once_per_scan() {
    let hits: Arc<std::sync::Mutex<HashMap<String, usize>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting server");
    let addr = listener.local_addr().expect("local addr");
    let server_hits = hits.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let hits = server_hits.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let read = match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                *hits.lock().unwrap().entry(path.clone()).or_insert(0) += 1;

                let body = match path.as_str() {
                    "/robots.txt" => "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n",
                    "/sitemap.xml" => {
                        "<?xml version=\"1.0\"?><urlset><url><loc>/</loc></url></urlset>"
                    }
                    _ => "Not found",
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            });
        }
    });

    let ctx = crate::checks::CheckContext {
        page: crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: url::Url::parse(&format!("http://{}", addr)).unwrap(),
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: String::new(),
            is_localhost: true,
            is_strict_localhost: true,
            http_version: None,
            body_lower_cache: std::sync::OnceLock::new(),
        },
        client: crate::http_client::for_url(true).clone(),
        probe_cache: Default::default(),
    };

    // Simulate the multiple consumers, including concurrent access.
    let (first, second) = tokio::join!(ctx.robots_txt(), ctx.robots_txt());
    assert!(matches!(first, crate::checks::RobotsTxtFetch::Found { .. }));
    assert!(matches!(
        second,
        crate::checks::RobotsTxtFetch::Found { .. }
    ));
    let _ = ctx.robots_txt().await;
    let (a, b) = tokio::join!(ctx.sitemap(), ctx.sitemap());
    let crate::checks::SitemapProbe::Found(found_a) = a else {
        panic!("expected the sitemap probe to find the fixture, got {a:?}");
    };
    let crate::checks::SitemapProbe::Found(found_b) = b else {
        panic!("expected the memoized sitemap fixture, got {b:?}");
    };
    assert_eq!(found_a.url, format!("http://{}/sitemap.xml", addr));
    assert_eq!(found_b.entry_count, 1);

    let counts = hits.lock().unwrap().clone();
    assert_eq!(
        counts.get("/robots.txt"),
        Some(&1),
        "robots.txt must be fetched exactly once per scan, got {:?}",
        counts
    );
    assert_eq!(
        counts.get("/sitemap.xml"),
        Some(&1),
        "sitemap must be downloaded exactly once per scan, got {:?}",
        counts
    );

    server.abort();
}

type NoCancel = fn() -> bool;

// A plain page with no scripts or stylesheet links, so no check has a
// third-party host to probe: every request a scan makes stays on the
// local fixture server.
fn plain_page_routes(_base_url: &str) -> HashMap<String, TestResponse> {
    let mut routes = HashMap::new();
    routes.insert(
        "/".to_string(),
        TestResponse::ok(
            "text/html; charset=utf-8",
            "<html><head><title>Fixture</title></head>\
             <body><h1>Hello</h1><p>Plain fixture page with no scripts.</p></body></html>",
        ),
    );
    routes
}

#[tokio::test]
async fn run_scan_rejects_invalid_urls() {
    let result =
        super::run_scan::<NoCancel>("not a url", None, None, None, ScanType::Health, false, None)
            .await;
    assert!(matches!(result, Err(super::ScanError::InvalidUrl(_))));
}

#[tokio::test]
async fn run_scan_fetch_failure_is_a_network_error() {
    // Closed loopback port: the page fetch fails before any check runs, and
    // the scan must surface that as an error, never as a zero-score result.
    let result = super::run_scan::<NoCancel>(
        "http://127.0.0.1:1/",
        None,
        None,
        None,
        ScanType::Health,
        false,
        None,
    )
    .await;
    match result {
        Err(super::ScanError::NetworkError(message)) => {
            assert!(message.contains("Failed to fetch"), "got: {message}");
        }
        Err(other) => panic!("expected NetworkError, got: {other}"),
        Ok(_) => panic!("expected NetworkError, scan succeeded"),
    }
}

#[tokio::test]
async fn run_scan_uses_the_effective_response_url_as_its_result_identity() {
    let server = spawn_test_server(|base_url| {
        let mut routes = plain_page_routes(base_url);
        routes.insert(
            "/start".to_string(),
            TestResponse::redirect(format!("{base_url}/final")),
        );
        routes.insert(
            "/final".to_string(),
            TestResponse::ok(
                "text/html; charset=utf-8",
                "<html><head><title>Final</title></head><body><h1>Final page</h1></body></html>",
            ),
        );
        routes
    })
    .await;

    let result = super::run_scan::<NoCancel>(
        &format!("{}/start", server.base_url),
        None,
        None,
        None,
        ScanType::Polish,
        false,
        None,
    )
    .await
    .expect("redirected scan completes");

    assert_eq!(result.url, format!("{}/final", server.base_url));
}

#[tokio::test]
async fn run_scan_honors_cancellation_before_any_work() {
    let cancel = || true;
    let result = super::run_scan(
        "http://127.0.0.1:1/",
        None,
        None,
        None,
        ScanType::Health,
        false,
        Some(&cancel),
    )
    .await;
    assert!(matches!(result, Err(super::ScanError::Cancelled)));
}

// Focused security scans must collect and score only security checks.
#[tokio::test]
async fn security_scan_type_collects_only_security_checks() {
    let server = spawn_test_server(plain_page_routes).await;
    let result = super::run_scan::<NoCancel>(
        &server.base_url,
        None,
        None,
        None,
        ScanType::Security,
        false,
        None,
    )
    .await
    .expect("security scan against the local fixture");

    assert_eq!(result.mode, "predeploy", "127.0.0.1 fixture is predeploy");
    assert!(!result.issues.is_empty());

    let predeploy_ids: std::collections::HashSet<String> =
        crate::checks::predeploy::all_predeploy_checks()
            .iter()
            .map(|check| check.id().to_string())
            .collect();
    for issue in &result.issues {
        assert!(
            issue.category == ScanCategory::Security || predeploy_ids.contains(&issue.check_id),
            "non-security result leaked into a security scan: {} ({:?})",
            issue.check_id,
            issue.category
        );
    }
    assert!(
        !result
            .issues
            .iter()
            .any(|issue| issue.check_id.starts_with("polish.")),
        "polish phase must not run for focused scan types"
    );
}

// A Polish scan is a focused run of the polish heuristics. It must not
// silently include the normal live-site registry (or localhost predeploy
// checks), because those findings would be mislabeled as a Polish artifact.
#[tokio::test]
async fn polish_scan_type_collects_only_polish_checks() {
    let server = spawn_test_server(plain_page_routes).await;
    let result = super::run_scan::<NoCancel>(
        &server.base_url,
        None,
        None,
        None,
        ScanType::Polish,
        false,
        None,
    )
    .await
    .expect("polish scan against the local fixture");

    assert_eq!(result.mode, "predeploy", "127.0.0.1 fixture is predeploy");
    assert_eq!(
        result.issues.len(),
        crate::checks::polish::POLISH_SIGNALS.len(),
        "one result per polish signal"
    );
    assert!(
        result
            .issues
            .iter()
            .all(|issue| issue.category == ScanCategory::Polish),
        "non-polish result leaked into a polish scan: {:?}",
        result
            .issues
            .iter()
            .filter(|issue| issue.category != ScanCategory::Polish)
            .map(|issue| (&issue.check_id, issue.category))
            .collect::<Vec<_>>()
    );
}

// enabled_categories is the user-facing category filter for Health scans;
// it must bound collection the same way scan_type forcing does.
#[tokio::test]
async fn enabled_categories_bound_health_scan_collection() {
    let server = spawn_test_server(plain_page_routes).await;
    let result = super::run_scan::<NoCancel>(
        &server.base_url,
        None,
        Some(vec!["seo".to_string()]),
        None,
        ScanType::Health,
        false,
        None,
    )
    .await
    .expect("seo-only scan against the local fixture");

    let predeploy_ids: std::collections::HashSet<String> =
        crate::checks::predeploy::all_predeploy_checks()
            .iter()
            .map(|check| check.id().to_string())
            .collect();
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.category == ScanCategory::Seo),
        "seo checks must run when seo is the enabled category"
    );
    for issue in &result.issues {
        assert!(
            issue.category == ScanCategory::Seo
                || issue.category == ScanCategory::Polish
                || predeploy_ids.contains(&issue.check_id),
            "disabled category ran: {} ({:?})",
            issue.check_id,
            issue.category
        );
    }
    // Health scans still run the polish phase after the filtered checks.
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.check_id.starts_with("polish.")),
        "health scans run the polish phase regardless of category filter"
    );
}

// Multi-page wiring: pages after the first pass skip_origin_checks=true,
// which must drop every origin-scoped async check from the run.
#[tokio::test]
async fn skip_origin_checks_drops_origin_scoped_probes() {
    let server = spawn_test_server(plain_page_routes).await;

    let progress_of = |skip: bool| {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        (events.clone(), skip)
    };
    let (with_origin_ids, _) = progress_of(false);
    let (without_origin_ids, _) = progress_of(true);

    let collect = |sink: std::sync::Arc<std::sync::Mutex<Vec<String>>>| {
        move |p: &super::ScanProgress| {
            sink.lock().unwrap().push(p.check_id.clone());
        }
    };

    let progress_with = collect(with_origin_ids.clone());
    super::run_scan::<NoCancel>(
        &server.base_url,
        Some(&progress_with),
        Some(vec!["seo".to_string()]),
        None,
        ScanType::Health,
        false,
        None,
    )
    .await
    .expect("entry-page scan");

    let progress_without = collect(without_origin_ids.clone());
    super::run_scan::<NoCancel>(
        &server.base_url,
        Some(&progress_without),
        Some(vec!["seo".to_string()]),
        None,
        ScanType::Health,
        true,
        None,
    )
    .await
    .expect("follow-up page scan");

    let seen_with = with_origin_ids.lock().unwrap().clone();
    let seen_without = without_origin_ids.lock().unwrap().clone();
    assert!(
        seen_with.iter().any(|id| id == "seo.robots_txt"),
        "entry page must run origin-scoped checks, got: {seen_with:?}"
    );
    assert!(
        !seen_without.iter().any(|id| id == "seo.robots_txt"),
        "follow-up pages must not re-run origin-scoped checks"
    );
    // Page-scoped checks still run on follow-up pages.
    assert!(
        seen_without.iter().any(|id| id == "seo.title"),
        "page-scoped checks must survive the origin filter, got: {seen_without:?}"
    );
}

struct StaticCheck {
    id: &'static str,
    skip_predeploy: bool,
    panics: bool,
}

impl crate::checks::Check for StaticCheck {
    fn id(&self) -> &str {
        self.id
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }
    fn run(&self, _ctx: &crate::checks::PageContext) -> Vec<CheckResult> {
        if self.panics {
            panic!("intentional test panic in {}", self.id);
        }
        vec![CheckResult {
            check_id: self.id.into(),
            category: ScanCategory::Seo,
            title: self.id.into(),
            description: "test double".into(),
            status: CheckStatus::Pass,
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }]
    }
    fn skip_in_predeploy(&self) -> bool {
        self.skip_predeploy
    }
}

fn offline_ctx() -> crate::checks::CheckContext {
    crate::checks::CheckContext {
        page: crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: url::Url::parse("https://example.com").unwrap(),
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: "<html></html>".to_string(),
            is_localhost: false,
            is_strict_localhost: false,
            http_version: None,
            body_lower_cache: std::sync::OnceLock::new(),
        },
        client: crate::http_client::for_url(false).clone(),
        probe_cache: Default::default(),
    }
}

#[test]
fn sync_checks_skip_predeploy_marked_checks_only_on_localhost() {
    let checks: Vec<Box<dyn crate::checks::Check>> = vec![
        Box::new(StaticCheck {
            id: "test.live_only",
            skip_predeploy: true,
            panics: false,
        }),
        Box::new(StaticCheck {
            id: "test.everywhere",
            skip_predeploy: false,
            panics: false,
        }),
    ];
    let ctx = offline_ctx();

    let events = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let events_sink = events.clone();
    let progress = move |p: &super::ScanProgress| {
        events_sink
            .lock()
            .unwrap()
            .push((p.check_id.clone(), p.status.clone()));
    };

    // Localhost (predeploy) run: the marked check is skipped but still
    // counted, so the progress denominator stays honest.
    let mut results = Vec::new();
    let mut done = 0usize;
    super::run_sync_checks::<NoCancel>(
        &checks,
        &ctx,
        true,
        Some(&progress),
        2,
        &mut done,
        &mut results,
        None,
    )
    .expect("predeploy sync run");
    assert_eq!(done, 2, "skipped checks still advance the progress count");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].check_id, "test.everywhere");
    assert!(events
        .lock()
        .unwrap()
        .contains(&("test.live_only".to_string(), "skipped".to_string())));

    // Live run: the same check runs.
    let mut results = Vec::new();
    let mut done = 0usize;
    super::run_sync_checks::<NoCancel>(
        &checks,
        &ctx,
        false,
        None,
        2,
        &mut done,
        &mut results,
        None,
    )
    .expect("live sync run");
    assert_eq!(results.len(), 2);
}

#[test]
fn panicking_sync_check_aborts_instead_of_returning_incomplete_results() {
    let checks: Vec<Box<dyn crate::checks::Check>> = vec![
        Box::new(StaticCheck {
            id: "test.panicky",
            skip_predeploy: false,
            panics: true,
        }),
        Box::new(StaticCheck {
            id: "test.survivor",
            skip_predeploy: false,
            panics: false,
        }),
    ];
    let ctx = offline_ctx();

    let mut results = Vec::new();
    let mut done = 0usize;
    let error = super::run_sync_checks::<NoCancel>(
        &checks,
        &ctx,
        false,
        None,
        2,
        &mut done,
        &mut results,
        None,
    )
    .expect_err("a detector panic must invalidate the scan");

    assert_eq!(done, 0, "a failed detector must not be marked complete");
    assert!(results.is_empty(), "no partial results may escape");
    assert_eq!(
        error.to_string(),
        "Scan error: Web check 'test.panicky' crashed; scan aborted to avoid reporting incomplete results"
    );
}

struct StaticAsyncCheck {
    id: &'static str,
    panics: bool,
}

#[async_trait::async_trait]
impl crate::checks::AsyncCheck for StaticAsyncCheck {
    fn id(&self) -> &str {
        self.id
    }

    fn category(&self) -> ScanCategory {
        ScanCategory::Seo
    }

    async fn run(&self, _ctx: &crate::checks::CheckContext) -> Vec<CheckResult> {
        if self.panics {
            panic!("intentional async test panic in {}", self.id);
        }
        vec![CheckResult {
            check_id: self.id.into(),
            category: ScanCategory::Seo,
            title: self.id.into(),
            description: "test double".into(),
            status: CheckStatus::Pass,
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }]
    }
}

#[tokio::test]
async fn panicking_async_check_aborts_instead_of_returning_incomplete_results() {
    let checks: Vec<Box<dyn crate::checks::AsyncCheck>> = vec![
        Box::new(StaticAsyncCheck {
            id: "test.async_panicky",
            panics: true,
        }),
        Box::new(StaticAsyncCheck {
            id: "test.async_survivor",
            panics: false,
        }),
    ];
    let ctx = offline_ctx();
    let mut results = Vec::new();
    let mut done = 0usize;

    let error = super::run_async_checks::<NoCancel>(
        &checks,
        &ctx,
        false,
        None,
        2,
        &mut done,
        &mut results,
        None,
    )
    .await
    .expect_err("an async detector panic must invalidate the scan");

    assert_eq!(done, 0, "a failed detector must not be marked complete");
    assert!(results.is_empty(), "no partial results may escape");
    assert_eq!(
        error.to_string(),
        "Scan error: Web check 'test.async_panicky' crashed; scan aborted to avoid reporting incomplete results"
    );
}

/// A fixture origin that serves one connection at a time after a fixed delay,
/// the way a small origin with a shallow accept queue behaves. It records the
/// path of every request in arrival order.
struct SerializedServer {
    base_url: String,
    arrivals: Arc<std::sync::Mutex<Vec<String>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for SerializedServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_serialized_server(handler_delay: std::time::Duration) -> SerializedServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind serialized server");
    let addr = listener.local_addr().expect("local addr");
    let arrivals: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server_arrivals = arrivals.clone();

    // No per-connection task: every request waits for the one before it, so a
    // burst of concurrent fetches queues exactly as it does on a real origin
    // with a small accept backlog.
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut buffer = [0u8; 8192];
            let read = match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => continue,
                Ok(bytes) => bytes,
            };
            let request = String::from_utf8_lossy(&buffer[..read]);
            let path = request
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .split('?')
                .next()
                .unwrap_or("/")
                .to_string();
            server_arrivals
                .lock()
                .expect("arrivals lock")
                .push(path.clone());

            tokio::time::sleep(handler_delay).await;

            let body = if path == "/" {
                "<html><head><title>Fixture</title></head><body></body></html>".to_string()
            } else {
                "binary".to_string()
            };
            let content_type = if path == "/" {
                "text/html"
            } else {
                "image/png"
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                content_type,
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    SerializedServer {
        base_url: format!("http://{}", addr),
        arrivals,
        handle,
    }
}

#[tokio::test]
async fn ttfb_is_sampled_before_the_scanner_starts_its_own_request_burst() {
    // 50 ms per request, 30 assets to sample. Sharing the phase with the asset
    // sampler put the timing request behind that queue and graded the wait as
    // server time (1 to 6 seconds on loopback fixtures).
    let handler_delay = std::time::Duration::from_millis(50);
    let server = spawn_serialized_server(handler_delay).await;
    // The scanner has already fetched the page by this phase, so the body is
    // supplied directly and every request the fixture sees comes from the
    // checks under test.
    let page: String = format!(
        "<html><head><title>Fixture</title></head><body>{}</body></html>",
        (0..30)
            .map(|index| format!("<img src=\"/asset-{index}.png\" alt=\"a\">"))
            .collect::<String>()
    );

    let ctx = crate::checks::CheckContext {
        page: crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: url::Url::parse(&server.base_url).expect("fixture url"),
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: page,
            is_localhost: true,
            is_strict_localhost: true,
            http_version: Some("HTTP/1.1".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        },
        client: crate::http_client::for_url(true).clone(),
        probe_cache: Default::default(),
    };

    let checks: Vec<Box<dyn crate::checks::AsyncCheck>> = vec![
        Box::new(crate::checks::performance::assets::AssetSamplerCheck),
        Box::new(crate::checks::performance::timing::TimingCheck),
    ];
    let mut results = Vec::new();
    let mut done = 0usize;
    super::run_async_checks::<NoCancel>(
        &checks,
        &ctx,
        false,
        None,
        checks.len(),
        &mut done,
        &mut results,
        None,
    )
    .await
    .expect("fixture scan completes");

    let ttfb = results
        .iter()
        .find(|result| result.check_id == "performance.ttfb")
        .expect("timing row");
    let ttfb_ms = ttfb.raw_data.as_ref().expect("timing evidence")["ttfb_ms"]
        .as_u64()
        .expect("ttfb_ms");
    // The lower bound matters as much as the upper one: the fixture sleeps
    // `handler_delay` before writing the response head, so a sample below that
    // is not a measurement of this origin at all.
    let handler_delay_ms = handler_delay.as_millis() as u64;
    assert!(
        (handler_delay_ms..1_000).contains(&ttfb_ms),
        "TTFB must measure the {handler_delay_ms} ms origin, not the scanner's own queue and not nothing: {ttfb_ms}ms ({})",
        ttfb.description
    );

    // The wire order proves the isolation: nothing else may reach the origin
    // until the timing samples are done.
    let arrivals = server.arrivals.lock().expect("arrivals lock").clone();
    let first_asset = arrivals
        .iter()
        .position(|path| path.starts_with("/asset-"))
        .expect("the asset sampler must have run");
    assert!(
        arrivals[..first_asset].iter().all(|path| path == "/"),
        "only timing requests may precede the first asset fetch: {arrivals:?}"
    );
    assert!(
        first_asset >= 2,
        "both timing samples must complete before the burst starts: {arrivals:?}"
    );
}

#[tokio::test]
async fn a_slow_origin_is_graded_rather_than_timed_out() {
    // Drives the sampling loop end to end, which the pure-function tests in
    // `checks::performance::timing` cannot: they would still pass if the loop
    // went back to giving every request the whole CHECK_TIMEOUT. A 2 s origin
    // is slow enough to be this check's headline Fail and still leaves room
    // for the repeat, so both samples must arrive and the row must grade.
    let handler_delay = std::time::Duration::from_millis(2_000);
    let server = spawn_serialized_server(handler_delay).await;

    let ctx = crate::checks::CheckContext {
        page: crate::checks::PageContext {
            evaluation_time: chrono::Utc::now(),
            url: url::Url::parse(&server.base_url).expect("fixture url"),
            response_headers: reqwest::header::HeaderMap::new(),
            status_code: 200,
            body: "<html><body></body></html>".to_string(),
            is_localhost: true,
            is_strict_localhost: true,
            http_version: Some("HTTP/1.1".to_string()),
            body_lower_cache: std::sync::OnceLock::new(),
        },
        client: crate::http_client::for_url(true).clone(),
        probe_cache: Default::default(),
    };

    let results =
        crate::checks::AsyncCheck::run(&crate::checks::performance::timing::TimingCheck, &ctx)
            .await;
    let ttfb = &results[0];

    assert_eq!(
        ttfb.status,
        CheckStatus::Fail,
        "a 2 s origin is the check's headline finding, not a timeout: {}",
        ttfb.description
    );
    let raw = ttfb.raw_data.as_ref().expect("timing evidence");
    assert!(
        raw["ttfb_ms"].as_u64().expect("ttfb_ms") >= handler_delay.as_millis() as u64,
        "{raw}"
    );
    assert_eq!(
        raw["sample_count"], 2,
        "2 s leaves most of the budget, so the repeat still runs: {raw}"
    );
    assert_eq!(
        server.arrivals.lock().expect("arrivals lock").len(),
        2,
        "both samples must reach the origin"
    );
    for sample in raw["samples_ms"].as_array().expect("samples") {
        assert!(
            sample.as_u64().expect("sample") >= handler_delay.as_millis() as u64,
            "every sample measures this origin: {raw}"
        );
    }
}

#[path = "polish_stylesheets_tests.rs"]
mod polish_stylesheets_tests;

#[path = "negotiated_protocol_tests.rs"]
mod negotiated_protocol_tests;
