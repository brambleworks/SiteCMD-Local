//! Supplied documents and probe answers for route discovery.

use sitecmd_engine::evaluation::{ExecutedProbe, PageArtifact, RouteSession};
use sitecmd_engine::probe::{decode_probe_body, ProbeOutcome, ProbeRequest, ProbeResponse};

pub const ORIGIN: &str = "https://example.com";
pub const LIMIT: usize = 99;
/// The desktop's own child limit, which these cases read an index under.
pub const CHILDREN: usize = 50;

pub fn artifact(body: &str, status: u16, final_path: &str) -> PageArtifact {
    PageArtifact {
        url: format!("{ORIGIN}{final_path}"),
        requested_url: Some(format!("{ORIGIN}/")),
        status_code: status,
        http_version: None,
        is_localhost: false,
        is_strict_localhost: false,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: body.into(),
        evaluation_time: "2026-08-05T00:00:00Z".parse().expect("static time"),
    }
}

pub fn home(anchors: &str) -> String {
    format!(
        "<!doctype html><html lang='en'><head><title>Example home page for scans</title></head><body>{anchors}</body></html>"
    )
}

pub fn urlset(locations: &[&str]) -> String {
    let entries: String = locations
        .iter()
        .map(|loc| format!("<url><loc>{loc}</loc></url>"))
        .collect();
    format!("<?xml version='1.0'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{entries}</urlset>")
}

pub fn index_of(children: &[&str]) -> String {
    let entries: String = children
        .iter()
        .map(|loc| format!("<sitemap><loc>{loc}</loc></sitemap>"))
        .collect();
    format!("<?xml version='1.0'?><sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{entries}</sitemapindex>")
}

pub fn response(final_url: &str, status: u16, content_type: &str, body: &str) -> ProbeOutcome {
    ProbeOutcome::Response(ProbeResponse {
        status,
        final_url: final_url.into(),
        content_type: Some(content_type.into()),
        content_length: None,
        headers: Vec::new(),
        body: Some(decode_probe_body(body.as_bytes().to_vec())),
    })
}

/// A site answering from `pages` by address, any method, and with an empty
/// HTML page everywhere else, which no sitemap candidate parses as a sitemap.
pub fn site<'a>(
    pages: &'a [(&'a str, ProbeOutcome)],
) -> impl Fn(&ProbeRequest) -> ProbeOutcome + 'a {
    move |request| {
        pages
            .iter()
            .find(|(url, _)| *url == request.url)
            .map(|(_, outcome)| outcome.clone())
            .unwrap_or_else(|| response(&request.url, 200, "text/html", ""))
    }
}

/// The entry route's session, its plan driven to its fixpoint against
/// `answer` as a runtime drives it, asked what it discovers.
pub fn discovered_with(
    children: usize,
    page: PageArtifact,
    answer: impl Fn(&ProbeRequest) -> ProbeOutcome,
    planned: &[&str],
    limit: usize,
) -> Option<Vec<String>> {
    let mut route = RouteSession::open(page)
        .expect("opens")
        .with_sitemap_children(children);
    for _ in 0..40 {
        let plan = route.plan();
        if plan.probes.is_empty() {
            let planned: Vec<String> = planned.iter().map(|route| route.to_string()).collect();
            return route.discover(&planned, limit).routes;
        }
        route.record(Some(
            plan.probes
                .into_iter()
                .map(|probe| ExecutedProbe::new(probe.key, answer(&probe.request)))
                .collect(),
        ));
    }
    panic!("the probe plan never reached its fixpoint");
}

pub fn discovered(
    page: PageArtifact,
    answer: impl Fn(&ProbeRequest) -> ProbeOutcome,
    planned: &[&str],
    limit: usize,
) -> Option<Vec<String>> {
    discovered_with(CHILDREN, page, answer, planned, limit)
}

pub fn routes(paths: &[&str]) -> Option<Vec<String>> {
    Some(paths.iter().map(|path| path.to_string()).collect())
}

pub const SITEMAP_URL: &str = "https://example.com/sitemap.xml";

pub fn with_sitemap(locations: &[&str]) -> [(&'static str, ProbeOutcome); 1] {
    [(
        SITEMAP_URL,
        response(SITEMAP_URL, 200, "application/xml", &urlset(locations)),
    )]
}

pub const POSTS: &str = "https://example.com/sitemap-posts.xml";
pub const PAGES: &str = "https://example.com/sitemap-pages.xml";

pub fn an_index_site(pages: ProbeOutcome) -> [(&'static str, ProbeOutcome); 3] {
    [
        (
            SITEMAP_URL,
            response(
                SITEMAP_URL,
                200,
                "application/xml",
                &index_of(&[POSTS, PAGES]),
            ),
        ),
        (
            POSTS,
            response(
                POSTS,
                200,
                "application/xml",
                &urlset(&["https://example.com/posts/first"]),
            ),
        ),
        (PAGES, pages),
    ]
}
