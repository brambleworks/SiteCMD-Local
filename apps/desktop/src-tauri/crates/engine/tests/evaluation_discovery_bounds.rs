// A sitemap URL cut loses the planned stand-ins when no listed page passes the gate.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

#[test]
fn oversized_sitemaps_keep_planned_stand_ins_after_their_candidates() {
    let locations: Vec<_> = (0..5_000)
        .map(|i| format!("https://example.com/search/{i}"))
        .collect();
    let first = urlset(&locations.iter().map(String::as_str).collect::<Vec<_>>());
    let last = "https://example.com/search/last";
    let mut all = locations.iter().map(String::as_str).collect::<Vec<_>>();
    all.push(last);
    for index in [false, true] {
        let sitemap = if index {
            index_of(&[POSTS, PAGES])
        } else {
            urlset(&all)
        };
        let pages = [
            (
                SITEMAP_URL,
                response(SITEMAP_URL, 200, "application/xml", &sitemap),
            ),
            (POSTS, response(POSTS, 200, "application/xml", &first)),
            (
                PAGES,
                response(PAGES, 200, "application/xml", &urlset(&[last])),
            ),
        ];
        assert_eq!(
            discovered(
                artifact(&home("<a href='/pricing'>Plans</a>"), 200, "/"),
                site(&pages),
                &["/stand-in", "/pricing"],
                LIMIT
            ),
            routes(&["/pricing", "/stand-in"]),
            "index: {index}"
        );
    }
}
