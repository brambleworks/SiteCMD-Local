//! Route selection retains document order through rejected and repeated links.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

#[test]
fn many_rejected_links_preserve_the_first_kept_routes_at_the_limit() {
    let mut links = String::from("<a href='/'>Home</a><a href='/en/'>English</a>");
    for index in 0..150 {
        links.push_str(&format!(
            "<a href='/{index}.css'>File</a><a href='/search/{index}'>Search</a>\
             <a href='/private/{index}'>Private</a><a href='/search/{index}'>Again</a>"
        ));
        if index % 20 == 0 {
            links.push_str(&format!(
                "<a href='/page/{index}#top'>Page</a><a href='/page/{index}'>Again</a>"
            ));
        }
    }
    let pages = [(
        "https://example.com/robots.txt",
        response(
            "https://example.com/robots.txt",
            200,
            "text/plain",
            "User-agent: *\nDisallow: /private",
        ),
    )];
    assert_eq!(
        discovered(artifact(&home(&links), 200, "/en/"), site(&pages), &[], 5),
        routes(&["/page/0", "/page/20", "/page/40", "/page/60", "/page/80"])
    );
}
