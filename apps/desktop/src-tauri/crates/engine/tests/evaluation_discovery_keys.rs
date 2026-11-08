//! Credential-shaped sitemap routes must not become stored page addresses.

#[path = "support/discovery.rs"]
mod support;
use sitecmd_engine::checks::security::key_pattern_services;
pub use support::*;

#[test]
fn sitemap_routes_with_fine_grained_tokens_are_refused() {
    let route = format!("/share/github_pat_{}", "abcdefghijklmnop".repeat(5) + "qr");
    assert_eq!(
        key_pattern_services(&route),
        vec!["GitHub Fine-Grained Token"]
    );
    let address = format!("{ORIGIN}{route}");
    let sitemap = with_sitemap(&[&address]);
    assert_eq!(
        discovered(artifact(&home(""), 200, "/"), site(&sitemap), &[], LIMIT),
        routes(&[])
    );
}

#[test]
fn sitemap_routes_with_lowercase_gitlab_tokens_are_refused_by_the_key_gate() {
    let route = format!("/docs/glpat-{}", "abcdefghijklmnopqrst");
    assert_eq!(key_pattern_services(&route), vec!["GitLab Token"]);
    let address = format!("{ORIGIN}{route}");
    let sitemap = with_sitemap(&[&address]);
    assert_eq!(
        discovered(artifact(&home(""), 200, "/"), site(&sitemap), &[], LIMIT),
        routes(&[])
    );
}

#[test]
fn sitemap_routes_with_a_gitlab_placeholder_remain_discoverable() {
    let route = format!("/docs/glpat-{}", "x".repeat(20));
    assert!(key_pattern_services(&route).is_empty());
    let address = format!("{ORIGIN}{route}");
    let sitemap = with_sitemap(&[&address]);
    assert_eq!(
        discovered(artifact(&home(""), 200, "/"), site(&sitemap), &[], LIMIT),
        routes(&[&route])
    );
}
