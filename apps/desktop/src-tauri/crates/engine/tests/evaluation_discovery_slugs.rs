//! Discovery permits word slugs while keeping the evidence privacy gates.

#[path = "support/discovery.rs"]
mod support;
pub use support::*;

use sitecmd_engine::log_sanitizer::evidence_safe_page_url;

#[test]
fn long_word_slugs_with_whole_numeric_parts_are_discovered() {
    for route in [
        "/blog/top-10-ways-to-improve-your-website-speed",
        "/blog/10-ways-to-build-a-faster-website-in-2026",
    ] {
        let address = format!("{ORIGIN}{route}");
        assert_ne!(evidence_safe_page_url(&address), address);
        let pages = with_sitemap(&[]);
        assert_eq!(
            discovered(
                artifact(&home(&format!("<a href='{route}'>Read</a>")), 200, "/"),
                site(&pages),
                &[],
                LIMIT
            ),
            routes(&[route])
        );
    }
}

#[test]
fn token_shapes_and_other_privacy_gates_are_still_refused() {
    let paths = [
        "/blog/123e4567-e89b-12d3-a456-426614174000",
        "/blog/aaaaaaaa-bbbb-cccc-dddd-123456789012",
        "/blog/0123456789abcdef0123456789abcdef01234567",
        "/blog/aB3deF6hiJ9klM2noP5qrS8tuV1wxY4zABCD",
        "/blog/documentation-10-implementations",
        "/blog/documentation-a-10-implementations",
        "/blog/reset-your-password-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "/blog/invite-your-team-XyZaBcDeFgHiJkLm-2026",
        "/blog/top-10-tips-for-joe@example.com",
        "/blog/sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // gitleaks:allow
        "/verify/top-10-ways-to-improve-your-website-speed",
    ];
    let links: String = paths
        .iter()
        .map(|path| format!("<a href='{path}'>Read</a>"))
        .collect();
    assert_eq!(
        discovered(artifact(&home(&links), 200, "/"), site(&[]), &[], LIMIT),
        routes(&[])
    );
}

#[test]
fn a_word_slug_does_not_escape_the_evidence_length_bound() {
    let route = format!("/blog/{}10-ways", "long-word-".repeat(60));
    let link = format!("<a href='{route}'>Read</a>");
    assert_eq!(
        discovered(artifact(&home(&link), 200, "/"), site(&[]), &[], LIMIT),
        routes(&[])
    );
}
