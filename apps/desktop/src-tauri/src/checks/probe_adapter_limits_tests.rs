use super::*;

#[test]
fn recorded_alone_probe_limits_use_their_published_byte_caps() {
    // Using the sitemap cap would let a sweep exceed its probe allowance.
    assert_eq!(body_limit_cap(BodyLimit::Sweep), 512 * 1024);
    assert_eq!(body_limit_cap(BodyLimit::Stylesheet), 2 * 1024 * 1024);
    assert_eq!(
        body_limit_cap(BodyLimit::Probe),
        crate::constants::MAX_PROBE_BODY_SIZE
    );
    for limit in [BodyLimit::Sitemap, BodyLimit::SitemapChild] {
        assert_eq!(body_limit_cap(limit), crate::constants::MAX_SITEMAP_SIZE);
    }
}
