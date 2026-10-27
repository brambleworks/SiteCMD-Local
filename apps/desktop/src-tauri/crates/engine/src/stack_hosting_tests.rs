use super::*;
use http::{HeaderMap, HeaderValue};

fn hosting_of(host: &str, headers: &HeaderMap) -> Option<String> {
    let mut stack = DetectedStack::default();
    detect_hosting(&mut stack, host, headers, "", "", None);
    stack.hosting
}

pub(super) fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(*name, HeaderValue::from_static(value));
    }
    map
}

#[test]
fn a_platform_subdomain_names_its_platform() {
    let none = HeaderMap::new();
    for (host, label) in [
        ("shop.pages.dev", "Cloudflare Pages"),
        ("api.example.workers.dev", "Cloudflare Workers"),
        ("example.vercel.app", "Vercel"),
        ("example.netlify.app", "Netlify"),
        ("example.github.io", "GitHub Pages"),
        ("example.myshopify.com", "Shopify"),
        ("example.webflow.io", "Webflow"),
        ("example.wixsite.com", "Wix"),
        ("example.squarespace.com", "Squarespace"),
        ("example.framer.website", "Framer"),
        ("example.wordpress.com", "WordPress.com"),
        ("SHOP.PAGES.DEV.", "Cloudflare Pages"),
    ] {
        assert_eq!(hosting_of(host, &none).as_deref(), Some(label), "{host}");
    }
}

#[test]
fn a_platform_s_own_domain_or_a_lookalike_names_nothing() {
    let none = HeaderMap::new();
    for host in [
        "pages.dev",
        "github.io",
        "evilpages.dev",
        "pages.dev.example.com",
        "example.com",
        "",
    ] {
        assert_eq!(hosting_of(host, &none), None, "{host:?}");
    }
}

#[test]
fn a_header_only_the_platform_sends_names_it() {
    assert_eq!(
        hosting_of(
            "www.example.com",
            &headers(&[("x-vercel-id", "iad1::abc123")])
        )
        .as_deref(),
        Some("Vercel")
    );
    for name in ["x-nf-request-id", "x-netlify-request-id"] {
        let mut map = HeaderMap::new();
        map.insert(name, HeaderValue::from_static("01HZX"));
        assert_eq!(
            hosting_of("www.example.com", &map).as_deref(),
            Some("Netlify"),
            "{name}"
        );
    }
    assert_eq!(
        hosting_of(
            "www.example.com",
            &headers(&[
                ("server", "GitHub.com"),
                ("x-github-request-id", "DFF7:79BB9:1557076"),
                ("x-fastly-request-id", "abc123")
            ]),
        )
        .as_deref(),
        Some("GitHub Pages")
    );
}

#[test]
fn github_s_server_without_its_request_id_names_no_host() {
    assert_eq!(
        hosting_of(
            "www.example.com",
            &headers(&[("server", "GitHub.com"), ("x-fastly-request-id", "abc123")])
        ),
        None
    );
}

#[test]
fn github_s_own_response_names_no_host() {
    assert_eq!(
        hosting_of(
            "www.example.com",
            &headers(&[
                ("server", "github.com"),
                ("x-github-request-id", "DFF7:79BB9:1557076")
            ])
        ),
        None
    );
}

#[test]
fn github_s_request_id_alone_names_no_host() {
    assert_eq!(
        hosting_of(
            "www.example.com",
            &headers(&[("x-github-request-id", "DFF7:79BB9:1557076")])
        ),
        None
    );
}

#[test]
fn a_non_github_server_names_no_host() {
    for server in ["nginx", "not-github"] {
        assert_eq!(
            hosting_of(
                "www.example.com",
                &headers(&[
                    ("server", server),
                    ("x-github-request-id", "DFF7:79BB9:1557076"),
                    ("x-fastly-request-id", "abc123")
                ])
            ),
            None,
            "{server}"
        );
    }
}

#[test]
fn cloudflare_s_own_headers_name_the_cdn_and_never_the_host() {
    let map = headers(&[("cf-ray", "8a1b2c3d4e5f6071-IAD"), ("server", "cloudflare")]);
    let body = "<html><body>Hello</body></html>";
    let mut stack = crate::stack::detect_stack(&map, body, &body.to_ascii_lowercase());
    detect_hosting(
        &mut stack,
        "www.example.com",
        &map,
        body,
        &body.to_ascii_lowercase(),
        None,
    );
    assert_eq!(stack.cdn.as_deref(), Some("Cloudflare"));
    assert_eq!(stack.hosting, None);
}

#[test]
fn the_site_s_own_subdomain_outranks_a_header() {
    assert_eq!(
        hosting_of(
            "example.netlify.app",
            &headers(&[("x-vercel-id", "iad1::abc123")])
        )
        .as_deref(),
        Some("Netlify")
    );
}

fn hosting_from_markup(body: &str) -> Option<String> {
    let mut stack = DetectedStack::default();
    detect_hosting(
        &mut stack,
        "www.example.com",
        &HeaderMap::new(),
        body,
        &body.to_ascii_lowercase(),
        None,
    );
    stack.hosting
}

#[test]
fn framer_s_generator_tag_names_it() {
    for body in [
        r#"<html><head><meta name="generator" content="Framer 3f2a1b9"></head><body></body></html>"#,
        r#"<html><head><meta content="Framer" name="generator"></head><body></body></html>"#,
    ] {
        assert_eq!(
            hosting_from_markup(body).as_deref(),
            Some("Framer"),
            "{body}"
        );
    }
}

#[test]
fn framer_s_asset_host_names_it() {
    let body = r#"<html><head><script type="module" src="https://framerusercontent.com/sites/3f2a1b9/script_main.abc123.mjs"></script></head></html>"#;
    assert_eq!(hosting_from_markup(body).as_deref(), Some("Framer"));
}

#[test]
fn framer_s_generator_after_a_viewport_tag_names_it() {
    let body = r#"<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="generator" content="Framer 715c8ea"></head><body></body></html>"#;
    assert_eq!(hosting_from_markup(body).as_deref(), Some("Framer"));
}

#[test]
fn a_wordpress_generator_outranks_a_neighboring_builder_title() {
    let body = r#"<html><head><meta property="og:title" content="Framer vs Webflow: which builder"><meta name="generator" content="WordPress 6.9"></head><body></body></html>"#;
    let map = HeaderMap::new();
    let lower = body.to_ascii_lowercase();
    let mut stack = crate::stack::detect_stack(&map, body, &lower);
    detect_hosting(&mut stack, "www.example.com", &map, body, &lower, None);
    assert_eq!(
        (stack.hosting.as_deref(), stack.cms.as_deref()),
        (None, Some("WordPress"))
    );
}

#[test]
fn a_framer_hosted_image_names_no_host() {
    let body =
        r#"<html><body><img src="https://framerusercontent.com/images/hero.png"></body></html>"#;
    assert_eq!(hosting_from_markup(body), None);
}

#[test]
fn a_brand_word_or_a_link_to_framer_names_nothing() {
    for body in [
        "<html><body><p>We moved from Netlify to Framer, then to Vercel.</p></body></html>",
        r#"<html><body><a href="https://www.framer.com/">Made in Framer</a></body></html>"#,
        r#"<html><head><meta name="generator" content="WordPress 6.9"></head></html>"#,
    ] {
        assert_eq!(hosting_from_markup(body), None, "{body}");
    }
}

#[test]
fn a_header_outranks_markup() {
    let mut stack = DetectedStack::default();
    let body = r#"<html><head><meta name="generator" content="Framer"></head></html>"#;
    detect_hosting(
        &mut stack,
        "www.example.com",
        &headers(&[("x-vercel-id", "iad1::abc123")]),
        body,
        &body.to_ascii_lowercase(),
        None,
    );
    assert_eq!(stack.hosting.as_deref(), Some("Vercel"));
}

#[test]
fn mentioning_framer_after_the_generator_first_word_does_not_mislabel_wordpress() {
    let body = r#"<meta name="generator" content="WordPress 6.9, migrated from Framer">"#;
    assert_eq!(hosting_from_markup(body), None);
}

#[test]
fn a_stray_quote_in_an_earlier_tag_does_not_hide_framer_hosting() {
    let body = r#"<div broken"><meta name="generator" content="Framer 715c8ea">"#;
    assert_eq!(hosting_from_markup(body).as_deref(), Some("Framer"));
}
