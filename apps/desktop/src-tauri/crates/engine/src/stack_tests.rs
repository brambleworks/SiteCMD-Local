use super::*;
use http::{HeaderMap, HeaderValue};

#[test]
fn test_detect_wordpress() {
    let headers = HeaderMap::new();
    let body = r#"<html><head></head><body>
        <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
        <script src="/wp-includes/js/jquery.js"></script>
    </body></html>"#;
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.cms, Some("WordPress".into()));
    assert_eq!(stack.framework, Some("PHP".into()));
}

#[test]
fn test_detect_nextjs() {
    let mut headers = HeaderMap::new();
    headers.insert("x-powered-by", HeaderValue::from_static("Next.js"));
    let body = r#"<html><head></head><body><div id="__next"></div>
        <script src="/_next/static/chunks/main.js"></script>
    </body></html>"#;
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.framework, Some("Next.js".into()));
    assert_eq!(stack.js_framework, Some("React".into()));
}

#[test]
fn test_detect_vercel() {
    let mut headers = HeaderMap::new();
    headers.insert("x-vercel-id", HeaderValue::from_static("iad1::abc123"));
    headers.insert("server", HeaderValue::from_static("Vercel"));
    let body = "<html><body>Hello</body></html>";
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.cdn, Some("Vercel".into()));
}

#[test]
fn test_detect_tailwind() {
    let headers = HeaderMap::new();
    let body = r#"<html><body>
        <div class="flex items-center px-4 py-2 mt-4 text-sm bg-white">
            <span class="mb-2">Hello</span>
        </div>
    </body></html>"#;
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.css_framework, Some("Tailwind CSS".into()));
}

#[test]
fn a_brand_word_in_page_copy_is_not_a_cms() {
    // astro.build lists a WordPress logo; tailwindcss.com and github.com
    // link Shopify as a customer.
    let headers = HeaderMap::new();
    let body = r#"<html><body><p class="heading-3">WordPress</p>
        <a aria-label="Shopify logo" href="https://shopify.com/">Shopify</a>
        <p>Built for Drupal, WordPress, and Shopify teams.</p>
        <symbol id="ai:local:logos/wordpress"></symbol></body></html>"#;
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.cms, None);
    assert_eq!(stack.framework, None, "PHP was inferred from a logo label");
}

#[test]
fn a_real_drupal_page_keeps_its_label() {
    let headers = HeaderMap::new();
    for body in [
        r#"<html><body><script type="application/json" data-drupal-selector="drupal-settings-json">{}</script></body></html>"#,
        r#"<html><body><script src="/core/misc/drupal.js"></script></body></html>"#,
        r#"<html><body><img src="/sites/default/files/hero.png"></body></html>"#,
    ] {
        let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
        assert_eq!(stack.cms, Some("Drupal".into()), "{body}");
        assert_eq!(stack.framework, Some("PHP".into()));
    }
}

#[test]
fn a_vendor_link_or_payload_key_is_not_a_headless_cms() {
    // tailwindcss.com links developers.webflow.com; github.com carries
    // "contentfulRawJsonResponse" in an embedded payload.
    let headers = HeaderMap::new();
    for body in [
        r#"<html><body><a href="https://developers.webflow.com/?utm_source=x">Webflow</a></body></html>"#,
        r#"<html><body><script type="application/json">{"contentfulRawJsonResponse":null}</script></body></html>"#,
    ] {
        let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
        assert_eq!(stack.cms, None, "{body} must not name a CMS");
    }
}

#[test]
fn published_webflow_and_contentful_markers_are_still_detected() {
    let headers = HeaderMap::new();
    let webflow = r#"<html data-wf-page="abc" data-wf-site="def"><body></body></html>"#;
    assert_eq!(
        detect_stack(&headers, webflow, &webflow.to_ascii_lowercase()).cms,
        Some("Webflow".into())
    );
    let contentful =
        r#"<html><body><img src="https://images.ctfassets.net/x/y/hero.png"></body></html>"#;
    assert_eq!(
        detect_stack(&headers, contentful, &contentful.to_ascii_lowercase()).cms,
        Some("Contentful".into())
    );
}

#[test]
fn a_shopify_cdn_asset_is_still_a_shopify_site() {
    let headers = HeaderMap::new();
    let body =
        r#"<html><body><img src="https://cdn.shopify.com/s/files/1/0000/hero.png"></body></html>"#;
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.cms, Some("Shopify".into()));
}

#[test]
fn an_app_name_ending_in_ng_app_is_not_angular() {
    let headers = HeaderMap::new();
    let body = r#"<html><head><meta name="govuk:publishing-app" content="frontend">
        <meta name="govuk:rendering-app" content="frontend"></head><body></body></html>"#;
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.js_framework, None);
}

#[test]
fn real_angular_attributes_are_still_detected() {
    let headers = HeaderMap::new();
    for body in [
        r#"<html><body><div ng-app="shop"></div></body></html>"#,
        r#"<html><body><div data-ng-app="shop"></div></body></html>"#,
        r#"<html><body><app-root ng-version="17.0.2"></app-root></body></html>"#,
        r#"<html><body><app-root data-ng-version="17.0.2"></app-root></body></html>"#,
    ] {
        let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
        assert_eq!(
            stack.js_framework,
            Some("Angular".into()),
            "{body} must read as Angular"
        );
    }
}

#[test]
fn the_github_server_header_is_reported_as_github() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("github.com"));
    headers.insert(
        "x-github-request-id",
        HeaderValue::from_static("DFF7:79BB9:1557076"),
    );
    let body = "<html><body>Hello</body></html>";
    let stack = detect_stack(&headers, body, &body.to_ascii_lowercase());
    assert_eq!(stack.cdn, Some("GitHub".into()));
}

#[test]
fn generator_detection_preserves_offsets_after_unicode_case_expansion() {
    let headers = HeaderMap::new();
    let body = format!(
        "<html><head>{}<meta name=\"generator\" content=\"WordPress 6.9\"></head></html>",
        "İ".repeat(128)
    );

    let stack = detect_stack(&headers, &body, &body.to_ascii_lowercase());

    assert_eq!(stack.cms, Some("WordPress".into()));
}

#[test]
fn an_empty_object_is_the_empty_stack() {
    assert_eq!(
        serde_json::from_str::<DetectedStack>("{}").unwrap(),
        DetectedStack::default()
    );
}
