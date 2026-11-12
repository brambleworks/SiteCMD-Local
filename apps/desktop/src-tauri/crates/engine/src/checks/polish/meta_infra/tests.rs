use super::*;

fn ctx(html: &str) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse("https://example.com").unwrap(),
        html.to_string().into(),
        Default::default(),
    )
}

#[test]
fn default_title_fires_with_vite_react() {
    let html = "<html><head><title>Vite + React</title></head></html>";
    let result = default_page_title(&ctx(html));
    assert!(result.fired, "Should fire with Vite + React title");
}

#[test]
fn default_title_fires_with_empty() {
    let html = "<html><head><title></title></head></html>";
    let result = default_page_title(&ctx(html));
    assert!(result.fired, "Should fire with empty title");
}

#[test]
fn default_title_fires_with_no_title() {
    let html = "<html><head></head></html>";
    let result = default_page_title(&ctx(html));
    assert!(result.fired, "Should fire with missing title tag");
}

#[test]
fn default_title_clear_with_custom() {
    let html =
        "<html><head><title>My Awesome SaaS - Project Management for Teams</title></head></html>";
    let result = default_page_title(&ctx(html));
    assert!(!result.fired, "Should not fire with custom title");
}

#[test]
fn default_title_clear_with_common_word_prefixes() {
    for title in [
        "Home | Acme Corp",
        "Index of Articles",
        "Application Portal",
        "Documentation - Acme",
    ] {
        let html = format!("<html><head><title>{title}</title></head></html>");
        let result = default_page_title(&ctx(&html));
        assert!(!result.fired, "must not fire on legitimate title {title:?}");
    }

    // Exact framework defaults must still fire.
    for title in super::super::word_lists::word_lists()
        .scaffold_titles
        .iter()
        .take(2)
        .chain(
            super::super::word_lists::word_lists()
                .placeholder_titles
                .iter()
                .take(1),
        )
        .map(|entry| &entry.value)
    {
        let html = format!("<html><head><title>{title}</title></head></html>");
        let result = default_page_title(&ctx(&html));
        assert!(result.fired, "must still fire on exact default {title:?}");
    }
}

#[test]
fn og_tags_fires_when_all_missing() {
    let html = "<html><head><title>Test</title></head></html>";
    let result = missing_og_tags(&ctx(html));
    assert!(result.fired, "Should fire when all OG tags missing");
}

#[test]
fn og_tags_clear_when_all_present() {
    let html = r#"<meta property="og:title" content="Test"><meta property="og:description" content="Desc"><meta property="og:image" content="/img.png">"#;
    let result = missing_og_tags(&ctx(html));
    assert!(!result.fired, "Should not fire when all OG tags present");
}

#[test]
fn og_tags_partial_missing_fires_at_low_weight() {
    let html = r#"<meta property="og:title" content="Test"><meta property="og:description" content="Desc">"#;
    let result = missing_og_tags(&ctx(html));
    assert!(result.fired);
    assert_eq!(
        result.points,
        super::SignalWeight::Low.points(),
        "partial OG coverage is a minor finding"
    );
}

#[test]
fn og_tags_name_attribute_variant_is_recognized() {
    let html = r#"<meta name="og:title" content="Test"><meta name="og:description" content="Desc"><meta name="og:image" content="/img.png">"#;
    let result = missing_og_tags(&ctx(html));
    assert!(!result.fired, "{}", result.detail);
}

#[test]
fn favicon_missing_link_tag_does_not_fire() {
    let html = "<html><head><title>Test</title></head></html>";
    let result = default_favicon(&ctx(html));
    assert!(
        !result.fired,
        "no link tag is not evidence of a default favicon"
    );
}

#[test]
fn favicon_fires_with_vite_default() {
    let html = r#"<link rel="icon" href="/vite.svg">"#;
    let result = default_favicon(&ctx(html));
    assert!(result.fired, "Should fire with Vite default favicon");
}

#[test]
fn favicon_clear_with_custom() {
    let html = r#"<link rel="icon" href="/brand-logo.svg">"#;
    let result = default_favicon(&ctx(html));
    assert!(!result.fired, "Should not fire with custom favicon");
}

#[test]
fn favicon_scaffold_marker_outside_link_tag_does_not_fire() {
    let html =
        r#"<link rel="icon" href="/brand-logo.svg"><img src="/vite.svg" alt="Built with Vite">"#;
    let result = default_favicon(&ctx(html));
    assert!(
        !result.fired,
        "scaffold icon outside the favicon link is not a default favicon: {}",
        result.detail
    );
}

#[test]
fn placeholder_titles_are_called_placeholders_not_framework_defaults() {
    let title = &super::super::word_lists::word_lists().placeholder_titles[0].value;
    let html = format!("<title>{title}</title>");
    let result = default_page_title(&ctx(&html));
    assert!(result.fired);
    assert!(
        result.detail.contains("placeholder") && !result.detail.contains("Framework default"),
        "{}",
        result.detail
    );

    let scaffold = default_page_title(&ctx("<title>Vite + React</title>"));
    assert!(scaffold.fired);
    assert!(
        scaffold.detail.contains("Framework default"),
        "{}",
        scaffold.detail
    );
}

#[test]
fn seo_markers_prose_words_do_not_clear_the_signal() {
    let html = r#"<html><body><p>Our robots are friendly and our sitemap of ideas grows.</p></body></html>"#;
    let result = no_sitemap_robots(&ctx(html));
    assert!(result.fired, "prose words are not SEO markers");
}

#[test]
fn seo_markers_canonical_or_robots_meta_clear_the_signal() {
    let canonical = r#"<link rel="canonical" href="https://example.com/">"#;
    assert!(!no_sitemap_robots(&ctx(canonical)).fired);
    let robots = r#"<meta name="robots" content="index,follow">"#;
    assert!(!no_sitemap_robots(&ctx(robots)).fired);
    let sitemap = r#"<link rel="sitemap" type="application/xml" href="/sitemap.xml">"#;
    assert!(!no_sitemap_robots(&ctx(sitemap)).fired);
}

#[test]
fn source_maps_fires_when_present() {
    let html = r#"<script>var x=1;//# sourceMappingURL=app.js.map</script>"#;
    let result = source_maps_production(&ctx(html));
    assert!(result.fired, "Should fire with sourceMappingURL");
    assert!(
        result.detail.contains("not verified as accessible"),
        "{}",
        result.detail
    );
}

#[test]
fn source_maps_clear_when_absent() {
    let html = "<script>var x = 1;</script>";
    let result = source_maps_production(&ctx(html));
    assert!(!result.fired, "Should not fire without source maps");
}

#[test]
fn console_log_fires_with_multiple() {
    let html = r#"<script>console.log("hello"); console.log("world");</script>"#;
    let result = console_log_production(&ctx(html));
    assert!(result.fired, "Should fire with 2+ console.log calls");
}

#[test]
fn console_log_clear_with_one() {
    let html = r#"<script>console.log("init");</script>"#;
    let result = console_log_production(&ctx(html));
    assert!(!result.fired, "Should not fire with just 1 console.log");
}

#[test]
fn console_log_sees_an_inline_script_after_an_empty_external_script_tag() {
    // The `regex-traps.html` fixture head: an empty `<script src>` element
    // immediately followed by the inline script that carries the calls.
    let html = concat!(
        r#"<link rel="stylesheet" href="/css/clean.css">"#,
        "\n",
        r#"<script src="/js/app.js"></script><script>"#,
        "\n",
        "console.log(\"first\");\n",
        "console.log(\"second\");\n",
        "//# sourceMappingURL=trap.js.map\n",
        "</script>\n",
    );
    let result = console_log_production(&ctx(html));
    assert!(
        result.fired,
        "an empty external script tag must not swallow the inline script after it"
    );
    assert_eq!(result.data["console_log_count"], 2);
}

#[test]
fn console_log_ignores_calls_inside_external_script_elements() {
    let html = concat!(
        r#"<script src="/js/app.js">console.log("a"); console.log("b");</script>"#,
        "\n",
        r#"<script SRC = "/js/late.js"></script>"#,
    );
    let result = console_log_production(&ctx(html));
    assert!(
        !result.fired,
        "a script element with a src attribute is external, whatever its body holds"
    );
}

#[test]
fn console_log_counts_an_inline_script_whose_tag_carries_a_prefixed_src_attribute() {
    // `data-src` is a data attribute, not a `src`: the script is still inline
    // and its calls still ship. A `\b` boundary would match at the hyphen.
    for attribute in ["data-src", "x-src", "data-src-set"] {
        let html = format!(
            r#"<script {attribute}="/js/lazy.js">console.log("one"); console.log("two");</script>"#
        );
        let result = console_log_production(&ctx(&html));
        assert!(
            result.fired,
            "{attribute} is not a src attribute and must not mark the script external"
        );
        assert_eq!(result.data["console_log_count"], 2, "{attribute}");
    }
}

#[test]
fn console_log_counts_an_inline_script_whose_body_mentions_src() {
    let html = r#"<script>el.src = "/a.png"; console.log("one"); console.log("two");</script>"#;
    let result = console_log_production(&ctx(html));
    assert!(
        result.fired,
        "a `src=` in the script body must not mark an inline script as external"
    );
    assert_eq!(result.data["console_log_count"], 2);
}
