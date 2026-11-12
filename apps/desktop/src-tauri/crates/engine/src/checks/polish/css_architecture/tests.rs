use super::*;

fn ctx(html: &str) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse("https://example.com").unwrap(),
        html.to_string().into(),
        Default::default(),
    )
}

#[allow(dead_code)]
fn ctx_with_css(html: &str, css: &str) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse("https://example.com").unwrap(),
        html.to_string().into(),
        crate::checks::polish::css_signal_counts(
            css,
            crate::checks::polish::CssTextKind::Stylesheet,
        ),
    )
}

#[test]
fn inline_style_density_fires_when_above_threshold() {
    // 4 out of 5 elements have inline styles = 80%
    let html = r#"
            <div style="color:red">A</div>
            <div style="color:blue">B</div>
            <div style="color:green">C</div>
            <div style="margin:0">D</div>
            <div>E</div>
        "#;
    let result = inline_style_density(&ctx(html));
    assert!(result.fired, "Should fire at 80% inline styles");
    assert_eq!(result.points, 15);
}

#[test]
fn inline_style_density_clear_when_below_threshold() {
    // 1 out of 10 elements = 10%
    let html = r#"
            <div style="color:red">A</div>
            <div>B</div><div>C</div><div>D</div><div>E</div>
            <div>F</div><div>G</div><div>H</div><div>I</div><div>J</div>
        "#;
    let result = inline_style_density(&ctx(html));
    assert!(!result.fired, "Should not fire at 10% inline styles");
}

#[test]
fn inline_style_density_handles_empty_html() {
    let result = inline_style_density(&ctx(""));
    assert!(!result.fired);
}

#[test]
fn inline_style_density_ignores_data_style_attributes() {
    let html = r#"
            <div data-style="card">A</div>
            <div data-style="card">B</div>
            <div data-style="card">C</div>
            <div data-style="card">D</div>
            <div>E</div>
        "#;
    let result = inline_style_density(&ctx(html));
    assert!(
        !result.fired,
        "data-style attributes are not inline styles: {}",
        result.detail
    );
}

#[test]
fn tailwind_density_fires_with_excessive_utilities() {
    // Each div has 12 Tailwind utilities, zero custom classes
    let html = r#"
            <div class="flex items-center justify-between p-4 m-2 bg-white text-gray-900 rounded-lg shadow-md border-b w-full">content</div>
            <div class="flex items-center justify-between p-4 m-2 bg-white text-gray-900 rounded-lg shadow-md border-b w-full">content</div>
            <div class="flex items-center justify-between p-4 m-2 bg-white text-gray-900 rounded-lg shadow-md border-b w-full">content</div>
        "#;
    let result = tailwind_class_density(&ctx(html));
    assert!(
        result.fired,
        "Should fire with avg >10 utility classes and 0% custom"
    );
}

#[test]
fn tailwind_density_clear_with_custom_classes() {
    // Mix of utility and custom classes
    let html = r#"
            <div class="flex items-center my-header nav-primary">content</div>
            <div class="p-4 card-wrapper content-section">content</div>
        "#;
    let result = tailwind_class_density(&ctx(html));
    assert!(
        !result.fired,
        "Should not fire with significant custom classes"
    );
}

#[test]
fn tailwind_density_clear_with_few_utilities() {
    let html = r#"<div class="flex p-4 mt-2">short</div>"#;
    let result = tailwind_class_density(&ctx(html));
    assert!(!result.fired, "Should not fire with avg <10 utilities");
}

#[test]
fn no_css_architecture_fires_when_no_styles_at_all() {
    let html = r#"<html><head></head><body><div>Hello</div></body></html>"#;
    let result = no_css_architecture(&ctx(html));
    assert!(
        result.fired,
        "Should fire when no CSS architecture is present"
    );
}

#[test]
fn no_css_architecture_clear_with_stylesheet() {
    let html =
        r#"<html><head><link rel="stylesheet" href="/style.css"></head><body></body></html>"#;
    let result = no_css_architecture(&ctx(html));
    assert!(!result.fired, "Should not fire when stylesheet is linked");
}

#[test]
fn no_css_architecture_clear_with_css_in_js() {
    // styled-components marker in class names
    let html = r#"<div class="sc-abc123 styled-header">Hello</div>"#;
    let result = no_css_architecture(&ctx(html));
    assert!(
        !result.fired,
        "Should not fire when CSS-in-JS markers are present"
    );
}

#[test]
fn no_css_architecture_clear_with_style_block() {
    let html = r#"<html><head><style>.foo { color: red; }</style></head><body></body></html>"#;
    let result = no_css_architecture(&ctx(html));
    assert!(
        !result.fired,
        "Should not fire when inline style block exists"
    );
}

#[test]
fn no_css_architecture_clear_with_css_modules() {
    let html = r#"<div class="header_a1b2c3d4">Hello</div>"#;
    let result = no_css_architecture(&ctx(html));
    assert!(
        !result.fired,
        "Should not fire when CSS module hashes are present"
    );
}

#[test]
fn is_utility_detects_tailwind_classes() {
    assert!(is_utility_class("flex"));
    assert!(is_utility_class("p-4"));
    assert!(is_utility_class("bg-white"));
    assert!(is_utility_class("hover:text-blue-500"));
    assert!(is_utility_class("-mt-4"));
    assert!(is_utility_class("sm:grid"));
    assert!(is_utility_class("dark:bg-gray-900"));
}

#[test]
fn is_utility_rejects_custom_classes() {
    assert!(!is_utility_class("my-header"));
    assert!(!is_utility_class("card-wrapper"));
    assert!(!is_utility_class("nav-primary"));
    assert!(!is_utility_class("content-section"));
    assert!(!is_utility_class("logo"));
}

#[test]
fn css_module_regex_matches_hashed_classes() {
    assert!(CSS_MODULE_RE.is_match("header_a1b2c3d4"));
    assert!(CSS_MODULE_RE.is_match("Button_x8y9z0ab"));
    assert!(!CSS_MODULE_RE.is_match("flex")); // too short hash
    assert!(!CSS_MODULE_RE.is_match("my-class")); // no underscore + hash
}
