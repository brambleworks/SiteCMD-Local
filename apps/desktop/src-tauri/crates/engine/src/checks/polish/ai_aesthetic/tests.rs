use super::super::css_counts::{is_gray_hex, is_gray_rgb, shadow_has_blur};
use super::*;

fn ctx(html: &str) -> PolishContext<'static> {
    PolishContext::new(
        url::Url::parse("https://example.com").unwrap(),
        html.to_string().into(),
        Default::default(),
    )
}

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
fn gradient_fires_with_multiple_chromatic_hues() {
    // The detector must count different hues without a favored-color whitelist.
    let css = "a{background:linear-gradient(purple,orange)}".repeat(MULTI_HUE_GRADIENT_MIN);
    assert!(gradient_backgrounds(&ctx_with_css("", &css)).fired);
}

#[test]
fn gradient_clear_with_no_gradients() {
    let result = gradient_backgrounds(&ctx("background: #ffffff;"));
    assert!(!result.fired, "Should not fire without gradients");
}

#[test]
fn gradient_clear_below_threshold() {
    // A page with fewer multi-hue gradients than the threshold must stay clear.
    let html =
        r#"<div class="from-purple-500 to-orange-500"></div>"#.repeat(MULTI_HUE_GRADIENT_MIN - 1);
    assert!(!gradient_backgrounds(&ctx(&html)).fired);
}

#[test]
fn gradient_fires_with_two_tailwind_families() {
    // Tailwind gradients with different families must not depend on an old color shortlist.
    let html = r#"<div class="bg-gradient-to-r from-green-500 to-orange-500"></div>"#
        .repeat(MULTI_HUE_GRADIENT_MIN);
    assert!(gradient_backgrounds(&ctx(&html)).fired);
}

#[test]
fn glassmorphism_fires_with_heavy_backdrop_blur() {
    let css = "\
        nav { backdrop-filter: blur(10px); } \
        .modal { backdrop-filter: blur(8px); } \
        .card { backdrop-filter: blur(12px); }";
    let result = glassmorphism(&ctx_with_css("", css));
    assert!(result.fired, "Should fire with 3+ backdrop-blur usages");
}

#[test]
fn glassmorphism_fires_with_heavy_tailwind_usage() {
    let html = r#"
        <nav class="backdrop-blur-lg">a</nav>
        <div class="backdrop-blur-sm">b</div>
        <aside class="backdrop-blur-md">c</aside>"#;
    let result = glassmorphism(&ctx(html));
    assert!(
        result.fired,
        "Should fire with 3+ Tailwind backdrop-blur usages"
    );
}

#[test]
fn glassmorphism_clear_with_single_backdrop_blur() {
    let html = r#"<nav class="backdrop-blur-lg bg-white/80">Nav</nav>"#;
    let result = glassmorphism(&ctx(html));
    assert!(
        !result.fired,
        "Single backdrop-blur is mainstream and must not fire"
    );
}

#[test]
fn glassmorphism_clear_without_blur() {
    let result = glassmorphism(&ctx("<nav>Nav</nav>"));
    assert!(!result.fired, "Should not fire without backdrop blur");
}

#[test]
fn scroll_anims_fires_with_aos() {
    let html = r#"
            <section><div data-aos="fade-up">1</div></section>
            <section><div data-aos="fade-up">2</div></section>
            <section><div data-aos="fade-up">3</div></section>
            <section><div data-aos="fade-up">4</div></section>
            <section><div data-aos="fade-up">5</div></section>
        "#;
    let result = scroll_animations(&ctx(html));
    assert!(result.fired, "Should fire with 5+ AOS animations");
}

#[test]
fn scroll_anims_clear_without_triggers() {
    let html = "<section>A</section><section>B</section><section>C</section>";
    let result = scroll_animations(&ctx(html));
    assert!(
        !result.fired,
        "Should not fire without scroll animation triggers"
    );
}

#[test]
fn border_radius_fires_with_excessive_rounding() {
    let divs: Vec<String> = (0..25)
        .map(|i| format!(r#"<div class="rounded-2xl">Card {}</div>"#, i))
        .collect();
    let result = excessive_border_radius(&ctx(&divs.join("")));
    assert!(
        result.fired,
        "Should fire with >20 large border-radius elements"
    );
}

#[test]
fn border_radius_clear_with_moderate_usage() {
    let html = r#"<div class="rounded-2xl">A</div><div class="rounded-3xl">B</div>"#;
    let result = excessive_border_radius(&ctx(html));
    assert!(
        !result.fired,
        "Should not fire with just 2 large radius elements"
    );
}

#[test]
fn glow_fires_with_colored_shadows() {
    let html = r#"
            <div class="shadow-purple-500">A</div>
            <div class="shadow-blue-400">B</div>
            <div class="shadow-pink-500">C</div>
        "#;
    let result = glow_shadows(&ctx(html));
    assert!(result.fired, "Should fire with 3+ Tailwind colored shadows");
}

#[test]
fn glow_fires_with_css_colored_shadows() {
    let css = r#"
            .card { box-shadow: 0 0 20px rgba(139, 92, 246, 0.5); }
            .btn { box-shadow: 0 0 15px rgba(59, 130, 246, 0.4); }
            .hero { box-shadow: 0 0 30px rgba(236, 72, 153, 0.3); }
        "#;
    let result = glow_shadows(&ctx_with_css("", css));
    assert!(result.fired, "Should fire with 3+ CSS colored box-shadows");
}

#[test]
fn glow_clear_with_gray_shadows() {
    let css = ".card { box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1); }";
    let result = glow_shadows(&ctx_with_css("", css));
    assert!(!result.fired, "Should not fire with gray shadows only");
}

#[test]
fn glow_clear_with_bootstrap_focus_rings() {
    let css = r#"
            .btn-primary:focus { box-shadow: 0 0 0 0.25rem rgba(49, 132, 253, 0.5); }
            .btn-check:focus + .btn { box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
            .form-control:focus { box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
            .form-check-input:focus { box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
        "#;
    let result = glow_shadows(&ctx_with_css("", css));
    assert!(
        !result.fired,
        "zero-blur focus rings are not glow effects: {}",
        result.detail
    );
}

#[test]
fn shadow_has_blur_separates_rings_from_glows() {
    assert!(!shadow_has_blur("0 0 0 0.25rem rgba(13, 110, 253, 0.25)"));
    assert!(!shadow_has_blur("inset 0 0 0 2px #7c3aed"));
    assert!(shadow_has_blur("0 0 30px rgba(139, 92, 246, 0.5)"));
    assert!(shadow_has_blur("0 4px 14px 0 rgb(99 102 241 / 0.4)"));
}

#[test]
fn blobs_fire_with_absolute_rounded_full() {
    let html = r#"
            <div class="absolute rounded-full w-96 h-96 blur-3xl bg-purple-400/30"></div>
            <div class="absolute rounded-full w-80 h-80 blur-3xl bg-blue-400/20"></div>
        "#;
    let result = floating_blobs(&ctx(html));
    assert!(
        result.fired,
        "Should fire with 2+ absolute rounded-full elements"
    );
}

#[test]
fn blobs_fire_with_blob_class() {
    let html = r#"<div class="blob"></div><div class="blob"></div>"#;
    let result = floating_blobs(&ctx(html));
    assert!(result.fired, "Should fire with blob class names");
}

#[test]
fn blobs_clear_without_pattern() {
    let html = "<div class='rounded-full'>Avatar</div>";
    let result = floating_blobs(&ctx(html));
    assert!(!result.fired, "Should not fire without blob pattern");
}

#[test]
fn blob_words_in_prose_do_not_count() {
    let html = r#"<article>
        <p>Get that healthy glow with our new serum.</p>
        <p>The wizard held a glowing orb; the orb pulsed softly.</p>
    </article>"#;
    let result = floating_blobs(&ctx(html));
    assert!(
        !result.fired,
        "prose words are not decorative blob classes: {}",
        result.detail
    );
}

#[test]
fn blob_classes_in_class_attributes_still_count() {
    let html = r#"<div class="glow blur-3xl"></div><div class='orb bg-purple-400/30'></div>"#;
    let result = floating_blobs(&ctx(html));
    assert!(result.fired, "class-attribute blob words must still count");
}

#[test]
fn is_gray_detects_grays() {
    assert!(is_gray_hex("808080")); // pure gray
    assert!(is_gray_hex("000000")); // black
    assert!(is_gray_hex("ffffff")); // white
    assert!(is_gray_hex("f5f5f5")); // near-white
    assert!(!is_gray_hex("7c3aed")); // purple
    assert!(!is_gray_hex("3b82f6")); // blue
}

#[test]
fn is_gray_rgb_detects_grays() {
    assert!(is_gray_rgb(128, 128, 128));
    assert!(is_gray_rgb(0, 0, 0));
    assert!(!is_gray_rgb(139, 92, 246)); // purple
}

#[test]
fn html_comments_do_not_add_class_or_colour_matches() {
    // The polish fixture declares its defects in a comment naming the very
    // classes these signals count.
    let comment = "<!-- FIXTURE polish. Declared defects: rounded-2xl cards, \
                   shadow-purple-500 glow, class=\"glow-orb\" blobs; ratio > 0.5 -->";

    // Border radius: 21 real usages, over the >20 threshold.
    let cards = "<div class=\"rounded-2xl\">Card</div>".repeat(21);
    let radius_with = excessive_border_radius(&ctx(&format!("{comment}{cards}")));
    let radius_without = excessive_border_radius(&ctx(&cards));
    assert!(radius_without.fired, "{}", radius_without.detail);
    assert_eq!(radius_without.data["tailwind_large_radius"], 21);
    assert_eq!(
        radius_with.data["tailwind_large_radius"], radius_without.data["tailwind_large_radius"],
        "a comment must not add a rounded-2xl usage"
    );

    // Colored shadows: three real usages, at the >=3 threshold.
    let glows = "<div class=\"shadow-purple-500\">Card</div>".repeat(3);
    let glow_with = glow_shadows(&ctx(&format!("{comment}{glows}")));
    let glow_without = glow_shadows(&ctx(&glows));
    assert!(glow_without.fired, "{}", glow_without.detail);
    assert_eq!(glow_without.data["tailwind_colored_shadows"], 3);
    assert_eq!(
        glow_with.data["tailwind_colored_shadows"], glow_without.data["tailwind_colored_shadows"],
        "a comment must not add a colored shadow"
    );

    // Blob classes: two real usages, at the >=2 threshold. The comment holds a
    // class attribute of its own.
    let blobs = "<div class=\"blob\"></div><div class=\"orb\"></div>";
    let blob_with = floating_blobs(&ctx(&format!("{comment}{blobs}")));
    let blob_without = floating_blobs(&ctx(blobs));
    assert!(blob_without.fired, "{}", blob_without.detail);
    assert_eq!(blob_without.data["blob_class_matches"], 2);
    assert_eq!(
        blob_with.data["blob_class_matches"], blob_without.data["blob_class_matches"],
        "a comment must not add a blob class"
    );
}
