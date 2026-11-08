use sitecmd_engine::checks::polish::ai_aesthetic::gradient_backgrounds;
use sitecmd_engine::checks::polish::gradient_hues::{
    GRADIENT_CHROMA_MIN, GRADIENT_HUE_MIN_DEGREES, MULTI_HUE_GRADIENT_MIN,
};
use sitecmd_engine::checks::polish::{css_signal_counts, CssTextKind, PolishContext, PolishResult};

fn verdict(css: &str) -> PolishResult {
    gradient_backgrounds(&PolishContext::new(
        url::Url::parse("https://example.com/").unwrap(),
        "".into(),
        css_signal_counts(css, CssTextKind::Stylesheet),
    ))
}

fn count(css: &str, expected: usize) {
    for kind in [CssTextKind::Page, CssTextKind::Stylesheet] {
        assert_eq!(
            css_signal_counts(css, kind).multi_hue_gradients,
            expected,
            "{css}"
        );
    }
}

#[test]
fn brand_gradients_built_from_custom_properties_clear() {
    // A site's single-hue brand gradients are reported as gradient-heavy styling, or many multi-color gradients go unreported.
    let css =
        "a{background:linear-gradient(170deg, var(--color-brand) 35%, var(--color-brand-dark));}"
            .repeat(31);
    assert!(!verdict(&css).fired);
    count(&css, 0);
}

#[test]
fn one_hue_literal_gradients_clear() {
    // Tonal brand fields and fades to white can be mistaken for multiple hues.
    for stops in ["#1e40af, #1e3a8a", "#1e40af, #ffffff", "#0047ab, #528bdb"] {
        let css = format!("a{{background:linear-gradient({stops});}}").repeat(8);
        assert!(!verdict(&css).fired, "{stops}");
        count(&css, 0);
    }
}

#[test]
fn multi_hue_gradients_fire_at_the_threshold() {
    // A color whitelist can miss genuinely multi-hue gradients at the firing boundary.
    let gradient = "a{background:linear-gradient(purple, orange);}";
    assert!(!verdict(&gradient.repeat(MULTI_HUE_GRADIENT_MIN - 1)).fired);
    let result = verdict(&gradient.repeat(MULTI_HUE_GRADIENT_MIN));
    assert!(result.fired);
    assert_eq!(
        result.data,
        serde_json::json!({"multi_hue_gradients": MULTI_HUE_GRADIENT_MIN})
    );
    assert_eq!(
        result.detail,
        format!("{MULTI_HUE_GRADIENT_MIN} gradients blend two or more hues")
    );
}

#[test]
fn vendor_prefixed_twins_count_once_per_declaration_block() {
    let css =
        "a{background:-webkit-linear-gradient(red, blue);background:linear-gradient(red, blue)}";
    count(css, 1);
    assert!(!verdict(&css.repeat(3)).fired);
    count(
        "a{background:linear-gradient(red, blue);background:-webkit-linear-gradient(red, blue)}",
        1,
    );
    count("a{background:-moz-linear-gradient(red, blue);background:-webkit-linear-gradient(red, blue);background:linear-gradient(red, blue)}", 1);
    count(
        "a{background:-webkit-linear-gradient(red, blue)}b{background:linear-gradient(red, blue)}",
        2,
    );
    count("a{background:-webkit-linear-gradient(red, blue);background:linear-gradient(orange, purple)}", 2);
    count(
        "a{background:linear-gradient(red, blue),linear-gradient(red, blue)}",
        2,
    );
}

#[test]
fn intervening_quoted_declarations_do_not_split_gradient_twins() {
    count("a{background:-webkit-linear-gradient(red, blue);content:\"Label\";background:linear-gradient(red, blue)}", 1);
    count("a{background:-WEBKIT-linear-gradient(red, blue),-webkit-linear-gradient(red, blue);background:linear-gradient(red, blue)}", 2);
}

#[test]
fn stop_syntax_is_read_whole() {
    // A first-closing-parenthesis regex truncates functional colors and loses their stops.
    for (css, expected) in [
        (
            "linear-gradient(to right, rgb(59 130 246 / 0.9), transparent)",
            0,
        ),
        ("radial-gradient(circle at 50% 50%, #fff, #000)", 0),
        ("linear-gradient(90deg, rgb(255,0,0), rgb(0,0,255))", 1),
        (
            "repeating-linear-gradient(45deg, hsl(0 100% 50%) 0 10%, oklch(60% 0.2 260) 20%)",
            1,
        ),
        ("radial-gradient(circle, rebeccapurple 10%, orange 90%)", 1),
        (
            "repeating-conic-gradient(from 20deg at center, red 0deg 30deg, blue 30deg 60deg)",
            1,
        ),
        ("LINEAR-GRADIENT(in oklch longer hue, red, blue)", 1),
        (
            "linear-gradient(red, blue), radial-gradient(circle, orange, purple)",
            2,
        ),
    ] {
        count(css, expected);
    }
}

#[test]
fn achromatic_and_unresolved_stops_never_add_a_hue() {
    // Neutral, invisible, and unresolved stops must not supply an extra hue.
    for stop in [
        "transparent",
        "currentColor",
        "var(--x)",
        "var(--x, blue)",
        "black",
        "white",
        "gray",
        "rgb(0 0 255 / 0)",
    ] {
        count(&format!("linear-gradient(red, {stop})"), 0);
    }
    count(
        &format!(
            "linear-gradient(oklch(60% {} 0), oklch(60% {} 100))",
            GRADIENT_CHROMA_MIN / 2.0,
            GRADIENT_CHROMA_MIN / 2.0
        ),
        0,
    );
}

#[test]
fn tailwind_shades_of_one_family_clear_and_two_families_fire() {
    // Tailwind stop references can inflate counts without two chromatic families in one class value.
    for classes in [
        "bg-gradient-to-r from-blue-400 to-blue-700",
        "bg-gradient-to-r from-yellow-100 to-yellow-950",
        "bg-linear-to-r from-blue-400 to-white",
        "bg-gradient-to-r from-slate-500 to-gray-800",
        "bg-gradient-to-r from-blue-400 to-transparent",
    ] {
        let html = format!("<i class=\"{classes}\"></i>").repeat(8);
        assert!(
            !gradient_backgrounds(&PolishContext::new(
                url::Url::parse("https://example.com").unwrap(),
                html.into(),
                Default::default()
            ))
            .fired,
            "{classes}"
        );
    }
    for classes in [
        "bg-gradient-to-r from-purple-500 to-orange-500",
        "bg-linear-to-r from-blue-400 to-sky-700",
        "hover:from-red-500 hover:to-blue-500",
        "from-[#ff0000] to-[rgb(0_0_255)]",
        "from-red-500 via-blue-500 to-white",
    ] {
        let html = format!("<i class=\"{classes}\"></i>").repeat(MULTI_HUE_GRADIENT_MIN);
        let result = gradient_backgrounds(&PolishContext::new(
            url::Url::parse("https://example.com").unwrap(),
            html.into(),
            Default::default(),
        ));
        assert!(result.fired, "{classes}");
        assert_eq!(result.data["multi_hue_gradients"], MULTI_HUE_GRADIENT_MIN);
    }
    let html = "<i class='from-red-500'></i><i class='to-blue-500'></i>".repeat(8);
    assert!(
        !gradient_backgrounds(&PolishContext::new(
            url::Url::parse("https://example.com").unwrap(),
            html.into(),
            Default::default()
        ))
        .fired
    );
}

#[test]
fn hue_is_compared_in_degrees() {
    // Incorrect hue units or missing seam normalization can misclassify chromatic stops.
    let color = |angle| csscolorparser::Color::from_oklcha(0.65, 0.12, angle, 1.0);
    let first = color(0.0);
    let quarter = color(std::f32::consts::FRAC_PI_2);
    assert!((quarter.to_oklcha()[2] - std::f32::consts::FRAC_PI_2).abs() < 0.001);
    count(
        &format!(
            "linear-gradient({}, {})",
            first.to_css_rgb(),
            quarter.to_css_rgb()
        ),
        1,
    );
    count(
        &format!(
            "linear-gradient({}, {})",
            first.to_css_rgb(),
            color(0.2).to_css_rgb()
        ),
        0,
    );
    // This pair crosses zero; the following pairs cross the parser's 180-degree seam.
    count("linear-gradient(oklch(65% 0.12 355), oklch(65% 0.12 5))", 0);
    count(
        "linear-gradient(oklch(65% 0.12 170), oklch(65% 0.12 190))",
        0,
    );
    count(
        "linear-gradient(oklch(65% 0.12 160), oklch(65% 0.12 195))",
        1,
    );
    for (angle, expected) in [
        (GRADIENT_HUE_MIN_DEGREES - 1.0, 0),
        (GRADIENT_HUE_MIN_DEGREES + 1.0, 1),
    ] {
        count(
            &format!("linear-gradient(oklch(65% 0.12 0), oklch(65% 0.12 {angle}))"),
            expected,
        );
    }
}

#[test]
fn tailwind_near_white_shades_share_the_literal_chroma_floor() {
    // Near-white Tailwind stops must not add hues that the same literal colors cannot supply.
    for (classes, literals) in [
        ("from-blue-50 to-indigo-50", "#eff6ff, #eef2ff"),
        ("from-green-50 to-blue-50", "#f0fdf4, #eff6ff"),
        (
            "from-white via-blue-50 to-red-50",
            "white, #eff6ff, #fef2f2",
        ),
    ] {
        count(&format!("linear-gradient({literals})"), 0);
        let html = format!("<i class=\"{classes}\"></i>");
        assert_eq!(
            css_signal_counts(&html, CssTextKind::Page).multi_hue_gradients,
            0,
            "{classes}"
        );
    }
    let html = "<i class='from-blue-500 to-indigo-500'></i>";
    assert_eq!(
        css_signal_counts(html, CssTextKind::Page).multi_hue_gradients,
        1
    );
}

#[test]
fn tailwind_variant_states_keep_their_stop_colors_separate() {
    // Pooling base and variant utilities can turn single-hue states into a multi-hue gradient.
    for variant in ["dark:", "hover:", "md:", "md:hover:", "[&:hover]:"] {
        let html = format!("<i class=\"from-blue-600 to-blue-700 {variant}from-purple-600 {variant}to-purple-700\"></i>");
        assert_eq!(
            css_signal_counts(&html, CssTextKind::Page).multi_hue_gradients,
            0,
            "{variant}"
        );
    }
    let html = "<i class='from-red-500 to-blue-500 hover:from-green-500 hover:to-orange-500 dark:from-blue-600 dark:to-blue-700'></i>";
    assert_eq!(
        css_signal_counts(html, CssTextKind::Page).multi_hue_gradients,
        2
    );
    let html = "<i class='hover:from-red-500 dark:to-blue-500'></i>";
    assert_eq!(
        css_signal_counts(html, CssTextKind::Page).multi_hue_gradients,
        0
    );
}

#[test]
fn tailwind_literals_use_the_named_stops_actual_shade() {
    // Substituting a family's middle shade can misclassify a mixed literal-color gradient.
    for (literal_hue, expected) in [(320, 0), (20, 1)] {
        let html = format!("<i class=\"from-pink-200 to-[oklch(65%_0.12_{literal_hue})]\"></i>");
        assert_eq!(
            css_signal_counts(&html, CssTextKind::Page).multi_hue_gradients,
            expected
        );
    }
}

#[test]
fn an_unclosed_gradient_stylesheet_returns_a_verdict() {
    // Repeated unclosed gradient functions must not repeatedly rescan the stylesheet tail.
    let mut css = "linear-gradient(".repeat(2 * 1024 * 1024 / "linear-gradient(".len());
    css.extend(std::iter::repeat_n(' ', 2 * 1024 * 1024 - css.len()));
    assert!(!verdict(&css).fired);
}

#[test]
fn gradient_guidance_describes_multi_color_treatments() {
    // Gradient guidance must distinguish multiple hues from intentional tonal brand treatments.
    let guidance =
        sitecmd_engine::checks::polish::guidance::polish_signal_guidance("gradient-backgrounds")
            .unwrap();
    assert_eq!(guidance.why_it_matters, "Many gradients that blend several hues can compete with content and make a visual system feel inconsistent, but gradients are a subjective brand choice rather than a quality defect.");
    assert_eq!(guidance.fix, "Review the detected multi-color gradients for contrast, consistency, and purpose. Consolidate arbitrary variants into design tokens and keep intentional brand treatments.");
}
