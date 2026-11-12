//! Heuristic visual-pattern signals for Polish Scan.

use super::{PolishContext, PolishResult, SignalCategory, SignalWeight};
use crate::checks::html_attrs::{all_tag_slices, attributes, slice_offset};
use regex::Regex;
use std::sync::LazyLock;

use super::css_counts::rendered_markup;
use super::gradient_hues::MULTI_HUE_GRADIENT_MIN;

const CATEGORY: SignalCategory = SignalCategory::AiAesthetic;

/// Matches AOS (Animate on Scroll) data attributes
static AOS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bdata-aos\s*=\s*["']"#).expect("aos regex"));

/// Matches Framer Motion scroll-triggered animation attributes
static FRAMER_SCROLL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(whileInView|useInView|useScroll)").expect("framer scroll regex")
});

/// Matches GSAP ScrollTrigger
static GSAP_SCROLL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)ScrollTrigger").expect("gsap scroll regex"));

/// Matches `<section` tags (for section count)
static SECTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(section|div)(?-u:\b)[^>]*>").expect("section regex"));

/// Detect repeated gradients that blend distinct chromatic hues.
pub fn gradient_backgrounds(ctx: &PolishContext) -> PolishResult {
    let count = ctx.css_counts().multi_hue_gradients;
    if count >= MULTI_HUE_GRADIENT_MIN {
        PolishResult::fired(
            "gradient-backgrounds",
            "Gradient Backgrounds",
            SignalWeight::Medium,
            CATEGORY,
            format!("{count} gradients blend two or more hues"),
            serde_json::json!({ "multi_hue_gradients": count }),
        )
    } else {
        PolishResult::clear(
            "gradient-backgrounds",
            "Gradient Backgrounds",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}
/// Detect repeated backdrop blur; one use is common and not meaningful.
pub fn glassmorphism(ctx: &PolishContext) -> PolishResult {
    let css_blur = ctx.css_counts().css_blur;
    let tw_blur = ctx.css_counts().tailwind_blur;
    let total = css_blur + tw_blur;

    if total >= 3 {
        PolishResult::fired(
            "glassmorphism",
            "Backdrop Blur Heavy Usage",
            SignalWeight::LowMedium,
            CATEGORY,
            format!(
                "{} backdrop-blur usage{} detected",
                total,
                if total != 1 { "s" } else { "" }
            ),
            serde_json::json!({
                "css_backdrop_blur": css_blur,
                "tailwind_backdrop_blur": tw_blur,
            }),
        )
    } else {
        PolishResult::clear(
            "glassmorphism",
            "Backdrop Blur Heavy Usage",
            SignalWeight::LowMedium,
            CATEGORY,
        )
    }
}

/// Flag scroll-triggered animation on more than half of sections (Medium, 8).
pub fn scroll_animations(ctx: &PolishContext) -> PolishResult {
    let html = rendered_markup(&ctx.html);
    let aos_count = AOS_RE.find_iter(&html).count();
    let framer_count = FRAMER_SCROLL_RE.find_iter(&html).count();
    let gsap_count = GSAP_SCROLL_RE.find_iter(&html).count();
    let total_scroll_anims = aos_count + framer_count + gsap_count;

    if total_scroll_anims == 0 {
        return PolishResult::clear(
            "scroll-animations",
            "Scroll Animations",
            SignalWeight::Medium,
            CATEGORY,
        );
    }

    // Both container counts and library markers are heuristic signals.
    let container_count = SECTION_RE.find_iter(&html).count().max(1);
    let ratio = total_scroll_anims as f64 / container_count as f64;

    if ratio > 0.5 || total_scroll_anims >= 5 {
        PolishResult::fired(
            "scroll-animations",
            "Scroll Animations",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{} scroll-animation marker{} (attributes or library references) across ~{} section/div containers",
                total_scroll_anims,
                if total_scroll_anims != 1 { "s" } else { "" },
                container_count
            ),
            serde_json::json!({
                "aos_count": aos_count,
                "framer_count": framer_count,
                "gsap_count": gsap_count,
                "container_count": container_count,
                "ratio": (ratio * 100.0).round() / 100.0,
            }),
        )
    } else {
        PolishResult::clear(
            "scroll-animations",
            "Scroll Animations",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Flag more than 20 large border-radius declarations (Low, 3).
pub fn excessive_border_radius(ctx: &PolishContext) -> PolishResult {
    let tw_count = ctx.css_counts().tailwind_radius;
    let css_count = ctx.css_counts().css_radius;

    let total = tw_count + css_count;

    if total > 20 {
        PolishResult::fired(
            "excessive-border-radius",
            "Large Border-Radius Heavy Usage",
            SignalWeight::Low,
            CATEGORY,
            // Counts class occurrences and CSS declarations, not rendered
            // elements (one CSS rule can style many elements or none).
            format!(
                "{} large border-radius usages (rounded-2xl/3xl/full classes or CSS declarations of 16px+)",
                total
            ),
            serde_json::json!({
                "tailwind_large_radius": tw_count,
                "css_large_radius": css_count,
            }),
        )
    } else {
        PolishResult::clear(
            "excessive-border-radius",
            "Large Border-Radius Heavy Usage",
            SignalWeight::Low,
            CATEGORY,
        )
    }
}

/// Flag three or more colored shadow declarations (Low, 3).
pub fn glow_shadows(ctx: &PolishContext) -> PolishResult {
    let tw_colored = ctx.css_counts().tailwind_shadows;
    let css_colored = ctx.css_counts().css_shadows;

    let total = tw_colored + css_colored;

    if total >= 3 {
        PolishResult::fired(
            "glow-shadows",
            "Colored Box-Shadow Heavy Usage",
            SignalWeight::Low,
            CATEGORY,
            format!(
                "{} colored box-shadow{} (glow effects)",
                total,
                if total != 1 { "s" } else { "" }
            ),
            serde_json::json!({
                "tailwind_colored_shadows": tw_colored,
                "css_colored_shadows": css_colored,
            }),
        )
    } else {
        PolishResult::clear(
            "glow-shadows",
            "Colored Box-Shadow Heavy Usage",
            SignalWeight::Low,
            CATEGORY,
        )
    }
}

/// Flag two or more decorative blurred-orb patterns (Medium, 8).
pub fn floating_blobs(ctx: &PolishContext) -> PolishResult {
    let blob_classes = ctx.css_counts().blob_classes;
    let abs_round = ctx.css_counts().absolute_rounded;
    let has_blob_css = ctx.css_counts().blob_pattern;
    let total = blob_classes + abs_round + usize::from(has_blob_css);

    if total >= 2 {
        PolishResult::fired(
            "floating-blobs",
            "Decorative Background Blobs",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{} blob-like decorative element{} detected",
                total,
                if total != 1 { "s" } else { "" }
            ),
            serde_json::json!({
                "blob_class_matches": blob_classes,
                "absolute_rounded_full": abs_round,
                "css_blob_pattern": has_blob_css,
            }),
        )
    } else {
        PolishResult::clear(
            "floating-blobs",
            "Decorative Background Blobs",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Minimum repeated labels needed for a finding.
pub const EYEBROW_MIN: usize = 3;
/// Maximum decoded characters in a heading label.
pub const EYEBROW_MAX_CHARS: usize = 40;
/// Maximum words in an unstyled all-capitals label.
pub const EYEBROW_MAX_WORDS: usize = 5;

static EYEBROW_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)^(?:p|span|div|small|h6)$").expect("heading label name regex")
});
static MAJOR_HEADING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u)^h[123]$").expect("major heading name regex"));
static EYEBROW_CONTENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)^([^<]*)</([a-z][a-z0-9]*)\s*>\s*$").expect("heading label content regex")
});
static EYEBROW_MARKER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u:\b(?:uppercase|tracking-wide|tracking-wider|tracking-widest|overline|eyebrow|kicker)\b)")
        .expect("heading label marker regex")
});

/// Count short text-only labels directly above major headings.
pub fn eyebrow_labels(ctx: &PolishContext) -> PolishResult {
    let markup = crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(&ctx.html, " ");
    let lower = markup.to_ascii_lowercase();
    let openings = all_tag_slices(&markup, &lower);
    let count = openings
        .windows(2)
        .filter(|pair| {
            let opening = pair[0];
            let name = super::markup::element_name(opening);
            if !EYEBROW_NAME_RE.is_match(name)
                || !MAJOR_HEADING_RE.is_match(super::markup::element_name(pair[1]))
            {
                return false;
            }
            let start = slice_offset(&markup, opening) + opening.len();
            let end = slice_offset(&markup, pair[1]);
            let Some(caps) = EYEBROW_CONTENT_RE.captures(&markup[start..end]) else {
                return false;
            };
            if !name.eq_ignore_ascii_case(&caps[2]) {
                return false;
            }
            let text = super::page_leftovers::copy_text(&caps[1]);
            let text = text.trim();
            if text.is_empty() || text.chars().count() > EYEBROW_MAX_CHARS {
                return false;
            }
            let capitals = text.split_whitespace().count() <= EYEBROW_MAX_WORDS
                && text.chars().any(char::is_uppercase)
                && !text.chars().any(char::is_lowercase);
            capitals
                || attributes(opening).any(|(name, value)| {
                    EYEBROW_MARKER_RE.is_match(&name)
                        || value.is_some_and(|value| EYEBROW_MARKER_RE.is_match(value))
                })
        })
        .count();
    let data = serde_json::json!({"count":count});
    if count < EYEBROW_MIN {
        let mut result = PolishResult::clear(
            "eyebrow-labels",
            "Labels Above Headings",
            SignalWeight::Medium,
            CATEGORY,
        );
        result.data = data;
        result
    } else {
        PolishResult::fired(
            "eyebrow-labels",
            "Labels Above Headings",
            SignalWeight::Medium,
            CATEGORY,
            format!("{count} short labels sit directly above headings"),
            data,
        )
    }
}

/// Detect a gradient clipped to text with a transparent fill across the sampled CSS inputs.
pub fn gradient_text(ctx: &PolishContext) -> PolishResult {
    let counts = ctx.css_counts();
    let data = serde_json::json!({
        "text_clip": counts.text_clip,
        "transparent_fill": counts.transparent_fill,
        "any_gradient": counts.any_gradient,
    });
    if counts.text_clip && counts.transparent_fill && counts.any_gradient {
        PolishResult::fired(
            "gradient-text",
            "Gradient Text",
            SignalWeight::Medium,
            CATEGORY,
            "A gradient is clipped to text with a transparent fill".into(),
            data,
        )
    } else {
        let mut result = PolishResult::clear(
            "gradient-text",
            "Gradient Text",
            SignalWeight::Medium,
            CATEGORY,
        );
        result.data = data;
        result
    }
}

#[cfg(test)]
mod tests;
