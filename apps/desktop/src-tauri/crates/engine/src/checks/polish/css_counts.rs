//! Compact, additive inputs for stylesheet-dependent polish signals.

use super::gradient_hues::{
    has_gradient_function, is_tailwind_gradient, multi_hue_gradients, tailwind_multi_hue_gradients,
    variant_utility,
};
use super::word_lists::decode_quote_entities;
use crate::checks::html_attrs::{all_tag_slices, attributes, raw_text_element_contents};
use crate::probe::{BodyLimit, ProbeRequest};
use regex::Regex;
use std::borrow::Cow;
use std::sync::LazyLock;

/// Whether counts come from page markup or a linked stylesheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CssTextKind {
    Page,
    Stylesheet,
}

/// Maximum linked stylesheets sampled from the entry page, in document order.
pub const STYLESHEET_SAMPLE_LIMIT: usize = 8;

/// Stylesheet signal counts and facts, combined without joining documents.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CssSignalCounts {
    pub multi_hue_gradients: usize,
    pub css_blur: usize,
    pub tailwind_blur: usize,
    pub css_radius: usize,
    pub tailwind_radius: usize,
    pub css_shadows: usize,
    pub tailwind_shadows: usize,
    pub blob_classes: usize,
    pub absolute_rounded: usize,
    pub blob_pattern: bool,
    pub text_clip: bool,
    pub transparent_fill: bool,
    pub any_gradient: bool,
}

impl std::ops::Add for CssSignalCounts {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            multi_hue_gradients: self.multi_hue_gradients + rhs.multi_hue_gradients,
            css_blur: self.css_blur + rhs.css_blur,
            tailwind_blur: self.tailwind_blur + rhs.tailwind_blur,
            css_radius: self.css_radius + rhs.css_radius,
            tailwind_radius: self.tailwind_radius + rhs.tailwind_radius,
            css_shadows: self.css_shadows + rhs.css_shadows,
            tailwind_shadows: self.tailwind_shadows + rhs.tailwind_shadows,
            blob_classes: self.blob_classes + rhs.blob_classes,
            absolute_rounded: self.absolute_rounded + rhs.absolute_rounded,
            blob_pattern: self.blob_pattern || rhs.blob_pattern,
            text_clip: self.text_clip || rhs.text_clip,
            transparent_fill: self.transparent_fill || rhs.transparent_fill,
            any_gradient: self.any_gradient || rhs.any_gradient,
        }
    }
}

/// An HTML comment.
static HTML_COMMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").expect("html comment regex"));

/// The page markup with comments removed. Nothing inside a comment is
/// rendered, so a commented-out class name or color is not a design choice the
/// visitor sees. `<script>` and `<style>` blocks stay: the library markers and
/// CSS declarations these signals count live in them.
pub(super) fn rendered_markup(text: &str) -> Cow<'_, str> {
    HTML_COMMENT_RE.replace_all(text, " ")
}

/// Matches backdrop-filter with blur
static BACKDROP_BLUR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)backdrop-filter\s*:\s*[^;]*blur\s*\(").expect("backdrop blur regex")
});

/// Matches Tailwind backdrop-blur classes
static TW_BACKDROP_BLUR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)backdrop-blur(?:-[a-z]+)?(?-u:\b)").expect("tw backdrop blur regex")
});

/// Matches large border-radius Tailwind classes
static LARGE_RADIUS_TW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)rounded-(2xl|3xl|full)(?-u:\b)").expect("large radius tw regex")
});

/// Matches large border-radius in CSS (>= 16px)
static LARGE_RADIUS_CSS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)border-radius\s*:\s*(\d+)px").expect("large radius css regex")
});

/// Matches box-shadow values (color checked separately)
static BOX_SHADOW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)box-shadow\s*:\s*([^;]+)").expect("box shadow regex"));

/// Matches Tailwind shadow-[color] classes (colored shadows)
static TW_COLORED_SHADOW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)shadow-(?:purple|blue|pink|indigo|violet|fuchsia|rose|sky|cyan|teal|emerald|green|red|orange|amber|yellow)-\d+")
        .expect("tw colored shadow regex")
});

/// Matches blob-suggesting words inside a class attribute VALUE. Running
/// this over the whole HTML matched "glow"/"orb" in body prose,
/// so callers must feed it class values only.
static BLOB_CLASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(blob|orb|glow|gradient-bg|bg-blur)(?-u:\b)")
        .expect("blob class regex")
});

/// A class attribute and its value (quoted or unquoted).
static CLASS_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\s"']class\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#)
        .expect("class attr regex")
});

/// Matches absolute positioning + rounded-full combined (potential blob)
static ABSOLUTE_ROUND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)class\s*=\s*["'][^"']*\babsolute\b[^"']*\brounded-full\b[^"']*["']"#)
        .expect("absolute round regex")
});

/// Matches absolute + rounded-full in reverse order
static ROUND_ABSOLUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)class\s*=\s*["'][^"']*\brounded-full\b[^"']*\babsolute\b[^"']*["']"#)
        .expect("round absolute regex")
});
/// Check if a box-shadow value contains a non-gray color.
fn has_colored_shadow(shadow: &str) -> bool {
    // Match hex colors in the shadow value
    static HEX_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?-u:\b)").expect("hex regex")
    });
    static RGB_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"rgba?\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)").expect("rgb regex")
    });

    // Check hex colors
    for cap in HEX_RE.captures_iter(shadow) {
        let hex = &cap[1];
        if !is_gray_hex(hex) {
            return true;
        }
    }

    // Check rgb/rgba colors
    for cap in RGB_RE.captures_iter(shadow) {
        let r: u8 = cap[1].parse().unwrap_or(0);
        let g: u8 = cap[2].parse().unwrap_or(0);
        let b: u8 = cap[3].parse().unwrap_or(0);
        if !is_gray_rgb(r, g, b) {
            return true;
        }
    }

    false
}

/// Check if a hex color is gray-ish (R, G, B channels within 30 of each other).
pub(super) fn is_gray_hex(hex: &str) -> bool {
    let bytes = if hex.len() == 3 {
        let chars: Vec<u8> = hex
            .chars()
            .filter_map(|c| u8::from_str_radix(&c.to_string(), 16).ok())
            .map(|v| v * 17) // expand #abc to #aabbcc
            .collect();
        if chars.len() != 3 {
            return true;
        }
        chars
    } else if hex.len() == 6 {
        let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
        let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
        let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
        vec![r, g, b]
    } else {
        return true;
    };

    let max = *bytes.iter().max().unwrap_or(&0);
    let min = *bytes.iter().min().unwrap_or(&0);
    (max - min) < 30
}

/// Check if an RGB color is gray-ish.
pub(super) fn is_gray_rgb(r: u8, g: u8, b: u8) -> bool {
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    (max - min) < 30
}

/// True when any shadow segment has a blur radius above zero (the third
/// length). Color functions are blanked first so space-separated
/// `rgb(13 110 253 /.25)` arguments cannot be read as lengths.
pub(super) fn shadow_has_blur(shadow: &str) -> bool {
    static COLOR_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:rgba?|hsla?|oklch|color)\([^)]*\)|#[0-9a-f]{3,8}")
            .expect("color token regex")
    });
    static LENGTH_RUN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)(?:^|,)\s*(?:inset\s+)?-?[\d.]+(?:px|rem|em)?\s+-?[\d.]+(?:px|rem|em)?\s+([\d.]+)(?:px|rem|em)?",
        )
        .expect("shadow length regex")
    });
    let cleaned = COLOR_TOKEN_RE.replace_all(shadow, "C");
    LENGTH_RUN_RE
        .captures_iter(&cleaned)
        .any(|cap| cap[1].parse::<f64>().map(|v| v > 0.0).unwrap_or(false))
}

/// Match a text-clipping declaration, including its optional importance flag.
static TEXT_CLIP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i-u)[;{]\s*(?:-webkit-)?background-clip\s*:\s*text\s*(?:!important\s*)?(?:[;}]|$)",
    )
    .expect("text clip declaration regex")
});
/// Capture text-fill values for alpha parsing without accepting non-text properties.
static TRANSPARENT_FILL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u:[;{]\s*(?:color|-webkit-text-fill-color)\s*:\s*)([^;}]+)")
        .expect("text fill declaration regex")
});
/// CSS comments cannot supply declarations or gradient functions.
static CSS_COMMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").expect("CSS comment regex"));
/// Strings and URL contents cannot supply declarations.
static CSS_LITERAL_START_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i-u:\burl\s*\()|["']"#).expect("CSS literal opening regex"));

/// Consume one quoted string or balanced URL, including escaped delimiters and an unclosed tail.
fn css_literal_end(
    bytes: &[u8],
    mut index: usize,
    mut depth: usize,
    mut quote: Option<u8>,
) -> usize {
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            index = (index + 2).min(bytes.len());
            continue;
        }
        if let Some(delimiter) = quote {
            if byte == delimiter {
                quote = None;
                if depth == 0 {
                    return index + 1;
                }
            }
        } else {
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return index + 1;
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    index
}

/// Blank literals once and resume after their consumed contents, preserving declaration boundaries.
fn without_css_literals(css: &str) -> Cow<'_, str> {
    let mut cursor = 0;
    let mut output = String::new();
    while let Some(opening) = CSS_LITERAL_START_RE.find_at(css, cursor) {
        output.push_str(&css[cursor..opening.start()]);
        output.push(' ');
        let first = css.as_bytes()[opening.start()];
        let quoted = first == b'\'' || first == b'"';
        cursor = css_literal_end(
            css.as_bytes(),
            opening.end(),
            usize::from(!quoted),
            quoted.then_some(first),
        );
    }
    if cursor == 0 {
        Cow::Borrowed(css)
    } else {
        output.push_str(&css[cursor..]);
        Cow::Owned(output)
    }
}

/// Parse the actual color alpha after removing an optional importance flag.
fn is_transparent_fill(value: &str) -> bool {
    let value = value
        .rsplit_once('!')
        .filter(|(_, flag)| flag.trim().eq_ignore_ascii_case("important"))
        .map_or(value, |(color, _)| color);
    csscolorparser::parse(value.trim()).is_ok_and(|color| color.a == 0.0)
}

/// Read independent declarations, while retaining any-gradient function matching.
fn gradient_text_declarations(counts: &mut CssSignalCounts, css: &str) {
    let css = CSS_COMMENT_RE.replace_all(css, " ");
    counts.any_gradient |= has_gradient_function(&css);
    let declarations = without_css_literals(&css);
    counts.text_clip |= TEXT_CLIP_RE.is_match(&declarations);
    counts.transparent_fill |= TRANSPARENT_FILL_RE
        .captures_iter(&declarations)
        .any(|capture| is_transparent_fill(&capture[1]));
}

/// Read page-only utilities and arbitrary properties through the shared tag and declaration readers.
fn gradient_text_page(counts: &mut CssSignalCounts, page: &str) {
    let lower = page.to_ascii_lowercase();
    for tag in all_tag_slices(page, &lower) {
        for (name, value) in attributes(tag) {
            let Some(value) = value else { continue };
            if name == "style" {
                // The opening style attribute is a declaration boundary, just like an opening brace.
                gradient_text_declarations(
                    counts,
                    &format!("{{{}}}", decode_quote_entities(value)),
                );
            } else if name == "class" {
                let value = decode_quote_entities(value);
                counts.any_gradient |= has_gradient_function(&value);
                for token in value.split_ascii_whitespace() {
                    let (_, utility) = variant_utility(token);
                    counts.text_clip |= utility == "bg-clip-text";
                    counts.transparent_fill |= utility == "text-transparent";
                    counts.any_gradient |= is_tailwind_gradient(utility);
                    if let Some(property) = utility
                        .strip_prefix('[')
                        .and_then(|value| value.strip_suffix(']'))
                    {
                        gradient_text_declarations(
                            counts,
                            &format!("{{{}}}", property.replace('_', " ")),
                        );
                    }
                }
            }
        }
    }
    for css in raw_text_element_contents(page, &lower, "style") {
        gradient_text_declarations(counts, css);
    }
}

/// Count one page or stylesheet independently so declarations cannot span files.
pub fn css_signal_counts(text: &str, kind: CssTextKind) -> CssSignalCounts {
    let text = match kind {
        CssTextKind::Page => rendered_markup(text),
        CssTextKind::Stylesheet => Cow::Borrowed(text),
    };
    let mut counts = CssSignalCounts {
        multi_hue_gradients: multi_hue_gradients(&text),
        css_blur: BACKDROP_BLUR_RE.find_iter(&text).count(),
        css_radius: LARGE_RADIUS_CSS_RE
            .captures_iter(&text)
            .filter(|cap| cap[1].parse::<u32>().is_ok_and(|px| px >= 16))
            .count(),
        css_shadows: BOX_SHADOW_RE
            .captures_iter(&text)
            .filter(|cap| has_colored_shadow(&cap[1]) && shadow_has_blur(&cap[1]))
            .count(),
        blob_pattern: text.contains("border-radius: 50%")
            && text.contains("filter: blur")
            && text.contains("position: absolute"),
        ..Default::default()
    };
    if kind == CssTextKind::Page {
        let blob_classes = CLASS_ATTR_RE
            .captures_iter(&text)
            .map(|cap| {
                let value = cap
                    .get(1)
                    .or_else(|| cap.get(2))
                    .or_else(|| cap.get(3))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                BLOB_CLASS_RE.find_iter(value).count()
            })
            .sum();
        counts.multi_hue_gradients += CLASS_ATTR_RE
            .captures_iter(&text)
            .map(|cap| {
                let value = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3));
                value.map_or(0, |value| tailwind_multi_hue_gradients(value.as_str()))
            })
            .sum::<usize>();
        counts.tailwind_blur = TW_BACKDROP_BLUR_RE.find_iter(&text).count();
        counts.tailwind_radius = LARGE_RADIUS_TW_RE.find_iter(&text).count();
        counts.tailwind_shadows = TW_COLORED_SHADOW_RE.find_iter(&text).count();
        counts.blob_classes = blob_classes;
        counts.absolute_rounded =
            ABSOLUTE_ROUND_RE.find_iter(&text).count() + ROUND_ABSOLUTE_RE.find_iter(&text).count();
        gradient_text_page(&mut counts, &text);
    } else {
        gradient_text_declarations(&mut counts, &text);
    }
    counts
}

/// A stylesheet GET follows redirects and reads only successful bodies under its cap.
pub fn stylesheet_request(url: &str) -> ProbeRequest {
    ProbeRequest::get(url).limit(BodyLimit::Stylesheet)
}

/// Regex to match `<link rel="stylesheet" href="...">` tags.
/// Handles both `rel` before `href` and `href` before `rel`.
static LINK_STYLESHEET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)<link\s[^>]*?(?:rel\s*=\s*["']stylesheet["'][^>]*?href\s*=\s*["']([^"']+)["']|href\s*=\s*["']([^"']+)["'][^>]*?rel\s*=\s*["']stylesheet["'])"#
    ).expect("Failed to compile link stylesheet regex")
});

/// Extract every stylesheet URL from HTML, resolving relative paths against
/// the base URL. The fetch cap is applied by the caller, not here:
/// the full list is what makes `stylesheets_discovered` an honest count.
pub fn extract_stylesheet_urls(html: &str, base_url: &url::Url) -> Vec<String> {
    LINK_STYLESHEET_RE
        .captures_iter(html)
        .filter_map(|cap| {
            // Group 1 or Group 2 depending on attribute order
            let href = decode_href_entities(cap.get(1).or_else(|| cap.get(2))?.as_str());
            // Resolve relative URLs
            match base_url.join(&href) {
                Ok(abs) => Some(abs.to_string()),
                Err(_) => Some(href),
            }
        })
        .collect()
}

fn decode_href_entities(href: &str) -> String {
    href.replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("&#x26;", "&")
        .replace("&#X26;", "&")
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
}
