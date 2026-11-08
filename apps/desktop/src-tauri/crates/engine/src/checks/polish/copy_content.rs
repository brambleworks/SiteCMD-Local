//! Heuristic copy and content signals for Polish Scan.
//!
//! Headings and hero copy receive full buzzword weight; body copy receives half.

use super::word_lists::{compile_formula, expanded_slots, word_lists, Listed};
use super::{PolishContext, PolishResult, SignalCategory, SignalWeight};
use crate::checks::html_attrs::{attr_value, tag_slices};
use crate::checks::security::dns_email::{registrable_domain_for_url, DomainTarget};
use regex::Regex;
use std::sync::LazyLock;

const CATEGORY: SignalCategory = SignalCategory::CopyContent;

/// Matches em dash characters (Unicode, HTML entity, and raw)
static EM_DASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\u{2014}|&mdash;|&#8212;)").expect("em dash regex"));

/// Approximate sentence boundary: period/question/exclamation followed by space or end
static SENTENCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[.!?]\s").expect("sentence regex"));

/// Extracts text content from heading tags (h1-h6)
static HEADING_TEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<h[1-6][^>]*>(.*?)</h[1-6]>").expect("heading text regex"));

/// The document title, whose site-name segment can name the brand.
static TITLE_TEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("title text regex"));

/// Separators between a title's page segment and its site-name segment.
const TITLE_SEPARATORS: &[char] = &[
    '|', '-', '\u{2013}', '\u{2014}', '\u{00b7}', '\u{2022}', ':',
];

/// Strips HTML tags to get plain text
static HTML_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("html tag regex"));

/// Matches "whether you're a" or "whether you are a" patterns
static INCLUSIVE_FRAMING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)whether you(?:'re| are) a(?-u:\b)").expect("inclusive framing regex")
});

/// Rendered emoji bases, excluding selectors and skin-tone modifiers.
static EMOJI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\x{1F300}-\x{1F3FA}\x{1F400}-\x{1F9FF}\x{2600}-\x{26FF}\x{2700}-\x{27BF}\x{1FA00}-\x{1FA6F}\x{1FA70}-\x{1FAFF}]")
        .expect("emoji regex")
});

/// An `<h2>`/`<h3>` element, optionally preceded by one short inline element
/// (the `<span>emoji</span><h3>Title</h3>` shape feature cards use). Group 1 is
/// that element's text, group 2 the heading's inner HTML.
static EMOJI_CARD_HEADING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)(?:<(?:span|div|p|em|strong|i|b)(?-u:\b)[^>]*>([^<]{0,80})</(?:span|div|p|em|strong|i|b)>\s*)?<h[23](?-u:\b)[^>]*>(.*?)</h[23]>",
    )
    .expect("emoji card heading regex")
});

/// A three-column grid utility class, in the Tailwind spelling or the spaced
/// variant some generators emit. Case-insensitive, so the caller does not have
/// to allocate a lowercase copy of the stripped markup.
static THREE_COLUMN_CLASS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)grid[- ]cols-3").expect("three column class regex"));

/// Heading and list text used for feature-section emoji detection.
static FEATURE_H2_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<h2(?-u:\b)[^>]*>(.*?)</h2>").expect("feature h2 regex"));
static FEATURE_H3_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<h3(?-u:\b)[^>]*>(.*?)</h3>").expect("feature h3 regex"));
static FEATURE_LI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<li(?-u:\b)[^>]*>(.*?)</li>").expect("feature li regex"));

static HEADER_FORMULAS: LazyLock<Vec<(Regex, &str)>> = LazyLock::new(|| {
    let lists = word_lists();
    let slots = expanded_slots(lists);
    lists
        .headline_formulas
        .iter()
        .map(|formula| {
            (
                compile_formula(formula, &slots).expect("recorded headline formula compiles"),
                formula.example.as_str(),
            )
        })
        .collect()
});

fn marketing_weight(term: &Listed) -> u32 {
    term.cites
        .iter()
        .map(|cite| cite.source.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        .min(3) as u32
}

/// Extract prose from HTML. Comments, scripts, and styles are removed whole:
/// none of them is rendered copy, and a comment that carries a `>` used to leak
/// its tail into the prose these signals count.
fn strip_html(html: &str) -> String {
    let without_non_content =
        crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(html, " ");
    let text = HTML_TAG_RE.replace_all(&without_non_content, " ");
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// The page markup with comments, scripts, and styles removed, tags intact.
/// Headings, list items, and card structure are rendered content: a heading
/// inside a comment or a JS template string is not on the page, so no signal
/// may count it. `strip_html` removes the same blocks before flattening to
/// prose; this keeps the tags the structural signals match on.
fn rendered_markup(html: &str) -> std::borrow::Cow<'_, str> {
    crate::checks::seo::headings::NON_CONTENT_BLOCK_RE.replace_all(html, " ")
}

/// Lowercase words of a site name, split at punctuation, spaces, and
/// camel-case boundaries ("SmartHomeU" gives smart, home, u).
fn brand_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for ch in name.chars() {
        if ch.is_alphanumeric() {
            if ch.is_uppercase() && previous_lower && !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            current.extend(ch.to_lowercase());
            previous_lower = ch.is_lowercase();
        } else {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = false;
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Lowercase alphanumerics only, so "Smart Home U" and "smarthomeu" compare equal.
fn alphanumeric_key(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Words that name the site rather than sell it. The registrable domain's
/// label is matched as a substring because labels concatenate words
/// (smarthomeu contains "smart"). `og:site_name`, and any `<title>` segment
/// that repeats the site name, contribute whole words; the rest of the title
/// is page copy and must not exempt its own buzzwords.
struct BrandTerms {
    domain_label: Option<String>,
    words: Vec<String>,
    /// Hyphen-joined site names, so a hyphenated dictionary entry such as
    /// "cutting-edge" matches a brand like "Cutting Edge Tools".
    phrases: Vec<String>,
}

impl BrandTerms {
    fn from_page(ctx: &PolishContext) -> Self {
        let domain_label = match registrable_domain_for_url(&ctx.url) {
            DomainTarget::Registrable(domain) => domain
                .split('.')
                .next()
                .map(|label| label.to_ascii_lowercase()),
            DomainTarget::LocalOrIp => None,
        };
        // Open Graph specifies `property`, but enough generators and CMS
        // templates emit `name` that reading only one of them loses the site
        // name on real pages. Either spelling identifies the same tag.
        let site_name = tag_slices(&ctx.html, ctx.html_lower(), "meta")
            .into_iter()
            .find(|tag| {
                // technical vocabulary: https://ogp.me/
                let property = attr_value(tag, "property");
                // technical vocabulary: https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-name
                let name = attr_value(tag, "name");
                property
                    .into_iter()
                    .chain(name)
                    .any(|value| value.eq_ignore_ascii_case("og:site_name"))
            })
            .and_then(|tag| attr_value(tag, "content"))
            .map(|content| strip_html(&content).trim().to_string())
            .filter(|content| !content.is_empty());
        let mut names: Vec<String> = site_name.into_iter().collect();
        if let Some(title) = TITLE_TEXT_RE
            .captures(&ctx.html)
            .map(|cap| strip_html(&cap[1]))
        {
            for segment in title.split(TITLE_SEPARATORS) {
                let key = alphanumeric_key(segment);
                if key.is_empty() {
                    continue;
                }
                let repeats_site_name = names.iter().any(|name| alphanumeric_key(name) == key)
                    || domain_label.as_deref() == Some(key.as_str());
                if repeats_site_name {
                    names.push(segment.trim().to_string());
                }
            }
        }
        let mut words = Vec::new();
        let mut phrases = Vec::new();
        for name in &names {
            let name_words = brand_words(name);
            phrases.push(name_words.join("-"));
            words.extend(name_words);
        }
        Self {
            domain_label,
            words,
            phrases,
        }
    }

    fn exempts(&self, word: &str) -> bool {
        self.domain_label
            .as_deref()
            .is_some_and(|label| label.contains(word))
            || self.words.iter().any(|brand_word| brand_word == word)
            || (word.contains('-') && self.phrases.iter().any(|phrase| phrase.contains(word)))
    }
}

/// The dictionary tier a scoring weight belongs to. The raw data reports both,
/// so "tier" always means the tier number and never the weight.
fn tier_for_weight(weight: u32) -> u32 {
    match weight {
        3 => 1,
        2 => 2,
        _ => 3,
    }
}

/// Count `<h2>`/`<h3>` headings whose own text, or the short inline element
/// immediately before them, carries an emoji. Matching "emoji ... next
/// heading" instead never counted the last card of a section, and used a
/// narrower emoji class than `emoji_as_icons`.
fn emoji_heading_count(html: &str) -> usize {
    EMOJI_CARD_HEADING_RE
        .captures_iter(html)
        .filter(|caps| {
            let preceding = caps.get(1).map_or("", |m| m.as_str());
            EMOJI_RE.is_match(preceding) || EMOJI_RE.is_match(&strip_html(&caps[2]))
        })
        .count()
}

/// Extract heading text content from HTML, ignoring comments, scripts, and
/// styles: a commented-out `<h2>` is not a heading on the page.
fn extract_heading_text(html: &str) -> Vec<String> {
    let rendered = rendered_markup(html);
    HEADING_TEXT_RE
        .captures_iter(&rendered)
        .map(|cap| strip_html(&cap[1]).trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

struct MarketingTerm {
    entry: &'static Listed,
    weight: u32,
}

struct MarketingDictionary {
    terms: Vec<MarketingTerm>,
    pattern: Regex,
}

static MARKETING_DICTIONARY: LazyLock<MarketingDictionary> = LazyLock::new(|| {
    let mut terms: Vec<_> = word_lists()
        .marketing_terms
        .iter()
        .map(|entry| MarketingTerm {
            entry,
            weight: marketing_weight(entry),
        })
        .collect();
    terms.sort_by_key(|term| std::cmp::Reverse(term.entry.value.chars().count()));
    let alternatives = terms
        .iter()
        .map(|term| format!("({})", regex::escape(&term.entry.value)))
        .collect::<Vec<_>>()
        .join("|");
    MarketingDictionary {
        terms,
        pattern: Regex::new(&format!(r"(?i)\b(?:{alternatives})\b"))
            .expect("recorded marketing terms compile"),
    }
});

fn marketing_counts(text: &str) -> Vec<usize> {
    let dictionary = &*MARKETING_DICTIONARY;
    let mut counts = vec![0; dictionary.terms.len()];
    for matched in dictionary.pattern.captures_iter(text) {
        if let Some(index) = matched.iter().skip(1).position(|capture| capture.is_some()) {
            counts[index] += 1;
        }
    }
    counts
}

/// Detect unusually dense em-dash use.
/// Threshold: more than one per three sentences. Weight: High.
pub fn em_dash_density(ctx: &PolishContext) -> PolishResult {
    let text = strip_html(&ctx.html);
    // Count only prose because the denominator is prose sentences.
    let em_dash_count = EM_DASH_RE.find_iter(&text).count();

    let sentences = SENTENCE_RE.find_iter(&text).count().max(1);

    if em_dash_count == 0 {
        return PolishResult::clear(
            "em-dash-density",
            "High Em-Dash Density",
            SignalWeight::High,
            CATEGORY,
        );
    }

    let ratio = em_dash_count as f64 / sentences as f64;

    // >1 per 3 sentences = >0.333
    if ratio > 0.333 {
        PolishResult::fired(
            "em-dash-density",
            "High Em-Dash Density",
            SignalWeight::High,
            CATEGORY,
            format!(
                "1 em dash per {:.1} sentences ({} em dashes, ~{} sentences)",
                1.0 / ratio,
                em_dash_count,
                sentences
            ),
            serde_json::json!({
                "em_dash_count": em_dash_count,
                "sentence_count": sentences,
                "ratio": (ratio * 1000.0).round() / 1000.0,
            }),
        )
    } else {
        PolishResult::clear(
            "em-dash-density",
            "High Em-Dash Density",
            SignalWeight::High,
            CATEGORY,
        )
    }
}

/// Flag weighted AI-favored phrasing above 15 points (High, 15).
pub fn ai_buzzword_dictionary(ctx: &PolishContext) -> PolishResult {
    let heading_text = extract_heading_text(&ctx.html).join(" ");
    let full_text = strip_html(&ctx.html);

    let mut total_score = 0.0f64;
    let mut found_words: Vec<(String, usize, u32)> = Vec::new(); // (word, count, tier_weight)

    // A dictionary word that names the site (SmartHomeU, "smart") is the
    // product category, not marketing filler.
    let brand = BrandTerms::from_page(ctx);
    let mut brand_words_excluded: Vec<&str> = Vec::new();

    let heading_counts = marketing_counts(&heading_text);
    let body_counts = marketing_counts(&full_text);
    for (index, term) in MARKETING_DICTIONARY.terms.iter().enumerate() {
        let word = term.entry.value.as_str();
        let weight = term.weight;
        let count = body_counts[index];
        if count == 0 {
            continue;
        }
        if brand.exempts(word) {
            brand_words_excluded.push(word);
            continue;
        }
        let heading_count = heading_counts[index];
        total_score += heading_count as f64 * weight as f64
            + count.saturating_sub(heading_count) as f64 * weight as f64 * 0.5;
        found_words.push((word.to_string(), count, weight));
    }

    // Sort by tier weight desc, then count desc
    found_words.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));

    if total_score > 15.0 {
        let rounded_score = total_score.round() as u32;
        let top_words: Vec<String> = found_words
            .iter()
            .take(5)
            .map(|(w, c, _)| format!("\"{}\" x{}", w, c))
            .collect();
        PolishResult::fired(
            "ai-buzzword-dictionary",
            "High Marketing Buzzword Density",
            SignalWeight::High,
            CATEGORY,
            format!("Buzzword score {rounded_score} ({})", top_words.join(", ")),
            serde_json::json!({
                "total_score": rounded_score,
                "words_found": found_words.len(),
                "top_words": found_words.iter().take(10)
                    .map(|(w, c, weight)| serde_json::json!({
                        "word": w,
                        "count": c,
                        "weight": weight,
                        "tier": tier_for_weight(*weight),
                    }))
                    .collect::<Vec<_>>(),
                "brand_words_excluded": brand_words_excluded,
            }),
        )
    } else {
        let mut result = PolishResult::clear(
            "ai-buzzword-dictionary",
            "High Marketing Buzzword Density",
            SignalWeight::High,
            CATEGORY,
        );
        if !brand_words_excluded.is_empty() {
            result.data = serde_json::json!({ "brand_words_excluded": brand_words_excluded });
        }
        result
    }
}

/// Flag two or more formulaic headings (Medium, 8).
pub fn ai_header_formulas(ctx: &PolishContext) -> PolishResult {
    let headings = extract_heading_text(&ctx.html);
    let mut matched_count = 0;
    let mut matched_formulas = Vec::new();

    for heading in &headings {
        let trimmed = heading.trim();
        let mut heading_matched = false;
        for (pattern, example) in HEADER_FORMULAS.iter() {
            if pattern.is_match(trimmed) {
                heading_matched = true;
                if matched_formulas.len() < 5 && !matched_formulas.contains(example) {
                    matched_formulas.push(*example);
                }
            }
        }
        matched_count += usize::from(heading_matched);
    }

    if matched_count >= 2 {
        PolishResult::fired(
            "ai-header-formulas",
            "Common Marketing Headline Patterns",
            SignalWeight::Medium,
            CATEGORY,
            format!("{matched_count} headings use common headline formulas"),
            serde_json::json!({
                "matched_count": matched_count,
                "matched_formulas": matched_formulas,
            }),
        )
    } else {
        PolishResult::clear(
            "ai-header-formulas",
            "Common Marketing Headline Patterns",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Flag generic "whether you're X or Y" framing (Medium, 8).
pub fn inclusive_framing(ctx: &PolishContext) -> PolishResult {
    let text = strip_html(&ctx.html);
    let matches = INCLUSIVE_FRAMING_RE.find_iter(&text).count();

    if matches > 0 {
        PolishResult::fired(
            "inclusive-framing",
            "Generic Audience Phrasing Detected",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{} occurrence{} of \"whether you're a\" pattern",
                matches,
                if matches != 1 { "s" } else { "" }
            ),
            serde_json::json!({ "occurrences": matches }),
        )
    } else {
        PolishResult::clear(
            "inclusive-framing",
            "Generic Audience Phrasing Detected",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Flag three or more emoji in feature headings and lists (Medium, 8).
pub fn emoji_as_icons(ctx: &PolishContext) -> PolishResult {
    let rendered = rendered_markup(&ctx.html);
    let mut emoji_count = 0usize;

    for re in [&*FEATURE_H2_RE, &*FEATURE_H3_RE, &*FEATURE_LI_RE] {
        for cap in re.captures_iter(&rendered) {
            let content = &cap[1];
            emoji_count += EMOJI_RE.find_iter(content).count();
        }
    }

    if emoji_count >= 3 {
        PolishResult::fired(
            "emoji-as-icons",
            "Emoji as Icons",
            SignalWeight::Medium,
            CATEGORY,
            format!("{} emoji in headings or list items", emoji_count),
            serde_json::json!({ "emoji_count": emoji_count }),
        )
    } else {
        PolishResult::clear(
            "emoji-as-icons",
            "Emoji as Icons",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}
/// Detect a three-column feature grid only when emoji headings add a second signal.
pub fn three_column_grid(ctx: &PolishContext) -> PolishResult {
    // All three conditions describe rendered markup, so all three read the
    // comment-, script-, and style-free view. A commented-out card section is
    // not a layout the visitor sees.
    let rendered = rendered_markup(&ctx.html);
    // A generic grid does not prove a three-column layout, so the specific
    // class is tracked separately and reused in the detail copy below.
    let has_three_col_class = THREE_COLUMN_CLASS_RE.is_match(&rendered);
    let has_grid_container = has_three_col_class
        || Regex::new(r#"(?i)class\s*=\s*["'][^"']*\bgrid\b[^"']*["']"#)
            .ok()
            .map(|r| r.is_match(&rendered))
            .unwrap_or(false);

    // Count h2/h3 tags that are immediately followed (within 200 chars) by a <p>
    let heading_p_pattern =
        Regex::new(r"(?is)<h[23][^>]*>.*?</h[23]>\s*(?:.{0,200}?)<p(?-u:\b)").ok();
    let heading_p_count = heading_p_pattern
        .map(|r| r.find_iter(&rendered).count())
        .unwrap_or(0);

    // Count card headings that carry an emoji, in the heading itself or in the
    // inline element immediately before it.
    let emoji_heading_count = emoji_heading_count(&rendered);

    // Require grid, repeated cards, and emoji headings together; grid alone is
    // too common to be meaningful.
    let detected = has_grid_container && heading_p_count >= 3 && emoji_heading_count >= 3;

    if detected {
        let detail = if has_three_col_class {
            "3-column feature grid with emoji headings and heading + paragraph cards detected"
        } else {
            "Feature-grid layout with emoji headings and heading + paragraph cards detected"
        };
        PolishResult::fired(
            "three-column-grid",
            "Three-Column Feature Pattern",
            SignalWeight::LowMedium,
            CATEGORY,
            detail.to_string(),
            serde_json::json!({
                "has_grid_container": has_grid_container,
                "has_three_column_class": has_three_col_class,
                "heading_paragraph_pairs": heading_p_count,
                "emoji_heading_pairs": emoji_heading_count,
            }),
        )
    } else {
        PolishResult::clear(
            "three-column-grid",
            "Three-Column Feature Pattern",
            SignalWeight::LowMedium,
            CATEGORY,
        )
    }
}

#[cfg(test)]
mod tests;
