//! Placeholder copy and social links that do not lead to a profile.

use super::markup::{element_name, without_elements};
use super::word_lists::{decode_quote_entities, lowercase_values, word_lists};
use super::{PolishContext, PolishResult, SignalCategory, SignalWeight};
use crate::checks::html_attrs::{
    all_tag_slices, attr_value, attributes, slice_offset, tag_slices, url_attr_value,
};
use crate::checks::seo::headings::NON_CONTENT_BLOCK_RE;
use regex::Regex;
use std::sync::LazyLock;

/// Minimum number of dead social links needed for a finding.
pub const DEAD_SOCIAL_LINK_MIN: usize = 2;

static TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<(?:[^>"']|"[^"]*"|'[^']*')*>"#).expect("text tag regex"));
static ANCHOR_CLOSE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:</a\s*>)").expect("anchor close regex"));

fn word_pattern(value: &str) -> Regex {
    let left = if value.starts_with('©') {
        ""
    } else {
        r"(?:^|[^\p{L}\p{N}])"
    };
    Regex::new(&format!(
        r"(?i){left}{}(?:$|[^\p{{L}}\p{{N}}])",
        regex::escape(value)
    ))
    .expect("escaped recorded phrase regex")
}

static PHRASES: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    word_lists()
        .placeholder_phrases
        .iter()
        .map(|entry| (entry.value.as_str(), word_pattern(&entry.value)))
        .collect()
});
static CLIENT_MARKERS: LazyLock<Vec<(&str, String)>> =
    LazyLock::new(|| lowercase_values(&word_lists().client_template_markers));

struct Platform {
    domain: &'static str,
    markers: Vec<Regex>,
    single_names: Vec<&'static str>,
}

static PLATFORMS: LazyLock<Vec<Platform>> = LazyLock::new(|| {
    word_lists()
        .social_platforms
        .iter()
        .map(|entry| Platform {
            domain: &entry.domain,
            markers: std::iter::once(&entry.domain)
                .chain(&entry.names)
                .filter(|value| value.chars().count() > 1)
                .map(|value| word_pattern(value))
                .collect(),
            single_names: entry
                .names
                .iter()
                .filter(|value| value.chars().count() == 1)
                .map(String::as_str)
                .collect(),
        })
        .collect()
});

/// Extract decoded copy without interpreting entity-encoded tags as elements.
pub(super) fn copy_text(markup: &str) -> String {
    let text = TAG_RE.replace_all(markup, " ");
    decode_quote_entities(&text)
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Detect full recorded placeholder shapes, image hosts, and unresolved template lines.
pub fn placeholder_text(ctx: &PolishContext) -> PolishResult {
    let rendered = NON_CONTENT_BLOCK_RE.replace_all(&ctx.html, " ");
    // technical vocabulary: https://html.spec.whatwg.org/multipage/grouping-content.html#the-pre-element
    let markup = without_elements(&rendered, &["pre", "code", "kbd", "samp"]);
    let markup = without_elements(&markup, &["template"]);
    let copy = copy_text(&markup);
    let phrase_copy = copy.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut matches: Vec<&str> = PHRASES
        .iter()
        .filter(|(_, pattern)| pattern.is_match(&phrase_copy))
        .map(|(value, _)| *value)
        .collect();
    let lower = markup.to_ascii_lowercase();
    let image_hosts: Vec<String> = tag_slices(&markup, &lower, "img")
        .into_iter()
        .filter_map(|tag| {
            let src = url_attr_value(tag, "src")?;
            ctx.url.join(&src).ok()?.host_str().map(str::to_string)
        })
        .collect();
    for entry in &word_lists().placeholder_image_hosts {
        if image_hosts.iter().any(|host| {
            host == &entry.value
                || host
                    .strip_suffix(&entry.value)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }) {
            matches.push(&entry.value);
        }
    }
    let client_template = all_tag_slices(&ctx.html, ctx.html_lower())
        .into_iter()
        .any(|tag| {
            attributes(tag).any(|(name, _)| {
                CLIENT_MARKERS.iter().any(|(_, marker)| {
                    name == *marker
                        || name
                            .strip_prefix(marker)
                            .is_some_and(|tail| tail.starts_with(':') || tail.starts_with('.'))
                })
            })
        });
    if !client_template
        && copy.lines().any(|line| {
            line.split_once("{{")
                .is_some_and(|(_, after)| after.contains("}}"))
        })
    {
        matches.push("template braces");
    }
    let data = serde_json::json!({"count": matches.len(), "matches": matches});
    if matches.is_empty() {
        let mut result = PolishResult::clear(
            "placeholder-text",
            "Placeholder Copy",
            SignalWeight::Medium,
            SignalCategory::CopyContent,
        );
        result.data = data;
        result
    } else {
        PolishResult::fired(
            "placeholder-text",
            "Placeholder Copy",
            SignalWeight::Medium,
            SignalCategory::CopyContent,
            format!("Placeholder copy found: {}", matches.join(", ")),
            data,
        )
    }
}

fn link_labels(opening: &str, content: &str) -> Vec<String> {
    let mut labels = vec![copy_text(content)];
    let lower = content.to_ascii_lowercase();
    for tag in std::iter::once(opening).chain(all_tag_slices(content, &lower)) {
        for (name, value) in attributes(tag) {
            let accessible = name == "aria-label"
                || name == "title"
                || (name == "alt" && element_name(tag).eq_ignore_ascii_case("img"));
            if accessible {
                if let Some(value) = value {
                    labels.push(decode_quote_entities(value).trim().to_string());
                }
            }
        }
    }
    labels
}

fn dead_link(opening: &str, content: &str) -> bool {
    let Some(href) = attr_value(opening, "href") else {
        return false;
    };
    let href = decode_quote_entities(href.trim());
    if href.is_empty() || href == "#" {
        if attributes(opening).any(|(name, _)| {
            name.starts_with("on")
                || name.starts_with('@')
                || name.starts_with("x-on:")
                || name.starts_with("v-on:")
                || name.starts_with("hx-")
        }) {
            return false;
        }
        let labels = link_labels(opening, content);
        return PLATFORMS.iter().any(|platform| {
            platform
                .markers
                .iter()
                .any(|marker| labels.iter().any(|label| marker.is_match(label)))
                || platform
                    .single_names
                    .iter()
                    .any(|name| labels.iter().any(|label| label.trim() == *name))
        });
    }
    let Ok(url) = url::Url::parse(&href) else {
        return false;
    };
    if !url.path().is_empty() && url.path() != "/" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    PLATFORMS.iter().any(|platform| {
        host == platform.domain || host.strip_prefix("www.") == Some(platform.domain)
    })
}

/// Read each anchor only to its close or next opening, so malformed pages stay linear.
pub fn dead_social_links(ctx: &PolishContext) -> PolishResult {
    let markup = NON_CONTENT_BLOCK_RE.replace_all(&ctx.html, " ");
    let lower = markup.to_ascii_lowercase();
    let openings = tag_slices(&markup, &lower, "a");
    let count = openings
        .iter()
        .enumerate()
        .filter(|(index, opening)| {
            let start = slice_offset(&markup, opening) + opening.len();
            let limit = openings
                .get(index + 1)
                .map_or(markup.len(), |next| slice_offset(&markup, next));
            let content = &markup[start..limit];
            let end = ANCHOR_CLOSE_RE
                .find(content)
                .map_or(content.len(), |close| close.start());
            dead_link(opening, &content[..end])
        })
        .count();
    let data = serde_json::json!({"count":count});
    if count < DEAD_SOCIAL_LINK_MIN {
        let mut result = PolishResult::clear(
            "dead-social-links",
            "Social Links Without a Profile",
            SignalWeight::Medium,
            SignalCategory::HtmlQuality,
        );
        result.data = data;
        result
    } else {
        PolishResult::fired(
            "dead-social-links",
            "Social Links Without a Profile",
            SignalWeight::Medium,
            SignalCategory::HtmlQuality,
            format!("{count} social links go nowhere or to a platform's home page"),
            data,
        )
    }
}
