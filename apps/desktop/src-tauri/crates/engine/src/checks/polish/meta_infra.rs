//! Heuristic meta-tag and infrastructure signals for Polish Scan.

use super::word_lists::{lowercase_values, word_lists};
use super::{PolishContext, PolishResult, SignalCategory, SignalWeight};
use regex::Regex;
use std::sync::LazyLock;

const CATEGORY: SignalCategory = SignalCategory::MetaInfrastructure;

static SCAFFOLD_TITLES: LazyLock<Vec<(&str, String)>> =
    LazyLock::new(|| lowercase_values(&word_lists().scaffold_titles));
static PLACEHOLDER_TITLES: LazyLock<Vec<(&str, String)>> =
    LazyLock::new(|| lowercase_values(&word_lists().placeholder_titles));
static FAVICON_VALUES: LazyLock<Vec<(&str, String)>> =
    LazyLock::new(|| lowercase_values(&word_lists().scaffold_favicons));

/// Extracts <title> content
static TITLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("title regex"));

/// Matches OG meta tags. `property=` is the spec form, but the
/// `name="og:..."` variant is common in the wild and parsers accept it
///.
static OG_TITLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s[^>]*(?:property|name)\s*=\s*["']?og:title["'\s/>]"#)
        .expect("og title regex")
});
static OG_DESC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s[^>]*(?:property|name)\s*=\s*["']?og:description["'\s/>]"#)
        .expect("og desc regex")
});
static OG_IMAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s[^>]*(?:property|name)\s*=\s*["']?og:image["'\s/>]"#)
        .expect("og image regex")
});

/// Matches favicon link tags
static FAVICON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<link\b[^>]*\brel\s*=\s*["'](?:icon|shortcut icon)["'][^>]*>"#)
        .expect("favicon regex")
});

/// A sitemap link tag (rel="sitemap" or an href ending in a sitemap xml)
static SITEMAP_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<link\s[^>]*(?:rel\s*=\s*["']?sitemap|href\s*=\s*["']?[^"'\s>]*sitemap[^"'\s>]*\.xml)"#)
        .expect("sitemap link regex")
});
/// A robots meta tag
static ROBOTS_META_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s[^>]*name\s*=\s*["']?robots["'\s/>]"#).expect("robots meta regex")
});
/// A canonical link tag
static CANONICAL_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<link\s[^>]*rel\s*=\s*["']?canonical["'\s/>]"#).expect("canonical regex")
});

/// Matches sourceMappingURL comments in inline scripts or fetchable JS
static SOURCE_MAP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"//[#@]\s*sourceMappingURL\s*=").expect("source map regex"));

/// Matches <script> elements, capturing the opening tag's attributes (group 1)
/// and the element body (group 2) separately. The body is `(.*?)` so an empty
/// element closes on its own end tag instead of swallowing the next element.
static SCRIPT_ELEMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<script(\s[^>]*)?>(.*?)</script>").expect("script element regex")
});

/// Matches a `src` attribute in a `<script>` opening tag. The attribute
/// boundary is `[\s"']`, not `\b` - a word boundary matches `data-src=` at the
/// hyphen, which would classify an inline script as external.
static SCRIPT_SRC_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:^|[\s"'])src\s*="#).expect("script src attribute regex"));

/// Matches console.log calls
static CONSOLE_LOG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"console\.(log|debug|info)\s*\(").expect("console log regex"));

/// Flag missing, empty, or framework-default titles (High, 15).
pub fn default_page_title(ctx: &PolishContext) -> PolishResult {
    let title = match TITLE_RE.captures(&ctx.html) {
        Some(cap) => cap[1].trim().to_string(),
        None => {
            return PolishResult::fired(
                "default-page-title",
                "Default Page Title",
                SignalWeight::High,
                CATEGORY,
                "No <title> tag found".to_string(),
                serde_json::json!({ "title": serde_json::Value::Null }),
            );
        }
    };

    if title.is_empty() {
        return PolishResult::fired(
            "default-page-title",
            "Default Page Title",
            SignalWeight::High,
            CATEGORY,
            "Empty <title> tag".to_string(),
            serde_json::json!({ "title": "" }),
        );
    }

    let lower = title.to_lowercase();
    // Match scaffold titles exactly; prefix matching misclassifies legitimate
    // titles that begin with common words.
    if SCAFFOLD_TITLES.iter().any(|(_, value)| lower == *value) {
        PolishResult::fired(
            "default-page-title",
            "Default Page Title",
            SignalWeight::High,
            CATEGORY,
            format!("Framework default title: \"{}\"", title),
            serde_json::json!({ "title": title, "match_kind": "framework_default" }),
        )
    } else if PLACEHOLDER_TITLES.iter().any(|(_, value)| lower == *value) {
        PolishResult::fired(
            "default-page-title",
            "Default Page Title",
            SignalWeight::High,
            CATEGORY,
            format!("Generic placeholder title: \"{}\"", title),
            serde_json::json!({ "title": title, "match_kind": "generic_placeholder" }),
        )
    } else {
        PolishResult::clear(
            "default-page-title",
            "Default Page Title",
            SignalWeight::High,
            CATEGORY,
        )
    }
}
/// Grade missing Open Graph tags more softly when the page has a partial set.
pub fn missing_og_tags(ctx: &PolishContext) -> PolishResult {
    let has_title = OG_TITLE_RE.is_match(&ctx.html);
    let has_desc = OG_DESC_RE.is_match(&ctx.html);
    let has_image = OG_IMAGE_RE.is_match(&ctx.html);

    let missing: Vec<&str> = [
        (!has_title).then_some("og:title"),
        (!has_desc).then_some("og:description"),
        (!has_image).then_some("og:image"),
    ]
    .iter()
    .filter_map(|x| *x)
    .collect();

    if missing.len() == 3 {
        PolishResult::fired(
            "missing-og-tags",
            "Missing Open Graph Tags",
            SignalWeight::Medium,
            CATEGORY,
            "No Open Graph meta tags found (og:title, og:description, og:image)".to_string(),
            serde_json::json!({
                "has_og_title": false,
                "has_og_description": false,
                "has_og_image": false,
            }),
        )
    } else if !missing.is_empty() {
        PolishResult::fired(
            "missing-og-tags",
            "Missing Open Graph Tags",
            SignalWeight::Low,
            CATEGORY,
            format!("Missing: {}", missing.join(", ")),
            serde_json::json!({
                "has_og_title": has_title,
                "has_og_description": has_desc,
                "has_og_image": has_image,
                "missing": missing,
            }),
        )
    } else {
        PolishResult::clear(
            "missing-og-tags",
            "Missing Open Graph Tags",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}
/// Detect exact framework scaffold icons in favicon link tags.
pub fn default_favicon(ctx: &PolishContext) -> PolishResult {
    if FAVICON_RE.is_match(&ctx.html) {
        // `/favicon.ico` is conventional; only exact scaffold SVGs count.
        let default_marker = FAVICON_RE.find_iter(&ctx.html).find_map(|link_tag| {
            let tag_lower = link_tag.as_str().to_lowercase();
            FAVICON_VALUES
                .iter()
                .find(|(_, icon)| tag_lower.contains(icon))
                .map(|(original, _)| *original)
        });

        if let Some(marker) = default_marker {
            PolishResult::fired(
                "default-favicon",
                "Default Favicon",
                SignalWeight::Medium,
                CATEGORY,
                format!("Favicon link points at framework scaffold icon {}", marker),
                serde_json::json!({ "is_default": true, "marker": marker }),
            )
        } else {
            PolishResult::clear(
                "default-favicon",
                "Default Favicon",
                SignalWeight::Medium,
                CATEGORY,
            )
        }
    } else {
        // Browsers may load `/favicon.ico` without a link tag, which this check cannot observe.
        PolishResult::clear(
            "default-favicon",
            "Default Favicon",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}
/// Detect absence of canonical, robots-meta, and sitemap-link markers.
pub fn no_sitemap_robots(ctx: &PolishContext) -> PolishResult {
    let lower = ctx.html_lower();
    let has_sitemap_link = SITEMAP_LINK_RE.is_match(lower);
    let has_robots_meta = ROBOTS_META_RE.is_match(lower);
    let has_canonical = CANONICAL_LINK_RE.is_match(lower);

    if !has_sitemap_link && !has_robots_meta && !has_canonical {
        PolishResult::fired(
            "no-sitemap-robots",
            "Page-Level SEO Markers",
            SignalWeight::Low,
            CATEGORY,
            "No page-level SEO markers found (canonical link, robots meta, or sitemap link)"
                .to_string(),
            serde_json::json!({
                "has_sitemap_link": false,
                "has_robots_meta": false,
                "has_canonical": false,
            }),
        )
    } else {
        PolishResult::clear(
            "no-sitemap-robots",
            "Page-Level SEO Markers",
            SignalWeight::Low,
            CATEGORY,
        )
    }
}
/// Detect source-map references without claiming the map file is reachable.
pub fn source_maps_production(ctx: &PolishContext) -> PolishResult {
    let count = SOURCE_MAP_RE.find_iter(&ctx.html).count();

    if count > 0 {
        PolishResult::fired(
            "source-maps-production",
            "Source Maps in Production",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{} sourceMappingURL reference{} in served JavaScript; the referenced .map file{} not verified as accessible",
                count,
                if count != 1 { "s" } else { "" },
                if count != 1 { "s were" } else { " was" }
            ),
            serde_json::json!({ "source_map_count": count }),
        )
    } else {
        PolishResult::clear(
            "source-maps-production",
            "Source Maps in Production",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

/// Flag two or more console calls in inline scripts (Medium, 8).
pub fn console_log_production(ctx: &PolishContext) -> PolishResult {
    let mut total_console = 0usize;

    // Check inline script blocks. "External" is decided from the opening tag's
    // own attributes; reading the whole match would let a `src` in the body (or
    // in a neighbouring element) hide an inline script.
    for cap in SCRIPT_ELEMENT_RE.captures_iter(&ctx.html) {
        let opening_attrs = cap.get(1).map_or("", |m| m.as_str());
        if SCRIPT_SRC_ATTR_RE.is_match(opening_attrs) {
            continue;
        }
        let script_body = &cap[2];
        total_console += CONSOLE_LOG_RE.find_iter(script_body).count();
    }

    if total_console >= 2 {
        PolishResult::fired(
            "console-log-production",
            "Console.log in Production",
            SignalWeight::Medium,
            CATEGORY,
            format!(
                "{} console.log/debug/info call{} in inline scripts",
                total_console,
                if total_console != 1 { "s" } else { "" }
            ),
            serde_json::json!({ "console_log_count": total_console }),
        )
    } else {
        PolishResult::clear(
            "console-log-production",
            "Console.log in Production",
            SignalWeight::Medium,
            CATEGORY,
        )
    }
}

#[cfg(test)]
mod tests;
