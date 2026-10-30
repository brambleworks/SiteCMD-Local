//! Shared tokenizer for quoted, unquoted, and boolean HTML attributes.

static URL_CHARACTER_REFERENCE_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)&(?:#x([0-9a-f]{1,6})|#([0-9]{1,7})|([a-z]+));")
            .expect("static URL character-reference regex")
    });

fn is_html_whitespace(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\x0c' | '\r' | ' ')
}

/// Decode character references before classifying browser-facing URLs.
pub fn decode_url_character_references(value: &str) -> String {
    URL_CHARACTER_REFERENCE_RE
        .replace_all(value, |captures: &regex::Captures<'_>| {
            let numeric = captures
                .get(1)
                .and_then(|value| u32::from_str_radix(value.as_str(), 16).ok())
                .or_else(|| {
                    captures
                        .get(2)
                        .and_then(|value| value.as_str().parse::<u32>().ok())
                });
            if let Some(value) = numeric.and_then(char::from_u32) {
                return value.to_string();
            }
            captures
                .get(3)
                .map(|value| value.as_str().to_ascii_lowercase())
                .and_then(|name| {
                    Some(match name.as_str() {
                        "amp" => '&',
                        "apos" => '\'',
                        "colon" => ':',
                        "comma" => ',',
                        "commat" => '@',
                        "equals" => '=',
                        "num" => '#',
                        "percnt" => '%',
                        "period" => '.',
                        "quest" => '?',
                        "quot" => '"',
                        "semi" => ';',
                        "sol" => '/',
                        _ => return None,
                    })
                })
                .map(|value| value.to_string())
                .unwrap_or_else(|| captures[0].to_string())
        })
        .into_owned()
}

/// Byte offset of a slice borrowed from `body`. `tag_slices` and
/// `raw_text_elements` return borrows, so this is how a caller turns one back
/// into a document position for line numbers or containment tests.
///
/// The slice must come from `body`. A foreign slice has no position in this
/// document, and silently answering 0 would put it at the start of the page;
/// debug builds assert instead so the misuse is loud in tests.
pub fn slice_offset(body: &str, slice: &str) -> usize {
    let start = body.as_ptr() as usize;
    let offset = slice.as_ptr() as usize;
    debug_assert!(
        offset >= start && offset + slice.len() <= start + body.len(),
        "slice_offset was given a slice that does not belong to body"
    );
    offset.saturating_sub(start)
}

/// Read an attribute whose value is a URL the browser will request: `src`,
/// `srcset`, `href`, `action`, and a URL-valued `meta content`. The raw
/// attribute text is HTML, so `&amp;` there is one `&` on the wire; a check
/// that fetches or classifies the raw text asks for a URL the browser never
/// requests (`/_image?href=x&amp;w=256` answered 400 on astro.build while the
/// decoded form answered 200). Returns `None` for a missing attribute and for
/// one whose value is empty or whitespace, since neither names a resource.
pub fn url_attr_value(tag: &str, name: &str) -> Option<String> {
    let value = attr_value(tag, name)?;
    let trimmed = value.trim_matches(is_html_whitespace);
    if trimmed.is_empty() {
        return None;
    }
    Some(decode_url_character_references(trimmed))
}

/// Slice every `<{tag_name}...>` open tag out of `body`, matching the tag
/// name case-insensitively and requiring a real tag boundary so `<img`
/// never matches `<imgfoo`. Returned slices keep original casing and
/// include the angle brackets.
pub fn tag_slices<'a>(body: &'a str, lower: &str, tag_name: &str) -> Vec<&'a str> {
    let target = tag_name.to_ascii_lowercase();
    opening_tag_slices_impl(body, lower, Some(&target))
}

/// Return real opening tags, excluding non-markup and raw-text/RCDATA content.
pub fn all_tag_slices<'a>(body: &'a str, lower: &str) -> Vec<&'a str> {
    opening_tag_slices_impl(body, lower, None)
}

fn opening_tag_slices_impl<'a>(body: &'a str, lower: &str, target: Option<&str>) -> Vec<&'a str> {
    let owned_lower = (body.len() != lower.len()).then(|| body.to_ascii_lowercase());
    let lower = owned_lower.as_deref().unwrap_or(lower);
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(found) = lower[pos..].find('<') {
        let abs = pos + found;

        if lower[abs..].starts_with("<!--") {
            pos = lower[abs + 4..]
                .find("-->")
                .map(|end| abs + 4 + end + 3)
                .unwrap_or(body.len());
            continue;
        }

        let bytes = lower.as_bytes();
        let Some(first) = bytes.get(abs + 1).copied() else {
            break;
        };
        if matches!(first, b'!' | b'?' | b'/') {
            pos = tag_end_offset(&body[abs..])
                .map(|end| abs + end + 1)
                .unwrap_or(body.len());
            continue;
        }
        if !first.is_ascii_alphabetic() {
            pos = abs + 1;
            continue;
        }

        let name_start = abs + 1;
        let mut name_end = name_start;
        while name_end < bytes.len()
            && !is_html_whitespace(bytes[name_end].into())
            && !matches!(bytes[name_end], b'/' | b'>')
        {
            name_end += 1;
        }
        let element_name = &lower[name_start..name_end];
        let Some(tag_end) = tag_end_offset(&body[abs..]).map(|end| abs + end) else {
            break;
        };
        if target.is_none_or(|target| element_name == target) {
            out.push(&body[abs..=tag_end]);
        }

        let opening_without_close = body[abs..tag_end].trim_end_matches(is_html_whitespace);
        let self_closing = opening_without_close.ends_with('/');
        pos = tag_end + 1;
        if !self_closing && is_raw_text_or_rcdata_element(element_name) {
            if element_name == "plaintext" {
                pos = body.len();
            } else {
                pos = raw_text_element_end(body, lower, pos, element_name);
            }
        }
    }
    out
}

/// Content inside these HTML elements is text, not nested markup. Treating
/// tag-looking examples in JavaScript, CSS, titles, or textareas as real DOM
/// elements creates false findings across every source check that shares this
/// tokenizer.
fn is_raw_text_or_rcdata_element(name: &str) -> bool {
    matches!(
        name,
        "script"
            | "style"
            | "title"
            | "textarea"
            | "xmp"
            | "iframe"
            | "noembed"
            | "noframes"
            | "plaintext"
    )
}

/// Return raw-text/RCDATA contents while excluding inert examples through the
/// shared tokenizer.
pub fn raw_text_element_contents<'a>(body: &'a str, lower: &str, tag_name: &str) -> Vec<&'a str> {
    raw_text_elements(body, lower, tag_name)
        .into_iter()
        .map(|(_, content)| content)
        .collect()
}

/// Return each real raw-text/RCDATA opening tag together with its source
/// content. The opening tag lets callers honor attributes such as a script's
/// MIME `type` while retaining the tokenizer's inert-example filtering.
pub fn raw_text_elements<'a>(
    body: &'a str,
    lower: &str,
    tag_name: &str,
) -> Vec<(&'a str, &'a str)> {
    let target = tag_name.to_ascii_lowercase();
    if !is_raw_text_or_rcdata_element(&target) || target == "plaintext" {
        return Vec::new();
    }
    let owned_lower = (body.len() != lower.len()).then(|| body.to_ascii_lowercase());
    let lower = owned_lower.as_deref().unwrap_or(lower);

    tag_slices(body, lower, &target)
        .into_iter()
        .map(|opening| {
            let content_start = opening.as_ptr() as usize - body.as_ptr() as usize + opening.len();
            let content_end =
                raw_text_close_start(lower, content_start, &target).unwrap_or(body.len());
            (opening, &body[content_start..content_end])
        })
        .collect()
}

fn raw_text_close_start(lower: &str, from: usize, element_name: &str) -> Option<usize> {
    let close = format!("</{element_name}");
    let mut cursor = from;
    while let Some(relative) = lower[cursor..].find(&close) {
        let start = cursor + relative;
        let after_name = start + close.len();
        let boundary = lower.as_bytes().get(after_name).copied();
        if boundary
            .is_some_and(|byte| is_html_whitespace(byte.into()) || matches!(byte, b'/' | b'>'))
        {
            return Some(start);
        }
        cursor = after_name;
    }
    None
}

fn raw_text_element_end(body: &str, lower: &str, from: usize, element_name: &str) -> usize {
    let Some(start) = raw_text_close_start(lower, from, element_name) else {
        return body.len();
    };
    tag_end_offset(&body[start..])
        .map(|end| start + end + 1)
        .unwrap_or(body.len())
}

/// Find the closing `>` without treating quoted values as tag boundaries.
fn tag_end_offset(tag_and_rest: &str) -> Option<usize> {
    enum State {
        BeforeName,
        Name,
        BeforeValue,
        Unquoted,
        Quoted(u8),
    }

    let region = attr_region(tag_and_rest);
    let offset = tag_and_rest.len() - region.len();
    let mut state = State::BeforeName;
    for (index, byte) in region.bytes().enumerate() {
        match state {
            State::Quoted(active) if byte == active => state = State::BeforeName,
            State::Quoted(_) => {}
            _ if byte == b'>' => return Some(offset + index),
            State::BeforeValue if is_html_whitespace(byte.into()) => {}
            State::BeforeValue if matches!(byte, b'"' | b'\'') => state = State::Quoted(byte),
            State::BeforeValue => state = State::Unquoted,
            State::Unquoted if is_html_whitespace(byte.into()) => state = State::BeforeName,
            State::Unquoted => {}
            State::Name if byte == b'=' => state = State::BeforeValue,
            State::Name if byte == b'/' => state = State::BeforeName,
            State::Name => {}
            State::BeforeName if !is_html_whitespace(byte.into()) && byte != b'/' => {
                state = State::Name
            }
            State::BeforeName => {}
        }
    }
    None
}

/// Read the first case-insensitive attribute while preserving value case.
/// Boolean and explicitly empty attributes both return `Some("")`.
pub fn attr_value(tag: &str, name: &str) -> Option<String> {
    let target = name.to_ascii_lowercase();
    Attributes {
        rest: attr_region(tag),
    }
    .find(|(attr, _)| *attr == target)
    .map(|(_, value)| value.unwrap_or("").to_string())
}

/// Whether attribute `name` is present on `tag` at all, with or without a
/// value. Same input and name-matching rules as `attr_value`.
pub fn has_attr(tag: &str, name: &str) -> bool {
    let target = name.to_ascii_lowercase();
    Attributes {
        rest: attr_region(tag),
    }
    .any(|(attr, _)| attr == target)
}

/// Skip a leading `<tagname` (and closing-tag slash) so callers can pass
/// either a full tag or a pre-captured attribute region.
fn attr_region(tag: &str) -> &str {
    let Some(rest) = tag.strip_prefix('<') else {
        return tag;
    };
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    let bytes = rest.as_bytes();
    let mut i = 0;
    // ASCII delimiters never occur inside multi-byte UTF-8 sequences, so
    // every stop position is a char boundary.
    while i < bytes.len()
        && !is_html_whitespace(bytes[i].into())
        && !matches!(bytes[i], b'/' | b'>')
    {
        i += 1;
    }
    &rest[i..]
}

/// Iterator over `(lowercased name, value)` pairs of an attribute region.
/// `None` values are boolean attributes.
struct Attributes<'a> {
    rest: &'a str,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = (String, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let bytes = self.rest.as_bytes();
            let mut i = 0;
            // Skip whitespace and self-closing slashes between attributes.
            while i < bytes.len() && (is_html_whitespace(bytes[i].into()) || bytes[i] == b'/') {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] == b'>' {
                self.rest = "";
                return None;
            }
            // Attribute name runs to whitespace, `=`, `/`, or `>`.
            let name_start = i;
            while i < bytes.len()
                && !is_html_whitespace(bytes[i].into())
                && !matches!(bytes[i], b'=' | b'/' | b'>')
            {
                i += 1;
            }
            if i == name_start {
                // Stray `=` with no name; skip it and keep scanning.
                self.rest = &self.rest[i + 1..];
                continue;
            }
            let name = self.rest[name_start..i].to_ascii_lowercase();
            // Optional whitespace around `=`.
            let mut j = i;
            while j < bytes.len() && is_html_whitespace(bytes[j].into()) {
                j += 1;
            }
            if j >= bytes.len() || bytes[j] != b'=' {
                // Boolean attribute; resume after the name.
                self.rest = &self.rest[i..];
                return Some((name, None));
            }
            j += 1;
            while j < bytes.len() && is_html_whitespace(bytes[j].into()) {
                j += 1;
            }
            if j >= bytes.len() || bytes[j] == b'>' {
                self.rest = "";
                return Some((name, Some("")));
            }
            let (value, resume) = match bytes[j] {
                quote @ (b'"' | b'\'') => {
                    let start = j + 1;
                    match bytes[start..].iter().position(|b| *b == quote) {
                        Some(len) => (&self.rest[start..start + len], start + len + 1),
                        // Unterminated quote: the rest of the tag is the value.
                        None => (&self.rest[start..], bytes.len()),
                    }
                }
                _ => {
                    let mut k = j;
                    while k < bytes.len()
                        && !is_html_whitespace(bytes[k].into())
                        && bytes[k] != b'>'
                    {
                        k += 1;
                    }
                    (&self.rest[j..k], k)
                }
            };
            self.rest = &self.rest[resume.min(bytes.len())..];
            return Some((name, Some(value)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{attr_value, has_attr, raw_text_element_contents, tag_slices, url_attr_value};

    #[test]
    fn url_attributes_are_decoded_to_what_the_browser_requests() {
        assert_eq!(
            url_attr_value(
                r#"<img src="/_image?href=%2Fa.png&amp;w=256&amp;f=webp">"#,
                "src"
            )
            .as_deref(),
            Some("/_image?href=%2Fa.png&w=256&f=webp")
        );
        assert_eq!(
            url_attr_value(r#"<a href="/search?q=1&#38;page=2">"#, "href").as_deref(),
            Some("/search?q=1&page=2")
        );
        assert_eq!(
            url_attr_value(r#"<img srcset="/a.png?w=1&amp;h=2 1x">"#, "srcset").as_deref(),
            Some("/a.png?w=1&h=2 1x")
        );
    }

    #[test]
    fn a_missing_or_blank_url_attribute_names_no_resource() {
        assert_eq!(url_attr_value("<img alt=x>", "src"), None);
        assert_eq!(url_attr_value(r#"<img src="">"#, "src"), None);
        assert_eq!(url_attr_value(r#"<img src="   ">"#, "src"), None);
        assert_eq!(url_attr_value("<img src>", "src"), None);
    }

    #[test]
    fn url_attribute_values_keep_percent_encoding_and_casing() {
        // Percent-escapes belong to the URL, not to HTML, so they survive.
        assert_eq!(
            url_attr_value(r#"<img src="/Photos/IMG%202024.JPG">"#, "src").as_deref(),
            Some("/Photos/IMG%202024.JPG")
        );
    }

    #[test]
    fn double_quoted_value_is_extracted() {
        assert_eq!(
            attr_value(r#"<img src="a.png" alt="hero">"#, "src").as_deref(),
            Some("a.png")
        );
    }

    #[test]
    fn single_quoted_value_is_extracted() {
        assert_eq!(
            attr_value("<img src='a.png'>", "src").as_deref(),
            Some("a.png")
        );
    }

    #[test]
    fn unquoted_value_ends_at_whitespace_or_tag_close() {
        assert_eq!(
            attr_value("<img src=a.png alt=x>", "src").as_deref(),
            Some("a.png")
        );
        assert_eq!(
            attr_value("<img loading=lazy>", "loading").as_deref(),
            Some("lazy")
        );
    }

    #[test]
    fn boolean_and_explicitly_empty_attributes_return_empty_string() {
        assert_eq!(attr_value("<img alt src=x>", "alt").as_deref(), Some(""));
        assert_eq!(
            attr_value(r#"<img alt="" src=x>"#, "alt").as_deref(),
            Some("")
        );
        assert!(has_attr("<script async src=x>", "async"));
    }

    #[test]
    fn missing_attribute_is_none() {
        assert_eq!(attr_value("<img src=x>", "alt"), None);
        assert!(!has_attr("<img src=x>", "alt"));
    }

    #[test]
    fn first_occurrence_wins_on_duplicates() {
        assert_eq!(
            attr_value(r#"<img src="first.png" src="second.png">"#, "src").as_deref(),
            Some("first.png")
        );
    }

    #[test]
    fn name_matching_is_case_insensitive_and_value_casing_kept() {
        assert_eq!(
            attr_value(r#"<IMG SRC="CamelCase.PNG">"#, "src").as_deref(),
            Some("CamelCase.PNG")
        );
    }

    #[test]
    fn prefixed_attribute_never_satisfies_the_base_name() {
        assert_eq!(attr_value(r#"<img data-src="lazy.png">"#, "src"), None);
        assert!(!has_attr(r#"<div data-onclick="x">"#, "onclick"));
    }

    #[test]
    fn text_inside_another_attributes_value_never_matches() {
        assert_eq!(
            attr_value(r#"<img alt="src=evil.png explained">"#, "src"),
            None
        );
        assert_eq!(
            attr_value(
                r#"<img alt="loading=lazy explained" src="real.png">"#,
                "src"
            )
            .as_deref(),
            Some("real.png")
        );
    }

    #[test]
    fn whitespace_around_equals_is_tolerated() {
        assert_eq!(
            attr_value("<link rel = \"icon\" href = /favicon.svg>", "href").as_deref(),
            Some("/favicon.svg")
        );
    }

    #[test]
    fn full_tag_and_attribute_region_inputs_agree() {
        assert_eq!(
            attr_value(r#"<a href="/x">"#, "href"),
            attr_value(r#" href="/x""#, "href")
        );
    }

    #[test]
    fn self_closing_tags_parse_cleanly() {
        assert_eq!(
            attr_value("<img src=a.png />", "src").as_deref(),
            Some("a.png")
        );
        assert!(!has_attr("<br/>", "src"));
    }

    #[test]
    fn unterminated_quote_takes_the_rest_of_the_tag() {
        assert_eq!(
            attr_value(r#"<img src="broken.png>"#, "src").as_deref(),
            Some("broken.png>")
        );
    }

    #[test]
    fn non_ascii_values_and_names_do_not_panic() {
        assert_eq!(
            attr_value(r#"<img alt="café ☕" src=x>"#, "alt").as_deref(),
            Some("café ☕")
        );
        assert_eq!(
            attr_value("<img données=oui src=x>", "src").as_deref(),
            Some("x")
        );
    }

    #[test]
    fn tag_slices_requires_a_real_tag_boundary() {
        let body = r#"<imgfoo src=no><img src=yes><IMG src=also>"#;
        let lower = body.to_ascii_lowercase();
        let tags = tag_slices(body, &lower, "img");
        assert_eq!(tags, vec!["<img src=yes>", "<IMG src=also>"]);
    }

    #[test]
    fn tag_slices_does_not_end_at_greater_than_inside_a_quoted_value() {
        let body = r#"<a title="1 > 0" href="/correct">link</a>"#;
        let lower = body.to_ascii_lowercase();
        let tags = tag_slices(body, &lower, "a");
        assert_eq!(tags, vec![r#"<a title="1 > 0" href="/correct">"#]);
        assert_eq!(attr_value(tags[0], "href").as_deref(), Some("/correct"));
    }

    #[test]
    fn tag_slices_ignores_commented_out_markup() {
        let body = r#"<!-- <img src="commented.png"> --><img src="real.png">"#;
        let lower = body.to_ascii_lowercase();
        assert_eq!(
            tag_slices(body, &lower, "img"),
            vec![r#"<img src="real.png">"#]
        );
    }

    #[test]
    fn tag_slices_ignores_tag_text_inside_raw_text_and_rcdata_elements() {
        let body = r#"<script>const example = '<img src="script.png">';</script>
            <style>.x::after { content: '<img src="style.png">'; }</style>
            <title>Documentation for <img src="title.png"></title>
            <textarea><img src="textarea.png"></textarea>
            <img src="real.png">"#;
        let lower = body.to_ascii_lowercase();

        assert_eq!(
            tag_slices(body, &lower, "img"),
            vec![r#"<img src="real.png">"#]
        );
        assert_eq!(tag_slices(body, &lower, "script").len(), 1);
        assert_eq!(tag_slices(body, &lower, "style").len(), 1);
    }

    #[test]
    fn raw_text_contents_returns_only_real_element_bodies() {
        let body = r#"<!-- <script>console.log('comment')</script> -->
            <script data-test="1 > 0">console.log('real')</script>
            <style>.hero { background: url(http://cdn.example.com/hero.png) }</style>"#;
        let lower = body.to_ascii_lowercase();

        assert_eq!(
            raw_text_element_contents(body, &lower, "script"),
            vec!["console.log('real')"]
        );
        assert_eq!(
            raw_text_element_contents(body, &lower, "style"),
            vec![".hero { background: url(http://cdn.example.com/hero.png) }"]
        );
    }

    #[test]
    fn stray_quotes_cannot_hide_following_tags_or_raw_text() {
        for earlier in [
            r#"<div broken">"#,
            "<div broken'>",
            r#"<div data-x=broken">"#,
            "<div data-x=broken'>",
        ] {
            let body =
                format!("{earlier}<meta name=generator content=Framer><script>payload</script>");
            let lower = body.to_ascii_lowercase();
            assert_eq!(
                tag_slices(&body, &lower, "meta"),
                ["<meta name=generator content=Framer>"],
                "{earlier}"
            );
            assert_eq!(super::all_tag_slices(&body, &lower).len(), 3, "{earlier}");
            assert_eq!(
                raw_text_element_contents(&body, &lower, "script"),
                ["payload"],
                "{earlier}"
            );
        }
    }

    #[test]
    fn a_nameless_equals_cannot_open_a_quoted_attribute_value() {
        let body = r#"<div ="x>"><meta name=generator content=Framer>"#;
        assert_eq!(
            super::all_tag_slices(body, &body.to_ascii_lowercase()),
            [r#"<div ="x>"#, "<meta name=generator content=Framer>"]
        );
    }

    #[test]
    fn a_second_equals_cannot_extend_a_tag_as_a_quoted_value() {
        let body = r#"<a b==" >"><meta name=generator content=Framer>"#;
        assert_eq!(
            super::all_tag_slices(body, &body.to_ascii_lowercase()),
            [r#"<a b==" >"#, "<meta name=generator content=Framer>"]
        );
    }

    #[test]
    fn html_form_feeds_cannot_hide_tags_or_merge_attributes() {
        for whitespace in ["\x0c", "\t", "\n", "\r", " "] {
            let tag = format!(
                "<a{whitespace}href=\"x>y\"{whitespace}target{whitespace}={whitespace}_blank{whitespace}download>"
            );
            assert_eq!(super::tag_end_offset(&tag), Some(tag.len() - 1));
            assert_eq!(
                tag_slices(&tag, &tag.to_ascii_lowercase(), "a"),
                [tag.as_str()]
            );
            assert_eq!(
                super::all_tag_slices(&tag, &tag.to_ascii_lowercase()),
                [tag.as_str()]
            );
            assert_eq!(attr_value(&tag, "href").as_deref(), Some("x>y"));
            assert_eq!(attr_value(&tag, "target").as_deref(), Some("_blank"));
            assert!(has_attr(&tag, "download"));
            let url = format!("<a href=\"{whitespace}/asset{whitespace}\">");
            assert_eq!(url_attr_value(&url, "href").as_deref(), Some("/asset"));
        }
    }

    #[test]
    fn html_form_feeds_cannot_hide_raw_text_opening_or_closing_tags() {
        for whitespace in ["\x0c", "\t", "\n", "\r", " "] {
            let body = format!(
                "<script{whitespace}type=\"application/json\">payload</script{whitespace}><img src=real>"
            );
            let lower = body.to_ascii_lowercase();
            assert_eq!(
                raw_text_element_contents(&body, &lower, "script"),
                ["payload"]
            );
            assert_eq!(tag_slices(&body, &lower, "img"), ["<img src=real>"]);
        }
    }

    #[test]
    fn non_html_whitespace_cannot_be_trimmed_or_make_raw_text_self_closing() {
        for whitespace in ["\x0b", "\u{a0}", "\u{2003}"] {
            let value = format!("{whitespace}/asset{whitespace}");
            let tag = format!("<a href=\"{value}\">");
            assert_eq!(url_attr_value(&tag, "href"), Some(value));
            let body = format!("<script/{whitespace}><img src=hidden></script><img src=real>");
            assert_eq!(
                tag_slices(&body, &body.to_ascii_lowercase(), "img"),
                ["<img src=real>"]
            );
            let tag = format!("<a{whitespace}href=x>");
            assert!(tag_slices(&tag, &tag.to_ascii_lowercase(), "a").is_empty());
        }
    }
}
