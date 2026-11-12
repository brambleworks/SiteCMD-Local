//! Shared exclusions for markup that represents code rather than page content.

use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

// technical vocabulary: https://html.spec.whatwg.org/multipage/indices.html#elements-3
static ELEMENT_PATTERNS: LazyLock<HashMap<&'static str, Regex>> = LazyLock::new(|| {
    ["pre", "code", "kbd", "samp", "template"]
        .into_iter()
        .map(|name| {
            let pattern = Regex::new(&format!(
                r"(?s)<(?i-u:{name})(?:\s[^>]*)?>.*?</(?i-u:{name})\s*>"
            ))
            .expect("static element name regex");
            (name, pattern)
        })
        .collect()
});

/// Read the element name from a shared-tokenizer opening tag.
pub(super) fn element_name(tag: &str) -> &str {
    tag.strip_prefix('<')
        .unwrap_or(tag)
        .split(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
        .next()
        .unwrap_or("")
}

/// Replace each complete named element, including its contents, with one space.
/// Nested, self-closing, and script-embedded elements are outside this textual removal's scope.
pub(super) fn without_elements<'a>(html: &'a str, names: &[&str]) -> Cow<'a, str> {
    let mut result = Cow::Borrowed(html);
    for name in names {
        let pattern = ELEMENT_PATTERNS.get(name).expect("supported element name");
        if let Cow::Owned(replaced) = pattern.replace_all(&result, " ") {
            result = Cow::Owned(replaced);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::without_elements;

    #[test]
    fn unicode_element_names_are_not_ascii_aliases() {
        // Unicode case folding removes non-HTML element names as ASCII elements.
        let html = "<ſamp>x</ſamp><Kbd>y</Kbd>";
        assert_eq!(without_elements(html, &["samp", "kbd"]), html);
        assert_eq!(
            without_elements("<SAMP>x</SAMP><KBD>y</KBD>", &["samp", "kbd"]),
            "  "
        );
    }
}
