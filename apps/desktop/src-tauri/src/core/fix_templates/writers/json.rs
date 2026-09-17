//! Minimal edits to JSON platform files that leave every byte the edit does
//! not own untouched. The document is parsed only to decide; the edit itself
//! is a text insertion at a position a small scanner finds, using the file's
//! own indent unit.

use super::super::Unsupported;

fn unsupported(reason: &str) -> Unsupported {
    Unsupported {
        reason: reason.to_string(),
    }
}

/// The leading whitespace of the first indented line, or two spaces.
fn indent_unit(source: &str) -> String {
    source
        .lines()
        .skip(1)
        .find(|line| line.starts_with([' ', '\t']) && line.trim_start().starts_with('"'))
        .map(|line| line[..line.len() - line.trim_start().len()].to_string())
        .unwrap_or_else(|| "  ".to_string())
}

/// Byte offsets of the top-level `"key"` value's `[` and its matching `]`.
fn top_level_array_span(source: &str, key: &str) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let needle = format!("\"{key}\"");
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match byte {
            b'"' => {
                if depth == 1 && source[i..].starts_with(&needle) {
                    let mut j = i + needle.len();
                    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b':' {
                        j += 1;
                        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b'[' {
                            let start = j;
                            let mut level = 0_i32;
                            let mut k = j;
                            let mut inner_string = false;
                            let mut inner_escaped = false;
                            while k < bytes.len() {
                                let b = bytes[k];
                                if inner_string {
                                    if inner_escaped {
                                        inner_escaped = false;
                                    } else if b == b'\\' {
                                        inner_escaped = true;
                                    } else if b == b'"' {
                                        inner_string = false;
                                    }
                                } else {
                                    match b {
                                        b'"' => inner_string = true,
                                        b'[' => level += 1,
                                        b']' => {
                                            level -= 1;
                                            if level == 0 {
                                                return Some((start, k));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                k += 1;
                            }
                            return None;
                        }
                    }
                }
                in_string = true;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

fn rule_text(key: &str, value: &str, unit: &str, base: usize) -> String {
    let at = |n: usize| unit.repeat(base + n);
    format!(
        "{}{{\n{}\"source\": \"/(.*)\",\n{}\"headers\": [\n{}{{ \"key\": \"{key}\", \"value\": \"{value}\" }}\n{}]\n{}}}",
        at(0), at(1), at(1), at(2), at(1), at(0)
    )
}

fn already_set(document: &serde_json::Value, key: &str, value: &str) -> bool {
    document["headers"].as_array().is_some_and(|rules| {
        rules.iter().any(|rule| {
            rule["headers"].as_array().is_some_and(|headers| {
                headers.iter().any(|header| {
                    header["key"]
                        .as_str()
                        .is_some_and(|k| k.eq_ignore_ascii_case(key))
                        && header["value"]
                            .as_str()
                            .is_some_and(|v| v.eq_ignore_ascii_case(value))
                })
            })
        })
    })
}

pub fn add_vercel_header(
    source: &str,
    key: &str,
    value: &str,
) -> Result<Option<String>, Unsupported> {
    let document: serde_json::Value = serde_json::from_str(source)
        .map_err(|_| unsupported("vercel.json is not plain JSON (comments or trailing commas)"))?;
    let object = document
        .as_object()
        .ok_or_else(|| unsupported("vercel.json is not a JSON object"))?;
    if already_set(&document, key, value) {
        return Ok(None);
    }
    let unit = indent_unit(source);
    let trailing_newline = if source.ends_with('\n') { "\n" } else { "" };
    let body = source.trim_end();
    if object.contains_key("headers") {
        let (start, end) = top_level_array_span(source, "headers")
            .ok_or_else(|| unsupported("vercel.json headers is not an array"))?;
        let inner = source[start + 1..end].trim();
        let separator = if inner.is_empty() { "\n" } else { ",\n" };
        let insertion = format!("{separator}{}\n{}", rule_text(key, value, &unit, 2), unit);
        let mut edited = String::with_capacity(source.len() + insertion.len());
        edited.push_str(&source[..start + 1]);
        if inner.is_empty() {
            edited.push_str(&insertion);
        } else {
            edited.push_str(source[start + 1..end].trim_end());
            edited.push_str(&insertion);
        }
        edited.push_str(&source[end..]);
        return Ok(Some(edited));
    }
    let close = body
        .rfind('}')
        .ok_or_else(|| unsupported("vercel.json has no closing brace"))?;
    let head = body[..close].trim_end();
    let separator = if head == "{" { "\n" } else { ",\n" };
    let block = format!(
        "{}\"headers\": [\n{}\n{}]",
        unit,
        rule_text(key, value, &unit, 2),
        unit
    );
    Ok(Some(format!(
        "{head}{separator}{block}\n}}{trailing_newline}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "X-Content-Type-Options";

    #[test]
    fn inserts_a_headers_block_into_a_config_without_one() {
        let source = "{\n  \"cleanUrls\": true\n}\n";
        let after = add_vercel_header(source, KEY, "nosniff").unwrap().unwrap();
        assert_eq!(
            after,
            "{\n  \"cleanUrls\": true,\n  \"headers\": [\n    {\n      \"source\": \"/(.*)\",\n      \"headers\": [\n        { \"key\": \"X-Content-Type-Options\", \"value\": \"nosniff\" }\n      ]\n    }\n  ]\n}\n"
        );
        let parsed: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["headers"][0]["headers"][0]["value"], "nosniff");
    }

    #[test]
    fn keeps_a_four_space_indent_and_no_trailing_newline() {
        let source = "{\n    \"cleanUrls\": true\n}";
        let after = add_vercel_header(source, KEY, "nosniff").unwrap().unwrap();
        assert!(after.starts_with("{\n    \"cleanUrls\": true,\n    \"headers\": [\n        {\n"));
        assert!(after.ends_with("    ]\n}"));
    }

    #[test]
    fn appends_a_rule_to_an_existing_headers_array() {
        let source = "{\n  \"headers\": [\n    { \"source\": \"/api/(.*)\", \"headers\": [ { \"key\": \"Cache-Control\", \"value\": \"no-store\" } ] }\n  ],\n  \"cleanUrls\": true\n}\n";
        let after = add_vercel_header(source, KEY, "nosniff").unwrap().unwrap();
        assert!(after.starts_with("{\n  \"headers\": [\n    { \"source\": \"/api/(.*)\", \"headers\": [ { \"key\": \"Cache-Control\", \"value\": \"no-store\" } ] },\n    {\n      \"source\": \"/(.*)\",\n"));
        assert!(after.ends_with("  ],\n  \"cleanUrls\": true\n}\n"));
        let parsed: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["headers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn handles_an_empty_object() {
        let after = add_vercel_header("{}\n", KEY, "nosniff").unwrap().unwrap();
        assert!(after.starts_with("{\n  \"headers\": ["));
        assert!(serde_json::from_str::<serde_json::Value>(&after).is_ok());
    }

    #[test]
    fn does_nothing_when_the_header_is_already_set() {
        let source = "{ \"headers\": [ { \"source\": \"/(.*)\", \"headers\": [ { \"key\": \"x-content-type-options\", \"value\": \"NOSNIFF\" } ] } ] }";
        assert_eq!(add_vercel_header(source, KEY, "nosniff").unwrap(), None);
    }

    #[test]
    fn declines_what_it_cannot_edit_faithfully() {
        assert!(add_vercel_header("[]", KEY, "nosniff").is_err());
        assert!(add_vercel_header("{ \"headers\": {} }", KEY, "nosniff").is_err());
        assert!(add_vercel_header("{ // comment\n \"a\": 1 }", KEY, "nosniff").is_err());
    }
}
