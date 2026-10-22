//! Same-length code views: comments and literals blanked, byte offsets and
//! newlines preserved, so a match in the view points at the real source.

use super::*;

/// Return a same-length executable-code view with comments and literals blanked.
pub(in crate::core::code_scan) fn blank_non_code_for_env(file: &SourceFile) -> String {
    let lower_path = file.relative_path.to_ascii_lowercase();
    if lower_path.ends_with(".py") {
        blank_python(&file.content, true)
    } else if lower_path.ends_with(".php") {
        super::laravel_routes::blank_php(&file.content, true)
    } else if lower_path.ends_with(".rs") {
        blank_rust_non_code(&file.content)
    } else {
        js_sinks::blank_js(&file.content, true)
    }
}

/// Blank Rust comments, strings and character literals while preserving byte offsets.
pub(in crate::core::code_scan) fn blank_rust_non_code(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0;
    let blank = |out: &mut Vec<u8>, start: usize, end: usize| {
        for slot in out.iter_mut().take(end).skip(start) {
            if !slot.is_ascii_whitespace() {
                *slot = b' ';
            }
        }
    };

    while index < bytes.len() {
        if let Some(end) = rust_character_end(content, index) {
            blank(&mut out, index, end);
            index = end;
            continue;
        }
        if let Some(end) = rust_raw_string_end(bytes, index) {
            blank(&mut out, index, end);
            index = end;
            continue;
        }
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let end = content[index..]
                    .find('\n')
                    .map(|offset| index + offset)
                    .unwrap_or(bytes.len());
                blank(&mut out, index, end);
                index = end;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let mut end = index + 2;
                let mut depth = 1;
                while end < bytes.len() && depth > 0 {
                    if bytes[end..].starts_with(b"/*") {
                        depth += 1;
                        end += 2;
                    } else if bytes[end..].starts_with(b"*/") {
                        depth -= 1;
                        end += 2;
                    } else {
                        end += 1;
                    }
                }
                blank(&mut out, index, end);
                index = end;
            }
            b'"' => {
                let mut cursor = index + 1;
                while cursor < bytes.len() {
                    if bytes[cursor] == b'\\' {
                        cursor += 2;
                        continue;
                    }
                    if bytes[cursor] == b'"' {
                        cursor += 1;
                        break;
                    }
                    cursor += 1;
                }
                let end = cursor.min(bytes.len());
                blank(&mut out, index, end);
                index = end;
            }
            _ => index += 1,
        }
    }

    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

fn rust_character_end(content: &str, start: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    if bytes.get(start) != Some(&b'\'') {
        return None;
    }
    let mut cursor = start + 1;
    if bytes.get(cursor) == Some(&b'\\') {
        cursor += 1;
        match bytes.get(cursor)? {
            b'x' => {
                cursor += 1;
                for _ in 0..2 {
                    if !bytes.get(cursor)?.is_ascii_hexdigit() {
                        return None;
                    }
                    cursor += 1;
                }
            }
            b'u' if bytes.get(cursor + 1) == Some(&b'{') => {
                cursor += 2;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| byte.is_ascii_hexdigit() || *byte == b'_')
                {
                    cursor += 1;
                }
                if bytes.get(cursor) != Some(&b'}') {
                    return None;
                }
                cursor += 1;
            }
            _ => cursor += 1,
        }
    } else {
        let character = content.get(cursor..)?.chars().next()?;
        if matches!(character, '\'' | '\n' | '\r') {
            return None;
        }
        cursor += character.len_utf8();
    }
    (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
}

fn rust_raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let raw_prefix = if bytes.get(start) == Some(&b'r') {
        start
    } else if matches!(bytes.get(start), Some(b'b' | b'c')) && bytes.get(start + 1) == Some(&b'r') {
        start + 1
    } else {
        return None;
    };
    if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        return None;
    }

    let mut quote = raw_prefix + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let hash_count = quote - raw_prefix - 1;
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && (0..hash_count).all(|offset| bytes.get(cursor + 1 + offset) == Some(&b'#'))
        {
            return Some((cursor + 1 + hash_count).min(bytes.len()));
        }
        cursor += 1;
    }
    Some(bytes.len())
}

/// Blank Python comments and optionally strings while preserving UTF-8 byte
/// offsets and newlines. Sink checks use separate keyword and taint views.
pub(in crate::core::code_scan) fn blank_python(content: &str, blank_strings: bool) -> String {
    let bytes = content.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0;
    // Preserve whitespace so byte offsets and line numbers remain stable.
    let blank = |out: &mut Vec<u8>, start: usize, end: usize| {
        for slot in out.iter_mut().take(end).skip(start) {
            if !slot.is_ascii_whitespace() {
                *slot = b' ';
            }
        }
    };
    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                let end = content[index..]
                    .find('\n')
                    .map(|offset| index + offset)
                    .unwrap_or(bytes.len());
                blank(&mut out, index, end);
                index = end;
            }
            quote @ (b'\'' | b'"') => {
                // Triple-quoted string when the same quote repeats twice more.
                let is_triple =
                    bytes.get(index + 1) == Some(&quote) && bytes.get(index + 2) == Some(&quote);
                let body_start = if is_triple { index + 3 } else { index + 1 };
                let mut cursor = body_start;
                let mut close = bytes.len();
                while cursor < bytes.len() {
                    if bytes[cursor] == b'\\' {
                        cursor += 2;
                        continue;
                    }
                    if is_triple {
                        if bytes[cursor] == quote
                            && bytes.get(cursor + 1) == Some(&quote)
                            && bytes.get(cursor + 2) == Some(&quote)
                        {
                            close = cursor + 3;
                            break;
                        }
                    } else if bytes[cursor] == quote || bytes[cursor] == b'\n' {
                        // A bare newline ends an unterminated single-line string.
                        close = if bytes[cursor] == quote {
                            cursor + 1
                        } else {
                            cursor
                        };
                        break;
                    }
                    cursor += 1;
                }
                let close = close.min(bytes.len());
                // Triple-quoted strings are overwhelmingly docstrings, so always
                // blank them; single-line strings only when blank_strings is set
                // (taint inside an f-string must survive the comment-only view).
                if blank_strings || is_triple {
                    blank(&mut out, index, close);
                }
                index = close;
            }
            _ => index += 1,
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

#[cfg(test)]
mod tests {
    use super::blank_rust_non_code;

    #[test]
    fn rust_raw_c_string_preserves_following_code_and_offsets() {
        for literal in [
            r##"cr"C:\Program Files\Probe\""##,
            r##"cr#"C:\Program Files\Probe\"#"##,
        ] {
            let source = format!("const PATH: &core::ffi::CStr = {literal};\nmod helper;\n");
            let blanked = blank_rust_non_code(&source);
            let start = source.find(literal).unwrap();
            let end = start + literal.len();
            assert!(
                blanked[start..end].trim().is_empty(),
                "{literal}: {blanked}"
            );
            assert_eq!(blanked.len(), source.len());
            assert_eq!(&blanked[..start], &source[..start]);
            assert_eq!(&blanked[end..], &source[end..]);
            assert_eq!(
                blanked.match_indices('\n').collect::<Vec<_>>(),
                source.match_indices('\n').collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn rust_nested_block_comments_preserve_offsets() {
        let source =
            "fn before() {}\n/* outer /* inner */ {\ninclude!(\"hidden.rs\"); */\nfn after() {}\n";
        let blanked = blank_rust_non_code(source);
        let start = source.find("/*").unwrap();
        let end = source.rfind("*/").unwrap() + 2;
        assert!(blanked[start..end].trim().is_empty(), "{blanked}");
        assert_eq!(blanked.len(), source.len());
        assert_eq!(&blanked[..start], &source[..start]);
        assert_eq!(&blanked[end..], &source[end..]);
        assert_eq!(
            blanked.match_indices('\n').collect::<Vec<_>>(),
            source.match_indices('\n').collect::<Vec<_>>()
        );
    }
}
