use std::{borrow::Cow, collections::HashMap, sync::LazyLock};

use icu_properties::{props::DefaultIgnorableCodePoint, CodePointSetData};
use percent_encoding::percent_decode_str;
use regex::Regex;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};
use unicode_security::skeleton;

const MAX_DECODE_PASSES: usize = 4;

static HTML_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)</?[a-z][a-z0-9-]*(?:[ \t\x0b\x0c\r\n]+[a-z_:][a-z0-9_.:-]*(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*\s*/?>"#,
    )
    .expect("inline HTML tag regex")
});
static HTML_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").expect("inline HTML comment regex"));

pub(super) fn text_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split(['\n', '\r', '\x0b', '\x0c', '\u{85}', '\u{2028}', '\u{2029}'])
}

pub(super) fn fingerprints(line: &str) -> impl Iterator<Item = String> {
    let decoded = decode(line);
    let plain = normalize(&decoded, false);
    // A Hangul filler can stand in for a space as well as being invisible inside a word.
    let spaced = decoded
        .chars()
        .any(hangul_filler)
        .then(|| normalize(&decoded, true));
    plain
        .into_iter()
        .chain(spaced.into_iter().flatten())
        .flatten()
}

fn decode(line: &str) -> Cow<'_, str> {
    let mut decoded = Cow::Borrowed(line);
    for _ in 0..MAX_DECODE_PASSES {
        let url = if decoded.contains('%') {
            percent_decode_str(&decoded).decode_utf8_lossy()
        } else {
            Cow::Borrowed(decoded.as_ref())
        };
        let html = if url.contains('&') {
            htmlize::unescape(url.as_ref())
        } else {
            Cow::Borrowed(url.as_ref())
        };
        if html == decoded {
            return decoded;
        }
        decoded = Cow::Owned(html.into_owned());
    }
    decoded
}

fn normalize(line: &str, space_for_filler: bool) -> [Option<String>; 2] {
    let cleaned = if line.is_ascii() && !line.contains('\0') {
        Cow::Borrowed(line)
    } else {
        let ignorable = CodePointSetData::new::<DefaultIgnorableCodePoint>();
        Cow::Owned(
            line.chars()
                .filter_map(|ch| {
                    if space_for_filler && hangul_filler(ch) {
                        Some(' ')
                    } else {
                        (ch != '\0' && !ignorable.contains(ch)).then_some(ch)
                    }
                })
                // Skeleton non-ASCII characters before NFKD diverts confusables such as U+03F2.
                .flat_map(|ch| {
                    let mut buf = [0u8; 4];
                    if ch.is_ascii() {
                        vec![ch]
                    } else {
                        skeleton(ch.encode_utf8(&mut buf)).collect()
                    }
                })
                .nfkd()
                .filter(|&ch| !is_combining_mark(ch))
                .collect(),
        )
    };
    let unescaped = if cleaned.contains('\\') {
        Cow::Owned(unescape_punctuation(&cleaned))
    } else {
        Cow::Borrowed(cleaned.as_ref())
    };
    let line = strip_markdown(&unescaped);
    let literal = fold(line);
    if !line.contains(['<', '[']) {
        return [Some(literal), None];
    }
    let visible = if line.contains("<!--") {
        HTML_COMMENT.replace_all(line, "")
    } else {
        Cow::Borrowed(line)
    };
    let visible = if visible.contains('<') {
        HTML_TAG.replace_all(&visible, "")
    } else {
        Cow::Borrowed(visible.as_ref())
    };
    let visible = strip_links(&visible);
    let visible = fold(strip_markdown(&visible));
    [
        Some(literal.clone()),
        (visible != literal).then_some(visible),
    ]
}

fn fold(line: &str) -> String {
    let unmarked: String = line
        .chars()
        .filter(|ch| !matches!(ch, '*' | '_' | '`' | '~'))
        .collect();
    // Take the skeleton before lowercasing to retain uppercase confusable mappings.
    let lower: String = skeleton(&unmarked).flat_map(char::to_lowercase).collect();
    let mut folded = String::with_capacity(lower.len());
    let mut space = false;
    for ch in skeleton(&lower)
        .flat_map(char::to_lowercase)
        .filter(|&ch| !is_combining_mark(ch))
    {
        if ch.is_whitespace() {
            space = !folded.is_empty();
        } else {
            if space {
                folded.push(' ');
                space = false;
            }
            folded.push(if ch == 'i' { 'l' } else { ch });
        }
    }
    folded
}

fn unescape_punctuation(line: &str) -> String {
    let mut unescaped = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' || !chars.peek().is_some_and(char::is_ascii_punctuation) {
            unescaped.push(ch);
        } else if let Some(punctuation) = chars.next() {
            unescaped.push(punctuation);
        }
    }
    unescaped
}

fn hangul_filler(ch: char) -> bool {
    matches!(ch, '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}')
}

fn strip_links(line: &str) -> Cow<'_, str> {
    if !line.contains("](") && !line.contains("][") {
        return Cow::Borrowed(line);
    }
    let mut ends = HashMap::new();
    let mut brackets = Vec::new();
    let mut parentheses = Vec::new();
    for (index, delimiter) in line.match_indices(['[', ']', '(', ')']) {
        let start = match delimiter {
            "[" => {
                brackets.push(index);
                continue;
            }
            "(" => {
                parentheses.push(index);
                continue;
            }
            "]" => brackets.pop(),
            _ => parentheses.pop(),
        };
        if let Some(start) = start {
            ends.insert(start, index);
        }
    }

    let mut plain = String::new();
    let mut cursor = 0;
    for (start, _) in line.match_indices('[') {
        if start < cursor {
            continue;
        }
        if let Some(end) = ends.get(&start) {
            if let Some(close) = ends.get(&(end + 1)) {
                let label_start = if start > cursor && line.as_bytes()[start - 1] == b'!' {
                    start - 1
                } else {
                    start
                };
                plain.push_str(&line[cursor..label_start]);
                plain.push_str(&line[start + 1..*end]);
                cursor = close + 1;
            }
        }
    }
    plain.push_str(&line[cursor..]);
    Cow::Owned(plain)
}

fn strip_markdown(line: &str) -> &str {
    strip_markdown_with_work(line, |_| {})
}

fn comment_closers(line: &str, visit: impl Fn(usize)) -> impl Iterator<Item = (usize, &str)> {
    let mut consumed = 0;
    line.match_indices("-->")
        .chain(std::iter::once((line.len(), "")))
        .filter_map(move |(offset, delimiter)| {
            let next = offset + delimiter.len();
            visit(next - consumed);
            consumed = next;
            (!delimiter.is_empty()).then_some((offset, delimiter))
        })
}

fn strip_markdown_with_work(line: &str, visit: impl Fn(usize)) -> &str {
    let last_comment_open = line.rfind("<!--");
    visit(line.len() - last_comment_open.unwrap_or(0));
    let mut comment_closes = comment_closers(line, &visit).peekable();
    let whitespace = |ch: char| {
        visit(1);
        ch.is_whitespace()
    };
    let backtick = |ch: char| {
        visit(1);
        ch == '`'
    };
    let mut start = 0;
    let mut end = line.len();
    loop {
        visit(1);
        let remaining = &line[start..end];
        let trimmed = remaining.trim_start_matches(whitespace);
        start += remaining.len() - trimmed.len();
        let remaining = trimmed.trim_end_matches(whitespace);
        end -= trimmed.len() - remaining.len();

        if remaining.starts_with('>') {
            start += 1;
        } else if let Some(inner) = remaining.strip_prefix("<!--") {
            let inner_start = end - inner.len();
            // Skip each closer at most once as the leading markers are consumed.
            while comment_closes
                .peek()
                .is_some_and(|&(offset, _)| offset < inner_start)
            {
                comment_closes.next();
            }
            if let Some(&(offset, delimiter)) = comment_closes.peek() {
                let after_close = offset + delimiter.len();
                if after_close < end {
                    return remaining;
                }
                if after_close == end {
                    end = offset;
                }
            }
            start = inner_start;
        } else if remaining.ends_with("-->") && last_comment_open.is_none_or(|open| open < start) {
            end -= 3;
        } else if remaining.starts_with('`') && remaining.ends_with('`') {
            let inner = remaining.trim_start_matches(backtick);
            start = end - inner.len();
            end = start + inner.trim_end_matches(backtick).len();
        } else if let Some(rest) = strip_list_marker(remaining, whitespace) {
            start = end - rest.len();
        } else {
            return remaining;
        }
    }
}

fn strip_list_marker(line: &str, whitespace: impl Fn(char) -> bool) -> Option<&str> {
    let (marker, rest) = line.split_once(whitespace)?;
    let ordered = marker.strip_suffix(['.', ')']).is_some_and(|digits| {
        (1..=9).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit())
    });
    let heading = marker.len() <= 6 && marker.bytes().all(|byte| byte == b'#');
    (ordered || heading || matches!(marker, "-" | "*" | "+")).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::{decode, strip_markdown, strip_markdown_with_work};
    use std::cell::Cell;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    fn best_of_five<T>(mut run: impl FnMut() -> T) -> Duration {
        (0..5)
            .map(|_| {
                let start = Instant::now();
                black_box(run());
                start.elapsed()
            })
            .min()
            .unwrap()
    }

    fn assert_linear_growth(small: Duration, large: Duration) {
        let ratio = large.as_secs_f64() / small.as_secs_f64();
        eprintln!("n: {small:?}, 4n: {large:?}, ratio: {ratio:.2}x");
        assert!(large < small * 8, "4n took {ratio:.2}x as long as n");
    }

    #[test]
    fn decoding_deeply_nested_input_is_bounded() {
        // Each nested percent escape can trigger a new full scan of the line.
        let depth = 64;
        let input = |depth| format!("%{}41{}", "25".repeat(depth), "x".repeat(2048 * depth));
        let small = input(depth);
        let large = input(4 * depth);
        assert_linear_growth(
            best_of_five(|| decode(black_box(&small))),
            best_of_five(|| decode(black_box(&large))),
        );
    }

    #[test]
    fn stripping_unclosed_html_comments_scales_linearly() {
        // Searching for a closer at every opening comment rescans the remaining line.
        let depth = 64;
        let input = |depth| format!("{}{}", "<!--".repeat(depth), "x".repeat(4096 * depth));
        let small = input(depth);
        let large = input(4 * depth);
        assert_linear_growth(
            best_of_five(|| strip_markdown(black_box(&small))),
            best_of_five(|| strip_markdown(black_box(&large))),
        );
    }

    #[test]
    fn stripping_nested_list_markers_scales_linearly() {
        // Searching the remaining line at each marker makes normalization quadratic.
        let depth = 4 * 1024;
        let input = |depth| format!("{}x", "- ".repeat(depth));
        let small = input(depth);
        let large = input(4 * depth);
        assert_linear_growth(
            best_of_five(|| strip_markdown(black_box(&small))),
            best_of_five(|| strip_markdown(black_box(&large))),
        );
    }

    #[test]
    fn stripping_deeply_nested_markdown_is_fast() {
        // Each opening comment or Markdown marker can trigger another scan of the line.
        let comments = format!("{}x", "<!--".repeat(30 * 1024));
        let markers = format!("{}x", "- ".repeat(120 * 1024));
        for (name, line, tenths_per_byte) in [
            ("nested comments", comments, 18),
            ("nested markers", markers, 36),
        ] {
            let visited = Cell::new(0);
            let bound = tenths_per_byte * line.len() / 10;
            let stripped = strip_markdown_with_work(&line, |count| {
                let total = visited.get() + count;
                assert!(
                    total <= bound,
                    "{name}: visited {total} with a bound of {bound}"
                );
                visited.set(total);
            });
            assert_eq!(stripped, "x", "{name}");
        }
    }
}
