//! Decoded path comparisons share normalization and word-slug classification.

use std::borrow::Cow;
use std::sync::LazyLock;

pub const SSN_DASHES: [char; 12] = [
    '\u{00ad}', '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}', '\u{2027}',
    '\u{2043}', '\u{2212}', '\u{2e3a}', '\u{30fc}',
];

pub fn nfkc(segment: &str) -> String {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfkc()
        .normalize(segment)
        .into_owned()
}

const MAX_SEGMENT_DECODE_DEPTH: usize = 4;

pub(crate) fn normalized_segment(segment: &str) -> Option<Cow<'_, str>> {
    let mut text = Cow::Borrowed(segment);
    for depth in 0..=MAX_SEGMENT_DECODE_DEPTH {
        if !text.is_ascii() {
            let normalized =
                icu_normalizer::ComposingNormalizerBorrowed::new_nfkc().normalize(&text);
            if let Cow::Owned(normalized) = normalized {
                text = Cow::Owned(normalized);
            }
        }
        if !text.contains('%') {
            return Some(text);
        }
        let encoded = format!("value={}", text.replace('+', "%2B").replace('&', "%26"));
        let Some((_, decoded)) = url::form_urlencoded::parse(encoded.as_bytes()).next() else {
            return Some(text);
        };
        if decoded == text {
            return Some(text);
        }
        if depth == MAX_SEGMENT_DECODE_DEPTH {
            return None;
        }
        text = Cow::Owned(decoded.into_owned());
    }
    None
}

static SLUG_WORD: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(?:[\p{L}\p{M}]+|\p{Nd}+)$").expect("static Unicode slug word regex")
});

/// Letter words separated by punctuation or spaces, with optional digit words.
pub fn word_slug(value: &str) -> bool {
    let pieces = || value.split(['-', '_', '.', ' ']);
    let uuid = value.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && value
            .split('-')
            .all(|piece| piece.bytes().all(|byte| byte.is_ascii_hexdigit()));
    !uuid
        && pieces().all(|piece| {
            !piece.is_empty()
                && (piece.bytes().all(|byte| byte.is_ascii_digit())
                    || if piece.is_ascii() {
                        piece.bytes().all(|byte| byte.is_ascii_alphabetic())
                    } else {
                        SLUG_WORD.is_match(piece)
                    })
        })
        && value.chars().any(char::is_alphabetic)
}

#[cfg(test)]
mod tests {
    use super::nfkc;

    #[test]
    fn nfkc_matches_unicode_normalization_conformance() {
        // https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt
        let cases = include_str!("../../../tests/fixtures/sync/nfkc-cases.txt");
        let mut count = 0;
        for row in cases.lines() {
            let columns: Vec<String> = row
                .split(';')
                .map(|column| {
                    column
                        .split_whitespace()
                        .map(|value| {
                            char::from_u32(u32::from_str_radix(value, 16).unwrap()).unwrap()
                        })
                        .collect()
                })
                .collect();
            assert_eq!(columns.len(), 5);
            for input in &columns {
                assert_eq!(nfkc(input), columns[3], "{row}");
            }
            count += 1;
        }
        assert_eq!(count, 20034);
    }
}
