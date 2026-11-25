//! Overlapping Basic schemes share decoded body indexes instead of rescanning suffixes.

use std::borrow::Cow;

use base64::Engine;

struct Candidate {
    start: usize,
    end: usize,
    normalized: usize,
    prefixes: [Option<usize>; 2],
    accepted: bool,
}

pub(super) fn redact(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    #[cfg(any(test, feature = "test-support"))]
    super::shared_test_support::count_redaction_work(bytes.len());
    let mut candidates = Vec::new();
    let mut chain_end = None;
    for start in 0..bytes.len().saturating_sub(4) {
        let width = if bytes
            .get(start..start + 5)
            .is_some_and(|value| value.eq_ignore_ascii_case(b"basic"))
        {
            5
        } else if bytes.get(start..start + 6).is_some_and(|value| {
            value[..2].eq_ignore_ascii_case(b"ba")
                && value[2..4] == [0xc5, 0xbf]
                && value[4..].eq_ignore_ascii_case(b"ic")
        }) {
            6
        } else {
            continue;
        };
        if !boundary(bytes, start) && chain_end != Some(start) {
            continue;
        }
        let mut end = start + width;
        let separator = separator_width(&text[end..]);
        if separator == 0 {
            continue;
        }
        end += separator;
        chain_end = Some(end);
        candidates.push(Candidate {
            start: end,
            end,
            normalized: 0,
            prefixes: [None; 2],
            accepted: false,
        });
    }
    let mut cursor = 0;
    let mut next = 0;
    while cursor < bytes.len() && next < candidates.len() {
        cursor = cursor.max(candidates[next].start);
        let start = cursor;
        let mut normalized = Vec::new();
        while let Some((value, width)) = atom(&bytes[cursor..]) {
            normalized.push(value);
            cursor += width;
        }
        let first = next;
        while next < candidates.len() && candidates[next].start < cursor {
            next += 1;
        }
        if first != next {
            classify(
                bytes,
                start,
                cursor,
                &normalized,
                &mut candidates[first..next],
            );
        }
        cursor += 1;
        while next < candidates.len() && candidates[next].start < cursor {
            next += 1;
        }
    }
    let mut output = String::new();
    let mut copied = 0;
    for candidate in candidates.iter().filter(|candidate| candidate.accepted) {
        if candidate.start < copied {
            continue;
        }
        output.push_str(&text[copied..candidate.start]);
        output.push_str("***");
        copied = candidate.end;
    }
    if copied == 0 {
        Cow::Borrowed(text)
    } else {
        output.push_str(&text[copied..]);
        Cow::Owned(output)
    }
}

fn separator_width(text: &str) -> usize {
    let mut width = 0;
    while width < text.len() {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(1);
        let tail = &text[width..];
        if tail.as_bytes().get(..3).is_some_and(|prefix| {
            [b"%09", b"%0A", b"%0B", b"%0C", b"%0D", b"%20"]
                .iter()
                .any(|encoded| prefix.eq_ignore_ascii_case(*encoded))
        }) {
            width += 3;
        } else if let Some(ch) = tail.chars().next().filter(|ch| {
            matches!(ch, '+' | ' ' | '\t'..='\r' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
        }) {
            width += ch.len_utf8();
        } else {
            break;
        }
    }
    width
}

fn boundary(bytes: &[u8], start: usize) -> bool {
    start == 0
        || !matches!(bytes[start - 1], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
        || [
            b"%2B".as_slice(),
            b"%2F",
            b"%3D",
            br"\u002B",
            br"\u002F",
            br"\u003D",
        ]
        .iter()
        .any(|suffix| {
            start >= suffix.len() && bytes[start - suffix.len()..start].eq_ignore_ascii_case(suffix)
        })
}

fn atom(bytes: &[u8]) -> Option<(u8, usize)> {
    #[cfg(any(test, feature = "test-support"))]
    super::shared_test_support::count_redaction_work(1);
    let first = *bytes.first()?;
    if first.is_ascii_alphanumeric() || matches!(first, b'+' | b'/' | b'=') {
        return Some((first, 1));
    }
    if bytes.starts_with(br"\/") {
        return Some((b'/', 2));
    }
    let (code, width) = if first == b'%' && bytes.len() >= 3 {
        (&bytes[1..3], 3)
    } else if bytes.len() >= 6 && bytes[..4].eq_ignore_ascii_case(br"\u00") {
        (&bytes[4..6], 6)
    } else {
        return None;
    };
    [(b"2B", b'+'), (b"2F", b'/'), (b"3D", b'=')]
        .into_iter()
        .find(|(encoded, _)| code.eq_ignore_ascii_case(*encoded))
        .map(|(_, decoded)| (decoded, width))
}

fn classify(
    bytes: &[u8],
    start: usize,
    end: usize,
    normalized: &[u8],
    candidates: &mut [Candidate],
) {
    let mut cursor = start;
    let mut next = 0;
    let mut escape = 0;
    let mut separators = [0; 4];
    for (index, value) in normalized.iter().enumerate() {
        let Some((_, width)) = atom(&bytes[cursor..]) else {
            return;
        };
        if width > 1 {
            while escape < candidates.len() && candidates[escape].start < cursor {
                candidates[escape].prefixes[0] = Some(index);
                escape += 1;
            }
        } else if matches!(value, b'+' | b'/') {
            let phase = cursor % 4;
            while separators[phase] < candidates.len()
                && candidates[separators[phase]].start < cursor
            {
                let candidate = &mut candidates[separators[phase]];
                if candidate.start % 4 == phase {
                    candidate.prefixes[1] = Some(index);
                }
                separators[phase] += 1;
            }
        }
        while next < candidates.len() && candidates[next].start == cursor {
            let candidate = &mut candidates[next];
            candidate.end = end;
            candidate.normalized = index;
            next += 1;
        }
        cursor += width;
    }
    for phase in 0..4 {
        if !candidates
            .iter()
            .any(|candidate| candidate.normalized % 4 == phase)
        {
            continue;
        }
        let index = CredentialIndex::new(&normalized[phase.min(normalized.len())..]);
        for candidate in candidates
            .iter_mut()
            .filter(|candidate| candidate.normalized % 4 == phase)
        {
            if candidate.end - candidate.start < 8
                && bytes[candidate.start..candidate.end]
                    .iter()
                    .any(|byte| matches!(byte, b'%' | b'\\'))
            {
                continue;
            }
            candidate.accepted = std::iter::once(normalized.len())
                .chain(candidate.prefixes.into_iter().flatten())
                .any(|end| {
                    end > candidate.normalized
                        && index.credential(candidate.normalized - phase, end - phase)
                });
        }
    }
}

struct CredentialIndex {
    bad: Vec<u32>,
    colons: Vec<u32>,
    starts: Vec<bool>,
    terminals: Vec<bool>,
}

impl CredentialIndex {
    fn new(encoded: &[u8]) -> Self {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(encoded.len());
        let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
        let mut lengths = Vec::with_capacity(encoded.len() / 4);
        for block in encoded.chunks_exact(4) {
            let mut bytes = [0; 3];
            let length = base64::engine::general_purpose::STANDARD
                .decode_slice(block, &mut bytes)
                .unwrap_or(0);
            if length == 0 {
                bytes.fill(0);
            }
            lengths.push(length as u8);
            decoded.extend_from_slice(&bytes);
        }
        let mut valid = vec![false; decoded.len()];
        let mut boundaries = vec![false; decoded.len() + 1];
        let mut offset = 0;
        while offset < decoded.len() {
            let (length, skip) = match std::str::from_utf8(&decoded[offset..]) {
                Ok(text) => (text.len(), 0),
                Err(error) => (
                    error.valid_up_to(),
                    error
                        .error_len()
                        .unwrap_or(decoded.len() - offset - error.valid_up_to()),
                ),
            };
            let text = std::str::from_utf8(&decoded[offset..offset + length])
                .expect("validated UTF-8 prefix"); // allow-expect: valid_up_to identifies valid UTF-8
            for (start, ch) in text.char_indices() {
                let start = offset + start;
                valid[start..start + ch.len_utf8()].fill(!ch.is_control());
                boundaries[start] = true;
                boundaries[start + ch.len_utf8()] = true;
            }
            offset += length + skip;
        }
        let mut bad = Vec::with_capacity(lengths.len() + 1);
        let mut colons = Vec::with_capacity(lengths.len() + 1);
        let mut starts = Vec::with_capacity(lengths.len());
        let mut terminals = Vec::with_capacity(lengths.len());
        bad.push(0);
        colons.push(0);
        for (block, length) in lengths.into_iter().enumerate() {
            let start = block * 3;
            let end = start + usize::from(length);
            bad.push(
                bad[block]
                    + valid[start..start + 3]
                        .iter()
                        .filter(|valid| !**valid)
                        .count() as u32,
            );
            colons.push(
                colons[block]
                    + decoded[start..start + 3]
                        .iter()
                        .filter(|byte| **byte == b':')
                        .count() as u32,
            );
            starts.push(boundaries[start]);
            terminals.push(
                length > 0 && boundaries[end] && valid[start..end].iter().all(|valid| *valid),
            );
        }
        Self {
            bad,
            colons,
            starts,
            terminals,
        }
    }

    fn credential(&self, start: usize, end: usize) -> bool {
        if start == end || !(end - start).is_multiple_of(4) {
            return false;
        }
        let last = end / 4 - 1;
        let Some(&terminal) = self.terminals.get(last) else {
            return false;
        };
        let first = start / 4;
        self.starts[first]
            && terminal
            && self.bad[first] == self.bad[last]
            && self.colons[first] < self.colons[last + 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_base64_ranges_match_the_decoder() {
        for plain in [
            "user:pass",
            "a:b",
            "é:密钥",
            "colonless",
            "bad:\u{85}",
            "first:second:third",
        ] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
            for prefix in ["", "A", "+", "Basic+"] {
                let value = format!("{prefix}{encoded}");
                for phase in 0..4.min(value.len()) {
                    let index = CredentialIndex::new(&value.as_bytes()[phase..]);
                    for start in (phase..value.len()).step_by(4) {
                        for end in start + 1..=value.len() {
                            let expected = base64::engine::general_purpose::STANDARD
                                .decode(&value.as_bytes()[start..end])
                                .ok()
                                .and_then(|bytes| String::from_utf8(bytes).ok())
                                .is_some_and(|text| {
                                    text.contains(':') && !text.chars().any(char::is_control)
                                });
                            assert_eq!(
                                index.credential(start - phase, end - phase),
                                expected,
                                "{value} {start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }
}
