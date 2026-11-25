//! Context-aware PEM masking shared by evidence and summaries.

use super::CountedRegex;
use std::{borrow::Cow, sync::LazyLock};

const PRIVATE_KEY_REDACTION: &str = "[redacted: possible key material]";

static PRIVATE_KEY_ARMOR: LazyLock<CountedRegex> = LazyLock::new(|| {
    CountedRegex::new(
        r"(?i)-----(?P<boundary>BEGIN|END)[ A-Z0-9_-]{0,100}?PRIVATE KEY(?: BLOCK)?-----",
    )
    .expect("static private key armor regex") // allow-expect: compile-time literal regex
});

fn strip_pem_comment(line: &str) -> &str {
    let mut body = line.trim();
    loop {
        body = body.trim_start_matches(|ch: char| !ch.is_ascii_alphanumeric());
        let end = body
            .find(|ch: char| !ch.is_ascii_alphabetic())
            .unwrap_or(body.len());
        let word = &body[..end];
        let lower = word.to_ascii_lowercase();
        let mut rest = lower.as_str();
        while let Some(tail) = ["rem", "dnl", "c"]
            .iter()
            .find_map(|marker| rest.strip_prefix(marker))
        {
            rest = tail;
        }
        if word.is_empty() || !rest.is_empty() {
            return body;
        }
        body = &body[end..];
    }
}

fn base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn continues_pem_body(line: &str) -> bool {
    let body = strip_pem_comment(line);
    let metadata = body.split_once(':').is_some_and(|(name, _)| {
        [
            "Proc-Type",
            "DEK-Info",
            "Version",
            "Comment",
            "Hash",
            "Charset",
        ]
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header))
    });
    // Inside armor, code wrappers cannot make the longest base64 run safe.
    metadata
        || body.bytes().all(base64_byte)
        || line
            .as_bytes()
            .split(|byte| !base64_byte(*byte))
            .any(|run| run.len() >= 8)
}

fn looks_like_pem_body_line(line: &str) -> bool {
    [line.trim(), strip_pem_comment(line)]
        .iter()
        .any(|body| body.len() >= 40 && body.bytes().all(base64_byte))
}

/// Streaming private-key context that ends at armor or the first unrelated line.
#[derive(Default)]
struct PemRedactor {
    in_private_key: bool,
}

impl PemRedactor {
    /// Mask body lines without allowing an unclosed block to hide unrelated code.
    pub fn redact_line<'a>(&mut self, line: &'a str) -> Cow<'a, str> {
        #[cfg(any(test, feature = "test-support"))]
        super::shared_test_support::count_redaction_work(line.len() + 1);
        self.in_private_key = self.in_private_key && continues_pem_body(line);
        let mut private_key_line = self.in_private_key;
        for armor in PRIVATE_KEY_ARMOR.captures_iter(line) {
            private_key_line = true;
            self.in_private_key = armor["boundary"].eq_ignore_ascii_case("BEGIN");
        }
        let uppercase = line.to_ascii_uppercase();
        if private_key_line
            || uppercase.contains("-----BEGIN")
            || uppercase.contains("-----END")
            || looks_like_pem_body_line(line)
        {
            Cow::Borrowed(PRIVATE_KEY_REDACTION)
        } else {
            Cow::Borrowed(line)
        }
    }
}

pub(super) fn redact_pem_lines(input: &str) -> String {
    let mut state = PemRedactor::default();
    let mut output = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        output.push_str(&state.redact_line(content));
        output.push_str(&line[content.len()..]);
    }
    output
}
