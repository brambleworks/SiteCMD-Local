//! The credential formats SiteCMD recognizes in public text, shared by the
//! exposed-key check and by every reader that must keep a key out of what the
//! hosted service stores. Matching a format does not validate a value.

use std::sync::LazyLock;

/// Whether a format represents a secret credential or a value that may be
/// intentionally delivered to a browser. Matching a format does not validate
/// the value or establish its privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyClass {
    Secret,
    Public,
}

/// A named pattern for a specific API key format.
pub(super) struct KeyPattern {
    pub(super) service: &'static str,
    prefixes: &'static [&'static str],
    pub(super) class: KeyClass,
    regex: regex::Regex,
    /// Capture group holding the key itself. Group 0 for patterns whose
    /// prefix is distinctive enough on its own; group 1 for patterns that
    /// need an explicit left-boundary group because Rust regex has no lookbehind.
    key_group: usize,
}

const PEM_BASE64_RUN: &str = r"(?-i:(?:[A-Za-z0-9+=]|\\*/){16,})";
const PEM_LINE_BREAK: &str =
    r"(?:\r\n?|\n|\\+[rn]|\\+u000a|&#13;&#10;|&#(?:10|x0a);|%0a|<br\s*/?>)";
const PEM_CHECKSUM: &str = r"(?-i:=(?:[A-Za-z0-9+]|\\*/){4})";
const PEM_PUNCTUATION: &str = r#"[\s"'`+()]"#;
const PEM_BEGIN: &str = r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----";
const PEM_END: &str = r"-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----";

fn pem_header_line() -> String {
    format!(
        r"(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset):(?:[^\r\n\\<&]|\\+/)*?{PEM_LINE_BREAK}"
    )
}

fn pem_key_regex() -> regex::Regex {
    let header = pem_header_line();
    let layout = format!(r"(?:{header}|{PEM_CHECKSUM}|{PEM_LINE_BREAK}|{PEM_PUNCTUATION})");
    regex::Regex::new(&format!(
        r"(?i){PEM_BEGIN}(?P<pem_body>{layout}*{PEM_BASE64_RUN}(?:{PEM_BASE64_RUN}|{layout})*){PEM_END}"
    )).expect("static private key armor regex") // allow-expect: compile-time regex fragments
}

static PEM_PATTERN: LazyLock<KeyPattern> = LazyLock::new(|| KeyPattern {
    service: "Private Key (PEM)",
    prefixes: &["-----BEGIN "],
    class: KeyClass::Secret,
    regex: pem_key_regex(),
    key_group: 0,
});

static PEM_TOKENS: LazyLock<regex::Regex> = LazyLock::new(|| {
    let header = pem_header_line();
    regex::Regex::new(&format!(
        r"(?i){header}|{PEM_CHECKSUM}|(?P<base64>{PEM_BASE64_RUN})|{PEM_LINE_BREAK}|{PEM_PUNCTUATION}"
    )).expect("static PEM material tokens regex") // allow-expect: compile-time regex fragments
});

static PEM_NESTED_ARMOR: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)-----(?:BEGIN|END)\b").expect("static nested armor regex")
    // allow-expect: compile-time literal regex
});

fn uniform_bytes(mut bytes: impl Iterator<Item = u8>) -> bool {
    bytes
        .next()
        .is_some_and(|first| bytes.all(|byte| byte == first))
}

impl KeyPattern {
    pub(super) fn matches<'a>(
        &'a self,
        text: &'a str,
    ) -> impl Iterator<Item = regex::Match<'a>> + 'a {
        let mut offset = 0;
        std::iter::from_fn(move || {
            while let Some(captures) = self.regex.captures_at(text, offset) {
                let whole = captures.get(0)?;
                offset = whole.end();
                let Some(value) = captures.get(self.key_group) else {
                    if whole.is_empty() {
                        offset += text[offset..].chars().next()?.len_utf8();
                    }
                    continue;
                };
                // Reuse a consumed right boundary as the next key's left boundary.
                offset = value.end();
                if let Some(body) = captures.name("pem_body") {
                    if PEM_NESTED_ARMOR.is_match(body.as_str()) {
                        offset = body.start();
                        continue;
                    }
                    let material = PEM_TOKENS
                        .captures_iter(body.as_str())
                        .filter_map(|token| token.name("base64"))
                        .flat_map(|run| run.as_str().bytes())
                        .filter(|byte| *byte != b'\\');
                    if uniform_bytes(material) {
                        continue;
                    }
                } else if self
                    .prefixes
                    .iter()
                    .filter_map(|prefix| {
                        value
                            .as_str()
                            .strip_prefix(prefix)
                            .map(|body| (prefix.len(), body))
                    })
                    .max_by_key(|(length, _)| *length)
                    .is_some_and(|(_, body)| {
                        body.split('.')
                            .all(|segment| uniform_bytes(segment.bytes()))
                    })
                {
                    continue;
                }
                return Some(value);
            }
            None
        })
    }
}

pub(super) static KEY_PATTERNS: LazyLock<Vec<KeyPattern>> = LazyLock::new(|| {
    vec![
        KeyPattern {
            // Cover modern and classic OpenAI formats without claiming Anthropic
            // keys or matching `sk-` fragments embedded in larger identifiers.
            service: "OpenAI",
            prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{20,})"#,
            )
            .expect("static openai key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "Anthropic",
            prefixes: &["sk-ant-"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"sk-ant-[a-zA-Z0-9\-]{20,}"#)
                .expect("static anthropic key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // Keep live and test keys separate so their findings remain accurate.
        KeyPattern {
            service: "Stripe Secret (live)",
            prefixes: &["sk_live_"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"sk_live_[a-zA-Z0-9]{20,}"#)
                .expect("static stripe live secret regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "Stripe Secret (test mode)",
            prefixes: &["sk_test_"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"sk_test_[a-zA-Z0-9]{20,}"#)
                .expect("static stripe test secret regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // Stripe `pk_live_` / `pk_test_` keys are publishable by design -
        // Stripe explicitly documents pairing them with restricted account
        // settings. Critical was wrong; surface a Low advisory instead.
        KeyPattern {
            service: "Stripe Publishable",
            prefixes: &["pk_live_", "pk_test_"],
            class: KeyClass::Public,
            regex: regex::Regex::new(r#"pk_(live|test)_[a-zA-Z0-9]{20,}"#)
                .expect("static stripe publishable regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // Boundary groups keep an exact-length credential from matching
        // inside a longer identifier that merely ends the same way.
        KeyPattern {
            service: "AWS Access Key",
            prefixes: &["AKIA"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9_-]|$)"#,
            )
            .expect("static aws key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        // Google and Firebase browser keys are public identifiers when properly restricted.
        KeyPattern {
            service: "Google API / Firebase",
            prefixes: &["AIza"],
            class: KeyClass::Public,
            regex: regex::Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#)
                .expect("static google/firebase api key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // This standard HS256 header cannot attribute the JWT to Supabase or
        // distinguish anon, service-role, and unrelated tokens.
        KeyPattern {
            service: "JWT (possibly Supabase)",
            prefixes: &["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."],
            class: KeyClass::Public,
            regex: regex::Regex::new(
                r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}"#,
            )
            .expect("static hs256 jwt regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "GitHub Token",
            prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"gh[pousr]_[A-Za-z0-9_]{36,}"#)
                .expect("static github token regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "GitHub Fine-Grained Token",
            prefixes: &["github_pat_"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"(?:^|[^A-Za-z0-9_-])(github_pat_[A-Za-z0-9_]{22,})"#)
                .expect("static github fine-grained token regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "Stripe Restricted (live)",
            prefixes: &["rk_live_"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"rk_live_[a-zA-Z0-9]{20,}"#)
                .expect("static stripe restricted key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "GitLab Token",
            prefixes: &["glpat-"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"(?:^|[^A-Za-z0-9_-])(glpat-[A-Za-z0-9_-]{20,})"#)
                .expect("static gitlab token regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "npm Token",
            prefixes: &["npm_"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"(?:^|[^A-Za-z0-9_-])(npm_[A-Za-z0-9]{36})(?:[^A-Za-z0-9_-]|$)"#)
                .expect("static npm token regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "Slack Token",
            prefixes: &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(xox[baprs]-[0-9a-zA-Z\-]{10,})(?:[^A-Za-z0-9_-]|$)"#,
            )
            .expect("static slack token regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "Twilio",
            prefixes: &["SK"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(SK[0-9a-fA-F]{32})(?:[^A-Za-z0-9_-]|$)"#,
            )
            .expect("static twilio key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "SendGrid",
            prefixes: &["SG."],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"#)
                .expect("static sendgrid key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // The left-boundary group keeps `key-` from matching inside larger
        // hyphenated tokens such as `cache-key-<32-char hash>`.
        KeyPattern {
            service: "Mailgun",
            prefixes: &["key-"],
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"(?:^|[^A-Za-z0-9_-])(key-[0-9a-zA-Z]{32})"#)
                .expect("static mailgun key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
    ]
});

pub(super) fn key_patterns(text: &str) -> impl Iterator<Item = &'static KeyPattern> {
    let has_pem_marker = text
        .as_bytes()
        .windows(b"-----BEGIN".len())
        .any(|window| window.eq_ignore_ascii_case(b"-----BEGIN"));
    KEY_PATTERNS
        .iter()
        .chain(has_pem_marker.then(|| &*PEM_PATTERN))
}

/// Whether `text` holds any credential format SiteCMD recognizes.
pub(crate) fn matches_key_pattern(text: &str) -> bool {
    key_patterns(text)
        .any(|pattern| pattern.regex.is_match(text) && pattern.matches(text).next().is_some())
}

/// Services whose credential formats occur in `text`, excluding uniform-body
/// placeholders. Matching a format does not validate a credential.
pub fn key_pattern_services(text: &str) -> Vec<&'static str> {
    key_patterns(text)
        .filter(|pattern| pattern.matches(text).next().is_some())
        .map(|pattern| pattern.service)
        .collect()
}

#[cfg(test)]
#[path = "key_patterns_tests.rs"]
mod prefix_tests;

#[cfg(test)]
mod tests {
    use super::matches_key_pattern;

    #[test]
    fn a_recognized_key_format_matches_and_an_ordinary_path_does_not() {
        assert!(matches_key_pattern("/share/sk-proj1234567890abcdefghij")); // gitleaks:allow
        assert!(!matches_key_pattern("/blog/how-we-ship-on-fridays"));
    }
}
