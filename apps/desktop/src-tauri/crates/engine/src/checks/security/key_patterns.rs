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
    pub(super) class: KeyClass,
    pub(super) regex: regex::Regex,
    /// Capture group holding the key itself. Group 0 for patterns whose
    /// prefix is distinctive enough on its own; group 1 for patterns that
    /// need an explicit left-boundary group because Rust regex has no lookbehind.
    pub(super) key_group: usize,
}

pub(super) static KEY_PATTERNS: LazyLock<Vec<KeyPattern>> = LazyLock::new(|| {
    vec![
        KeyPattern {
            // Cover modern and classic OpenAI formats without claiming Anthropic
            // keys or matching `sk-` fragments embedded in larger identifiers.
            service: "OpenAI",
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{20,})"#,
            )
            .expect("static openai key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "Anthropic",
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"sk-ant-[a-zA-Z0-9\-]{20,}"#)
                .expect("static anthropic key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // Keep live and test keys separate so their findings remain accurate.
        KeyPattern {
            service: "Stripe Secret (live)",
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"sk_live_[a-zA-Z0-9]{20,}"#)
                .expect("static stripe live secret regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "Stripe Secret (test mode)",
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
            class: KeyClass::Public,
            regex: regex::Regex::new(r#"pk_(live|test)_[a-zA-Z0-9]{20,}"#)
                .expect("static stripe publishable regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // Boundary groups keep an exact-length credential from matching
        // inside a longer identifier that merely ends the same way.
        KeyPattern {
            service: "AWS Access Key",
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
            class: KeyClass::Public,
            regex: regex::Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#)
                .expect("static google/firebase api key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // This standard HS256 header cannot attribute the JWT to Supabase or
        // distinguish anon, service-role, and unrelated tokens.
        KeyPattern {
            service: "JWT (possibly Supabase)",
            class: KeyClass::Public,
            regex: regex::Regex::new(
                r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}"#,
            )
            .expect("static hs256 jwt regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "GitHub Token",
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"gh[pousr]_[A-Za-z0-9_]{36,}"#)
                .expect("static github token regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        KeyPattern {
            service: "Slack Token",
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(xox[baprs]-[0-9a-zA-Z\-]{10,})(?:[^A-Za-z0-9_-]|$)"#,
            )
            .expect("static slack token regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "Twilio",
            class: KeyClass::Secret,
            regex: regex::Regex::new(
                r#"(?:^|[^A-Za-z0-9_-])(SK[0-9a-fA-F]{32})(?:[^A-Za-z0-9_-]|$)"#,
            )
            .expect("static twilio key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
        KeyPattern {
            service: "SendGrid",
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"#)
                .expect("static sendgrid key regex"), // allow-expect: compile-time literal regex
            key_group: 0,
        },
        // The left-boundary group keeps `key-` from matching inside larger
        // hyphenated tokens such as `cache-key-<32-char hash>`.
        KeyPattern {
            service: "Mailgun",
            class: KeyClass::Secret,
            regex: regex::Regex::new(r#"(?:^|[^A-Za-z0-9_-])(key-[0-9a-zA-Z]{32})"#)
                .expect("static mailgun key regex"), // allow-expect: compile-time literal regex
            key_group: 1,
        },
    ]
});

/// Whether `text` holds any credential format SiteCMD recognizes.
pub(crate) fn matches_key_pattern(text: &str) -> bool {
    KEY_PATTERNS
        .iter()
        .any(|pattern| pattern.regex.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::matches_key_pattern;

    #[test]
    fn a_recognized_key_format_matches_and_an_ordinary_path_does_not() {
        assert!(matches_key_pattern("/share/sk-proj1234567890abcdefghij")); // gitleaks:allow
        assert!(!matches_key_pattern("/blog/how-we-ship-on-fridays"));
    }
}
