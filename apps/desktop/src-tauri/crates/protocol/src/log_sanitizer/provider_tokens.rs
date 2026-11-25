//! Provider masks with separate URL and MCP free-text boundaries.

use super::{Captures, CountedRegex};
use std::{borrow::Cow, sync::LazyLock};

struct SecretPattern {
    literals: &'static [&'static str],
    pattern: &'static str,
    unicode_pattern: &'static str,
    mask: super::mask::Mask,
    replacement: &'static str,
}

macro_rules! secret_pattern {
    ($literals:expr, $pattern:literal, $replacement:literal) => {
        SecretPattern {
            literals: $literals,
            pattern: $pattern,
            unicode_pattern: $pattern,
            mask: $crate::log_sanitizer::mask::Mask::new(),
            replacement: $replacement,
        }
    };
    ($literals:expr, $pattern:literal, $unicode_pattern:literal, $replacement:literal) => {
        SecretPattern {
            literals: $literals,
            pattern: $pattern,
            unicode_pattern: $unicode_pattern,
            mask: $crate::log_sanitizer::mask::Mask::new(),
            replacement: $replacement,
        }
    };
}

mod evidence;

/// Run a provider mask only when its required literal could be present. Route
/// sessions prime the ASCII masks; Unicode masks need non-ASCII text with a required literal.
// Bearer keeps an explicit whitespace set with non-ASCII members only in Unicode mode.
static SECRET_PATTERNS: [SecretPattern; 11] = [
    secret_pattern!(
        &["bearer"],
        r#"(?i)(?-u:\b)(?P<bearer_scheme>bearer(?:[ \t-\r]+|%20|\+))(?P<bearer_body>(?:[^ \t-\r"'`<>()\[\]{},;&*\\]|\\u00(?:2[BF]|3D)|\\/){8,})"#,
        r#"(?i)(?-u:\b)(?P<bearer_scheme>bearer(?:[ \t-\r\x{85}\xA0\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+|%20|\+))(?P<bearer_body>(?:[^ \t-\r\xA0\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}"'`<>()\[\]{},;&*\\]|\\u00(?:2[BF]|3D)|\\/){8,})"#,
        "${bearer_scheme}***"
    ),
    secret_pattern!(
        &["basic"],
        r"(?i)(?P<basic_boundary>(?-u:\b)|%2[BbFf]|%3[Dd]|\\u00(?:2[BbFf]|3[Dd])|\\/)(?P<basic_scheme>(?:basic(?:[ \t-\r]|%(?:20|0[9A-D])|\+)+)+)(?P<basic_body>(?:(?-i:[A-Za-z0-9+/=])|%2[BbFf]|%3[Dd]|\\u00(?:2[BbFf]|3[Dd])|\\/)+)",
        r"(?i)(?P<basic_boundary>(?-u:\b)|%2[BbFf]|%3[Dd]|\\u00(?:2[BbFf]|3[Dd])|\\/)(?P<basic_scheme>(?:basic(?:[ \t-\r\x{85}\xA0\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]|%(?:20|0[9A-D])|\+)+)+)(?P<basic_body>(?:(?-i:[A-Za-z0-9+/=])|%2[BbFf]|%3[Dd]|\\u00(?:2[BbFf]|3[Dd])|\\/)+)",
        "${basic_boundary}${basic_scheme}***"
    ),
    secret_pattern!(&["ya29."], r"(?-u:\b)ya29\.[A-Za-z0-9._\-]{8,}", "ya29.***"),
    secret_pattern!(&["1//"], r"(?-u:\b)1//[A-Za-z0-9._\-]{8,}", "1//***"),
    secret_pattern!(
        &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        r"(?i)(?-u:\b)(?P<prefix>gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}",
        "${prefix}***"
    ),
    secret_pattern!(&["AKIA"], r"(?-u:\b)AKIA[0-9A-Z]{16}(?-u:\b)", "AKIA***"),
    secret_pattern!(
        &["sk-live", "sk-test", "sk_live", "sk_test", "rk-live", "rk-test", "rk_live", "rk_test"],
        r"(?i)(?P<boundary>^|(?-i:[^A-Za-z0-9_]))(?P<prefix>(?:sk|rk)[-_](?:live|test)[-_])[A-Za-z0-9]{12,}",
        "${boundary}${prefix}***"
    ),
    secret_pattern!(
        &["sk-"],
        r"(?i)(?P<boundary>^|(?-i:[^A-Za-z0-9_]))(?P<prefix>sk-(?:proj-|svcacct-|admin-|ant-)?)[A-Za-z0-9_-]{16,}",
        "${boundary}${prefix}***"
    ),
    secret_pattern!(
        &["AIza"],
        r"(?i)(?-u:\b)(?P<prefix>AIza)[0-9A-Za-z_-]{16,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["@"],
        r"(?P<pair_scheme>(?:[A-Za-z][A-Za-z0-9+.-]*)?://)[^/\s:@]+:[^/\s@]+@(?P<pair_digest>sha256:)?",
        "${pair_scheme}***:***@${pair_digest}"
    ),
    secret_pattern!(
        &["@"],
        r"(?P<userinfo_scheme>(?:[A-Za-z][A-Za-z0-9+.-]*)?://)(?P<userinfo>[^/\s:@]+)@(?P<image_digest>sha256:)?",
        "${userinfo_scheme}***@${image_digest}"
    ),
];

// MCP free-text values have broader boundaries than URL credentials.
static EMBEDDED_MCP_PATTERNS: LazyLock<Vec<(CountedRegex, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"(?i)(?P<prefix>gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}",
            "${prefix}***",
        ),
        (
            r"(?i)(?P<prefix>sk-(?:proj-|svcacct-|admin-|ant-)?)[A-Za-z0-9_-]{16,}",
            "${prefix}***",
        ),
        (r"(?i)(?P<prefix>AIza)[0-9A-Za-z_-]{16,}", "${prefix}***"),
    ]
    .into_iter()
    .map(|(pattern, replacement)| {
        (
            CountedRegex::new(pattern).expect("static embedded MCP regex"),
            replacement,
        )
    })
    .collect()
});

pub(super) fn redact_embedded_mcp_values(input: &str) -> String {
    let mut redacted = input.to_string();
    for (pattern, replacement) in EMBEDDED_MCP_PATTERNS.iter() {
        if let std::borrow::Cow::Owned(masked) = pattern.replace_all(&redacted, *replacement) {
            redacted = masked;
        }
    }
    redacted
}

pub(super) fn redact_mcp_values_outside_urls(input: &str, urls: &CountedRegex) -> String {
    let mut redacted = input.to_string();
    for (pattern, replacement) in EMBEDDED_MCP_PATTERNS.iter() {
        if !pattern.is_match(&redacted) {
            continue;
        }
        let protected: Vec<_> = urls.find_iter(&redacted).map(|url| url.range()).collect();
        let mut protected_index = 0;
        redacted = pattern
            .replace_all(&redacted, |captures: &Captures<'_>| {
                let Some(found) = captures.get(0) else {
                    return String::new();
                };
                #[cfg(any(test, feature = "test-support"))]
                super::shared_test_support::count_redaction_work(1);
                while protected
                    .get(protected_index)
                    .is_some_and(|url| url.end <= found.start())
                {
                    #[cfg(any(test, feature = "test-support"))]
                    super::shared_test_support::count_redaction_work(1);
                    protected_index += 1;
                }
                if protected
                    .get(protected_index)
                    .is_some_and(|url| url.start <= found.start() && found.end() <= url.end)
                {
                    found.as_str().to_string()
                } else {
                    let mut masked = String::new();
                    captures.expand(replacement, &mut masked);
                    masked
                }
            })
            .into_owned();
    }
    redacted
}

pub(super) fn redact_error_tokens(input: &str) -> String {
    let mut out = redact_webhook_urls(input);
    for secret in &SECRET_PATTERNS {
        if !super::may_contain_literal(input, secret.literals) {
            continue;
        }
        if let Cow::Owned(masked) = redact_matches(secret, &out) {
            out = masked;
        }
    }
    out
}

pub(super) fn redact_evidence_tokens(input: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(input);
    for secret in &evidence::PATTERNS {
        if super::may_contain_literal(&out, secret.literals) {
            if let Cow::Owned(masked) = redact_matches(secret, &out) {
                out = Cow::Owned(masked);
            }
        }
    }
    out
}

fn redact_matches<'a>(secret: &SecretPattern, input: &'a str) -> Cow<'a, str> {
    let pattern = secret.mask.regex_with_unicode(
        secret.pattern,
        secret.unicode_pattern,
        false,
        input.is_ascii(),
    );
    pattern.replace_all(input, |captures| secret_replacement(secret, captures))
}

pub(super) fn encoded_segment_contains_credentials(
    segment: &str,
    mask_url: super::UrlMask,
) -> bool {
    if !segment.contains('%') {
        return false;
    }
    let contains_credentials =
        |value: &str| redact_error_tokens(value) != value || mask_url(value) != value;
    let mut decoded = segment.to_string();
    for layer in 0..=2 {
        if contains_credentials(&decoded) {
            return true;
        }
        if layer == 2 || !decoded.contains('%') {
            break;
        }
        // Query decoding preserves path plus signs and ampersands when they are escaped first.
        let encoded = format!("value={}", decoded.replace('+', "%2B").replace('&', "%26"));
        let Some((_, value)) = url::form_urlencoded::parse(encoded.as_bytes()).next() else {
            break;
        };
        if value == decoded {
            break;
        }
        decoded = value.into_owned();
    }
    crate::url_path::normalized_segment(segment)
        .is_none_or(|decoded| contains_credentials(&decoded))
}

pub(super) fn prime_ascii_masks() {
    for secret in &SECRET_PATTERNS {
        secret
            .mask
            .regex_with_unicode(secret.pattern, secret.unicode_pattern, false, true);
    }
}

fn secret_replacement(secret: &SecretPattern, captures: &super::mask::Captures<'_>) -> String {
    if captures.name("bearer_body").is_some_and(|body| {
        body.as_str()
            .trim_end_matches('.')
            .eq_ignore_ascii_case("undefined")
    }) {
        return captures[0].to_string();
    }
    if captures.name("pair_scheme").is_some_and(|scheme| {
        scheme.as_str().eq_ignore_ascii_case("docker://") && captures.name("pair_digest").is_some()
    }) {
        return captures[0].to_string();
    }
    if captures.name("userinfo").is_some_and(|userinfo| {
        userinfo.as_str() == "git"
            || (captures["userinfo_scheme"].eq_ignore_ascii_case("docker://")
                && captures.name("image_digest").is_some())
    }) {
        return captures[0].to_string();
    }
    let mut masked = String::new();
    captures.expand(secret.replacement, &mut masked);
    masked
}

// Slack documents these three path components as the secret incoming webhook URL.
static SLACK_WEBHOOK: LazyLock<CountedRegex> = LazyLock::new(|| {
    CountedRegex::new(
        r"https://hooks\.slack(?:-gov)?\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9_-]{24,}",
    )
    .expect("static Slack webhook URL regex")
});

/// Mask secret incoming webhook URLs, including their short path components.
pub(super) fn redact_webhook_urls(input: &str) -> String {
    SLACK_WEBHOOK.replace_all(input, "[redacted]").into_owned()
}

#[cfg(test)]
mod literal_tests {
    use super::super::literal_test_support::{assert_literal_coverage, mask_corpus};

    #[test]
    fn secret_pattern_literals_cover_every_ascii_match() {
        for secret in &super::SECRET_PATTERNS {
            assert_literal_coverage(secret.pattern, secret.pattern, false, secret.literals);
            if secret.unicode_pattern != secret.pattern {
                assert_literal_coverage(
                    secret.unicode_pattern,
                    secret.unicode_pattern,
                    false,
                    secret.literals,
                );
            }
        }
    }

    #[test]
    fn ascii_and_unicode_secret_masks_have_identical_output() {
        // Log mask coverage must stand on generic witnesses without the detector corpus.
        for secret in &super::SECRET_PATTERNS {
            assert!(secret.pattern.is_ascii());
            let mask = crate::log_sanitizer::mask::Mask::new();
            let ascii =
                mask.regex_with_unicode(secret.pattern, secret.unicode_pattern, false, true);
            let unicode =
                mask.regex_with_unicode(secret.pattern, secret.unicode_pattern, false, false);
            let mut changed = false;
            for text in mask_corpus(secret.literals) {
                let actual = ascii.replace_all(&text, |captures| {
                    super::secret_replacement(secret, captures)
                });
                changed |= actual != text;
                assert_eq!(
                    actual,
                    unicode.replace_all(&text, |captures| super::secret_replacement(
                        secret, captures
                    )),
                    "{} on {text:?}",
                    secret.pattern
                );
            }
            assert!(changed, "{} has no masking witness", secret.pattern);
        }
    }
}
