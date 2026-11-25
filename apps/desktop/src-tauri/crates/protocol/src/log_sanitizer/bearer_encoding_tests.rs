use super::{redact_log_config_credentials, redact_log_diagnostic, redact_secrets};

fn assert_body_masked(body: &str) {
    for separator in [" ", "\t", "%20", "+"] {
        for (before, after) in [
            ("", ""),
            ("Authorization: ", ""),
            (r#"{"Authorization":""#, r#""}"#),
            ("Proxy-Authorization: '", "'"),
            ("map[Authorization:[", "]]"),
            ("authorization=", "&next=/home"),
        ] {
            let source = format!("{before}Bearer{separator}{body}{after}");
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                redact_log_config_credentials,
            ] {
                let masked = redact(&source);
                assert_eq!(masked, format!("{before}Bearer{separator}***{after}"));
                assert_eq!(redact(&masked), masked);
            }
        }
    }
}

#[test]
fn bearer_json_escaped_plus_masks_the_entire_body() {
    // A JSON-escaped plus in a Bearer token leaves credential bytes in the log.
    for escape in ["+", r"\u002b", r"\u002B", r"\U002B"] {
        assert_body_masked(&format!("AbC{escape}DeFgHi{escape}JkLmNo"));
    }
}

#[test]
fn bearer_json_escaped_slash_masks_the_entire_body() {
    // A JSON-escaped slash in a Bearer token leaves the token's tail in the log.
    for escape in ["/", r"\u002f", r"\u002F", r"\U002F", r"\/"] {
        assert_body_masked(&format!("AbC{escape}DeFgHi{escape}JkLmNo"));
    }
}

#[test]
fn bearer_json_escaped_padding_masks_the_entire_body() {
    // JSON-escaped padding inside a Bearer token leaves credential bytes in the log.
    for escape in [r"\u003d", r"\u003D", r"\U003D"] {
        assert_body_masked(&format!("AbC{escape}DeFgHi{escape}JkLmNo"));
    }
}

#[test]
fn bearer_next_line_character_does_not_expose_the_body_tail() {
    // U+0085 inside a Bearer body leaves credential bytes after a false separator.
    assert_body_masked("AbCdEfGh\u{85}IjKlMnOp");
}

#[test]
fn authorization_after_unicode_letters_masks_the_body() {
    // A Unicode letter before an ASCII scheme hides the credential from its word boundary.
    for prefix in ["ſ", "K", "é"] {
        for (scheme, body) in [("Bearer", "AbCdEfGhIjKl"), ("Basic", "dXNlcjpwYXNz")] {
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                redact_log_config_credentials,
            ] {
                let masked = redact(&format!("{prefix}{scheme} {body}"));
                assert_eq!(masked, format!("{prefix}{scheme} ***"));
                assert_eq!(redact(&masked), masked);
            }
        }
    }
}

#[test]
fn provider_after_unicode_letters_masks_the_body() {
    // A Unicode letter before a provider prefix leaves an adjacent credential in the log.
    for prefix in ["ſ", "K", "é"] {
        for token in [
            "ya29.AbCdEfGhIjKl",
            "1//AbCdEfGhIjKl",
            "sk-live_AbCdEfGhIjKl",
        ] {
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                redact_log_config_credentials,
            ] {
                let source = format!("{prefix}{token}");
                assert_ne!(redact(&source), source);
                assert!(!redact(&source).contains("AbCdEfGhIjKl"));
            }
        }
    }
}

#[test]
fn doubled_authorization_schemes_mask_credentials() {
    // A doubled scheme consumes the credential as an unvalidated body and leaves it visible.
    for separator in [" ", "\t", "+", "%20"] {
        for (scheme, body) in [("Bearer", "AbCdEfGhIjKl"), ("Basic", "dXNlcjpwYXNz")] {
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                redact_log_config_credentials,
            ] {
                let source = format!("Authorization: {scheme}{separator}{scheme}{separator}{body}");
                let masked = redact(&source);
                assert!(!masked.contains(body));
                assert!(masked.contains("***"));
                assert_eq!(redact(&masked), masked);
            }
        }
    }
}

#[test]
fn bearer_byte_order_mark_separator_masks_the_body() {
    // A byte order mark between Bearer and its body leaves the credential in the log.
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        assert_eq!(redact("Bearer\u{feff}AbCdEfGhIjKl"), "Bearer\u{feff}***");
    }
}

#[test]
fn folded_scheme_and_prefix_letters_mask_adjacent_credentials() {
    // Case-folded letters inside a scheme or prefix leave credential bytes visible.
    for (source, body) in [
        ("baſic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("ſk-live_AbCdEfGhIjKl", "AbCdEfGhIjKl"),
        ("ſk_live_AbCdEfGhIjKl", "AbCdEfGhIjKl"),
        ("sK-live_AbCdEfGhIjKl", "AbCdEfGhIjKl"),
        ("xſk-AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
        ("xsK-AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
    ] {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let masked = redact(source);
            assert!(!masked.contains(body));
            assert_eq!(redact(&masked), masked);
        }
    }
}

#[test]
fn bearer_explicit_whitespace_set_masks_separators_and_ends_bodies() {
    // Differing whitespace definitions can reveal credentials or swallow following log fields.
    for separator in [
        '\t', '\n', '\u{b}', '\u{c}', '\r', ' ', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}',
        '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}',
        '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
        '\u{feff}',
    ] {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let source = format!("Bearer{separator}AbCdEfGhIjKl{separator}next");
            assert_eq!(
                redact(&source),
                format!("Bearer{separator}***{separator}next")
            );
        }
    }
}
