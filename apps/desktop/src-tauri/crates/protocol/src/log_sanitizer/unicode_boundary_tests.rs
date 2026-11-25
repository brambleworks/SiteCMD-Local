use super::{
    log_safe_url_reference, redact_log_config_credentials, redact_log_diagnostic, redact_secrets,
};

#[test]
fn ascii_suffixes_do_not_hide_evidence_emails() {
    for (source, expected) in [
        ("jane@example.com_backup", "[email]_backup"),
        ("contact jane@example.com1 now", "contact [email]1 now"),
        ("mail jane@example.co_uk", "mail [email]_uk"),
        ("contact éjane@example.com_ now", "contact é[email]_ now"),
    ] {
        let masked = redact_log_diagnostic(source);
        assert_eq!(masked, expected, "{source}");
        assert_eq!(redact_log_diagnostic(&masked), masked);
    }
}

#[test]
fn unicode_neighbors_do_not_hide_evidence_emails_or_urls() {
    // Unicode word boundaries hide adjacent email addresses and URL query credentials.
    let mut failures = Vec::new();
    for (source, expected) in [
        ("contact éjane@example.com now", "contact é[email] now"),
        ("邮箱jane@example.com已泄露", "邮箱[email]已泄露"),
        ("jane@example.comé", "[email]é"),
        ("jane@example.com已泄露", "[email]已泄露"),
        (
            "见https://example.com/cb?code=Zx9QwErTy1&state=x",
            "见https://example.com/cb",
        ),
        (
            "éhttps://example.com/cb?code=Zx9QwErTy1&state=x",
            "éhttps://example.com/cb",
        ),
        ("contact jane@example.com now", "contact [email] now"),
        (
            "see https://example.com/cb?code=Zx9QwErTy1&state=x",
            "see https://example.com/cb",
        ),
    ] {
        let masked = redact_log_diagnostic(source);
        if masked != expected || redact_log_diagnostic(&masked) != masked {
            failures.push(format!("{source:?} -> {masked:?}, expected {expected:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unicode_neighbors_do_not_invalidate_basic_bodies() {
    // A case-folded letter after a Basic body is absorbed and prevents credential validation.
    for letter in ["ſ", "K", "é", "密钥"] {
        for (before, after) in [(letter, ""), ("", letter), (letter, letter)] {
            let source = format!("{before}Basic dXNlcjpwYXNzMQ=={after}");
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                redact_log_config_credentials,
            ] {
                let masked = redact(&source);
                assert_eq!(masked, format!("{before}Basic ***{after}"));
                assert_eq!(redact(&masked), masked);
            }
            let source = format!("https://example.com/share/{source}");
            assert_eq!(
                log_safe_url_reference(&source),
                "https://example.com/share/[redacted]"
            );
        }
    }
}

#[test]
fn bearer_next_line_separator_masks_the_body() {
    // U+0085 between Bearer and its body leaves the entire credential visible.
    for prefix in ["", "Authorization: "] {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            assert_eq!(
                redact(&format!("{prefix}Bearer\u{85}AbCdEfGhIjKl")),
                format!("{prefix}Bearer\u{85}***")
            );
        }
    }
    assert_eq!(
        log_safe_url_reference("https://example.com/share/Bearer%C2%85AbCdEfGhIjKl"),
        "https://example.com/share/[redacted]"
    );
}

#[test]
fn short_basic_bodies_with_escape_units_are_masked() {
    // Counting Basic escape units instead of characters leaves short valid credentials visible.
    for body in ["YTo=", r"YTo\u003d", r"YTpi\u002f", "YTpi%2F%2F"] {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            assert_eq!(redact(&format!("Basic {body}")), "Basic ***");
        }
        assert_eq!(
            log_safe_url_reference(&format!(
                "https://example.com/share/Basic%20{}",
                body.replace('\\', "%5C")
            )),
            "https://example.com/share/[redacted]"
        );
    }
}

#[test]
fn unicode_neighbors_do_not_hide_provider_credentials() {
    // A non-ASCII letter beside a provider key hides it from credential boundaries.
    for (token, expected) in [
        ("AKIAZ7QK2PL4MV8XR3NB", "AKIA***"),
        (concat!("sk_", "test_abcdefghijkl"), "sk_test_***"),
        (concat!("rk_", "test_AbCdEfGhIjKl"), "rk_test_***"),
        ("ghp_abcdefghijkl", "ghp_***"),
        ("github_pat_abcdefghijkl", "github_pat_***"),
        ("sk-AbCdEfGhIjKlMnOpQr", "sk-***"),
    ] {
        for letter in ["ſ", "K", "é", "密钥"] {
            for (before, after) in [(letter, ""), ("", letter), (letter, letter)] {
                let source = format!("{before}{token}{after}");
                for redact in [
                    redact_secrets,
                    redact_log_diagnostic,
                    redact_log_config_credentials,
                ] {
                    let masked = redact(&source);
                    assert!(
                        !masked.contains(token),
                        "credential retained: {source:?} -> {masked:?}"
                    );
                    assert_eq!(masked.replace(letter, ""), expected);
                    assert_eq!(redact(&masked), masked);
                }
                let source = format!("https://example.com/share/{source}");
                let masked = log_safe_url_reference(&source);
                assert!(
                    !masked.contains(token),
                    "URL credential retained: {source:?} -> {masked:?}"
                );
                assert_eq!(masked, "https://example.com/share/[redacted]");
                assert_eq!(log_safe_url_reference(&masked), masked);
            }
        }
    }
}
