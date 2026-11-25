use super::{redact_log_config_credentials, redact_log_diagnostic, redact_secrets};
use base64::Engine;

fn credential() -> String {
    base64::engine::general_purpose::STANDARD.encode(["user", ":", "pass"].concat())
}

fn token() -> String {
    ["aB3dE5", "fG7hI9"].concat()
}

fn assert_masked(source: &str, expected: &str) {
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        let masked = redact(source);
        assert_eq!(masked, expected);
        assert_eq!(redact(&masked), masked);
    }
}

#[test]
fn repeated_basic_plus_schemes_do_not_leak_credentials() {
    assert_masked(&format!("Basic+Basic+{}", credential()), "Basic+Basic+***");
}

#[test]
fn repeated_basic_percent_space_schemes_do_not_leak_credentials() {
    assert_masked(
        &format!("Basic%20Basic%20{}", credential()),
        "Basic%20Basic%20***",
    );
}

#[test]
fn basic_aligned_slash_suffix_is_masked_with_credential() {
    assert_masked(&format!("Basic {}/next", credential()), "Basic ***");
}

#[test]
fn basic_aligned_plus_suffix_is_masked_with_credential() {
    assert_masked(&format!("Basic {}+x", credential()), "Basic ***");
}

#[test]
fn bearer_line_feed_separator_does_not_leak_token() {
    assert_masked(
        &format!("Authorization: Bearer\n{}", token()),
        "Authorization: Bearer\n***",
    );
}

#[test]
fn bearer_folded_crlf_separator_does_not_leak_token() {
    assert_masked(
        &format!("Authorization: Bearer\r\n {}", token()),
        "Authorization: Bearer\r\n ***",
    );
}

#[test]
fn bearer_nonbreaking_space_separator_does_not_leak_token() {
    assert_masked(
        &format!("Authorization: Bearer\u{a0}{}", token()),
        "Authorization: Bearer\u{a0}***",
    );
}

#[test]
fn bearer_line_feed_short_token_body_is_masked_instead_of_prose() {
    assert_masked("Bearer\nshort-token-body", "Bearer\n***");
}

#[test]
fn unicode_case_folded_basic_scheme_keeps_its_mask() {
    assert_masked(&format!("ba\u{17f}ic {}", credential()), "ba\u{17f}ic ***");
}
