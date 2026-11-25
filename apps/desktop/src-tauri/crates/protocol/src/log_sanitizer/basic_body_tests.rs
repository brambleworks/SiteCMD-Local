use super::shared_test_support::{
    basic_credential_routes, visit_basic_separator_cases, visit_short_basic_cases,
    visit_short_basic_routes,
};
use super::{
    log_safe_url_reference, redact_log_config_credentials, redact_log_diagnostic, redact_secrets,
};

#[test]
fn basic_whitespace_and_encoded_separators_mask_credentials() {
    visit_basic_separator_cases(|source, expected, route| {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
            super::bounded_log_diagnostic,
        ] {
            assert_eq!(redact(source), expected);
        }
        assert!(!log_safe_url_reference(route).contains("dXNlcjpwYXNz"));
    });
}

#[test]
fn short_basic_bodies_do_not_hide_following_credentials() {
    // A kept Basic body consumes the following scheme and leaves its credential visible.
    let mut failures = Vec::new();
    visit_short_basic_cases(|source, expected| {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let masked = redact(source);
            if masked != expected || redact(&masked) != masked {
                failures.push(format!("{source:?} -> {masked:?}, expected {expected:?}"));
            }
        }
        visit_short_basic_routes(source, |route| {
            let address = format!("https://example.com{route}");
            let masked = log_safe_url_reference(&address);
            if masked != "https://example.com/share/[redacted]" {
                failures.push(format!("{address:?} -> {masked:?}, route must be masked"));
            }
        });
    });
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn escaped_and_doubled_separators_do_not_hide_basic_credentials() {
    let mut failures = Vec::new();
    for (source, expected) in [
        (r"Basic \u002bBasic dXNlcjpwYXNz", r"Basic \u002bBasic ***"),
        (
            r"Basic \u002B\u002BBasic dXNlcjpwYXNz",
            r"Basic \u002B\u002BBasic ***",
        ),
        ("Basic %2BBasic dXNlcjpwYXNz", "Basic %2BBasic ***"),
        ("Basic ++Basic++dXNlcjpwYXNz", "Basic ++Basic++***"),
        ("Basic++dXNlcjpwYXNz", "Basic++***"),
    ] {
        for neighbor in ["", "é", "密钥"] {
            let source = format!("{neighbor}{source}");
            let expected = format!("{neighbor}{expected}");
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                redact_log_config_credentials,
            ] {
                let masked = redact(&source);
                if masked != expected || redact(&masked) != masked {
                    failures.push(format!("{source:?} -> {masked:?}, expected {expected:?}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn basic_credentials_behind_kept_bodies_are_private_in_every_sink() {
    let mut failures = Vec::new();
    for route in basic_credential_routes() {
        let address = format!("https://example.com{route}");
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
            log_safe_url_reference,
            super::bounded_log_diagnostic,
        ] {
            for source in [&address, &route] {
                let masked = redact(source);
                if masked == *source
                    || ["dXNlcjpwYXNz", "YTpi", "QWxhZGRpbjpvcGVuIHNlc2FtZQ"]
                        .iter()
                        .any(|body| masked.contains(body))
                {
                    failures.push(format!("{route} -> {masked}"));
                }
                assert_eq!(redact(&masked), masked);
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn arbitrary_length_kept_basic_bodies_do_not_hide_text_credentials() {
    for length in [59, 120, 4096, 65536] {
        for separator in ["+", "%2B", "%2b", "%3D", "%2F", r"\u002B", r"\/"] {
            for neighbor in ["", "é", "密钥"] {
                let source = format!(
                    "{neighbor}Basic+{}{separator}Basic+dXNlcjpwYXNz",
                    "x".repeat(length)
                );
                for redact in [
                    redact_secrets,
                    redact_log_diagnostic,
                    redact_log_config_credentials,
                ] {
                    let masked = redact(&source);
                    assert!(
                        !masked.contains("dXNlcjpwYXNz"),
                        "length={length} separator={separator}"
                    );
                    assert_eq!(redact(&masked), masked);
                }
            }
        }
    }
}
