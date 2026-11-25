use super::{log_safe_url_reference, redact_log_diagnostic};
use base64::Engine;

fn assert_url_segment_masked(segment: &str) {
    let source = format!("https://example.com/share/{segment}");
    assert_eq!(
        log_safe_url_reference(&source),
        "https://example.com/share/[redacted]"
    );
    assert_eq!(
        redact_log_diagnostic(&source),
        "https://example.com/share/[redacted]"
    );
}

#[test]
fn encoded_bearer_separators_do_not_expose_url_credentials() {
    // A percent-encoded Bearer separator leaves the credential body in URL evidence.
    for separator in ["%09", "%2520", "%2B", "%2b", "%2509", "%252B"] {
        for body in ["AbCdEfGhIjKl", "AbCdEf!GhIjKl", "AbCdEf~GhIjKl"] {
            assert_url_segment_masked(&format!("Bearer{separator}{body}"));
        }
    }
}

#[test]
fn encoded_basic_separators_do_not_expose_url_credentials() {
    // A percent-encoded Basic separator leaves a valid credential in URL evidence.
    for separator in ["%09", "%2520", "%2B", "%2b", "%2509", "%252B"] {
        for credential in ["user:pass1", ":pass", "user:"] {
            let body = base64::engine::general_purpose::STANDARD.encode(credential);
            assert_url_segment_masked(&format!("Basic{separator}{body}"));
        }
    }
}

#[test]
fn encoded_basic_padding_does_not_expose_url_credentials() {
    // Percent-encoded JSON padding makes a Basic URL credential fail validation.
    for credential in ["user:pass1", ":pass", "user:"] {
        let body = base64::engine::general_purpose::STANDARD.encode(credential);
        for padding in ["%5Cu003d", "%5Cu003D", "%253D"] {
            let body = body.replace('=', padding);
            assert_url_segment_masked(&format!("Basic%20{body}"));
        }
    }
}

#[test]
fn encoded_url_parts_without_credentials_stay_encoded() {
    // Credential detection can rewrite safe encoded path syntax or placeholders.
    for path in ["/a%2Fb/c", "/caf%C3%A9", "/broken/%E0%A4%A", "/a+b%26c=1"] {
        let source = format!("https://example.com{path}");
        assert_eq!(log_safe_url_reference(&source), source);
    }
}
