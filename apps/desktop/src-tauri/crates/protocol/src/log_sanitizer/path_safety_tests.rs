use super::shared_test_support::{
    visit_seeded_paths, visit_social_security_routes, BACKSLASH_REFERENCES,
};
use super::{
    bounded_log_diagnostic, log_safe_url_reference, redact_log_config_credentials,
    redact_log_diagnostic, redact_secrets,
};

const SINKS: [fn(&str) -> String; 5] = [
    redact_secrets,
    redact_log_diagnostic,
    redact_log_config_credentials,
    log_safe_url_reference,
    bounded_log_diagnostic,
];

#[test]
fn social_security_dash_forms_are_private_in_every_sink() {
    visit_social_security_routes(|route| {
        for redact in SINKS {
            for source in [route, &format!("https://example.com{route}")] {
                assert!(redact(source).contains("[redacted]"), "{source:?}");
            }
        }
    });
}

#[test]
fn backslash_references_mask_private_segments_without_recursion() {
    for source in BACKSLASH_REFERENCES {
        for redact in SINKS {
            let masked = redact(source);
            assert_ne!(masked, source, "{source:?}");
            for private in ["user:pass@db", "a:b@c", "123-45-6789", "%252525252541"] {
                assert!(!masked.contains(private), "{source:?} -> {masked:?}");
            }
        }
    }
}

#[test]
fn seeded_paths_and_prose_have_bounded_panic_free_output() {
    visit_seeded_paths(|case, source| {
        for redact in SINKS {
            let masked = std::panic::catch_unwind(|| redact(source))
                .unwrap_or_else(|_| panic!("case {case}: {source:?}"));
            assert!(
                masked.len() <= source.len() * 4 + 64,
                "case {case}: {source:?}"
            );
        }
    });
}
