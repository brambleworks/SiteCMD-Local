use super::shared_test_support::{
    visit_compatibility_credentials, visit_deep_escapes, visit_nested_separator_credentials,
    visit_opaque_runs_and_credentials, visit_unusual_social_security_routes,
    visit_version_shaped_emails, visit_word_slugs, VERSION_SHAPED_EMAILS,
};
use super::{log_safe_page_url, looks_like_opaque_token};

#[test]
fn boundary_free_mcp_masks_preserve_page_urls_in_log_sinks() {
    // Broad MCP token masks can corrupt ordinary URL paths.
    for path in [
        "/blog/how-to-ask-for-a-raise-without-fear",
        "/products/standing-desk-converter-adjustable",
        "/docs/Disk-Encryption-Overview",
        "/highs_and_lows_2024",
        "/blog/top-10-ways-to-improve-your-website-speed",
        "/blog/10-ways-to-build-a-faster-website-in-2026",
    ] {
        let address = format!("https://example.com{path}");
        for redact in [
            log_safe_page_url,
            super::redact_log_diagnostic,
            super::redact_secrets,
        ] {
            assert_eq!(redact(&address), address);
        }
    }
}

#[test]
fn short_credentials_remain_private_through_nested_separator_encoding() {
    visit_nested_separator_credentials(|route| {
        let address = format!("https://example.com{route}");
        assert_ne!(log_safe_page_url(&address), address, "{route}");
    });
}

#[test]
fn compatibility_credentials_and_tokens_remain_private() {
    visit_compatibility_credentials(|route| {
        let address = format!("https://example.com{route}");
        assert_ne!(
            log_safe_page_url(&address),
            url::Url::parse(&address).unwrap().as_str()
        );
    });
}

#[test]
fn decoded_word_slugs_survive_url_sanitizing() {
    visit_word_slugs(|route| {
        let address = format!("https://example.com{route}");
        let expected = url::Url::parse(&address).unwrap().to_string();
        assert_eq!(log_safe_page_url(&address), expected, "{route}");
    });
}

#[test]
fn decoded_opaque_runs_and_credentials_remain_private() {
    visit_opaque_runs_and_credentials(|route, encoded, opaque| {
        let address = format!("https://example.com{route}");
        if opaque {
            assert!(looks_like_opaque_token(encoded), "{encoded}");
            assert!(log_safe_page_url(&address).contains("[redacted]"));
        } else {
            assert_ne!(log_safe_page_url(&address), address);
        }
    });
}

#[test]
fn version_shaped_email_domains_never_receive_the_package_exemption() {
    for email in VERSION_SHAPED_EMAILS {
        assert!(super::contains_email(email));
        assert!(!super::package_coordinate(email));
    }
    visit_version_shaped_emails(|route| {
        let address = format!("https://example.com{route}");
        assert_ne!(log_safe_page_url(&address), address, "{route}");
    });
}

#[test]
fn nested_escapes_past_the_decode_limit_are_opaque() {
    visit_deep_escapes(|route, value| {
        let address = format!("https://example.com{route}");
        assert!(log_safe_page_url(&address).contains("[redacted]"));
        let query = format!("https://example.com/docs?{value}");
        assert!(
            super::log_safe_page_url_for_site(&query, Some("https://example.com"))
                .contains("[redacted]")
        );
    });
}

#[test]
fn userinfo_path_segments_and_social_security_separators_are_redacted() {
    for value in ["user:pass@host", "admin:hunter2@db"] {
        let mut encoded = value.to_owned();
        for _ in 0..4 {
            for path in [
                format!("/{encoded}"),
                format!("//{encoded}"),
                format!("/x//{encoded}/backup"),
            ] {
                let address = format!("https://example.com{path}");
                assert!(
                    log_safe_page_url(&address).contains("[redacted]"),
                    "{address}"
                );
            }
            encoded = encoded
                .replace('%', "%25")
                .replace(':', "%3A")
                .replace('@', "%40");
        }
    }
    visit_unusual_social_security_routes(|route| {
        assert!(log_safe_page_url(&format!("https://example.com{route}")).contains("[redacted]"));
    });
}
