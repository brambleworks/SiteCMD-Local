// A credential format recognized in served pages fires on a real minified bundle or a documentation sample, so every site that ships it gets a false exposed-key finding.

use sitecmd_engine::checks::security::{exposed_keys::ExposedApiKeysCheck, key_pattern_services};
use sitecmd_engine::checks::{Check, CheckStatus, PageContext, Severity};

#[path = "support/bundle_corpus.rs"]
mod bundle_corpus;

fn corpus() -> Vec<(String, String)> {
    bundle_corpus::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
}

#[test]
fn every_credential_format_is_silent_on_the_bundle_and_documentation_corpus() {
    let failures: Vec<_> = corpus()
        .into_iter()
        .filter_map(|(name, text)| {
            let services = key_pattern_services(&text);
            (!services.is_empty()).then_some((name, services))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "false exposed-key matches: {failures:?}"
    );
}

#[test]
fn corpus_files_match_their_recorded_hashes_and_sizes() {
    drop(corpus());
}

#[test]
fn near_misses_and_uniform_body_placeholders_are_not_credentials() {
    let mut negatives = vec![
        "npm_config_user_agent".to_owned(),
        "npm_package_dependencies_react_dom".to_owned(),
        format!("rk_live_{}", "aB3".repeat(6) + "a"),
        format!("github_pat_{}", "aB3".repeat(7)),
        format!("identifier_glpat-{}", "aB3_".repeat(5)),
        format!("npm_{}", "aB3".repeat(13)),
        format!("identifier_npm_{}", "aB3".repeat(12)),
        format!("npm_{}_suffix", "aB3".repeat(12)),
    ];
    for kind in ["CERTIFICATE", "PUBLIC KEY"] {
        negatives.push(format!(
            "-----BEGIN {kind}-----\n{}\n-----END {kind}-----",
            "aB3+".repeat(32)
        ));
    }
    for (prefix, length) in [
        ("sk-", 24),
        ("sk-proj-", 24),
        ("sk-svcacct-", 24),
        ("sk-admin-", 24),
        ("sk-ant-", 24),
        ("sk_live_", 24),
        ("sk_test_", 24),
        ("pk_live_", 24),
        ("pk_test_", 24),
        ("AKIA", 16),
        ("AIza", 35),
        ("ghp_", 36),
        ("gho_", 36),
        ("ghu_", 36),
        ("ghs_", 36),
        ("ghr_", 36),
        ("xoxb-", 24),
        ("xoxa-", 24),
        ("xoxp-", 24),
        ("xoxr-", 24),
        ("xoxs-", 24),
        ("SK", 32),
        ("key-", 32),
        ("rk_live_", 24),
        ("github_pat_", 82),
        ("glpat-", 20),
        ("npm_", 36),
    ] {
        let character = if prefix == "AKIA" {
            "A"
        } else if prefix == "SK" {
            "a"
        } else {
            "x"
        };
        negatives.push(format!("{prefix}{}", character.repeat(length)));
    }
    for text in negatives {
        assert!(key_pattern_services(&text).is_empty(), "near miss: {text}");
    }
}

#[test]
fn new_formats_in_inline_scripts_are_found_once_and_masked_to_four_characters() {
    let mut tokens = vec![
        (
            "GitHub Fine-Grained Token",
            format!("github_pat_{}", "aB3_".repeat(20) + "Z9"),
        ),
        (
            "Stripe Restricted (live)",
            format!("rk_live_{}", "aB3".repeat(8)),
        ),
        ("GitLab Token", format!("glpat-{}", "aB3_-".repeat(4))),
        ("npm Token", format!("npm_{}", "aB3".repeat(12))),
    ];
    for kind in [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        tokens.push((
            "Private Key (PEM)",
            format!(
                "-----BEGIN {kind}-----\n{}\n-----END {kind}-----",
                "aB3+".repeat(32)
            ),
        ));
    }
    for (service, token) in tokens {
        assert_eq!(key_pattern_services(&token), vec![service], "{service}");
        for delivered in [
            token.clone(),
            token.replace('\n', "\\n"),
            token.replace('\n', "\\n\" + \""),
        ] {
            let page = PageContext {
                evaluation_time: "2026-08-05T00:00:00Z".parse().unwrap(),
                url: url::Url::parse("https://example.com").unwrap(),
                response_headers: http::HeaderMap::new(),
                status_code: 200,
                body: format!("<script>const credential = `{delivered}`;</script>"),
                is_localhost: false,
                is_strict_localhost: false,
                http_version: None,
                body_lower_cache: std::sync::OnceLock::new(),
            };
            let results = ExposedApiKeysCheck.run(&page);
            assert_eq!(results.len(), 1, "{service}");
            let result = &results[0];
            assert_eq!(result.status, CheckStatus::Fail, "{service}");
            assert_eq!(result.severity, Severity::High, "{service}");
            assert!(result
                .description
                .contains("secret-key formats for 1 service"));
            assert!(result.description.contains(&format!("{}***", &token[..4])));
            assert_eq!(
                result.raw_data.as_ref().unwrap()["exposed_keys"],
                serde_json::json!([format!("{service}: {}***", &token[..4])])
            );
            let serialized = serde_json::to_string(result).unwrap();
            assert!(!serialized.contains(&token), "unmasked {service}");
            assert!(!serialized.contains(&"aB3+".repeat(8)), "unmasked PEM body");
            assert_eq!(
                result.description.matches(&format!("{service} (")).count(),
                1
            );
        }
    }
}

#[test]
fn a_bounded_placeholder_does_not_hide_the_adjacent_credential() {
    for (service, prefix, body, placeholder) in [
        ("AWS Access Key", "AKIA", "A1B2".repeat(4), "A".repeat(16)),
        ("npm Token", "npm_", "aB3".repeat(12), "x".repeat(36)),
    ] {
        let text = format!("{prefix}{placeholder} {prefix}{body}");
        assert_eq!(key_pattern_services(&text), vec![service], "{service}");
    }
}

#[test]
fn github_fine_grained_tokens_glued_to_identifiers_are_not_credentials() {
    let glued = format!("identifier_github_pat_{}", "aB3_".repeat(20) + "Z9");
    assert!(key_pattern_services(&glued).is_empty());
}

#[test]
fn a_body_differing_from_a_placeholder_by_one_character_is_a_credential() {
    let token = format!("glpat-{}1", "x".repeat(19));
    assert_eq!(key_pattern_services(&token), vec!["GitLab Token"]);
}

#[test]
fn a_private_header_followed_by_source_or_public_armor_is_not_key_material() {
    let source = format!(
        "const privateHeader = '-----BEGIN PRIVATE KEY-----';\n{}\nconst publicHeader = '-----BEGIN PUBLIC KEY-----';",
        "ordinaryCode();".repeat(10)
    );
    assert!(key_pattern_services(&source).is_empty());
}
