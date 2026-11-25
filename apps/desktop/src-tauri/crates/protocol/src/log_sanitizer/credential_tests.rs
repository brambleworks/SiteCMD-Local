use super::shared_test_support::{assert_redaction_work_linear, generic_linear_bound_cases};
use super::{
    bounded_log_diagnostic, redact_log_config_credentials, redact_log_diagnostic, redact_secrets,
};
use base64::Engine;

#[test]
fn config_pem_context_precedes_embedded_token_masks() {
    // Embedded token masks can break PEM body recognition and expose adjacent key bytes.
    let body = format!("{}AIza{}+/=", "aB3+".repeat(4), "cD4".repeat(12));
    for marker in ["", "# ", "// "] {
        let source = format!(
            "{marker}-----BEGIN {}-----\n{marker}{body}\nconst ready = true;",
            "PRIVATE KEY"
        );
        let rendered = super::redact_log_config_credentials(&source);
        assert!(
            !rendered.contains("aB3+"),
            "adjacent PEM body bytes escaped"
        );
        assert!(rendered.contains("const ready = true;"));
    }
}

#[test]
fn summary_pem_comments_keep_bodies_private() {
    // Summary redaction misses commented and unterminated private key bodies.
    for marker in ["#", "//", ";", "*", "--", ">"] {
        for terminated in [false, true] {
            let body = "aB3+".repeat(16);
            let mut source = format!(
                "{marker} -----BEGIN {}-----\n{marker} {body}\n",
                "PRIVATE KEY"
            );
            if terminated {
                source.push_str(&format!("{marker} -----END {}-----\n", "PRIVATE KEY"));
            }
            source.push_str("const ready = true;");
            for rendered in [redact_secrets(&source), redact_log_diagnostic(&source)] {
                assert!(!rendered.contains(&body), "commented PEM summary leaked");
                assert!(rendered.contains("const ready = true;"));
            }
        }
    }
}

#[test]
fn authorization_masks_tokens_and_keeps_schemes() {
    for scheme in ["Bearer", "Basic"] {
        let body = if scheme == "Basic" {
            base64::engine::general_purpose::STANDARD
                .encode(format!("user:{}", "opaque-".repeat(4)))
        } else {
            "opaque-".repeat(4)
        };
        let source = format!("Authorization: {scheme} {body}");
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            super::redact_log_config_credentials,
        ] {
            let rendered = redact(&source);
            assert!(rendered.contains(scheme), "authorization scheme lost");
            assert!(!rendered.contains("opaque-"), "authorization token leaked");
            assert!(!rendered.contains(&body), "authorization body leaked");
        }
    }
}

#[test]
fn comment_pem_bodies_mask_without_hiding_context() {
    let body = "aB3+".repeat(16);
    for marker in ["#", "//", ";", "*", "--", ">"] {
        for terminated in [false, true] {
            let mut lines = vec![
                format!("{marker} -----BEGIN {}-----", "PRIVATE KEY"),
                format!("{marker} {body}"),
                format!("{marker} {}", "aB3+".repeat(4)),
            ];
            if terminated {
                lines.push(format!("{marker} -----END {}-----", "PRIVATE KEY"));
            }
            lines.push("const ready = true;".into());
            lines.extend((0..10).map(|i| format!("const visible{i} = true;")));
            let source = lines.join("\n");
            for redact in [
                redact_secrets,
                redact_log_diagnostic,
                super::redact_log_config_credentials,
            ] {
                let rendered = redact(&source);
                assert!(
                    !rendered.contains("aB3+"),
                    "PEM body leaked behind {marker}"
                );
                assert!(rendered.contains("const visible9 = true;"));
            }
        }
    }
}

#[test]
fn authorization_masks_keep_harmless_prose_and_missing_token_diagnostics() {
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        super::redact_log_config_credentials,
    ] {
        for text in [
            "Basic features included",
            "Basic Membership | Acme Gym",
            "Authorization: Bearer undefined",
        ] {
            assert_eq!(redact(text), text);
        }
        let body = "qR7zP9".repeat(8);
        for (scheme, body) in [
            ("Bearer", body.clone()),
            (
                "Basic",
                base64::engine::general_purpose::STANDARD.encode(format!("user:{body}")),
            ),
        ] {
            for header in ["Authorization", "Proxy-Authorization"] {
                assert!(!redact(&format!("{header}: {scheme} {body}")).contains(&body));
            }
        }
    }
}

#[test]
fn authorization_header_forms_mask_tokens_in_every_sink() {
    let body = ["9f8e7d6c", "5b4a3921"].concat();
    let short_body = ["dXNl", "cjpw", "YXNz"].concat();
    let forms = [
        format!("Authorization: Bearer {body}"),
        format!(r#"{{"Authorization": "Bearer {body}"}}"#),
        format!("authorization: 'Bearer {body}'"),
        format!(r#"'Authorization': 'Basic {short_body}'"#),
        format!(r#"Authorization="Basic {short_body}""#),
        format!(r#"("Authorization", "Bearer {body}")"#),
        format!(r#"{{"authorization": "Bearer {short_body}"}}"#),
        format!("headers:\n  Authorization: 'Bearer {short_body}'\n"),
        format!("Bearer {body}"),
        format!("Basic {short_body}"),
        format!("Bearer {}", "opaque-".repeat(4)),
    ];
    let mut leaks = Vec::new();
    for (form, source) in forms.iter().enumerate() {
        for (sink, redact) in [
            redact_secrets,
            redact_log_diagnostic,
            super::redact_log_config_credentials,
        ]
        .into_iter()
        .enumerate()
        {
            let masked = redact(source);
            if masked.contains(&body) || masked.contains(&short_body) || masked.contains("opaque-")
            {
                leaks.push((form, sink));
            }
            assert!(masked.contains("Bearer") || masked.contains("Basic"));
        }
    }
    assert!(leaks.is_empty(), "Authorization forms escaped: {leaks:?}");
}

#[test]
fn single_part_url_userinfo_is_masked_in_every_sink() {
    let body = ["private", "url", "credential"].join("-");
    let source = format!("git+https://{body}@git.example.test/acme/ui.git");
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        super::redact_log_config_credentials,
    ] {
        let masked = redact(&source);
        assert!(!masked.contains(&body), "URL credential escaped: {masked}");
        assert!(masked.contains("git.example.test/acme/ui.git"));
        assert_eq!(redact(&masked), masked);
        for text in [
            "ssh://git@github.com/acme/ui.git",
            "docker://alpine@sha256:0123456789abcdef",
        ] {
            assert_eq!(redact(text), text);
        }
    }
}

#[test]
fn provider_bodies_never_reach_log_diagnostics() {
    // Generic token masks can miss uppercase prefixes, repeated credentials, or PEM bodies.
    let mut leaked = Vec::new();
    let pem_begin = format!("-----BEGIN {}-----\n", "PRIVATE KEY");
    let pem_end = format!("\n-----END {}-----", "PRIVATE KEY");
    for (prefix, body) in [
        ("rk_live_", "aB3".repeat(8)),
        ("rk_test_", "aB3".repeat(8)),
        ("sk-", "aB3".repeat(8)),
        ("sk-proj-", "aB3_".repeat(6)),
        ("sk-ant-", "aB3".repeat(8)),
        ("AIza", "aB3_".repeat(6)),
        ("AKIA", "A1B2".repeat(4)),
        (pem_begin.as_str(), "aB3+".repeat(32)),
    ] {
        let suffix = if prefix.starts_with("-----BEGIN") {
            pem_end.as_str()
        } else {
            ""
        };
        for prefix in [prefix.to_string(), prefix.to_uppercase()] {
            let token = format!("{prefix}{body}{suffix}");
            for source in [
                format!("const value = '{token}';"),
                format!("{token} {token}"),
            ] {
                for redacted in [redact_secrets(&source), redact_log_diagnostic(&source)] {
                    if redacted.contains(&body)
                        || (suffix.is_empty()
                            && redacted != source.replace(&token, &format!("{prefix}***")))
                    {
                        leaked.push(prefix.clone());
                    }
                }
            }
        }
    }
    assert!(leaked.is_empty(), "credential bodies survived: {leaked:?}");
}

#[test]
fn provider_masking_is_idempotent() {
    // A masked credential can be rewritten on a second redaction pass.
    let mut samples = Vec::new();
    for (prefix, body) in [
        ("rk_live_", "aB3".repeat(8)),
        ("sk-proj-", "aB3_".repeat(6)),
        ("ghp_", "aB3".repeat(12)),
        ("AIza", "aB3_".repeat(8) + "aB3"),
    ] {
        samples.push(format!("const value = '{prefix}{body}';"));
        samples.push(format!("https://example.com/{prefix}{body}"));
    }
    samples.push(format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----",
        "PRIVATE KEY",
        "aB3+".repeat(16),
        "PRIVATE KEY"
    ));
    for source in samples {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
            bounded_log_diagnostic,
        ] {
            let once = redact(&source);
            assert_eq!(redact(&once), once, "non-idempotent masking for {source:?}");
        }
    }
}

#[test]
fn secret_properties_linear_bound() {
    // Repeated credentials or encoded input can make redaction take superlinear time.
    for (field, sources) in generic_linear_bound_cases() {
        for (name, redact) in [
            ("secrets", redact_secrets as fn(&str) -> String),
            ("log", redact_log_diagnostic),
            ("configuration", redact_log_config_credentials),
            ("bounded log", bounded_log_diagnostic),
        ] {
            assert_redaction_work_linear(redact, name, field, &sources);
        }
    }
}

#[test]
fn log_diagnostic_redacts_urls_emails_and_provider_tokens() {
    // A generic provider credential can survive URL and email cleanup.
    for body in [
        format!("rk_live_{}", "aB3".repeat(12)),
        format!("rk_live_{}", "cD4".repeat(12)),
    ] {
        let safe = redact_log_diagnostic(&format!(
            "Failed for person@example.com at https://example.com/reset/short-token?token=supersecret password={body}.",
        ));
        assert_eq!(
            safe,
            "Failed for [email] at https://example.com/reset/[redacted] password=rk_live_***."
        );
    }
}

#[test]
fn bounded_log_diagnostic_scrubs_and_caps_untrusted_diagnostics() {
    // A bounded log diagnostic can preserve a generic provider credential or exceed its cap.
    for body in [
        format!("rk_test_{}", "aB3".repeat(12)),
        format!("rk_test_{}", "cD4".repeat(12)),
    ] {
        let unsafe_detail = format!(
            "request to https://person:pass@example.com/reset/short-token?api_key=secret for person@example.com failed: password={body}\ncontext {}",
            "x".repeat(1_000)
        );
        let safe = bounded_log_diagnostic(&unsafe_detail);

        assert!(safe.chars().count() <= super::ISSUE_EVIDENCE_TEXT_MAX_CHARS + 1);
        assert!(safe.ends_with('…'));
        for secret in [
            "person:pass",
            "short-token",
            "secret",
            "person@example.com",
            body.as_str(),
        ] {
            assert!(!safe.contains(secret), "secret leaked in: {safe}");
        }
        assert!(safe.contains("https://example.com/reset/[redacted]"));
    }
}

#[test]
fn generic_credential_fragments_are_masked_in_every_log_sink() {
    // A missing generic mask can leave six credential bytes in the log.
    let mut witnesses: Vec<_> = [
        ("sk-", "aB3".repeat(8)),
        ("sk-proj-", "aB3_".repeat(6)),
        ("sk-svcacct-", "aB3_".repeat(6)),
        ("sk-admin-", "aB3_".repeat(6)),
        ("sk-ant-", "aB3".repeat(8)),
        ("sk_live_", "aB3".repeat(8)),
        ("sk_test_", "aB3".repeat(8)),
        ("rk_live_", "aB3".repeat(8)),
        ("rk_test_", "aB3".repeat(8)),
        ("AKIA", "A1B2".repeat(4)),
        ("AIza", "aB3_".repeat(8) + "aB3"),
        ("ghp_", "aB3".repeat(12)),
        ("gho_", "aB3".repeat(12)),
        ("ghu_", "aB3".repeat(12)),
        ("ghs_", "aB3".repeat(12)),
        ("ghr_", "aB3".repeat(12)),
        ("github_pat_", "aB3_".repeat(20) + "Z9"),
    ]
    .into_iter()
    .map(|(prefix, body)| (format!("{prefix}{body}"), body))
    .collect();
    let pem_body = "aB3+".repeat(32);
    witnesses.push((
        format!(
            "-----BEGIN {0}-----\n{pem_body}\n-----END {0}-----",
            "PRIVATE KEY"
        ),
        pem_body,
    ));
    let body = "qR7zP9".repeat(8);
    let team = ["T", "9pR2zK7"].concat();
    let channel = ["B", "5xJ7tV9"].concat();
    let slack = format!("https://hooks.slack.com/services/{team}/{channel}/{body}");
    let basic_body = base64::engine::general_purpose::STANDARD.encode(format!("user:{body}"));
    witnesses.extend([
        (slack.clone(), body.clone()),
        (slack.clone(), team),
        (slack, channel),
        (format!("ya29.{body}"), body.clone()),
        (format!("1//{body}"), body.clone()),
        (format!("Authorization: Bearer {body}"), body.clone()),
        (
            format!("Proxy-Authorization: Basic {basic_body}"),
            basic_body,
        ),
    ]);
    for (source, body) in witnesses {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let once = redact(&source);
            assert!(!once.contains(&body), "credential body escaped: {once}");
            for fragment in body.as_bytes().windows(6) {
                let fragment = std::str::from_utf8(fragment).unwrap();
                assert!(
                    !once.contains(fragment),
                    "six credential body bytes escaped: {once}"
                );
            }
            assert_eq!(redact(&once), once, "non-idempotent mask");
        }
    }
}
