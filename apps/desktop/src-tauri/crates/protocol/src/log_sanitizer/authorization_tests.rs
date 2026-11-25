use super::{redact_log_config_credentials, redact_log_diagnostic, redact_secrets};
use base64::Engine;

#[test]
fn serialized_authorization_schemes_mask_short_and_letters_only_bodies() {
    let mut leaks = Vec::new();
    for (scheme, bodies) in [
        (
            "Bearer",
            vec![
                ["9f8e7d", "6c5b4a"].concat(),
                ["AbCdEf", "GhIjKl"].concat(),
                format!("{}!{}", ["00Dxx", "0000001gPL"].concat(), "aB3".repeat(8)),
                format!(r"{}\/{}", "aB3".repeat(2), "cD4".repeat(3)),
            ],
        ),
        (
            "Basic",
            vec![
                ["dXNl", "cjpw", "YXNz"].concat(),
                ["bGxh", "Omxs", "YWFh"].concat(),
            ],
        ),
    ] {
        for body in bodies {
            for source in [
                format!("Authorization: {scheme} {body}"),
                format!(r#"{{"Authorization": "{scheme} {body}"}}"#),
                format!("authorization: '{scheme} {body}'"),
                format!(r#"'Authorization': '{scheme} {body}'"#),
                format!(r#"Authorization="{scheme} {body}""#),
                format!(r#"("Authorization", "{scheme} {body}")"#),
                format!("headers:\n  Authorization: '{scheme} {body}'\n"),
                format!(r#""Host: x\nAuthorization: {scheme} {body}""#),
                format!(r"send: b'GET / HTTP/1.1\r\nAuthorization: {scheme} {body}\r\n'"),
                format!("HTTP_AUTHORIZATION={scheme} {body}"),
                format!(r#"{{\"Authorization\":\"{scheme} {body}\"}}"#),
                format!("map[Authorization:[{scheme} {body}]]"),
                format!(r#"{{"Authorization":["{scheme} {body}"]}}"#),
                format!(r#""Authorization" => "{scheme} {body}""#),
                format!("[Authorization] => {scheme} {body}"),
                format!("Authorization: `{scheme} {body}`"),
                format!("authorization={scheme}%20{body}"),
                format!("authorization={scheme}+{body}"),
                format!("Authorization:{scheme}\t{body}"),
                format!("Proxy-Authorization: {scheme} {body}"),
                format!("{scheme} {body}"),
            ] {
                for (sink, redact) in [
                    redact_secrets,
                    redact_log_diagnostic,
                    redact_log_config_credentials,
                ]
                .into_iter()
                .enumerate()
                {
                    let masked = redact(&source);
                    if body
                        .as_bytes()
                        .windows(6)
                        .any(|part| masked.contains(std::str::from_utf8(part).unwrap()))
                    {
                        leaks.push((scheme, source.clone(), sink));
                    }
                    assert!(masked.contains(scheme));
                    assert_eq!(masked, source.replace(&body, "***"));
                    assert_eq!(redact(&masked), masked);
                }
            }
        }
    }
    for body in [
        format!("{}~{}", "aB3".repeat(2), "cD4".repeat(3)),
        format!("{}%2B{}", "aB3".repeat(2), "cD4".repeat(3)),
        format!("{}!{}", ["00Dxx", "0000001gPL"].concat(), "aB3".repeat(8)),
        format!(r"{}\/{}", "aB3".repeat(2), "cD4".repeat(3)),
    ] {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let masked = redact(&format!("Bearer {body}"));
            if masked.contains("cD4")
                || body
                    .as_bytes()
                    .windows(6)
                    .any(|part| masked.contains(std::str::from_utf8(part).unwrap()))
            {
                leaks.push(("Bearer", "body alphabet".into(), 0));
            }
            assert_eq!(redact(&masked), masked);
        }
    }
    assert!(leaks.is_empty(), "scheme body leaks: {leaks:?}");
}

#[test]
fn bearer_query_delimiter_preserves_following_parameters() {
    let body = ["9f8e7d", "6c5b4a"].concat();
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        let masked = redact(&format!("Bearer%20{body}&next=/home"));
        assert_eq!(masked, "Bearer%20***&next=/home");
        assert_eq!(redact(&masked), masked);
    }
}

#[test]
fn bearer_userinfo_mask_is_idempotent() {
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        let masked = redact("Bearer x://a,b@host");
        assert_eq!(masked, "Bearer x://***@host");
        assert_eq!(redact(&masked), masked);
    }
}

#[test]
fn basic_encoded_suffix_masks_valid_unpadded_credential_whole() {
    let body = base64::engine::general_purpose::STANDARD.encode(["user", ":pass"].concat());
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        let masked = redact(&format!("Basic%20{body}%2Fnext"));
        assert_eq!(masked, "Basic%20***");
        assert_eq!(redact(&masked), masked);
    }
}

fn assert_basic_unicode_unit(credential: &str, unit: char, escapes: &[&str]) {
    let body = base64::engine::general_purpose::STANDARD.encode(credential);
    assert!(body.contains(unit));
    for escape in escapes {
        let encoded = body.replace(unit, escape);
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let source = format!(r#"{{"Authorization":"Basic {encoded}"}}"#);
            let masked = redact(&source);
            assert_eq!(masked, source.replace(&encoded, "***"), "unit {escape}");
            assert_eq!(redact(&masked), masked);
        }
    }
}

#[test]
fn basic_unicode_padding_masks_whole_body() {
    assert_basic_unicode_unit(&["user", ":pass1"].concat(), '=', &[r"\u003d", r"\u003D"]);
}

#[test]
fn basic_unicode_plus_masks_whole_body() {
    assert_basic_unicode_unit(
        &["deploy", ":pw0000x>"].concat(),
        '+',
        &[r"\u002b", r"\u002B"],
    );
}

#[test]
fn basic_unicode_slash_masks_whole_body() {
    assert_basic_unicode_unit(
        &["deploy", ":pw0000x?"].concat(),
        '/',
        &[r"\u002f", r"\u002F"],
    );
}

#[test]
fn basic_prose_and_missing_bearer_diagnostics_remain_readable() {
    for text in [
        "Basic features included",
        "Basic Membership | Acme Gym",
        "Requires authorization, basic authentication for admins",
        "Basic state-of-the-art tooling",
        "Basic config/settings.json",
        r#"class="ui basic card-container-wrapper""#,
        "Plan: Basic\n10GB-storage-included",
        "Authorization: Bearer undefined",
        "Authorization: Bearer undefined.",
        "Authorization: Bearer null",
    ] {
        for redact in [
            redact_secrets,
            redact_log_diagnostic,
            redact_log_config_credentials,
        ] {
            let masked = redact(text);
            assert_eq!(masked, text);
            assert_eq!(redact(&masked), masked);
        }
    }
}

#[test]
fn url_userinfo_masks_optional_schemes() {
    let body = ["9f8e7d", "6c5b4a"].concat();
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        for source in [
            format!("clone ${{PROTO}}://{body}@host/path"),
            format!(r#""://{body}@host""#),
            format!("docker://user:{body}@registry.test/image"),
        ] {
            let masked = redact(&source);
            assert!(!masked.contains(&body), "userinfo leaked: {masked}");
            assert_eq!(redact(&masked), masked);
        }
    }
}

#[test]
fn tagged_docker_digest_references_remain_readable() {
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        for source in [
            "docker://node:20-alpine@sha256:0123456789abcdef",
            "uses: docker://alpine:3.19@sha256:0123456789abcdef",
        ] {
            let masked = redact(source);
            assert_eq!(masked, source);
            assert_eq!(redact(&masked), masked);
        }
    }
}

#[test]
fn bearer_words_mask_and_basic_requires_printable_colon_credentials() {
    for redact in [
        redact_secrets,
        redact_log_diagnostic,
        redact_log_config_credentials,
    ] {
        for word in ["internationalization", "extraordinarilylongordinaryword"] {
            let masked = redact(&format!("Bearer {word}"));
            assert_eq!(masked, "Bearer ***");
            assert_eq!(redact(&masked), masked);
        }
        for credential in ["user:pass", "usér:päss", ":pass", "user:", "u:pa"] {
            let body = base64::engine::general_purpose::STANDARD.encode(credential);
            let masked = redact(&format!("bAsIc {body}"));
            assert_eq!(masked, "bAsIc ***");
            assert_eq!(redact(&masked), masked);
        }
        for bytes in [
            b"no-colon".as_slice(),
            b"user:\npass",
            b"user:\x00pass",
            b"user:\xffpass",
        ] {
            let body = base64::engine::general_purpose::STANDARD.encode(bytes);
            let source = format!("Basic {body}");
            let masked = redact(&source);
            assert_eq!(masked, source);
            assert_eq!(redact(&masked), masked);
        }
        for text in [
            format!("Basic {}", ["dXNl", "cjpw", "YXN="].concat()),
            format!("Basic {}", ["dXNl", "cjpw", "YQ"].concat()),
            format!("preBearer {}", ["abcdef", "ghijkl"].concat()),
        ] {
            let masked = redact(&text);
            assert_eq!(masked, text);
            assert_eq!(redact(&masked), masked);
        }
    }
}

#[test]
fn encoded_basic_bodies_are_masked_in_every_sink() {
    let credentials = [
        ["user", ":pass1"].concat(),
        ["admin", ":hunter22"].concat(),
        ["deploy", ":pw0000x>"].concat(),
        ["deploy", ":pw0000x?"].concat(),
        ["deploy", ":pw0000x?", "pw>"].concat(),
    ];
    let mut leaks = Vec::new();
    for credential in credentials {
        let body = base64::engine::general_purpose::STANDARD.encode(credential);
        for encoded in [
            body.replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D"),
            body.replace('+', "%2b")
                .replace('/', "%2f")
                .replace('=', "%3d"),
            body.replace('/', r"\/"),
            body.replace('+', "%2b")
                .replace('/', r"\/")
                .replace('=', "%3d"),
        ] {
            for source in [
                format!("authorization=Basic%20{encoded}"),
                format!(r#"{{"Authorization":"Basic {encoded}"}}"#),
            ] {
                for redact in [
                    redact_secrets,
                    redact_log_diagnostic,
                    redact_log_config_credentials,
                ] {
                    let masked = redact(&source);
                    if encoded
                        .as_bytes()
                        .windows(6)
                        .any(|part| masked.contains(std::str::from_utf8(part).unwrap()))
                    {
                        leaks.push(source.clone());
                    }
                    if masked != source.replace(&encoded, "***") {
                        leaks.push(source.clone());
                    }
                    assert_eq!(redact(&masked), masked);
                }
            }
        }
    }
    assert!(leaks.is_empty(), "encoded Basic body leaks: {leaks:?}");
}
