//! PEM payloads in served inline scripts must retain supported source encodings.

use sitecmd_engine::checks::security::{exposed_keys::ExposedApiKeysCheck, key_pattern_services};
use sitecmd_engine::checks::{Check, CheckStatus, PageContext, Severity};

fn pem(kind: &str, body: &str) -> String {
    format!("-----BEGIN {kind}-----\n{body}\n-----END {kind}-----")
}

fn material() -> String {
    format!("{}\n{}", "aB3+".repeat(16), "cD4/".repeat(16))
}

fn assert_inline_private_key(token: &str) {
    assert_eq!(key_pattern_services(token), vec!["Private Key (PEM)"]);
    let page = PageContext {
        evaluation_time: "2026-08-05T00:00:00Z".parse().unwrap(),
        url: url::Url::parse("https://example.com").unwrap(),
        response_headers: http::HeaderMap::new(),
        status_code: 200,
        body: format!("<script>const credential = `{token}`;</script>"),
        is_localhost: false,
        is_strict_localhost: false,
        http_version: None,
        body_lower_cache: std::sync::OnceLock::new(),
    };
    let results = ExposedApiKeysCheck.run(&page);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert_eq!(results[0].severity, Severity::High);
    assert_eq!(
        results[0].raw_data.as_ref().unwrap()["exposed_keys"],
        serde_json::json!(["Private Key (PEM): ----***"])
    );
    assert!(!serde_json::to_string(&results)
        .unwrap()
        .contains(&"aB3+".repeat(16)));
}

#[test]
fn double_escaped_pem_in_an_inline_script_is_found_and_masked() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', r"\\n"));
}

#[test]
fn legacy_encrypted_pem_headers_in_an_inline_script_are_supported() {
    let body = format!(
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,{}\n\n{}",
        "0123456789ABCDEF".repeat(2),
        material()
    );
    assert_inline_private_key(&pem("RSA PRIVATE KEY", &body));
}

#[test]
fn pgp_headers_and_checksum_in_an_inline_script_are_supported() {
    let body = format!("Version: OpenPGP.js v4.10.10\nComment: https://example.com/keys\nHash: SHA256\nCharset: UTF-8\n\n{}\n=ab12", material());
    assert_inline_private_key(&pem("PGP PRIVATE KEY BLOCK", &body));
}

#[test]
fn unicode_newline_escapes_in_inline_pem_are_supported() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', r"\u000a"));
}

#[test]
fn html_newline_entities_in_inline_pem_are_supported() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', "&#10;"));
}

#[test]
fn html_line_breaks_in_inline_pem_are_supported() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', "<br>"));
}

#[test]
fn json_escaped_slashes_in_inline_pem_are_supported() {
    let body = std::iter::repeat_n("aB3/cD4+".repeat(8), 25)
        .collect::<Vec<_>>()
        .join("\n");
    let token = pem("RSA PRIVATE KEY", &body)
        .replace('/', r"\/")
        .replace('\n', r"\n");
    assert_inline_private_key(&token);
    let pgp_body = format!(
        "Version: OpenPGP.js\nComment: https://example.com/keys\n\n{}\n=aB/2",
        material()
    );
    let pgp = pem("PGP PRIVATE KEY BLOCK", &pgp_body)
        .replace('/', r"\/")
        .replace('\n', r"\n");
    assert_inline_private_key(&pgp);
    let placeholder = pem("PRIVATE KEY", &"/".repeat(64)).replace('/', r"\/");
    assert!(key_pattern_services(&placeholder).is_empty());
}

#[test]
fn hex_html_newline_entities_in_inline_pem_are_supported() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', "&#x0a;"));
}

#[test]
fn html_carriage_return_and_newline_entities_in_inline_pem_are_supported() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', "&#13;&#10;"));
}

#[test]
fn percent_encoded_newlines_in_inline_pem_are_supported() {
    assert_inline_private_key(&pem("PRIVATE KEY", &material()).replace('\n', "%0A"));
}

#[test]
fn a_prose_description_of_private_armor_is_not_key_material() {
    let sentence = format!(
        "The file begins with {} and then the encoded key lines follow until the matching footer line {} closes it",
        format_args!("-----{} PRIVATE KEY-----", "BEGIN"),
        format_args!("-----{} PRIVATE KEY-----", "END"),
    );
    assert!(key_pattern_services(&sentence).is_empty());
}

#[test]
fn private_templates_cannot_span_public_keys_or_certificates() {
    for kind in ["PUBLIC KEY", "CERTIFICATE"] {
        let crossing = pem(
            "PRIVATE KEY",
            &format!("\" + \"\n{}\n\" + \"", pem(kind, &material())),
        );
        assert!(key_pattern_services(&crossing).is_empty(), "{kind}");
    }
}

#[test]
fn empty_private_templates_and_header_only_blocks_are_not_keys() {
    for body in [
        String::new(),
        "${body}".into(),
        "Version: DocumentationOnlyWithoutPayload\n".into(),
    ] {
        assert!(key_pattern_services(&pem("PRIVATE KEY", &body)).is_empty());
    }
}

#[test]
fn jwt_with_uniform_payload_and_signature_segments_is_a_placeholder() {
    let token = format!(
        "{}.{}.{}",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "x".repeat(24),
        "y".repeat(24)
    );
    assert!(key_pattern_services(&token).is_empty());
}

#[test]
fn sendgrid_with_uniform_segments_is_a_placeholder() {
    let token = format!("SG.{}.{}", "x".repeat(22), "y".repeat(43));
    assert!(key_pattern_services(&token).is_empty());
}

#[test]
fn pem_with_uniform_material_is_a_placeholder() {
    for token in [
        pem("PRIVATE KEY", &"x".repeat(64)),
        pem(
            "PGP PRIVATE KEY BLOCK",
            &format!("Version: OpenPGP.js\n\n{}\n=ab12", "x".repeat(64)),
        ),
    ] {
        assert!(
            key_pattern_services(&token).is_empty(),
            "structured placeholder"
        );
    }
}

#[test]
fn a_nonuniform_segment_keeps_a_structured_credential_detectable() {
    for (service, token) in [
        (
            "SendGrid",
            format!("SG.{}.{}", "x".repeat(22), "aB3_".repeat(10) + "aB3"),
        ),
        (
            "JWT (possibly Supabase)",
            format!(
                "{}.{}.{}",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "x".repeat(24),
                "aB3".repeat(8)
            ),
        ),
        (
            "Private Key (PEM)",
            pem("PRIVATE KEY", &("x".repeat(63) + "1")),
        ),
    ] {
        assert_eq!(key_pattern_services(&token), vec![service]);
    }
}
