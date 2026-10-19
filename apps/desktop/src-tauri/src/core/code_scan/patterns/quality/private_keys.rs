use super::HARDCODED_SECRET_PATTERNS;

fn matches_secret(source: &str) -> bool {
    HARDCODED_SECRET_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(source))
}

#[test]
fn pem_armor_around_a_runtime_body_is_not_a_secret() {
    assert!(!matches_secret(
        r#"`-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`"#
    ));
}

#[test]
fn pem_private_key_blocks_are_secrets() {
    for kind in [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        let block = format!(
            "-----BEGIN {kind}-----\n{}\n-----END {kind}-----",
            "A".repeat(64)
        ); // gitleaks:allow
        assert!(matches_secret(&block), "{kind}");
        assert!(matches_secret(&format!(
            "\"private_key\": \"{}\"",
            block.replace('\n', "\\n")
        )));
        assert!(matches_secret(&block.replace('\n', "\\n\" + \"")));
    }
    for kind in ["PUBLIC KEY", "CERTIFICATE", "RSA PUBLIC KEY"] {
        assert!(!matches_secret(&format!(
            "-----BEGIN {kind}-----\n{}\n-----END {kind}-----",
            "A".repeat(64)
        )));
    }
}
