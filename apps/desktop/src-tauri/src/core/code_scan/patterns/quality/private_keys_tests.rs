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

#[test]
fn formatting_both_key_halves_keeps_the_cross_armor_match() -> Result<(), Box<dyn std::error::Error>>
{
    let source = concat!(
        "const privatePem = `-----BEGIN PRIVATE KEY-----\\n${priv}\\n-----END PRIVATE KEY-----\\n`;\n", // gitleaks:allow
        "const publicPem = `-----BEGIN PUBLIC KEY-----\\n${pub}\\n-----END PUBLIC KEY-----\\n`;",
    );
    assert!(matches_secret(source));
    let temp = tempfile::TempDir::new()?;
    std::fs::create_dir(temp.path().join("src"))?;
    std::fs::write(temp.path().join("src/keys.ts"), source)?;
    let report = crate::core::code_scan::audit_project(temp.path())?;
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id == "hardcoded-secret:src/keys.ts"
            && issue.severity == crate::checks::Severity::High));
    Ok(())
}
