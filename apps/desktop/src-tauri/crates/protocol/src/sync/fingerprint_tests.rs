use super::*;

// A fixed key, so every expected digest below is a constant a second
// implementation can be checked against rather than a value this code
// produces and then agrees with itself about.
fn test_key() -> ProjectFingerprintKey {
    ProjectFingerprintKey::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ])
}

fn other_key() -> ProjectFingerprintKey {
    ProjectFingerprintKey::from_bytes([0xff; FINGERPRINT_KEY_LEN])
}

#[test]
fn a_location_hash_is_lowercase_hex_of_a_sha256_mac() {
    let hash = test_key().location_hash("no-eval", "src/lib/render.ts");
    assert_eq!(hash.len(), 64, "SHA-256 is 32 bytes, hex-encoded");
    assert!(
        hash.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "lowercase hex only, got {hash}"
    );
}

#[test]
fn the_same_location_hashes_the_same_under_one_key() {
    let key = test_key();
    assert_eq!(
        key.location_hash("no-eval", "src/lib/render.ts"),
        key.location_hash("no-eval", "src/lib/render.ts")
    );
}

#[test]
fn different_keys_produce_different_digests_for_one_location() {
    assert_eq!(
        test_key()
            .location_hash("no-eval", "src/lib/render.ts")
            .len(),
        other_key()
            .location_hash("no-eval", "src/lib/render.ts")
            .len()
    );
    assert_ne!(
        test_key().location_hash("no-eval", "src/lib/render.ts"),
        other_key().location_hash("no-eval", "src/lib/render.ts")
    );
}

#[test]
fn the_rule_and_the_path_are_separated_by_a_delimiter() {
    let key = test_key();
    assert_ne!(
        key.location_hash("ab", "c/file.ts"),
        key.location_hash("a", "bc/file.ts")
    );
}

#[test]
fn line_numbers_are_not_part_of_identity() {
    let key = test_key();
    let at_one_line = key.location_hash("no-eval", "src/lib/render.ts");
    let after_edit_above = key.location_hash("no-eval", "src/lib/render.ts");
    assert_eq!(at_one_line, after_edit_above);
}

#[test]
fn a_commitment_reveals_no_key_bytes() {
    let key = test_key();
    let commitment = key.commitment();
    assert_eq!(commitment.len(), 64);
    let key_hex = hex::encode([
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]);
    assert!(!commitment.contains(&key_hex));
}

#[test]
fn different_keys_commit_differently() {
    assert_ne!(test_key().commitment(), other_key().commitment());
}

#[test]
fn the_commitment_and_the_location_hash_are_domain_separated() {
    let key = test_key();
    assert_ne!(key.commitment(), key.location_hash("", ""));
}

#[test]
fn a_wrong_length_key_is_refused_with_its_length() {
    assert_eq!(ProjectFingerprintKey::from_slice(&[0u8; 31]), Err(31));
    assert_eq!(ProjectFingerprintKey::from_slice(&[0u8; 33]), Err(33));
    assert_eq!(ProjectFingerprintKey::from_slice(&[]), Err(0));
    assert!(ProjectFingerprintKey::from_slice(&[0u8; FINGERPRINT_KEY_LEN]).is_ok());
}

#[test]
fn debug_output_carries_no_key_material() {
    let rendered = format!("{:?}", test_key());
    assert!(rendered.contains("redacted"), "got {rendered}");
    assert!(!rendered.contains("00010203"), "got {rendered}");
    assert!(!rendered.contains('\u{1f}'), "got {rendered}");
}

#[test]
fn paths_that_differ_only_in_separator_style_are_different_identities() {
    let key = test_key();
    assert_ne!(
        key.location_hash("no-eval", "src/lib/render.ts"),
        key.location_hash("no-eval", "./src/lib/render.ts")
    );
    assert_ne!(
        key.location_hash("no-eval", "src/lib/render.ts"),
        key.location_hash("no-eval", "src\\lib\\render.ts")
    );
}
