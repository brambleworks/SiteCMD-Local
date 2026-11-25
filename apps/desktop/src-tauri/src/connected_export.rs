//! Authenticated transfer of a connected site's fingerprint key.
//! Exports contain no installation token and grant no service authorization.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ring::{aead, pbkdf2};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use zeroize::{Zeroize, Zeroizing};

const EXPORT_SCHEMA_VERSION: u16 = 1;
const KDF_ALGORITHM: &str = "pbkdf2-hmac-sha256";
const CIPHER_ALGORITHM: &str = "chacha20-poly1305";
const KDF_ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const MIN_PASSPHRASE_CHARS: usize = 12;
pub const MAX_CONNECTION_EXPORT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfEnvelope {
    algorithm: String,
    iterations: u32,
    salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherEnvelope {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportEnvelope {
    schema_version: u16,
    kdf: KdfEnvelope,
    cipher: CipherEnvelope,
}

/// Header fields authenticated as associated data. The ciphertext is excluded
/// because it is the value the authentication tag covers.
#[derive(Serialize)]
struct AuthenticatedHeader<'a> {
    schema_version: u16,
    kdf_algorithm: &'a str,
    kdf_iterations: u32,
    salt: &'a str,
    cipher_algorithm: &'a str,
    nonce: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportContent {
    site_id: String,
    environment_scope_key: String,
    fingerprint_key_version: u16,
    fingerprint_key: String,
}

impl Drop for ExportContent {
    fn drop(&mut self) {
        self.fingerprint_key.zeroize();
    }
}

/// Decrypted connection material. Its `Debug` output deliberately omits the
/// key so an ordinary error report or trace cannot become a second export.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedSiteConnection {
    pub site_id: String,
    pub environment_scope_key: String,
    pub fingerprint_key_version: u16,
    pub fingerprint_key: [u8; KEY_LEN],
}

impl std::fmt::Debug for ImportedSiteConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedSiteConnection")
            .field("site_id", &self.site_id)
            .field("environment_scope_key", &self.environment_scope_key)
            .field("fingerprint_key_version", &self.fingerprint_key_version)
            .field("fingerprint_key", &"[redacted]")
            .finish()
    }
}

impl Drop for ImportedSiteConnection {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for ImportedSiteConnection {
    fn zeroize(&mut self) {
        self.fingerprint_key.zeroize();
    }
}

fn validate_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(format!(
            "connection export passphrases need at least {MIN_PASSPHRASE_CHARS} characters"
        ));
    }
    Ok(())
}

fn decoded_exact<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| format!("connection export has invalid {label}"))?;
    decoded
        .try_into()
        .map_err(|_: Vec<u8>| format!("connection export has invalid {label}"))
}

fn derived_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(KDF_ITERATIONS).expect("nonzero connection-export KDF iterations"),
        salt,
        passphrase.as_bytes(),
        key.as_mut(),
    );
    key
}

fn authenticated_header(envelope: &ExportEnvelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AuthenticatedHeader {
        schema_version: envelope.schema_version,
        kdf_algorithm: &envelope.kdf.algorithm,
        kdf_iterations: envelope.kdf.iterations,
        salt: &envelope.kdf.salt,
        cipher_algorithm: &envelope.cipher.algorithm,
        nonce: &envelope.cipher.nonce,
    })
    .map_err(|error| format!("failed to encode connection export header: {error}"))
}

fn cipher_key(bytes: &[u8; KEY_LEN]) -> Result<aead::LessSafeKey, String> {
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
        .map_err(|_| "failed to initialize connection export encryption".to_string())?;
    Ok(aead::LessSafeKey::new(unbound))
}

/// Encrypt site metadata and a fingerprint key under a user-supplied
/// passphrase. There is intentionally no credential parameter.
pub fn encrypt_site_connection(
    site_id: &str,
    environment_scope_key: &str,
    fingerprint_key_version: u16,
    fingerprint_key: [u8; KEY_LEN],
    passphrase: &str,
) -> Result<String, String> {
    let fingerprint_key = Zeroizing::new(fingerprint_key);
    validate_passphrase(passphrase)?;
    if site_id.trim().is_empty() || environment_scope_key.trim().is_empty() {
        return Err("connection export needs a site and environment".into());
    }
    if fingerprint_key_version == 0 {
        return Err("connection export needs a positive fingerprint key version".into());
    }

    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|error| format!("OS RNG unavailable: {error}"))?;
    getrandom::fill(&mut nonce).map_err(|error| format!("OS RNG unavailable: {error}"))?;

    let mut envelope = ExportEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION,
        kdf: KdfEnvelope {
            algorithm: KDF_ALGORITHM.into(),
            iterations: KDF_ITERATIONS,
            salt: STANDARD.encode(salt),
        },
        cipher: CipherEnvelope {
            algorithm: CIPHER_ALGORITHM.into(),
            nonce: STANDARD.encode(nonce),
            ciphertext: String::new(),
        },
    };
    let aad = authenticated_header(&envelope)?;
    let content = ExportContent {
        site_id: site_id.into(),
        environment_scope_key: environment_scope_key.into(),
        fingerprint_key_version,
        fingerprint_key: hex::encode(*fingerprint_key),
    };
    let mut plaintext = serialize_content(&content)?;
    let key_bytes = derived_key(passphrase, &salt);
    let key = cipher_key(&key_bytes)?;
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        &mut *plaintext,
    )
    .map_err(|_| "failed to encrypt connection export".to_string())?;
    envelope.cipher.ciphertext = STANDARD.encode(plaintext.as_slice());
    serde_json::to_string_pretty(&envelope)
        .map_err(|error| format!("failed to render connection export: {error}"))
}

/// Decrypt and authenticate a connection export. Wrong passphrases and
/// tampering intentionally share one error so the file exposes no oracle.
pub fn decrypt_site_connection(
    serialized: &str,
    passphrase: &str,
) -> Result<ImportedSiteConnection, String> {
    validate_passphrase(passphrase)?;
    if serialized.len() > MAX_CONNECTION_EXPORT_BYTES {
        return Err("connection export is too large".into());
    }
    let envelope: ExportEnvelope = serde_json::from_str(serialized)
        .map_err(|_| "connection export is not valid JSON".to_string())?;
    if envelope.schema_version != EXPORT_SCHEMA_VERSION
        || envelope.kdf.algorithm != KDF_ALGORITHM
        || envelope.kdf.iterations != KDF_ITERATIONS
        || envelope.cipher.algorithm != CIPHER_ALGORITHM
    {
        return Err("connection export uses an unsupported format".into());
    }
    let salt = decoded_exact::<SALT_LEN>(&envelope.kdf.salt, "salt")?;
    let nonce = decoded_exact::<NONCE_LEN>(&envelope.cipher.nonce, "nonce")?;
    let mut ciphertext = Zeroizing::new(
        STANDARD
            .decode(&envelope.cipher.ciphertext)
            .map_err(|_| "connection export has invalid ciphertext".to_string())?,
    );
    let aad = authenticated_header(&envelope)?;
    let key_bytes = derived_key(passphrase, &salt);
    let key = cipher_key(&key_bytes)?;
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            ciphertext.as_mut(),
        )
        .map_err(|_| "connection export could not be decrypted".to_string())?;
    let mut content: ExportContent = serde_json::from_slice(plaintext)
        .map_err(|_| "connection export could not be decrypted".to_string())?;
    let fingerprint_key = hex::decode(&content.fingerprint_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "connection export could not be decrypted".to_string())?;
    if content.site_id.trim().is_empty()
        || content.environment_scope_key.trim().is_empty()
        || content.fingerprint_key_version == 0
    {
        return Err("connection export could not be decrypted".into());
    }
    Ok(ImportedSiteConnection {
        site_id: std::mem::take(&mut content.site_id),
        environment_scope_key: std::mem::take(&mut content.environment_scope_key),
        fingerprint_key_version: content.fingerprint_key_version,
        fingerprint_key,
    })
}

/// Allocate once before serializing key-bearing content or appending the tag.
fn serialize_content(content: &ExportContent) -> Result<Zeroizing<Vec<u8>>, String> {
    struct Length(usize);
    impl std::io::Write for Length {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("export too large"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let failed = || "failed to encode connection export".to_string();
    let mut length = Length(0);
    serde_json::to_writer(&mut length, content).map_err(|_| failed())?;
    let capacity = length
        .0
        .checked_add(aead::CHACHA20_POLY1305.tag_len())
        .ok_or_else(failed)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
    serde_json::to_writer(&mut *plaintext, content).map_err(|_| failed())?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn export_round_trips_without_a_credential_or_plaintext_metadata() {
        let rendered = encrypt_site_connection(
            "site_9f2c81d0a4b3",
            "https://example.com",
            1,
            [7_u8; KEY_LEN],
            PASSPHRASE,
        )
        .expect("encrypt");

        for forbidden in [
            "site_9f2c81d0a4b3",
            "https://example.com",
            &hex::encode([7_u8; KEY_LEN]),
            "installation_token",
        ] {
            assert!(!rendered.contains(forbidden), "export leaked {forbidden}");
        }
        let imported = decrypt_site_connection(&rendered, PASSPHRASE).expect("decrypt");
        assert_eq!(imported.site_id, "site_9f2c81d0a4b3");
        assert_eq!(imported.environment_scope_key, "https://example.com");
        assert_eq!(imported.fingerprint_key_version, 1);
        assert_eq!(imported.fingerprint_key, [7_u8; KEY_LEN]);
        assert!(!format!("{imported:?}").contains(&hex::encode([7_u8; KEY_LEN])));
    }

    #[test]
    fn wrong_passphrases_and_tampering_fail_authentication() {
        let rendered = encrypt_site_connection(
            "site_9f2c81d0a4b3",
            "https://example.com",
            1,
            [3_u8; KEY_LEN],
            PASSPHRASE,
        )
        .expect("encrypt");
        assert_eq!(
            decrypt_site_connection(&rendered, "this is the wrong passphrase")
                .expect_err("wrong passphrase"),
            "connection export could not be decrypted"
        );

        let mut envelope: ExportEnvelope = serde_json::from_str(&rendered).expect("parse");
        let mut ciphertext = STANDARD
            .decode(&envelope.cipher.ciphertext)
            .expect("ciphertext");
        ciphertext[0] ^= 1;
        envelope.cipher.ciphertext = STANDARD.encode(ciphertext);
        let tampered = serde_json::to_string(&envelope).expect("render tampered");
        assert_eq!(
            decrypt_site_connection(&tampered, PASSPHRASE).expect_err("tampering"),
            "connection export could not be decrypted"
        );
    }

    #[test]
    fn untrusted_kdf_work_factors_cannot_control_resource_use() {
        let rendered = encrypt_site_connection(
            "site_9f2c81d0a4b3",
            "https://example.com",
            1,
            [5_u8; KEY_LEN],
            PASSPHRASE,
        )
        .expect("encrypt");
        let mut envelope: ExportEnvelope = serde_json::from_str(&rendered).expect("parse");
        envelope.kdf.iterations = u32::MAX;
        let hostile = serde_json::to_string(&envelope).expect("render hostile");
        assert_eq!(
            decrypt_site_connection(&hostile, PASSPHRASE).expect_err("unsupported work factor"),
            "connection export uses an unsupported format"
        );
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn connect_export_plaintext_does_not_grow_while_writing_the_key_or_tag() {
        // Bug: JSON growth at 255 or 256 key-bearing bytes can free an unzeroized copy of the full key.
        for length in [67, 68] {
            let content = ExportContent {
                site_id: "s".repeat(36),
                environment_scope_key: format!("https://example.com/{}", "x".repeat(length - 20)),
                fingerprint_key_version: 2,
                fingerprint_key: "ab".repeat(KEY_LEN),
            };
            let mut bytes = serialize_content(&content).unwrap();
            assert_eq!(
                bytes.capacity(),
                bytes.len() + aead::CHACHA20_POLY1305.tag_len()
            );
            let start = bytes.as_ptr();
            bytes.extend_from_slice(&[0; 16]);
            assert!(start == bytes.as_ptr());
        }
    }
}
