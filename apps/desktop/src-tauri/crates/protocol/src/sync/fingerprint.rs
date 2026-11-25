//! Keyed code-location fingerprints.
//!
//! The random project key stays in local custody. The service receives only a
//! commitment and keyed hashes; losing the key requires rotation.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Fixed 256-bit project fingerprint key length.
pub const FINGERPRINT_KEY_LEN: usize = 32;

/// Versioned domain separator for code-location fingerprints.
const CODE_LOCATION_DOMAIN: &str = "sitecmd-fp-v1|code|";

/// Separate domain for non-secret key commitments.
const KEY_COMMITMENT_DOMAIN: &str = "sitecmd-fpk-commit|";

/// Non-serializable project key exposing only one-way digests.
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectFingerprintKey {
    bytes: [u8; FINGERPRINT_KEY_LEN],
}

impl ProjectFingerprintKey {
    /// Adopt key bytes supplied by the platform-owned entropy source.
    pub fn from_bytes(bytes: [u8; FINGERPRINT_KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Reject unknown-length keys and return the observed length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, usize> {
        <[u8; FINGERPRINT_KEY_LEN]>::try_from(bytes)
            .map(Self::from_bytes)
            .map_err(|_| bytes.len())
    }

    /// One-way `SHA-256("sitecmd-fpk-commit|" + key)` commitment used to detect
    /// a fingerprint key that does not match its claimed version.
    pub fn commitment(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(KEY_COMMITMENT_DOMAIN.as_bytes());
        hasher.update(self.bytes);
        hex::encode(hasher.finalize())
    }

    /// Returns a lowercase HMAC-SHA256 fingerprint for an already-canonical
    /// producer rule and relative path. Line numbers are excluded for stability.
    pub fn location_hash(&self, producer_rule: &str, relative_path: &str) -> String {
        // `new_from_slice` is infallible for HMAC at any key length, and this
        // key is a fixed-size array, so the error arm is unreachable rather
        // than merely unlikely.
        let mut mac = HmacSha256::new_from_slice(&self.bytes)
            .expect("allow-expect: HMAC accepts any key length, and this key is 32 bytes");
        mac.update(CODE_LOCATION_DOMAIN.as_bytes());
        mac.update(producer_rule.as_bytes());
        mac.update(b"|");
        mac.update(relative_path.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

// Never expose key bytes through Debug output.
impl std::fmt::Debug for ProjectFingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProjectFingerprintKey([redacted; {FINGERPRINT_KEY_LEN}])"
        )
    }
}

/// Best-effort overwrite of this copy, not a process-memory defense.
impl Drop for ProjectFingerprintKey {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: `byte` is a valid, aligned, uniquely borrowed `u8` for
            // the duration of this write.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

#[cfg(test)]
#[path = "fingerprint_tests.rs"]
mod tests;
