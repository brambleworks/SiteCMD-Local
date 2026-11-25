//! GitHub Actions repository-secret sealed boxes.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use crypto_box::{aead::OsRng, PublicKey};

/// Encrypt bytes using libsodium's sealed-box format and standard base64.
pub fn seal_for_github(public_key_base64: &str, value: &[u8]) -> Result<String, String> {
    let bytes = STANDARD
        .decode(public_key_base64)
        .map_err(|_| "GitHub returned an invalid repository public key")?;
    let key = PublicKey::from_slice(&bytes)
        .map_err(|_| "GitHub returned an invalid repository public key")?;
    let sealed = key
        .seal(&mut OsRng, value)
        .map_err(|_| "could not seal the repository secret")?;
    Ok(STANDARD.encode(sealed))
}
