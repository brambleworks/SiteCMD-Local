//! Where the fix job reads its secrets: an environment variable in CI, so
//! nothing carrying the fingerprint key touches the runner's disk, or a
//! file on a laptop. Values live in zeroizing memory only.

use std::path::PathBuf;

use sitecmd_protocol::sync::ProjectFingerprintKey;
use zeroize::Zeroizing;

use crate::connected_export::decrypt_site_connection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportSource {
    File(PathBuf),
    Env(String),
}

pub fn read_env_secret(name: &str) -> Result<Zeroizing<String>, String> {
    let value = Zeroizing::new(std::env::var(name).map_err(|_| format!("set {name}"))?);
    if value.trim().is_empty() {
        return Err(format!("{name} is empty"));
    }
    Ok(value)
}

pub fn read_export(source: &ExportSource) -> Result<Zeroizing<String>, String> {
    match source {
        ExportSource::Env(name) => read_env_secret(name),
        ExportSource::File(path) => {
            crate::cli::connected::read_connection_export(path).map(Zeroizing::new)
        }
    }
}

/// The site's fingerprint key, copied out of the decrypted connection so
/// everything else the export carries is dropped where it was read.
///
/// A failure answers with a reason built here rather than the underlying
/// error: it names the variable that is missing or says the export could not
/// be decrypted, and never any part of a value.
pub(super) fn site_fingerprint_key(
    export: &ExportSource,
    passphrase_env: &str,
) -> Result<ProjectFingerprintKey, String> {
    let serialized = read_export(export).map_err(|_| match export {
        ExportSource::Env(name) => format!("{name} is missing or empty"),
        ExportSource::File(_) => "the connection export could not be read".to_string(),
    })?;
    let passphrase = read_env_secret(passphrase_env)
        .map_err(|_| format!("{passphrase_env} is missing or empty"))?;
    let connection = decrypt_site_connection(&serialized, &passphrase)
        .map_err(|_| "could not decrypt the connection export".to_string())?;
    let key = ProjectFingerprintKey::from_bytes(connection.fingerprint_key);
    drop(connection);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_export_from_a_variable_or_a_bounded_file() {
        std::env::set_var("SITECMD_TEST_EXPORT_VALUE", "{\"schema_version\":1}");
        assert_eq!(
            read_export(&ExportSource::Env("SITECMD_TEST_EXPORT_VALUE".into()))
                .unwrap()
                .as_str(),
            "{\"schema_version\":1}"
        );
        assert!(
            read_export(&ExportSource::Env("SITECMD_TEST_EXPORT_MISSING".into()))
                .unwrap_err()
                .contains("SITECMD_TEST_EXPORT_MISSING")
        );
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("connection.json");
        std::fs::write(&path, "{}").unwrap();
        assert_eq!(
            read_export(&ExportSource::File(path)).unwrap().as_str(),
            "{}"
        );
    }
}
