//! Where the fix job reads its secrets: an environment variable in CI, so
//! nothing carrying the fingerprint key touches the runner's disk, or a
//! file on a laptop. Values live in zeroizing memory only.

use std::path::PathBuf;

use zeroize::Zeroizing;

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
