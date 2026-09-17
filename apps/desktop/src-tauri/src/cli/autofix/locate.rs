//! `sitecmd autofix locate`: the identity hashes a checkout's code findings
//! carry under this site's fingerprint key, so a person can name a finding
//! to Connect without the desktop app.

use std::path::PathBuf;

use sitecmd_engine::sync::ProjectFingerprintKey;

use super::brief::identities;
use super::secrets::{read_env_secret, read_export, ExportSource};
use crate::connected_export::decrypt_site_connection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocateArgs {
    pub path: PathBuf,
    pub export: ExportSource,
    pub passphrase_env: String,
    pub check: Option<String>,
}

pub(super) fn parse(mut args: impl Iterator<Item = String>) -> Result<LocateArgs, String> {
    let mut path = PathBuf::from(".");
    let mut export = None;
    let mut passphrase_env = "SITECMD_CONNECTION_PASSPHRASE".to_string();
    let mut check = None;
    while let Some(token) = args.next() {
        match token.as_str() {
            "--path" => path = PathBuf::from(super::next_value(&mut args, "--path")?),
            "--connection-export" => {
                export = Some(ExportSource::File(PathBuf::from(super::next_value(
                    &mut args,
                    "--connection-export",
                )?)))
            }
            "--connection-export-env" => {
                export = Some(ExportSource::Env(super::next_value(
                    &mut args,
                    "--connection-export-env",
                )?))
            }
            "--passphrase-env" => {
                passphrase_env = super::next_value(&mut args, "--passphrase-env")?
            }
            "--check" => check = Some(super::next_value(&mut args, "--check")?),
            other => return Err(format!("Unknown option: {other}")),
        }
    }
    Ok(LocateArgs {
        check,
        export: export
            .ok_or("locate needs --connection-export <path> or --connection-export-env <NAME>")?,
        passphrase_env,
        path,
    })
}

/// Print one tab-separated row per code finding: check ID, identity hash,
/// relative path and line. `--check` accepts the canonical check ID or its
/// rule slug.
pub fn run(args: &LocateArgs) -> Result<(u8, String), String> {
    let root = std::fs::canonicalize(&args.path)
        .map_err(|error| format!("cannot resolve {}: {error}", args.path.display()))?;
    let serialized = read_export(&args.export)?;
    let passphrase = read_env_secret(&args.passphrase_env)?;
    let connection = decrypt_site_connection(&serialized, &passphrase)?;
    let key = ProjectFingerprintKey::from_bytes(connection.fingerprint_key);
    let rows = identities(&root, &key)?;
    let lines: Vec<String> = rows
        .into_iter()
        .filter(|(check_id, _, _, _)| {
            args.check.as_deref().is_none_or(|wanted| {
                check_id == wanted || check_id.strip_prefix("code_scan.") == Some(wanted)
            })
        })
        .map(|(check_id, identity, path, line)| {
            format!(
                "{check_id}\t{identity}\t{path}\t{}",
                line.map_or_else(|| "-".to_string(), |line| line.to_string())
            )
        })
        .collect();
    Ok((
        0,
        if lines.is_empty() {
            "no code findings matched".to_string()
        } else {
            lines.join("\n")
        },
    ))
}
