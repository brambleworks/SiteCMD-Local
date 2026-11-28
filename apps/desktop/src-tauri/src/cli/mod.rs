//! Project configuration, scan artifacts, and connected-service commands.

pub mod audit;
#[cfg(unix)]
pub mod audit_interrupt;
pub mod audit_suppressions;
pub mod autofix;
pub mod check;
pub mod connect;
pub mod connect_repo;
pub mod connect_seal;
pub mod connected;
pub mod connected_submit;
pub mod credential_store;
pub mod engine;
pub mod export;
pub mod fix;
pub mod hosted;
pub mod impact;
pub mod init;
pub mod lane;
#[cfg(any(test, feature = "test-support"))]
mod lane_test_support;
mod local_redirects;
pub mod login;
mod output;
pub mod rules;
pub mod scan;
pub mod watch;

#[cfg(test)]
pub(crate) mod test_support;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::connected_service::{
    inactive_output, is_account_inactive, ConnectedServiceError, ACCOUNT_INACTIVE_GATE_NOTICE,
    ACCOUNT_INACTIVE_NOTICE, ACCOUNT_INACTIVE_RESULT_NOTICE,
};

pub use audit_suppressions::CodeScanConfig;

/// Why a command that reaches Connect stopped before its answer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnectStop {
    /// Connect said the account is inactive. `notice` is the sentence that is
    /// true of the door that said so, and `earlier` is what the command had
    /// already done, printed ahead of it when there is any.
    AccountInactive {
        notice: &'static str,
        earlier: String,
    },
    /// Anything else, in the words the command reports it with.
    Failed(String),
}

impl ConnectStop {
    /// A Connect refusal, read for an inactive account before `describe`
    /// turns it into the command's failure.
    pub(crate) fn refused(
        error: &ConnectedServiceError,
        describe: impl FnOnce(&ConnectedServiceError) -> String,
    ) -> Self {
        if is_account_inactive(error) {
            // A first door, which sent nothing of the person's, unless the
            // caller says otherwise.
            Self::AccountInactive {
                notice: ACCOUNT_INACTIVE_NOTICE,
                earlier: String::new(),
            }
        } else {
            Self::Failed(describe(error))
        }
    }

    /// A fix-job door's refusal, reported as `<door> refused: <code> (<detail>)`.
    pub(crate) fn refused_as(error: &ConnectedServiceError, door: &str) -> Self {
        Self::refused(error, |error| {
            format!("{door} refused: {} ({})", error.code, error.message)
        })
    }

    /// The stop at a door whose request carries the person's data, or that
    /// runs after a step that changed state: an inactive account there says
    /// the result was not recorded, after `earlier`, what the command had
    /// already done, rather than saying nothing was sent.
    pub(crate) fn unrecorded(self, earlier: impl Into<String>) -> Self {
        match self {
            Self::AccountInactive { .. } => Self::AccountInactive {
                notice: ACCOUNT_INACTIVE_RESULT_NOTICE,
                earlier: earlier.into(),
            },
            failed => failed,
        }
    }

    /// The gate's stop. The gate records nothing even for an active account,
    /// so an inactive one is told the gate graded nothing.
    pub(crate) fn ungraded(self) -> Self {
        match self {
            Self::AccountInactive { .. } => Self::AccountInactive {
                notice: ACCOUNT_INACTIVE_GATE_NOTICE,
                earlier: String::new(),
            },
            failed => failed,
        }
    }
}

impl From<String> for ConnectStop {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

impl From<&str> for ConnectStop {
    fn from(error: &str) -> Self {
        Self::Failed(error.to_string())
    }
}

/// End a command that reaches Connect. An inactive account ends it as a
/// success, so the person's CI stays green, answering with the inactive
/// output shaped by `answer` into the command's own.
pub(crate) fn settle<T>(
    outcome: Result<T, ConnectStop>,
    answer: impl FnOnce(String) -> T,
) -> Result<T, String> {
    settle_in(outcome, answer, |name| std::env::var(name).ok())
}

/// `settle` reading the environment through `get_env`, where
/// `GITHUB_ACTIONS` decides whether the output carries the notice annotation.
pub(crate) fn settle_in<T>(
    outcome: Result<T, ConnectStop>,
    answer: impl FnOnce(String) -> T,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<T, String> {
    match outcome {
        Ok(done) => Ok(done),
        Err(ConnectStop::AccountInactive { notice, earlier }) => {
            let github_actions = get_env("GITHUB_ACTIONS").as_deref() == Some("true");
            Ok(answer(inactive_output(&earlier, notice, github_actions)))
        }
        Err(ConnectStop::Failed(error)) => Err(error),
    }
}

/// Version of the `.sitecmd/config.json` schema.
const CONFIG_VERSION: u32 = 1;

/// Project-level configuration stored in `.sitecmd/config.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Schema version - increment when breaking changes are made.
    pub version: u32,
    /// Primary URL to scan (e.g. `https://example.com`).
    pub url: String,
    /// Human-readable project name.
    pub name: String,
    /// Optional minimum score threshold. CI fails if score < fail_under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_under: Option<u32>,
    /// Named environments mapping name → URL (e.g. `"staging"` → `"https://staging.example.com"`).
    #[serde(default)]
    pub environments: HashMap<String, String>,
    /// Code Scan findings acknowledged in source control for CLI and CI audits.
    #[serde(default, skip_serializing_if = "CodeScanConfig::is_empty")]
    pub code_scan: CodeScanConfig,
}

impl CliConfig {
    /// Create a new config with sensible defaults.
    pub fn new(url: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            version: CONFIG_VERSION,
            url: url.into(),
            name: name.into(),
            fail_under: None,
            environments: HashMap::new(),
            code_scan: CodeScanConfig::default(),
        }
    }
}

/// Walk up from the current directory looking for a `.sitecmd/` folder.
///
/// Returns the path to the `.sitecmd/` directory if found, or `None`.
pub fn find_config_dir() -> Option<PathBuf> {
    let start = std::env::current_dir().ok()?;
    let mut current: &Path = &start;
    loop {
        let candidate = current.join(".sitecmd");
        if let Ok(metadata) = std::fs::symlink_metadata(&candidate) {
            if metadata.is_symlink() {
                return None;
            }
            if metadata.is_dir() {
                return Some(candidate);
            }
        }
        current = current.parent()?;
    }
}

/// Read and parse `config.json` from a `.sitecmd/` directory.
pub fn read_config(sitecmd_dir: &Path) -> Result<CliConfig, String> {
    let path = sitecmd_dir.join("config.json");
    let contents = read_cli_artifact(sitecmd_dir, &path, crate::constants::MAX_CLI_CONFIG_BYTES)?;
    let config: CliConfig = serde_json::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {}", path.display(), e))?;
    if config.version != CONFIG_VERSION {
        return Err(format!(
            "unsupported .sitecmd/config.json version {}; expected {}",
            config.version, CONFIG_VERSION
        ));
    }
    Ok(config)
}

fn read_cli_artifact(root: &Path, path: &Path, max_bytes: u64) -> Result<String, String> {
    read_optional_cli_artifact(root, path, max_bytes)?
        .ok_or_else(|| format!("{} does not exist", path.display()))
}

fn read_last_scan(dir: &Path) -> Result<Option<String>, String> {
    read_optional_cli_artifact(
        dir,
        &dir.join("last-scan.json"),
        crate::constants::MAX_CLI_SCAN_BYTES,
    )
}

fn read_optional_cli_artifact(
    root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Result<Option<String>, String> {
    use crate::core::safe_fs::{open_project_dir, read_project_path};

    let refusal = || {
        format!(
            "refused unsafe or unreadable CLI artifact {}",
            path.display()
        )
    };
    let relative = path.strip_prefix(root).map_err(|_| refusal())?;
    let dir = match open_project_dir(root) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refusal()),
    };
    let metadata = match dir.symlink_metadata(relative) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Err(refusal()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to inspect {}: {}", path.display(), error)),
    };
    if metadata.len() > max_bytes {
        return Err(format!(
            "{} is too large ({} bytes; maximum {})",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }
    let bytes = read_project_path(&dir, relative, max_bytes).map_err(|_| refusal())?;
    String::from_utf8(bytes).map(Some).map_err(|_| refusal())
}

/// Serialize and write `config.json` into a `.sitecmd/` directory.
///
/// Creates the directory if it does not exist.
pub fn write_config(sitecmd_dir: &Path, config: &CliConfig) -> Result<(), String> {
    std::fs::create_dir_all(sitecmd_dir)
        .map_err(|e| format!("failed to create {}: {}", sitecmd_dir.display(), e))?;
    let contents = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize config: {}", e))?;
    export::write_file(sitecmd_dir, "config.json", &contents)
}

pub fn default_desktop_db_path() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("SITECMD_DB_PATH") {
        return Some(PathBuf::from(env_path));
    }
    crate::app_identity::default_app_db_path()
}

#[cfg(test)]
mod tests {
    use super::{read_config, CliConfig};
    use crate::connected_service::{ConnectedServiceError, ACCOUNT_INACTIVE_NOTICE};

    #[test]
    fn config_does_not_publish_a_second_scan_focus() {
        // The CLI config exposes a second focus vocabulary beside categories.
        let config = CliConfig::new("https://example.com", "Example");
        let value = serde_json::to_value(&config).unwrap();
        assert!(value.get("scan_type").is_none());
    }

    fn error(code: &str, message: &str) -> ConnectedServiceError {
        ConnectedServiceError {
            status: 409,
            code: code.into(),
            message: message.into(),
            request_id: Some("req_9f2".into()),
            details: None,
            retry_after: None,
        }
    }

    #[test]
    fn the_inactive_notice_is_annotated_only_when_github_actions_is_true() {
        // The variable is injected rather than set, so no test changes what a
        // parallel test reads from the process environment.
        let answer = |get_env: &dyn Fn(&str) -> Option<String>| {
            crate::cli::settle_in(
                Err::<String, _>(crate::cli::ConnectStop::refused(
                    &error("account_inactive", "This account is inactive."),
                    ToString::to_string,
                )),
                |notice| notice,
                get_env,
            )
            .expect("an inactive account is not a failure")
        };
        let github_actions = |value: &'static str| {
            move |name: &str| (name == "GITHUB_ACTIONS").then(|| value.to_string())
        };

        assert_eq!(
            answer(&github_actions("true")),
            format!("{ACCOUNT_INACTIVE_NOTICE}\n::notice title=SiteCMD::{ACCOUNT_INACTIVE_NOTICE}")
        );
        for value in ["false", "1", "TRUE", ""] {
            assert_eq!(
                answer(&github_actions(value)),
                ACCOUNT_INACTIVE_NOTICE,
                "{value:?}"
            );
        }
        assert_eq!(answer(&|_| None), ACCOUNT_INACTIVE_NOTICE);
        // Only this variable counts.
        assert_eq!(
            answer(&|name| (name != "GITHUB_ACTIONS").then(|| "true".to_string())),
            ACCOUNT_INACTIVE_NOTICE
        );
    }

    #[test]
    fn settle_reads_github_actions_from_the_process_environment() {
        // Read here, never written: the answer must match whatever this process
        // was started with, which under GitHub Actions is `true`.
        let github_actions = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true");
        let answer = crate::cli::settle(
            Err::<String, _>(crate::cli::ConnectStop::refused(
                &error("account_inactive", "This account is inactive."),
                ToString::to_string,
            )),
            |notice| notice,
        )
        .expect("an inactive account is not a failure");
        assert_eq!(
            answer,
            crate::connected_service::inactive_output("", ACCOUNT_INACTIVE_NOTICE, github_actions)
        );
    }

    #[test]
    fn read_config_rejects_oversized_files_before_json_parsing() {
        let project_root = tempfile::tempdir().expect("project tempdir");
        let sitecmd_dir = project_root.path().join(".sitecmd");
        std::fs::create_dir_all(&sitecmd_dir).expect("create .sitecmd");
        std::fs::write(sitecmd_dir.join("config.json"), "x".repeat(1_000_000))
            .expect("write oversized config");

        let error = read_config(&sitecmd_dir).expect_err("oversized config must be rejected");
        assert!(error.contains("too large"), "unexpected error: {error}");
    }

    #[test]
    fn read_config_rejects_an_unsupported_schema_version() {
        let project_root = tempfile::tempdir().expect("project tempdir");
        let sitecmd_dir = project_root.path().join(".sitecmd");
        std::fs::create_dir_all(&sitecmd_dir).expect("sitecmd directory");
        std::fs::write(
            sitecmd_dir.join("config.json"),
            r#"{"version":2,"url":"https://example.com","name":"Future config"}"#,
        )
        .expect("config fixture");

        let error = read_config(&sitecmd_dir).expect_err("future config must fail closed");
        assert!(
            error.contains("unsupported .sitecmd/config.json version 2"),
            "unexpected error: {error}"
        );
    }
}
