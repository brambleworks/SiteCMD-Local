//! Project-aware commands shared by the standalone CLI and desktop export.

pub mod audit;
pub mod audit_suppressions;
pub mod check;
pub mod connected;
pub mod connected_submit;
pub mod export;
pub mod fix;
pub mod impact;
pub mod init;
pub mod scan;
pub mod watch;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use audit_suppressions::{CodeScanConfig, CodeScanSuppression, CodeScanSuppressionMatch};

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
    /// Web-scan focus. See `crate::core::scanner::ScanType` for the vocabulary.
    #[serde(default)]
    pub scan_type: crate::core::scanner::ScanType,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliImportSyncResult {
    pub project_id: i64,
    pub name: String,
    pub url: String,
    pub imported_scan: bool,
    pub scan_id: Option<i64>,
}

impl CliConfig {
    /// Create a new config with sensible defaults.
    pub fn new(url: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            version: CONFIG_VERSION,
            url: url.into(),
            name: name.into(),
            scan_type: crate::core::scanner::ScanType::default(),
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
        if candidate.is_dir() {
            return Some(candidate);
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
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {}: {}", path.display(), error))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{} is too large ({} bytes; maximum {})",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }
    crate::core::code_scan::read_bounded_project_text(root, path, max_bytes).ok_or_else(|| {
        format!(
            "refused unsafe or unreadable CLI artifact {}",
            path.display()
        )
    })
}

/// Serialize and write `config.json` into a `.sitecmd/` directory.
///
/// Creates the directory if it does not exist.
pub fn write_config(sitecmd_dir: &Path, config: &CliConfig) -> Result<(), String> {
    std::fs::create_dir_all(sitecmd_dir)
        .map_err(|e| format!("failed to create {}: {}", sitecmd_dir.display(), e))?;
    let path = sitecmd_dir.join("config.json");
    let contents = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize config: {}", e))?;
    std::fs::write(&path, contents)
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))
}

fn import_cli_scan_if_present(
    db: &crate::db::Database,
    sitecmd_dir: &Path,
) -> Result<Option<i64>, String> {
    let last_scan_path = sitecmd_dir.join("last-scan.json");
    if !last_scan_path.is_file() {
        return Ok(None);
    }

    let contents = read_cli_artifact(
        sitecmd_dir,
        &last_scan_path,
        crate::constants::MAX_CLI_SCAN_BYTES,
    )?;
    let result: crate::core::scanner::ScanResult = serde_json::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {}", last_scan_path.display(), e))?;

    if db
        .get_scan_history(&result.url, 1)
        .ok()
        .and_then(|history| history.into_iter().next())
        .is_some_and(|latest| {
            latest.timestamp == result.timestamp
                && latest.scan_type == result.scan_type
                && latest.overall_score == result.overall_score
        })
    {
        return Ok(None);
    }

    let site_id = db.get_or_create_site(&result.url)?;
    db.save_scan(site_id, &result)
        .map(Some)
        .map_err(String::from)
}

pub fn import_project_artifacts(
    db: &crate::db::Database,
    project_root: &Path,
) -> Result<CliImportSyncResult, String> {
    let project_root = std::fs::canonicalize(project_root).map_err(|e| {
        format!(
            "failed to resolve project path {}: {}",
            project_root.display(),
            e
        )
    })?;
    let sitecmd_dir = project_root.join(".sitecmd");
    if !sitecmd_dir.is_dir() {
        return Err(format!(
            "no .sitecmd directory found at {}",
            project_root.display()
        ));
    }

    let config = read_config(&sitecmd_dir)?;
    let project_root_str = project_root.to_string_lossy().to_string();
    let framework = crate::core::project::detect_project(&project_root).framework;
    let primary_environment = crate::core::localhost::resolve_environment_name(&config.url, None);

    let project_id = if let Some(existing_id) = db.find_project_for_url(&config.url) {
        db.rename_project(existing_id, &config.name)?;
        db.update_project_path(existing_id, &project_root_str, framework.as_deref())?;
        existing_id
    } else {
        db.upsert_project(&config.name, &project_root_str, framework.as_deref())?
    };

    db.add_environment(
        project_id,
        &config.url,
        &format!("{} ({})", config.name, primary_environment),
        primary_environment,
        "sitecmd-cli",
    )?;

    for (environment, env_url) in &config.environments {
        if env_url.trim().is_empty() || env_url == &config.url {
            continue;
        }
        let normalized_environment =
            crate::core::localhost::resolve_environment_name(env_url, Some(environment));
        db.add_environment(
            project_id,
            env_url,
            &format!("{} ({})", config.name, normalized_environment),
            normalized_environment,
            "sitecmd-cli",
        )?;
    }

    let imported_scan_id = import_cli_scan_if_present(db, &sitecmd_dir)?;

    Ok(CliImportSyncResult {
        project_id,
        name: config.name,
        url: config.url,
        imported_scan: imported_scan_id.is_some(),
        scan_id: imported_scan_id,
    })
}

pub fn default_desktop_db_path() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("SITECMD_DB_PATH") {
        return Some(PathBuf::from(env_path));
    }
    crate::app_identity::default_app_db_path()
}

fn build_import_deep_link_url(project_root: &Path) -> String {
    let path_str = project_root.to_string_lossy();
    let encoded = urlencoding::encode(&path_str);
    format!("sitecmd://import?path={}", encoded)
}

fn validate_deep_link_launch_status(
    launch_succeeded: bool,
    exit_code: Option<i32>,
    deep_link_url: &str,
) -> Result<(), String> {
    if launch_succeeded {
        return Ok(());
    }

    match exit_code {
        Some(code) => Err(format!(
            "desktop deep link launcher exited with code {} for {}",
            code, deep_link_url
        )),
        None => Err(format!(
            "desktop deep link launcher terminated before opening {}",
            deep_link_url
        )),
    }
}

pub fn sync_project_to_local_database(
    project_root: &Path,
) -> Result<Option<CliImportSyncResult>, String> {
    let Some(db_path) = default_desktop_db_path() else {
        return Ok(None);
    };
    if !db_path.exists() {
        return Ok(None);
    }

    crate::app_identity::validate_private_file_target(&db_path)
        .map_err(|error| format!("refused unsafe SiteCMD database path: {error}"))?;
    let db = crate::db::Database::open(db_path)?;
    import_project_artifacts(&db, project_root).map(Some)
}

/// Best-effort deep link that asks the desktop app to import or refresh the
/// project rooted at `project_root`. Used by `sitecmd init` and by scan/export
/// commands after `.sitecmd/` artifacts are updated.
pub fn fire_import_deep_link(project_root: &Path) -> Result<(), String> {
    let deep_link_url = build_import_deep_link_url(project_root);

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("open")
            .arg(&deep_link_url)
            .status()
            .map_err(|e| format!("failed to open deep link: {}", e))?;
        return validate_deep_link_launch_status(status.success(), status.code(), &deep_link_url);
    }

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("xdg-open")
            .arg(&deep_link_url)
            .status()
            .map_err(|e| format!("failed to open deep link: {}", e))?;
        return validate_deep_link_launch_status(status.success(), status.code(), &deep_link_url);
    }

    #[cfg(target_os = "windows")]
    {
        // Avoid `cmd /C start`, which interprets URL metacharacters. Explorer's
        // exit code is unreliable after URI handoff, so only spawn failure is fatal.
        let status = std::process::Command::new("explorer.exe")
            .arg(&deep_link_url)
            .status()
            .map_err(|e| format!("failed to open deep link: {}", e))?;
        return validate_deep_link_launch_status(true, status.code(), &deep_link_url);
    }

    #[allow(unreachable_code)]
    Err("unsupported platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        build_import_deep_link_url, import_project_artifacts, read_config,
        validate_deep_link_launch_status, write_config, CliConfig, CodeScanConfig,
    };
    use crate::db::test_helpers::temp_db;
    use std::path::Path;

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

    #[test]
    fn import_rejects_oversized_last_scan_before_json_parsing() {
        let db = temp_db();
        let project_root = tempfile::tempdir().expect("project tempdir");
        let sitecmd_dir = project_root.path().join(".sitecmd");
        write_config(
            &sitecmd_dir,
            &CliConfig::new("https://example.com", "Oversized Scan"),
        )
        .expect("write config");
        std::fs::write(
            sitecmd_dir.join("last-scan.json"),
            "x".repeat(11 * 1024 * 1024),
        )
        .expect("write oversized scan");

        let error = import_project_artifacts(&db, project_root.path())
            .expect_err("oversized last-scan must be rejected");
        assert!(error.contains("too large"), "unexpected error: {error}");
    }

    #[test]
    fn import_project_artifacts_marks_local_primary_url_as_local() {
        let db = temp_db();
        let project_root = tempfile::tempdir().expect("project tempdir");
        let sitecmd_dir = project_root.path().join(".sitecmd");

        write_config(
            &sitecmd_dir,
            &CliConfig {
                version: 1,
                url: "http://127.0.0.1:4321".into(),
                name: "sitecmd-landing".into(),
                scan_type: crate::core::scanner::ScanType::Health,
                fail_under: None,
                environments: std::collections::HashMap::new(),
                code_scan: CodeScanConfig::default(),
            },
        )
        .expect("write config");

        import_project_artifacts(&db, project_root.path()).expect("import");

        let projects = db.get_projects().expect("get projects");
        let project = projects
            .iter()
            .find(|project| project.name == "sitecmd-landing")
            .expect("imported project");
        let environment = project
            .environments
            .iter()
            .find(|env| env.url == "http://127.0.0.1:4321")
            .expect("local environment");

        assert_eq!(environment.environment, "local");
        assert_eq!(environment.label, "sitecmd-landing (local)");
    }

    #[test]
    fn import_project_artifacts_normalizes_remote_environment_aliases() {
        let db = temp_db();
        let project_root = tempfile::tempdir().expect("project tempdir");
        let sitecmd_dir = project_root.path().join(".sitecmd");
        let mut environments = std::collections::HashMap::new();
        environments.insert("preview".into(), "https://preview-app.vercel.app".into());
        environments.insert("dev".into(), "https://dev.example.com".into());
        environments.insert("prod".into(), "https://example.com".into());

        write_config(
            &sitecmd_dir,
            &CliConfig {
                version: 1,
                url: "https://preview-app.vercel.app".into(),
                name: "sitecmd-landing".into(),
                scan_type: crate::core::scanner::ScanType::Health,
                fail_under: None,
                environments,
                code_scan: CodeScanConfig::default(),
            },
        )
        .expect("write config");

        import_project_artifacts(&db, project_root.path()).expect("import");

        let projects = db.get_projects().expect("get projects");
        let project = projects
            .iter()
            .find(|project| project.name == "sitecmd-landing")
            .expect("imported project");

        let primary_environment = project
            .environments
            .iter()
            .find(|env| env.url == "https://preview-app.vercel.app")
            .expect("preview environment");
        assert_eq!(primary_environment.environment, "staging");
        assert_eq!(primary_environment.label, "sitecmd-landing (staging)");

        let development_environment = project
            .environments
            .iter()
            .find(|env| env.url == "https://dev.example.com")
            .expect("development environment");
        assert_eq!(development_environment.environment, "development");
        assert_eq!(
            development_environment.label,
            "sitecmd-landing (development)"
        );

        let production_environment = project
            .environments
            .iter()
            .find(|env| env.url == "https://example.com")
            .expect("production environment");
        assert_eq!(production_environment.environment, "production");
        assert_eq!(production_environment.label, "sitecmd-landing (production)");
    }

    #[test]
    fn build_import_deep_link_url_encodes_project_paths() {
        let url =
            build_import_deep_link_url(Path::new("/Users/dev/Projects/Web/SiteCMD/My Project"));

        assert_eq!(
            url,
            "sitecmd://import?path=%2FUsers%2Fdev%2FProjects%2FWeb%2FSiteCMD%2FMy%20Project"
        );
    }

    #[test]
    fn validate_deep_link_launch_status_accepts_success() {
        assert_eq!(
            validate_deep_link_launch_status(
                true,
                Some(0),
                "sitecmd://import?path=%2Ftmp%2Fproject",
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_deep_link_launch_status_reports_non_zero_exit() {
        let error = validate_deep_link_launch_status(
            false,
            Some(1),
            "sitecmd://import?path=%2Ftmp%2Fproject",
        )
        .expect_err("non-zero exit should fail");

        assert!(error.contains("exited with code 1"));
        assert!(error.contains("sitecmd://import?path=%2Ftmp%2Fproject"));
    }

    #[test]
    fn validate_deep_link_launch_status_reports_terminated_processes() {
        let error =
            validate_deep_link_launch_status(false, None, "sitecmd://import?path=%2Ftmp%2Fproject")
                .expect_err("terminated process should fail");

        assert!(error.contains("terminated before opening"));
        assert!(error.contains("sitecmd://import?path=%2Ftmp%2Fproject"));
    }
}
