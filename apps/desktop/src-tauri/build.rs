//! Registers custom Tauri commands with the v2 ACL manifest.
//! New commands must appear in both `APP_COMMANDS` and `lib.rs`'s
//! `invoke_handler!`; a parity test enforces the contract.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

const NUMERIC_LICENSE_CONFIG_ENVS: &[&str] = &[
    "SITECMD_LICENSE_STORE_ID",
    "SITECMD_LICENSE_CORE_MONTHLY_VARIANT_ID",
    "SITECMD_LICENSE_CORE_ANNUAL_VARIANT_ID",
    "SITECMD_LICENSE_PRO_MONTHLY_VARIANT_ID",
    "SITECMD_LICENSE_PRO_ANNUAL_VARIANT_ID",
];

const CHECKOUT_URL_ENVS: &[&str] = &[
    "SITECMD_LICENSE_CORE_CHECKOUT_URL",
    "SITECMD_LICENSE_PRO_CHECKOUT_URL",
];

// Bake optional public connected-service configuration into release binaries.
const OPTIONAL_BAKED_ENVS: &[&str] = &[
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GITHUB_CLIENT_ID",
    "SITECMD_CONNECTED_ENDPOINT",
    "VITE_SITECMD_SENTRY_DSN",
];

const REQUIRE_LICENSE_CONFIG_ENV: &str = "SITECMD_REQUIRE_LICENSE_CONFIG";
const CHECKOUT_URL_PREFIX: &str = "https://shop.sitecmd.com/checkout/buy/";

#[cfg(feature = "desktop")]
const APP_COMMANDS: &[&str] = &[
    "ping",
    "get_app_setting",
    "set_app_setting",
    "add_project",
    "add_project_by_url",
    "rename_project",
    "get_projects",
    "get_all_projects_summary",
    "get_all_projects_work_summary",
    "get_project_signal_snapshot",
    "get_project_nav_badge_snapshot",
    "get_dashboard_snapshot",
    "get_dashboard_reference_signals",
    "invalidate_project_signal_snapshot",
    "dismiss_first_scan_banner",
    "get_connected_status",
    "inspect_connected_sync",
    "issue_data_admin_command_token",
    "issue_external_connector_command_token",
    "issue_filesystem_access_command_token",
    "issue_filesystem_export_command_token",
    "issue_project_execution_command_token",
    "issue_sensitive_privileged_command_token",
    "run_data_admin_command",
    "run_filesystem_export_command",
    "run_external_connector_command",
    "run_filesystem_access_command",
    "run_project_execution_command",
    "add_environment_url",
    "get_integrations",
    "get_telemetry_consent",
    "set_telemetry_consent",
    "send_telemetry_request",
    "get_telemetry_delete_proof_hash",
    "clear_telemetry_delete_secret",
    "get_db_size",
    "run_webview_analysis",
    "verify_scan_checks",
    "get_scan_executions",
    "get_scan_execution_detail",
    "get_score_trend",
    "get_resolved_issues",
    "build_prompt",
    "export_scan_markdown",
    "discover_sitemap",
    "fetch_sitemap_manual",
    "save_site_pages",
    "get_site_pages",
    "get_scan_scope",
    "get_scan_scope_revision",
    "set_scan_scope",
    "refresh_sitemap",
    "set_site_sitemap_url",
    "get_or_create_site_id",
    "cancel_scan",
    "check_ssl",
    "get_events",
    "record_verification_event",
    "record_update_event",
    "record_search_event",
    "record_security_event",
    "get_correlations",
    "refresh_events",
    "backfill_events",
    "generate_report_data",
    "generate_report_html",
    "render_report_html_from_data",
    "save_report_history",
    "get_report_history",
    "save_scan_schedule",
    "get_scan_schedule",
    "get_fix_document",
    "restart_app",
    "log_frontend",
    "update_tray_scan_status",
    "update_tray_summary",
    "send_actionable_desktop_notification",
    "get_webhook_configs",
    "get_issue_links",
    "get_issue_link_for_check",
    "block_issue",
    "count_unread_alerts",
    "dismiss_alert",
    "get_alerts",
    "get_current_score",
    "get_score_snapshot_history",
    "get_issue_state",
    "get_issue_check_memory",
    "get_work_items",
    "ignore_issue",
    "mark_alerts_viewed_bulk",
    "mark_alert_unread",
    "mark_alert_viewed",
    "mark_issue_fixed",
    "reopen_issue",
    "snooze_issue",
    "verify_issue",
    "create_fix_attempt",
    "get_fix_attempt_for_issue",
    "cancel_fix_attempt",
    "detect_agent_tools",
    "get_agent_tool_manual_config",
    "get_license_status",
    "get_pages_with_issues",
    "get_issues_for_page",
    "dismiss_integration_hint",
    "preview_deploy_risk_cmd",
    "whatif_resolve_cmd",
    "get_catalog_status",
    "confirm_link_license_activation",
    "retry_catalog_refresh",
    "resolve_fix_guide",
];

fn repo_env_file() -> Option<PathBuf> {
    let mut path = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    for _ in 0..3 {
        path.pop();
    }
    path.push(".env");
    Some(path)
}

fn parse_dotenv_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return None;
    }

    let raw_value = value.trim();
    let mut value = raw_value.to_string();
    if raw_value.len() >= 2 {
        let starts_with_single = raw_value.starts_with('\'') && raw_value.ends_with('\'');
        let starts_with_double = raw_value.starts_with('"') && raw_value.ends_with('"');
        if starts_with_single || starts_with_double {
            value = raw_value[1..raw_value.len() - 1].to_string();
        } else if let Some((before_comment, _)) = raw_value.split_once(" #") {
            value = before_comment.trim_end().to_string();
        }
    }

    Some((key.to_string(), value))
}

fn load_dotenv_values(path: &Path) -> HashMap<String, String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.lines().filter_map(parse_dotenv_line).collect())
        .unwrap_or_default()
}

fn config_value(key: &str, dotenv: &HashMap<String, String>) -> Option<String> {
    std::env::var(key)
        .ok()
        .or_else(|| dotenv.get(key).cloned())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn expose_dotenv_fallbacks(dotenv: &HashMap<String, String>) {
    for key in NUMERIC_LICENSE_CONFIG_ENVS
        .iter()
        .chain(CHECKOUT_URL_ENVS.iter())
        .chain(OPTIONAL_BAKED_ENVS.iter())
    {
        if std::env::var(key).is_err() {
            if let Some(value) = config_value(key, dotenv) {
                println!("cargo:rustc-env={key}={value}");
            }
        }
    }
}

fn main() {
    let env_file = repo_env_file();
    if let Some(path) = &env_file {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let dotenv = env_file
        .as_ref()
        .filter(|path| path.exists())
        .map(|path| load_dotenv_values(path))
        .unwrap_or_default();

    for key in NUMERIC_LICENSE_CONFIG_ENVS
        .iter()
        .chain(CHECKOUT_URL_ENVS.iter())
        .chain(OPTIONAL_BAKED_ENVS.iter())
    {
        println!("cargo:rerun-if-env-changed={key}");
    }
    println!("cargo:rerun-if-env-changed={REQUIRE_LICENSE_CONFIG_ENV}");
    expose_dotenv_fallbacks(&dotenv);

    if config_value(REQUIRE_LICENSE_CONFIG_ENV, &dotenv).as_deref() == Some("1") {
        let mut missing_or_invalid: Vec<_> = NUMERIC_LICENSE_CONFIG_ENVS
            .iter()
            .filter(|key| {
                config_value(key, &dotenv)
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none_or(|value| value == 0)
            })
            .copied()
            .collect();

        missing_or_invalid.extend(
            CHECKOUT_URL_ENVS
                .iter()
                .filter(|key| {
                    config_value(key, &dotenv).is_none_or(|value| {
                        let value = value.trim();
                        value.is_empty() || !value.starts_with(CHECKOUT_URL_PREFIX)
                    })
                })
                .copied(),
        );

        if !missing_or_invalid.is_empty() {
            panic!(
                "release builds require real LemonSqueezy config; missing/invalid env vars: {}",
                missing_or_invalid.join(", ")
            );
        }
    }

    #[cfg(feature = "desktop")]
    {
        let attributes = tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(APP_COMMANDS));
        tauri_build::try_build(attributes).expect("failed to run tauri-build");
    }
}
