//! Domain-organized Tauri IPC command handlers.

mod agent_tools;
mod alerts;
mod app_settings;
pub mod catalog;
mod code_scan;
pub(crate) mod connected;
mod connected_alerts;
mod connected_credentials;
mod connected_delivery;
mod connected_notifications;
mod connected_providers;
mod connected_recovery;
mod connected_rotation;
mod connected_setup;
mod connected_transfer;
pub mod correlation;
mod correlation_preview;
mod data;
mod desktop;
mod desktop_project_commands;
mod desktop_watch;
mod error;
mod events;
mod fix_attempt_guidance;
mod fix_attempts;
mod integrations;
mod issue_links;
pub(crate) mod issue_source_capabilities;
pub(crate) mod issues;
mod oauth;
pub(crate) mod privileged_command_broker;
mod project;
mod project_dashboard;
mod project_git;
mod project_maintenance_items;
mod project_signal_monitoring;
mod project_signal_snapshots;
mod project_signal_state;
mod project_work_items;
mod reports;
pub(crate) mod scan;
mod scan_scope;
mod site_baseline;
mod sitemap;
mod telemetry;
pub mod telemetry_schema;
mod updates;
mod webhooks;

use std::sync::LazyLock;

pub use error::{CommandError, CommandResult};
pub use tokio::sync::Mutex as TokioMutex;

/// Every privileged broker's scope: its broker command, label, allowlist,
/// and sensitive-command subset. For code that audits or documents the
/// table itself rather than dispatching through it; currently only the
/// broker threat model guardrail (`lib_tests.rs`) calls this.
#[cfg(test)]
pub(crate) fn privileged_command_broker_scopes() -> &'static [privileged_command_broker::BrokerScope]
{
    privileged_command_broker::SCOPES
}

/// Unix paths: two or more slash-separated segments. A segment may contain
/// spaces (`"Application Support"`), so this is deliberately permissive: it
/// also over-matches into any trailing prose that happens to follow a path
/// (`"...open /a/b/c then it failed"`). The regex crate has no lookaround,
/// so a single pattern cannot both allow spaces inside a segment and stop
/// exactly at the real path; `path_trailing_prose` recovers the prose half
/// after the match, in a second, non-regex pass.
pub(crate) static PATH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    let pattern = r"(?:/[\w.@-]+(?: [\w.@-]+)*){2,}";
    regex::Regex::new(pattern).expect("static Unix path regex") // allow-expect: compile-time literal regex
});

/// Windows drive paths (`C:\a\b`) and UNC paths (`\\server\share\a`). The
/// segment class already allows spaces (`"Program Files"`), which is the
/// same permissive-match tradeoff `PATH_RE` makes; `path_trailing_prose`
/// trims the same way.
static WINDOWS_PATH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?:[A-Za-z]:|\\\\[^\\\s]+)(?:\\[^\\/:*?"<>|\r\n]+)+"#)
        .expect("static Windows path regex") // allow-expect: compile-time literal regex
});

/// Split a permissive path-regex match (`PATH_RE` or `WINDOWS_PATH_RE`) into
/// its real final segment and whatever prose follows it. The real path ends
/// at the first space after the last `separator`; a segment with an
/// embedded space (`"Application Support"`, `"Program Files"`) survives
/// because it is a middle segment, not the last one on the line that
/// decides where the match ends here. A space inside the *final* segment is
/// the one shape this can't tell apart from trailing prose and still leaks:
/// see the `..._leaks_a_spaced_final_segment` tests.
fn path_trailing_prose(candidate: &str, separator: char) -> &str {
    let last_separator = candidate.rfind(separator).unwrap_or(0);
    let after_separator = &candidate[last_separator..];
    let cut = last_separator + after_separator.find(' ').unwrap_or(after_separator.len());
    &candidate[cut..]
}

/// URLs whose path segments must survive the path stripping.
static URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    let pattern = r#"(?:https?|wss?)://[^\s'"<>]+"#;
    regex::Regex::new(pattern).expect("static URL regex") // allow-expect: compile-time literal regex
});

/// Sanitize error messages before returning to the frontend. Strips Windows
/// and Unix filesystem paths, keeps URLs intact, then redacts secret formats.
pub(crate) fn sanitize_error(msg: impl std::fmt::Display) -> String {
    let raw = msg.to_string();
    let mut urls = Vec::new();
    let held = URL_RE.replace_all(&raw, |captures: &regex::Captures| {
        urls.push(captures[0].to_string());
        format!("\u{1}URL{}\u{1}", urls.len() - 1)
    });
    let stripped = WINDOWS_PATH_RE.replace_all(&held, |captures: &regex::Captures| {
        format!("[internal path]{}", path_trailing_prose(&captures[0], '\\'))
    });
    let stripped = PATH_RE.replace_all(&stripped, |captures: &regex::Captures| {
        format!("[internal path]{}", path_trailing_prose(&captures[0], '/'))
    });
    let mut restored = stripped.into_owned();
    for (index, url) in urls.iter().enumerate() {
        restored = restored.replace(&format!("\u{1}URL{index}\u{1}"), url);
    }
    crate::log_sanitizer::redact_secrets(&restored)
}

/// Validate a scan URL the person named. It may point at their own machine or
/// the networks it is attached to; link-local targets, the addresses that are
/// not hosts, and DNS names resolving to them are rejected.
#[cfg(test)]
pub(crate) fn validate_url(url: &str) -> Result<(), String> {
    crate::network_policy::validate_url_blocking(url, crate::network_policy::UrlPolicy::ScanTarget)
}

/// Async version of `validate_url`; use this from Tauri commands so DNS
/// resolution does not occupy Tokio's foreground IPC workers.
pub(crate) async fn validate_url_async(url: &str) -> Result<(), String> {
    crate::network_policy::validate_url(url, crate::network_policy::UrlPolicy::ScanTarget).await
}

/// Validate an outbound callback/webhook URL. Unlike scans, external callbacks
/// cannot target localhost or any private/internal address.
#[cfg(test)]
pub(crate) fn validate_external_callback_url(url: &str) -> Result<(), String> {
    crate::network_policy::validate_url_blocking(
        url,
        crate::network_policy::UrlPolicy::ExternalCallback,
    )
}

pub(crate) async fn validate_external_callback_url_async(url: &str) -> Result<(), String> {
    crate::network_policy::validate_url(url, crate::network_policy::UrlPolicy::ExternalCallback)
        .await
}

pub(crate) async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| sanitize_error(format!("Background task failed: {}", e)))
}

/// Distinguishes a user-declined confirmation from a dialog failure.
#[derive(Debug)]
pub(crate) enum SensitiveActionError {
    Declined,
    Failed(String),
}

impl std::fmt::Display for SensitiveActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SensitiveActionError::Declined => write!(f, "Sensitive operation cancelled"),
            SensitiveActionError::Failed(error) => write!(f, "{error}"),
        }
    }
}

impl From<SensitiveActionError> for String {
    fn from(error: SensitiveActionError) -> String {
        error.to_string()
    }
}

/// How loud a native confirmation should be. `Warning` is for an action that
/// destroys data, revokes access, or discloses a secret, where the dialog is
/// telling the person what is about to happen to them. `Notice` is for the
/// rest, where the dialog exists only to prove a person asked for the action
/// and a warning icon would overstate a save they just clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SensitiveActionTone {
    Notice,
    Warning,
}

/// Whether a native confirmation dialog is currently on screen. See the swap
/// in `confirm_sensitive_action` for why this outlives the timeout.
static CONFIRM_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) async fn confirm_sensitive_action(
    app: tauri::AppHandle,
    title: &'static str,
    tone: SensitiveActionTone,
    message: String,
    approve_label: &'static str,
) -> Result<(), SensitiveActionError> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

    let kind = match tone {
        SensitiveActionTone::Notice => MessageDialogKind::Info,
        SensitiveActionTone::Warning => MessageDialogKind::Warning,
    };

    // Native dialogs cannot be cancelled, so serialize them until each closes.
    if CONFIRM_IN_FLIGHT.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err(SensitiveActionError::Failed(
            "A confirmation is already waiting for an answer. Answer it before trying again."
                .to_string(),
        ));
    }
    let dialog = tauri::async_runtime::spawn_blocking(move || {
        let answer = app
            .dialog()
            .message(message)
            .title(title)
            .kind(kind)
            .buttons(MessageDialogButtons::OkCancelCustom(
                approve_label.to_string(),
                "Cancel".to_string(),
            ))
            .blocking_show();
        CONFIRM_IN_FLIGHT.store(false, std::sync::atomic::Ordering::SeqCst);
        answer
    });

    // A dialog nobody can answer must not hold the invoke open forever; see
    // the constant for what that failure actually looks like.
    let approved =
        match tokio::time::timeout(crate::constants::SENSITIVE_CONFIRM_TIMEOUT, dialog).await {
            Ok(joined) => {
                joined.map_err(|error| SensitiveActionError::Failed(sanitize_error(error)))?
            }
            Err(_) => {
                // Say what actually happened. "The confirmation dialog did not
                // open" was false in the common case: the dialog opened and is
                // still sitting there unanswered, which is exactly why the
                // deadline expired.
                return Err(SensitiveActionError::Failed(
                    "The confirmation was not answered in time. Nothing was changed.".to_string(),
                ));
            }
        };

    if approved {
        Ok(())
    } else {
        Err(SensitiveActionError::Declined)
    }
}

pub(crate) use crate::core::app_emit::{emit_event, emit_site_score_changed};

/// Convert a period string like "7d", "30d", "90d" to an integer day count.
/// Falls back to 30 if the format is unrecognized.
#[tracing::instrument(fields(period = %period))]
pub(crate) fn period_to_days(period: &str) -> u32 {
    match period {
        "7d" => 7,
        "30d" => 30,
        "90d" => 90,
        "365d" => 365,
        _ => {
            // Try parsing number from string like "14d"
            period.trim_end_matches('d').parse().unwrap_or(30)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_external_callback_url, validate_url, SensitiveActionError};

    /// The decline-versus-failure distinction is the contract callers rely
    /// on: Cancelled renders as silence in the licensing UI, so a dialog
    /// that died must never stringify into the decline's exact wording.
    #[test]
    fn a_decline_and_a_dead_dialog_stay_distinguishable() {
        let declined: String = SensitiveActionError::Declined.into();
        assert_eq!(declined, "Sensitive operation cancelled");
        let failed: String = SensitiveActionError::Failed("dialog task died".to_string()).into();
        assert_eq!(failed, "dialog task died");
        assert_ne!(declined, failed);
    }

    #[test]
    fn validate_url_allows_explicit_local_dev_loopback() {
        assert!(validate_url("http://localhost:5173").is_ok());
        assert!(validate_url("http://127.0.0.1:5173").is_ok());
        assert!(validate_url("http://[::1]:5173").is_ok());
    }

    #[test]
    fn validate_url_accepts_a_dev_server_on_the_persons_own_network() {
        // The app and the CLI reach the same scanner, so they answer the same
        // way about a LAN dev server. They did not before: the app refused it
        // here while the CLI never checked a bare address at all.
        assert!(validate_url("http://192.168.1.10").is_ok());
        assert!(validate_url("http://10.0.0.5").is_ok());
        assert!(validate_url("http://100.100.4.7").is_ok());
    }

    #[test]
    fn validate_url_still_rejects_link_local_and_the_addresses_that_are_not_hosts() {
        // Cloud metadata answers on link-local and a scan body travels.
        assert!(validate_url("http://169.254.169.254").is_err());
        assert!(validate_url("http://[fe80::1]").is_err());
        assert!(validate_url("http://224.0.0.1").is_err());
    }

    #[test]
    fn external_callback_validation_rejects_local_targets() {
        assert!(validate_external_callback_url("http://localhost:5173").is_err());
        assert!(validate_external_callback_url("http://127.0.0.1:5173").is_err());
        assert!(validate_external_callback_url("http://[::1]:5173").is_err());
    }

    #[test]
    fn external_callback_validation_rejects_metadata_host() {
        assert!(validate_external_callback_url("https://metadata.google.internal").is_err());
    }
}

/// Update the system tray menu item and tooltip to reflect scan progress.
#[tauri::command]
#[tracing::instrument(skip(tray_state, url), fields(scanning, pct))]
pub async fn update_tray_scan_status(
    tray_state: tauri::State<'_, crate::TrayState>,
    scanning: bool,
    url: Option<String>,
    pct: Option<u32>,
) -> Result<(), String> {
    tray_state
        .is_scanning
        .store(scanning, std::sync::atomic::Ordering::Relaxed);

    if scanning {
        let host = url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "site".to_string());
        let p = pct.unwrap_or(0);
        let _ = tray_state
            .scan_item
            .set_text(format!("Scanning {} - {}%", host, p));
        let _ = tray_state
            .tray_icon
            .set_tooltip(Some(&format!("SiteCMD - Scanning {} ({}%)", host, p)));
    } else {
        let _ = tray_state.scan_item.set_text("Scan Now");
        let tooltip = tray_state
            .summary_tooltip
            .read()
            .map(|value| value.clone())
            .unwrap_or_else(|_| "SiteCMD".to_string());
        let _ = tray_state.tray_icon.set_tooltip(Some(&tooltip));
    }

    Ok(())
}

pub use agent_tools::*;
pub use alerts::*;
pub use app_settings::*;
pub use catalog::*;
pub use code_scan::*;
pub use connected::*;
pub use connected_alerts::*;
pub use connected_credentials::*;
pub use connected_delivery::*;
pub use connected_notifications::*;
pub use connected_providers::*;
pub use connected_recovery::*;
pub use connected_rotation::*;
pub use connected_setup::*;
pub use connected_transfer::*;
pub use correlation::*;
pub use correlation_preview::*;
pub use data::*;
pub use desktop::*;
pub use desktop_project_commands::*;
pub use events::*;
pub use fix_attempts::*;
pub use integrations::*;
pub use issue_links::*;
pub use issues::*;
pub use oauth::*;
pub use privileged_command_broker::*;
pub use project::*;
pub use project_dashboard::*;
pub use project_git::*;
pub use reports::*;
pub use scan::*;
pub use scan_scope::*;
pub use site_baseline::*;
pub use sitemap::*;
pub use telemetry::*;
pub use updates::*;
pub use webhooks::*;

#[cfg(test)]
mod async_work_tests;
