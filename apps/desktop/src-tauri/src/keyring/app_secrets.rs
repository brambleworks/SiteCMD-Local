//! Installation-wide secrets stored without a project namespace.

use tauri::AppHandle;

use super::store::{delete_secret, get_secret, get_secret_strict, set_secret};

/// Keychain entry name for the optional Google PageSpeed Insights API key.
const PAGESPEED_API_KEY_USER: &str = "app:pagespeed_api_key";

/// Store the PageSpeed Insights API key in the OS keychain.
pub fn store_pagespeed_api_key<R: tauri::Runtime>(
    app: &AppHandle<R>,
    key: &str,
) -> Result<(), String> {
    set_secret(app, PAGESPEED_API_KEY_USER, key)
}

/// Read the PageSpeed Insights API key from the OS keychain, if set.
pub fn get_pagespeed_api_key<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<String>, String> {
    get_secret(app, PAGESPEED_API_KEY_USER)
}

/// Remove the stored PageSpeed Insights API key.
pub fn delete_pagespeed_api_key<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    delete_secret(app, PAGESPEED_API_KEY_USER)
}

/// Keychain entry name for the LemonSqueezy license key.
const LICENSE_KEY_USER: &str = "app:license_key";

/// Store the license key in the OS keychain, never SQLite.
pub fn store_license_key<R: tauri::Runtime>(app: &AppHandle<R>, key: &str) -> Result<(), String> {
    set_secret(app, LICENSE_KEY_USER, key)
}

/// Read the license key strictly so keychain failures cannot masquerade as absence.
pub fn get_license_key<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<Option<String>, String> {
    get_secret_strict(app, LICENSE_KEY_USER)
}

/// Remove the stored license key (on deactivation).
pub fn delete_license_key<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    delete_secret(app, LICENSE_KEY_USER)
}

/// Keychain entry name for the usage-telemetry deletion secret.
const TELEMETRY_DELETE_SECRET_USER: &str = "app:telemetry_delete_secret";

/// Store the telemetry deletion secret in the OS keychain. It is the only
/// proof a person holds when asking the ingest service to erase what they
/// uploaded, so it never lives in the webview or in SQLite.
pub fn store_telemetry_delete_secret<R: tauri::Runtime>(
    app: &AppHandle<R>,
    secret: &str,
) -> Result<(), String> {
    set_secret(app, TELEMETRY_DELETE_SECRET_USER, secret)
}

/// Read the deletion secret strictly. A keychain failure must not read as
/// absence: absence mints a replacement, and a replacement orphans every
/// event already uploaded under the old proof.
pub fn get_telemetry_delete_secret<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<String>, String> {
    get_secret_strict(app, TELEMETRY_DELETE_SECRET_USER)
}

/// Remove the deletion secret when the telemetry subject is reset.
pub fn delete_telemetry_delete_secret<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    delete_secret(app, TELEMETRY_DELETE_SECRET_USER)
}

/// Keychain entry name for the catalog entitlement token.
const CATALOG_TOKEN_USER: &str = "app:catalog_token";

/// Store the one-time catalog token in the OS keychain.
pub fn store_catalog_token<R: tauri::Runtime>(
    app: &AppHandle<R>,
    token: &str,
) -> Result<(), String> {
    set_secret(app, CATALOG_TOKEN_USER, token)
}

/// Read the catalog token, treating keychain failures as errors rather than absence.
pub fn get_catalog_token<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<Option<String>, String> {
    get_secret_strict(app, CATALOG_TOKEN_USER)
}

/// Remove the stored catalog token (on license deactivation, or when the
/// catalog service reports the credential revoked).
pub fn delete_catalog_token<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    delete_secret(app, CATALOG_TOKEN_USER)
}

/// Keychain entry name for an activation attempt's pending nonce.
const PENDING_ACTIVATION_NONCE_USER: &str = "app:catalog_pending_nonce";

/// Persist an activation nonce with its issuing identity so retries remain
/// idempotent and cannot replay across identity changes.
pub fn store_pending_activation<R: tauri::Runtime>(
    app: &AppHandle<R>,
    pending: &crate::catalog::activation::PendingActivation,
) -> Result<(), String> {
    let record = serde_json::to_string(pending)
        .map_err(|error| format!("pending activation could not be encoded: {error}"))?;
    set_secret(app, PENDING_ACTIVATION_NONCE_USER, &record)
}

/// Read a pending activation strictly from storage but ignore undecodable,
/// identity-less records that the service cannot replay.
pub fn get_pending_activation<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<crate::catalog::activation::PendingActivation>, String> {
    Ok(get_secret_strict(app, PENDING_ACTIVATION_NONCE_USER)?
        .and_then(|raw| serde_json::from_str(&raw).ok()))
}

/// Clear the pending attempt once it reaches a conclusive outcome.
pub fn delete_pending_activation<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    delete_secret(app, PENDING_ACTIVATION_NONCE_USER)
}

/// Separate keychain slot for a pending connected activation nonce.
const PENDING_CONNECT_ACTIVATION_NONCE_USER: &str = "app:connect_pending_nonce";

pub fn store_pending_connect_activation<R: tauri::Runtime>(
    app: &AppHandle<R>,
    pending: &crate::catalog::activation::PendingActivation,
) -> Result<(), String> {
    let record = serde_json::to_string(pending)
        .map_err(|error| format!("pending connect activation could not be encoded: {error}"))?;
    set_secret(app, PENDING_CONNECT_ACTIVATION_NONCE_USER, &record)
}

/// Read pending connected activation state, ignoring malformed records.
pub fn get_pending_connect_activation<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<crate::catalog::activation::PendingActivation>, String> {
    Ok(
        get_secret_strict(app, PENDING_CONNECT_ACTIVATION_NONCE_USER)?
            .and_then(|raw| serde_json::from_str(&raw).ok()),
    )
}

pub fn delete_pending_connect_activation<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<(), String> {
    delete_secret(app, PENDING_CONNECT_ACTIVATION_NONCE_USER)
}

/// Keychain entry name for releases a service has not confirmed.
const PENDING_RELEASE_USER: &str = "app:catalog_pending_release";

/// Where an undecodable pending-release record is preserved, verbatim, when
/// the write path must move it aside to keep recording new owed releases.
const PENDING_RELEASE_QUARANTINE_USER: &str = "app:catalog_pending_release_quarantine";

/// Durable retry handle for independently owed catalog and license releases.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingRelease {
    pub license_key: String,
    pub installation_id: String,
    /// The catalog service has not confirmed the credential release.
    pub catalog: bool,
    /// The LemonSqueezy instance has not been deactivated.
    pub lemonsqueezy: bool,
}

impl PendingRelease {
    fn same_slot(&self, other: &PendingRelease) -> bool {
        self.license_key == other.license_key && self.installation_id == other.installation_id
    }

    fn settled(&self) -> bool {
        !self.catalog && !self.lemonsqueezy
    }
}

/// Merge owed release sides without displacing unresolved slots.
pub fn merge_pending_release(
    mut existing: Vec<PendingRelease>,
    addition: PendingRelease,
) -> Vec<PendingRelease> {
    if let Some(entry) = existing.iter_mut().find(|entry| entry.same_slot(&addition)) {
        entry.catalog |= addition.catalog;
        entry.lemonsqueezy |= addition.lemonsqueezy;
    } else {
        existing.push(addition);
    }
    existing
}

/// Clear only the sides settled by one drain pass, preserving concurrent additions.
pub fn settle_pending_release(
    mut existing: Vec<PendingRelease>,
    slot: &PendingRelease,
    resolved_catalog: bool,
    resolved_lemonsqueezy: bool,
) -> Vec<PendingRelease> {
    if let Some(position) = existing.iter().position(|entry| entry.same_slot(slot)) {
        if resolved_catalog {
            existing[position].catalog = false;
        }
        if resolved_lemonsqueezy {
            existing[position].lemonsqueezy = false;
        }
        if existing[position].settled() {
            existing.remove(position);
        }
    }
    existing
}

/// Record an undelivered release for retry while the caller holds the credential lock.
pub fn store_pending_release<R: tauri::Runtime>(
    app: &AppHandle<R>,
    release: PendingRelease,
) -> Result<(), String> {
    let mut retried = false;
    let existing = loop {
        match get_pending_releases(app) {
            Ok(existing) => break existing,
            // Retry one storage failure; only decode failures prove corruption.
            Err(PendingReleaseReadError::Storage(_)) if !retried => {
                retried = true;
            }
            // Preserve unreadable records and report that this release was not
            // recorded; callers have no later retry after local cleanup.
            Err(PendingReleaseReadError::Storage(error)) => {
                return Err(format!(
                    "pending releases unreadable after a retry ({error}); nothing was changed and this release was not recorded"
                ));
            }
            // Quarantine proven-corrupt bytes before starting a fresh list so
            // new releases are retained without destroying recovery evidence.
            Err(PendingReleaseReadError::Undecodable { raw, error }) => {
                quarantine_pending_release_record(app, &raw).map_err(|quarantine_error| {
                    format!("{error}; quarantine also failed: {quarantine_error}")
                })?;
                break Vec::new();
            }
        }
    };
    let merged = merge_pending_release(existing, release);
    replace_pending_releases(app, &merged)
}

/// Quarantine the exact undecodable release record without a second read.
/// The latest corrupt record replaces any earlier quarantine.
fn quarantine_pending_release_record<R: tauri::Runtime>(
    app: &AppHandle<R>,
    raw: &str,
) -> Result<(), String> {
    set_secret(app, PENDING_RELEASE_QUARANTINE_USER, raw)?;
    delete_secret(app, PENDING_RELEASE_USER)
}

/// Distinguishes storage failures from successfully read but undecodable data.
/// Only `Undecodable` records may be quarantined.
#[derive(Debug)]
pub enum PendingReleaseReadError {
    Storage(String),
    Undecodable { raw: String, error: String },
}

impl std::fmt::Display for PendingReleaseReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PendingReleaseReadError::Storage(error) => write!(f, "{error}"),
            PendingReleaseReadError::Undecodable { error, .. } => write!(f, "{error}"),
        }
    }
}

/// Read every unconfirmed release without treating storage or decode failures as empty.
/// Only the write path may quarantine corrupt records.
pub fn get_pending_releases<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<Vec<PendingRelease>, PendingReleaseReadError> {
    match get_secret_strict(app, PENDING_RELEASE_USER).map_err(PendingReleaseReadError::Storage)? {
        None => Ok(Vec::new()),
        Some(raw) => match serde_json::from_str::<Vec<PendingRelease>>(&raw) {
            Ok(releases) => Ok(releases),
            Err(error) => Err(PendingReleaseReadError::Undecodable {
                error: format!("pending-release record is unreadable (left in place): {error}"),
                raw,
            }),
        },
    }
}

/// Replace unresolved releases, deleting the entry when none remain.
pub fn replace_pending_releases<R: tauri::Runtime>(
    app: &AppHandle<R>,
    releases: &[PendingRelease],
) -> Result<(), String> {
    if releases.is_empty() {
        return delete_secret(app, PENDING_RELEASE_USER);
    }
    let record = serde_json::to_string(releases)
        .map_err(|error| format!("pending releases could not be encoded: {error}"))?;
    set_secret(app, PENDING_RELEASE_USER, &record)
}
