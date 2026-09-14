//! License lifecycle commands: activate, validate, deactivate, status.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};

#[cfg(debug_assertions)]
use super::dev_info_from_state_when_licensing_unconfigured;
use super::{
    classify_offline_validation, free_info, info_from_state, info_from_state_with_warning, now_iso,
    state_refreshed_from_validation_result, LicenseInfo, OfflineValidationState, ValidationWarning,
    INSTANCE_DEACTIVATED_STATUS,
};
use crate::db::Database;
use crate::licensing::access::is_entitled_license_status;
use crate::licensing::activation_errors::{
    classify_activation_error, normalize_license_key, LicenseActivationErrorCode,
    LicenseActivationErrorPayload,
};
use crate::licensing::api;
use crate::licensing::config::{self, Tier};
use crate::licensing::store::{self, LicenseState};

/// Serializes keyring and row generation comparisons and writes.
/// Network and dialogs run unlocked. The credential lock may acquire this lock
/// for bounded reads, but this lock is never held while acquiring that one.
static LICENSE_MUTATION: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Expose the generation lock for atomic keyring and row reads.
pub(crate) fn license_mutation() -> &'static tokio::sync::Mutex<()> {
    &LICENSE_MUTATION
}

pub use crate::licensing::generation::note_license_rows_replaced;
use crate::licensing::generation::{license_write_generation, record_license_write};

fn activation_error(code: LicenseActivationErrorCode) -> String {
    LicenseActivationErrorPayload::new(code).to_json_string()
}

/// Whether a captured key and instance still identify the installed generation.
fn same_license_generation(
    captured_instance: &str,
    current: Option<&LicenseState>,
    captured_key: Option<&str>,
    current_key: Option<&str>,
) -> bool {
    snapshot_unchanged(Some(captured_instance), current, captured_key, current_key)
}

/// Compare generations when either snapshot may be empty.
fn snapshot_unchanged(
    captured_instance: Option<&str>,
    current: Option<&LicenseState>,
    captured_key: Option<&str>,
    current_key: Option<&str>,
) -> bool {
    let instance_matches = match (captured_instance, current) {
        (Some(captured), Some(state)) => state.instance_id == captured,
        (None, None) => true,
        _ => false,
    };
    let key_matches = match (captured_key, current_key) {
        (Some(captured), Some(current)) => {
            license_key_fingerprint(captured) == license_key_fingerprint(current)
        }
        (None, None) => true,
        _ => false,
    };
    instance_matches && key_matches
}

/// Whether an activation-limit refusal may release this machine's own seat and retry.
fn own_seat_retry_applies(
    plan: &ActivationPlan,
    same_key: bool,
    has_orphaned_row: bool,
    code: LicenseActivationErrorCode,
) -> bool {
    if code != LicenseActivationErrorCode::LimitReached {
        return false;
    }
    match plan {
        ActivationPlan::Teardown { .. } => same_key,
        ActivationPlan::Fresh => has_orphaned_row,
        ActivationPlan::AlreadyActive => false,
    }
}

/// Classify either transport errors or parseable provider refusals from a mint.
fn mint_refusal_code(
    minted: &Result<api::LicenseResult, String>,
) -> Option<LicenseActivationErrorCode> {
    match minted {
        Err(error) => Some(classify_activation_error(error)),
        Ok(result) if !result.valid => Some(
            crate::licensing::activation_errors::classify_provider_refusal(
                result.error.as_deref().unwrap_or("Activation failed"),
            ),
        ),
        Ok(_) => None,
    }
}

/// Treat empty stored values as an absent license key across every reader.
pub(crate) fn usable_key(stored: Option<String>) -> Option<String> {
    stored.filter(|key| !key.trim().is_empty())
}

/// Read the cached license row off the async runtime workers:
/// `Database::execute` blocks the calling thread on the DB worker's reply.
async fn load_cached_license_state(db: &Arc<Database>) -> Result<Option<LicenseState>, String> {
    let db = db.clone();
    crate::commands::run_blocking(move || db.execute(store::load)).await??
}

fn activation_error_from_raw(raw: &str) -> String {
    LicenseActivationErrorPayload::new(classify_activation_error(raw)).to_json_string()
}

/// Maximum provider refusal text forwarded to the UI.
const MAX_PROVIDER_REASON_CHARS: usize = 200;

/// Preserve conclusive provider refusals and bounded provider text.
fn provider_refusal_error(raw: &str) -> String {
    let code = crate::licensing::activation_errors::classify_provider_refusal(raw);
    let payload = LicenseActivationErrorPayload::new(code);
    if code != LicenseActivationErrorCode::ProviderRefused {
        return payload.to_json_string();
    }
    // Do not attribute internal response diagnostics to the provider.
    if raw.contains("License response missing") {
        return LicenseActivationErrorPayload::new(LicenseActivationErrorCode::ServerError)
            .to_json_string();
    }
    payload
        .with_message(
            raw.chars()
                .take(MAX_PROVIDER_REASON_CHARS)
                .collect::<String>(),
        )
        .to_json_string()
}

/// Release an instance whose local handles are about to disappear.
/// Retryable failures leave a pending-release tombstone.
async fn release_orphaned_instance(app: &AppHandle, license_key: &str, instance_id: &str) {
    let error = match api::deactivate(license_key, instance_id).await {
        Ok(()) => return,
        Err(error) if api::deactivate_failure_proves_absence(&error) => {
            tracing::info!(
                "Upstream instance {} needs no release ({}); nothing recorded",
                instance_id,
                error
            );
            return;
        }
        Err(error) if api::deactivate_failure_is_terminal(&error) => {
            tracing::error!(
                "Upstream instance {} was refused conclusively ({}) and was not proven free; nothing will retry it",
                instance_id,
                error
            );
            return;
        }
        Err(error) => error,
    };
    match crate::background::catalog_refresh::record_pending_provider_release(
        app,
        license_key,
        instance_id,
        false,
    )
    .await
    {
        crate::background::CatalogRelease::PendingRecorded => tracing::warn!(
            "Upstream instance {} could not be released; recorded for retry: {}",
            instance_id,
            error
        ),
        outcome => tracing::error!(
            "Upstream instance {} could not be released ({}) and its retry could not be \
             recorded ({:?}); this seat is stranded until support frees it",
            instance_id,
            error,
            outcome
        ),
    }
}

/// Adopt the server-authoritative tier when the same installation is still current.
pub(crate) async fn adopt_server_tier(
    db: &Arc<Database>,
    fetched_for_instance: &str,
    server_tier: &str,
) {
    let adopted = match server_tier {
        "core" => Tier::Core,
        "pro" => Tier::Pro,
        _ => return,
    };
    let _generation = LICENSE_MUTATION.lock().await;
    let row = match load_cached_license_state(db).await {
        Ok(Some(row)) => row,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!("Server tier not adopted; license row unreadable: {error}");
            return;
        }
    };
    if row.instance_id != fetched_for_instance || row.tier == adopted {
        return;
    }
    tracing::info!(
        "Adopting plan change from catalog service: {} -> {}",
        row.tier,
        adopted
    );
    let updated = LicenseState {
        tier: adopted,
        ..row
    };
    let save_result = {
        let db = (*db).clone();
        crate::commands::run_blocking(move || db.execute(move |conn| store::save(conn, &updated)))
            .await
    };
    record_license_write();
    match save_result {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => tracing::warn!("Adopted tier could not be saved: {error}"),
        Ok(Err(error)) => tracing::warn!("Adopted tier could not be saved: {error}"),
        Err(error) => tracing::warn!("Adopted tier could not be saved: {error}"),
    }
}

/// Return cached license status without an API call.
#[tauri::command]
#[tracing::instrument(skip(db))]
pub async fn get_license_status(db: State<'_, Arc<Database>>) -> Result<LicenseInfo, String> {
    if !config::license_configured() {
        #[cfg(debug_assertions)]
        {
            let cached = load_cached_license_state(&db).await?;
            if let Some(info) = cached
                .as_ref()
                .and_then(dev_info_from_state_when_licensing_unconfigured)
            {
                return Ok(info);
            }
        }

        return Ok(free_info());
    }

    let cached = load_cached_license_state(&db).await?;

    match cached {
        Some(state) => {
            if is_entitled_license_status(&state.status) {
                offline_validation_or_downgrade(&state)
            } else {
                Ok(info_from_state(&state))
            }
        }
        None => Ok(free_info()),
    }
}

use activation::{license_key_fingerprint, ActivationPlan};
use validation::offline_validation_or_downgrade;

#[path = "license_lifecycle_activation.rs"]
mod activation;
#[path = "license_lifecycle_deactivation.rs"]
mod deactivation;
#[path = "license_lifecycle_validation.rs"]
mod validation;

pub use activation::activate_license;
#[cfg(test)]
use activation::{activation_plan, license_activation_audit_detail, license_replacement_required};
pub use deactivation::deactivate_license;
#[cfg(test)]
use deactivation::{
    deactivate_key_source, deactivation_result, worst_release, DeactivateKeySource,
    UpstreamRelease, DEACTIVATION_KEYCHAIN_REMNANT,
};
pub use validation::validate_license;
#[cfg(test)]
use validation::{
    capped_by_observation, conservative_answer, grace_warning_for, revalidation_required,
    GraceCause,
};

#[cfg(test)]
#[path = "license_lifecycle_tests.rs"]
mod tests;
