//! Commands for connected email destinations and per-site routing.
//!
//! Consent-gated sends use native confirmation, and actionable service refusals
//! return structured outcomes.

use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, State};
use ts_rs::TS;

use crate::connected_notifications::{
    destination_in_use_sites, stale_revision_current, DestinationPolicy, NotificationSettings,
};
use crate::connected_service::ConnectedServiceError;
use crate::db::Database;

use super::connected_providers::installation_client;
use super::connected_setup::connected_client;
use super::sanitize_error;

/// Account email destination. Non-admin installations omit `address` but can
/// still read verification and suppression state.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedDestination {
    pub destination_id: String,
    pub address: Option<String>,
    pub verification: String,
    pub verified_at: Option<String>,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub immediate_disabled: bool,
    pub digest_disabled: bool,
    pub revision: i64,
    pub created_at: Option<String>,
}

/// Result of a revision-guarded destination write.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedDestinationWrite {
    pub applied: bool,
    pub refusal: String,
    pub message: String,
    pub revision: i64,
}

/// Verification resend result, including rate-limit refusals.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedVerificationResend {
    pub sent: bool,
    pub refusal: String,
    pub message: String,
}

/// Deletion result, including sites that still use the destination.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedDestinationDeletion {
    pub deleted: bool,
    pub refusal: String,
    pub message: String,
    pub sites: Vec<String>,
}

/// Site alert routing; `None` destination means unconfigured.
/// `threshold_count` preserves service-side thresholds the desktop cannot edit.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedNotificationSettings {
    pub revision: i64,
    pub destination_id: Option<String>,
    pub mute: bool,
    pub all_quiet_heartbeat: bool,
    pub severity_floor: Option<String>,
    pub digest_cadence: String,
    pub content_mode: String,
    pub threshold_count: i64,
}

/// The answer to a settings write, in the same shape as a guarded destination
/// write so the two refusals read alike on screen.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedNotificationSettingsWrite {
    pub applied: bool,
    pub refusal: String,
    pub message: String,
    pub revision: i64,
}

const SEVERITY_FLOORS: [&str; 4] = ["critical", "high", "medium", "low"];
const DIGEST_CADENCES: [&str; 3] = ["weekly", "daily", "off"];
const CONTENT_MODES: [&str; 2] = ["private", "minimal"];

fn present_destination(
    row: crate::connected_notifications::DestinationRow,
) -> ConnectedDestination {
    ConnectedDestination {
        address: row.address,
        created_at: row.created_at,
        destination_id: row.id,
        digest_disabled: row.policy.digest_disabled,
        immediate_disabled: row.policy.immediate_disabled,
        revision: row.revision,
        suppressed: row.suppressed,
        suppression_reason: row.suppression_reason,
        verification: row.verification,
        verified_at: row.verified_at,
    }
}

/// Add or return an email destination without implicitly resending confirmation.
#[tracing::instrument(skip(app, address))]
pub async fn create_connected_destination(
    app: AppHandle,
    address: String,
) -> Result<ConnectedDestination, String> {
    let address = address.trim();
    if address.is_empty() {
        return Err("an email address is required".into());
    }
    let client = installation_client(&app)?;
    let created = client.create_destination(address).await.map_err(|error| {
        // The service answers a bad address with its uniform malformed-body
        // refusal, which tells the person nothing about what they typed.
        if error.code == "malformed_request" {
            "that does not look like an email address".to_string()
        } else {
            sanitize_error(error)
        }
    })?;
    crate::audit_log::record(
        "connect.destination_create",
        serde_json::json!({ "destination": created.id }),
        "ok",
    );
    Ok(present_destination(created))
}

/// Every destination the caller may see. An admin reads the account's whole
/// inventory; anyone else reads only the health of what its own sites already
/// point at, without addresses.
#[tracing::instrument(skip(app))]
pub async fn list_connected_destinations(
    app: AppHandle,
) -> Result<Vec<ConnectedDestination>, String> {
    let client = installation_client(&app)?;
    let rows = client.list_destinations().await.map_err(sanitize_error)?;
    Ok(rows.into_iter().map(present_destination).collect())
}

/// Update delivery policy only at the revision the caller observed.
#[tracing::instrument(skip(app))]
pub async fn update_connected_destination_policy(
    app: AppHandle,
    destination_id: String,
    revision: i64,
    immediate_disabled: bool,
    digest_disabled: bool,
) -> Result<ConnectedDestinationWrite, String> {
    let client = installation_client(&app)?;
    let policy = DestinationPolicy {
        digest_disabled,
        immediate_disabled,
    };
    match client
        .patch_destination_policy(destination_id.trim(), revision, policy)
        .await
    {
        Ok(row) => Ok(ConnectedDestinationWrite {
            applied: true,
            message: String::new(),
            refusal: String::new(),
            revision: row.revision,
        }),
        Err(error) if error.is_stale_revision() => Ok(ConnectedDestinationWrite {
            applied: false,
            message: "This destination changed somewhere else while you were deciding. Check what it says now before changing it again.".into(),
            refusal: error.code.clone(),
            revision: stale_revision_current(&error).unwrap_or(revision),
        }),
        Err(error) => Err(sanitize_error(error)),
    }
}

/// Re-send the confirmation email for one destination.
///
/// Also the one deliberate path out of suppression: a bounced or
/// complained-about address resumes only by confirming again.
#[tracing::instrument(skip(app))]
pub async fn resend_connected_destination_verification(
    app: AppHandle,
    destination_id: String,
) -> Result<ConnectedVerificationResend, String> {
    let client = installation_client(&app)?;
    match client
        .resend_destination_verification(destination_id.trim())
        .await
    {
        Ok(receipt) => Ok(ConnectedVerificationResend {
            message: String::new(),
            refusal: String::new(),
            sent: receipt.resent,
        }),
        Err(error) if error.code == "rate_limited" => Ok(ConnectedVerificationResend {
            message: "A confirmation email went out recently. Wait a few minutes before asking for another one.".into(),
            refusal: error.code.clone(),
            sent: false,
        }),
        Err(error) => Err(sanitize_error(error)),
    }
}

/// Delete a destination.
///
/// A destination a site still delivers to comes back refused with those sites
/// named, so removal is always an explicit detach-then-delete.
#[tracing::instrument(skip(app))]
pub async fn delete_connected_destination(
    app: AppHandle,
    destination_id: String,
) -> Result<ConnectedDestinationDeletion, String> {
    let client = installation_client(&app)?;
    match client.delete_destination(destination_id.trim()).await {
        Ok(_) => {
            crate::audit_log::record(
                "connect.destination_delete",
                serde_json::json!({ "destination": destination_id.trim() }),
                "ok",
            );
            Ok(ConnectedDestinationDeletion {
                deleted: true,
                message: String::new(),
                refusal: String::new(),
                sites: Vec::new(),
            })
        }
        Err(error) if error.code == "destination_in_use" => Ok(ConnectedDestinationDeletion {
            deleted: false,
            message: "Sites still send their alerts here. Point them somewhere else first, then delete this address.".into(),
            refusal: error.code.clone(),
            sites: destination_in_use_sites(&error),
        }),
        Err(error) => Err(sanitize_error(error)),
    }
}

/// One site's alert routing, as the service holds it.
#[tracing::instrument(skip(app, db), fields(project_id))]
pub async fn get_connected_notification_settings(
    app: AppHandle,
    db: State<'_, Arc<Database>>,
    project_id: i64,
    environment_scope_key: String,
) -> Result<ConnectedNotificationSettings, String> {
    let (client, site) = connected_client(&app, &db, project_id, environment_scope_key).await?;
    let settings = client
        .notification_settings(&site)
        .await
        .map_err(sanitize_error)?;
    Ok(present_settings(settings))
}

fn present_settings(settings: NotificationSettings) -> ConnectedNotificationSettings {
    ConnectedNotificationSettings {
        revision: settings.revision,
        all_quiet_heartbeat: settings.all_quiet_heartbeat,
        content_mode: settings.content_mode,
        destination_id: settings.destination_id,
        digest_cadence: settings.digest_cadence,
        mute: settings.mute,
        severity_floor: settings.severity_floor,
        threshold_count: settings.thresholds.len() as i64,
    }
}

/// Replace alert routing while preserving thresholds this client cannot edit.
/// The service notifies the prior address when the destination changes.
#[tracing::instrument(skip(app, db), fields(project_id))]
pub async fn put_connected_notification_settings(
    app: AppHandle,
    db: State<'_, Arc<Database>>,
    project_id: i64,
    environment_scope_key: String,
    revision: i64,
    destination_id: Option<String>,
    mute: bool,
    all_quiet_heartbeat: bool,
    severity_floor: Option<String>,
    digest_cadence: String,
    content_mode: String,
) -> Result<ConnectedNotificationSettingsWrite, String> {
    let severity_floor = severity_floor.filter(|floor| !floor.is_empty());
    if let Some(floor) = severity_floor.as_deref() {
        if !SEVERITY_FLOORS.contains(&floor) {
            return Err("choose a severity floor the service knows".into());
        }
    }
    if !DIGEST_CADENCES.contains(&digest_cadence.as_str()) {
        return Err("choose a digest cadence the service knows".into());
    }
    if !CONTENT_MODES.contains(&content_mode.as_str()) {
        return Err("choose a content mode the service knows".into());
    }
    let (client, site) = connected_client(&app, &db, project_id, environment_scope_key).await?;
    let current = client
        .notification_settings(&site)
        .await
        .map_err(sanitize_error)?;
    let next = NotificationSettings {
        revision: current.revision,
        all_quiet_heartbeat,
        content_mode,
        destination_id: destination_id.filter(|id| !id.trim().is_empty()),
        digest_cadence,
        mute,
        severity_floor,
        thresholds: current.thresholds,
    };
    match client
        .put_notification_settings(&site, revision, &next)
        .await
    {
        Ok(receipt) => Ok(ConnectedNotificationSettingsWrite {
            applied: true,
            message: String::new(),
            refusal: String::new(),
            revision: receipt.revision,
        }),
        Err(error) => settings_refusal(error, revision),
    }
}

/// Convert actionable settings refusals into response outcomes.
fn settings_refusal(
    error: ConnectedServiceError,
    attempted_revision: i64,
) -> Result<ConnectedNotificationSettingsWrite, String> {
    if error.is_stale_revision() {
        let revision = stale_revision_current(&error).unwrap_or(attempted_revision);
        return Ok(ConnectedNotificationSettingsWrite {
            applied: false,
            message: "These settings changed somewhere else while you were deciding. Check what they say now before saving again.".into(),
            refusal: error.code,
            revision,
        });
    }
    if error.code == "unknown_destination" {
        return Ok(ConnectedNotificationSettingsWrite {
            applied: false,
            message:
                "That destination is no longer on this account. Refresh the list and choose again."
                    .into(),
            refusal: error.code,
            revision: attempted_revision,
        });
    }
    Err(sanitize_error(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connected_notifications::{DestinationRow, NotificationThreshold};

    fn stale(current: Option<i64>) -> ConnectedServiceError {
        ConnectedServiceError {
            status: 409,
            code: "stale_revision".into(),
            message: "The settings changed since this revision was read.".into(),
            request_id: None,
            details: current
                .map(|value| Box::new(serde_json::json!({ "current_revision": value }))),
            retry_after: None,
        }
    }

    #[test]
    fn a_non_admin_row_presents_without_an_address_rather_than_inventing_one() {
        let presented = present_destination(DestinationRow {
            address: None,
            created_at: None,
            id: "dst_1".into(),
            policy: DestinationPolicy::default(),
            revision: 0,
            suppressed: true,
            suppression_reason: None,
            verification: "verified".into(),
            verified_at: None,
        });
        assert!(presented.address.is_none());
        assert!(presented.suppressed);
        assert_eq!(presented.destination_id, "dst_1");
    }

    #[test]
    fn thresholds_are_reported_as_a_count_the_desktop_can_state_it_is_keeping() {
        let presented = present_settings(NotificationSettings {
            revision: 6,
            all_quiet_heartbeat: true,
            content_mode: "private".into(),
            destination_id: None,
            digest_cadence: "weekly".into(),
            mute: false,
            severity_floor: None,
            thresholds: vec![NotificationThreshold {
                bound: "upper".into(),
                hysteresis: Some(50.0),
                series_id: "lcp_ms".into(),
                value: 2500.0,
            }],
        });
        assert_eq!(presented.threshold_count, 1);
        assert_eq!(presented.revision, 6);
        assert!(presented.all_quiet_heartbeat);
        assert!(presented.destination_id.is_none());
    }

    #[test]
    fn a_stale_settings_write_answers_the_current_revision_not_a_failure() {
        let refused = settings_refusal(stale(Some(9)), 4).expect("actionable refusal");
        assert!(!refused.applied);
        assert_eq!(refused.refusal, "stale_revision");
        assert_eq!(refused.revision, 9);
        assert!(refused.message.contains("changed somewhere else"));
    }

    #[test]
    fn a_stale_refusal_without_a_revision_leaves_the_caller_where_it_was() {
        // Adopting a guess here would put the next write on top of a change
        // nobody saw. The invalidated settings read supplies the real value.
        assert_eq!(
            settings_refusal(stale(None), 4)
                .expect("actionable refusal")
                .revision,
            4
        );
    }

    #[test]
    fn an_unknown_destination_is_an_outcome_the_person_can_act_on() {
        let refused = settings_refusal(
            ConnectedServiceError {
                status: 400,
                code: "unknown_destination".into(),
                message: "No destination of that id exists on this account.".into(),
                request_id: None,
                details: None,
                retry_after: None,
            },
            2,
        )
        .expect("actionable refusal");
        assert!(!refused.applied);
        assert_eq!(refused.refusal, "unknown_destination");
        assert_eq!(refused.revision, 2);
        assert!(refused.message.contains("Refresh the list"));
    }

    #[test]
    fn a_non_actionable_settings_failure_is_re_raised() {
        let error = settings_refusal(
            ConnectedServiceError {
                status: 0,
                code: "transport_failed".into(),
                message: "The connected service could not be reached.".into(),
                request_id: None,
                details: None,
                retry_after: None,
            },
            1,
        )
        .expect_err("transport failures are not actionable refusals");
        assert!(error.contains("could not be reached"));
    }
}
