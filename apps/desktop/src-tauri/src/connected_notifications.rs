//! Connected email destinations and per-site notification settings.
//!
//! Non-admin projections omit addresses and revisions, so those wire fields are
//! optional even when the admin response requires them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connected_service::{local_error, ConnectedServiceClient, ConnectedServiceError};

/// Independent suppression controls for immediate and digest delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DestinationPolicy {
    #[serde(default)]
    pub immediate_disabled: bool,
    #[serde(default)]
    pub digest_disabled: bool,
}

/// One service destination. Admin-only fields remain optional.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DestinationRow {
    pub id: String,
    #[serde(default)]
    pub address: Option<String>,
    pub verification: String,
    #[serde(default)]
    pub verified_at: Option<String>,
    #[serde(default)]
    pub suppressed: bool,
    #[serde(default)]
    pub suppression_reason: Option<String>,
    #[serde(default)]
    pub policy: DestinationPolicy,
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DestinationList {
    #[serde(default)]
    destinations: Vec<DestinationRow>,
}

#[derive(Debug, Serialize)]
struct CreateDestinationRequest<'a> {
    address: &'a str,
}

#[derive(Debug, Serialize)]
struct PatchDestinationRequest {
    revision: i64,
    policy: DestinationPolicy,
}

/// The service answers the resend with `202 {"resent": true}`. Modelled rather
/// than discarded so a body that stops saying so is a parse failure here
/// instead of a silent "sent" the user believes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct VerificationResent {
    #[serde(default)]
    pub resent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct DestinationDeleted {
    #[serde(default)]
    pub deleted: bool,
}

/// One opt-in measurement threshold. The desktop has no editor for these, but
/// the settings PUT is a full replacement, so they are modelled precisely
/// enough to be read and written back unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationThreshold {
    pub series_id: String,
    pub bound: String,
    pub value: f64,
    #[serde(default)]
    pub hysteresis: Option<f64>,
}

/// The delivery spec's deliberately small control set, plus the destination
/// reference a site subscribes through. A `destination_id` of `None` is the
/// service's "alerts unconfigured" state, which is what every site starts in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// The optimistic-concurrency guard the next PUT must carry. It arrives on
    /// reads, but is skipped when this document is flattened into a PUT body
    /// because the request wrapper owns the single wire-level revision field.
    #[serde(default, skip_serializing)]
    pub revision: i64,
    #[serde(default)]
    pub destination_id: Option<String>,
    #[serde(default)]
    pub mute: bool,
    #[serde(default)]
    pub all_quiet_heartbeat: bool,
    #[serde(default)]
    pub severity_floor: Option<String>,
    pub digest_cadence: String,
    pub content_mode: String,
    #[serde(default)]
    pub thresholds: Vec<NotificationThreshold>,
}

#[derive(Debug, Serialize)]
struct PutNotificationSettingsRequest<'a> {
    revision: i64,
    #[serde(flatten)]
    settings: &'a NotificationSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct NotificationSettingsReceipt {
    pub revision: i64,
}

impl ConnectedServiceClient {
    /// Add or return an email destination without implicitly resending verification.
    pub async fn create_destination(
        &self,
        address: &str,
    ) -> Result<DestinationRow, ConnectedServiceError> {
        let body = serde_json::to_string(&CreateDestinationRequest { address })
            .map_err(|_| serialization_refused("destination"))?;
        let url = self.url(&["v1", "destinations"])?;
        self.request(reqwest::Method::POST, url, None, Some(body))
            .await
    }

    /// List destinations visible to the current installation.
    pub async fn list_destinations(&self) -> Result<Vec<DestinationRow>, ConnectedServiceError> {
        let url = self.url(&["v1", "destinations"])?;
        let listing: DestinationList = self.request(reqwest::Method::GET, url, None, None).await?;
        Ok(listing.destinations)
    }

    /// Update policy only at the caller's observed revision.
    pub async fn patch_destination_policy(
        &self,
        destination_id: &str,
        revision: i64,
        policy: DestinationPolicy,
    ) -> Result<DestinationRow, ConnectedServiceError> {
        let body = serde_json::to_string(&PatchDestinationRequest { policy, revision })
            .map_err(|_| serialization_refused("destination policy"))?;
        let url = self.url(&["v1", "destinations", destination_id])?;
        self.request(reqwest::Method::PATCH, url, None, Some(body))
            .await
    }

    /// Re-mint and re-send the confirmation email. Rate-limited per
    /// destination, and the one deliberate path out of suppression.
    pub async fn resend_destination_verification(
        &self,
        destination_id: &str,
    ) -> Result<VerificationResent, ConnectedServiceError> {
        let url = self.url(&["v1", "destinations", destination_id, "resend"])?;
        self.request(reqwest::Method::POST, url, None, Some("{}".to_string()))
            .await
    }

    /// Delete a destination no site still points at. One that is still
    /// referenced refuses and names the sites, so unplugging a shared pager is
    /// always a deliberate detach-then-delete.
    pub async fn delete_destination(
        &self,
        destination_id: &str,
    ) -> Result<DestinationDeleted, ConnectedServiceError> {
        let url = self.url(&["v1", "destinations", destination_id])?;
        self.request(reqwest::Method::DELETE, url, None, None).await
    }

    pub async fn notification_settings(
        &self,
        site_id: &str,
    ) -> Result<NotificationSettings, ConnectedServiceError> {
        let url = self.url(&["v1", "sites", site_id, "notification-settings"])?;
        self.request(reqwest::Method::GET, url, None, None).await
    }

    /// Replace all notification settings under a revision guard.
    /// Callers must preserve thresholds the desktop cannot edit.
    pub async fn put_notification_settings(
        &self,
        site_id: &str,
        revision: i64,
        settings: &NotificationSettings,
    ) -> Result<NotificationSettingsReceipt, ConnectedServiceError> {
        let body = serde_json::to_string(&PutNotificationSettingsRequest { revision, settings })
            .map_err(|_| serialization_refused("notification settings"))?;
        let url = self.url(&["v1", "sites", site_id, "notification-settings"])?;
        self.request(reqwest::Method::PUT, url, None, Some(body))
            .await
    }
}

/// The sites a `409 destination_in_use` named. Empty for any other refusal, so
/// a caller can ask unconditionally and branch on what comes back.
pub fn destination_in_use_sites(error: &ConnectedServiceError) -> Vec<String> {
    if error.code != "destination_in_use" {
        return Vec::new();
    }
    error
        .details
        .as_ref()
        .and_then(|details| details.get("sites"))
        .and_then(Value::as_array)
        .map(|sites| {
            sites
                .iter()
                .filter_map(|site| site.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Return the current revision reported by a stale-write response.
pub fn stale_revision_current(error: &ConnectedServiceError) -> Option<i64> {
    if !error.is_stale_revision() {
        return None;
    }
    error
        .details
        .as_ref()
        .and_then(|details| details.get("current_revision"))
        .and_then(Value::as_i64)
}

fn serialization_refused(kind: &str) -> ConnectedServiceError {
    local_error(
        "serialization_failed",
        &format!("connected {kind} request could not be encoded"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admin_listing_carries_addresses_and_consent_state() {
        let listing: DestinationList = serde_json::from_str(
            r#"{"destinations": [{
                "id": "dst_1",
                "address": "ops@example.com",
                "verification": "unverified",
                "verified_at": null,
                "suppressed": false,
                "suppression_reason": null,
                "policy": {"immediate_disabled": false, "digest_disabled": true},
                "revision": 3,
                "created_at": "2026-08-01T00:00:00Z"
            }]}"#,
        )
        .expect("parse");
        let row = &listing.destinations[0];
        assert_eq!(row.address.as_deref(), Some("ops@example.com"));
        assert_eq!(row.verification, "unverified");
        assert!(row.policy.digest_disabled);
        assert_eq!(row.revision, 3);
    }

    #[test]
    fn the_non_admin_projection_parses_without_address_or_revision() {
        let listing: DestinationList = serde_json::from_str(
            r#"{"destinations": [{
                "id": "dst_1",
                "verification": "verified",
                "suppressed": true,
                "policy": {"immediate_disabled": false, "digest_disabled": false}
            }]}"#,
        )
        .expect("parse");
        let row = &listing.destinations[0];
        assert!(row.address.is_none());
        assert_eq!(row.revision, 0);
        assert!(row.suppressed);
    }

    #[test]
    fn the_settings_put_body_carries_the_revision_beside_the_full_replacement() {
        let settings = NotificationSettings {
            revision: 4,
            all_quiet_heartbeat: true,
            content_mode: "private".into(),
            destination_id: Some("dst_1".into()),
            digest_cadence: "weekly".into(),
            mute: false,
            severity_floor: Some("high".into()),
            thresholds: vec![NotificationThreshold {
                bound: "upper".into(),
                hysteresis: None,
                series_id: "lcp_ms".into(),
                value: 2500.0,
            }],
        };
        let body = serde_json::to_string(&PutNotificationSettingsRequest {
            revision: 4,
            settings: &settings,
        })
        .expect("encode");
        assert_eq!(
            body,
            r#"{"revision":4,"destination_id":"dst_1","mute":false,"all_quiet_heartbeat":true,"severity_floor":"high","digest_cadence":"weekly","content_mode":"private","thresholds":[{"series_id":"lcp_ms","bound":"upper","value":2500.0,"hysteresis":null}]}"#
        );
    }

    #[test]
    fn settings_read_back_with_the_service_defaults_a_never_written_site_has() {
        let settings: NotificationSettings = serde_json::from_str(
            r#"{"revision": 7, "destination_id": null, "mute": false, "severity_floor": null,
                "digest_cadence": "weekly", "content_mode": "private", "thresholds": []}"#,
        )
        .expect("parse");
        assert!(settings.destination_id.is_none());
        assert_eq!(settings.revision, 7);
        assert_eq!(settings.digest_cadence, "weekly");
        assert!(!settings.all_quiet_heartbeat);
        assert!(settings.thresholds.is_empty());
    }

    #[test]
    fn an_in_use_refusal_names_the_sites_and_other_refusals_name_none() {
        let in_use = ConnectedServiceError {
            status: 409,
            code: "destination_in_use".into(),
            message: "Sites still deliver to this destination.".into(),
            request_id: None,
            details: Some(Box::new(
                serde_json::json!({ "sites": ["site_a", "site_b"] }),
            )),
            retry_after: None,
        };
        assert_eq!(destination_in_use_sites(&in_use), ["site_a", "site_b"]);

        let unrelated = ConnectedServiceError {
            status: 403,
            code: "admin_required".into(),
            message: "Only an admin installation may change this account.".into(),
            request_id: None,
            details: Some(Box::new(serde_json::json!({ "sites": ["site_a"] }))),
            retry_after: None,
        };
        assert!(destination_in_use_sites(&unrelated).is_empty());
    }

    #[test]
    fn a_stale_refusal_reads_the_service_revision_when_the_write_loses_a_race() {
        let stale = ConnectedServiceError {
            status: 409,
            code: "stale_revision".into(),
            message: "The settings changed since this revision was read.".into(),
            request_id: None,
            details: Some(Box::new(serde_json::json!({ "current_revision": 7 }))),
            retry_after: None,
        };
        assert_eq!(stale_revision_current(&stale), Some(7));

        let bare = ConnectedServiceError {
            details: None,
            ..stale.clone()
        };
        assert_eq!(stale_revision_current(&bare), None);
        assert_eq!(
            stale_revision_current(&ConnectedServiceError {
                code: "unknown_destination".into(),
                status: 400,
                ..stale
            }),
            None
        );
    }
}
