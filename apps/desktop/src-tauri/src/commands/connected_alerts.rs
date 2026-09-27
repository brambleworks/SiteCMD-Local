//! Connected alert timelines grouped by local and remote site scope.

use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, State};
use ts_rs::TS;

use crate::connected_alerts::{AlertStreamItem, ALERT_STREAM_PAGE_LIMIT};
use crate::connected_service::ConnectedServiceError;
use crate::db::{ConnectedSiteBinding, Database};

use super::connected_providers::installation_client;
use super::{run_blocking, sanitize_error};

// Mirror the service's availability vocabulary without reclassifying it.
const AVAILABILITY_READY: &str = "ready";
const AVAILABILITY_SERVICE_UNCONFIGURED: &str = "service_unconfigured";
const AVAILABILITY_SITE_NOT_CONNECTED: &str = "site_not_connected";
const AVAILABILITY_NO_INSTALLATION_TOKEN: &str = "no_installation_token";
const AVAILABILITY_NOT_ENTITLED: &str = "not_entitled";

/// Aggregated alert cause by event class and severity.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedAlertCause {
    pub kind: String,
    pub severity: Option<String>,
    pub count: i64,
}

/// Alert delivery metadata using opaque target IDs, never addresses.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedAlertDelivery {
    pub target_kind: String,
    pub target_id: String,
    pub outcome: String,
}

/// One alert the connected service raised for this environment's site.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedAlert {
    pub alert_id: String,
    pub sequence: i64,
    pub severity: Option<String>,
    pub causes: Vec<ConnectedAlertCause>,
    /// The mode the site had when the alert was minted. A later mode change
    /// cannot rewrite what the mail already said, so this travels per alert.
    pub content_mode: Option<String>,
    pub deployment_id: Option<String>,
    pub delivery: Vec<ConnectedAlertDelivery>,
    pub raised_at: String,
    pub updated_at: Option<String>,
}

/// Reference to an alert owned by another site, without cross-site finding details.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedAlertElsewhere {
    pub alert_id: String,
    /// Local project binding, or `None` when another machine owns the binding.
    pub project_id: Option<i64>,
    pub project_name: Option<String>,
    pub environment_url: Option<String>,
}

/// One read of the connected alert stream, scoped to one project environment.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct ConnectedAlertFeed {
    pub availability: String,
    /// Newest-first timeline rows.
    pub alerts: Vec<ConnectedAlert>,
    pub elsewhere: Vec<ConnectedAlertElsewhere>,
    /// Whether the bounded read may have omitted older alerts.
    pub truncated: bool,
}

fn unavailable(availability: &str) -> ConnectedAlertFeed {
    ConnectedAlertFeed {
        alerts: Vec::new(),
        availability: availability.to_string(),
        elsewhere: Vec::new(),
        truncated: false,
    }
}

fn present_alert(item: AlertStreamItem) -> ConnectedAlert {
    ConnectedAlert {
        alert_id: item.id,
        causes: item
            .causes
            .into_iter()
            .map(|cause| ConnectedAlertCause {
                count: cause.count,
                kind: cause.kind,
                severity: cause.severity,
            })
            .collect(),
        content_mode: item.content_mode,
        delivery: item
            .delivery
            .into_iter()
            .map(|cell| ConnectedAlertDelivery {
                outcome: cell.outcome,
                target_id: cell.target_id,
                target_kind: cell.target_kind,
            })
            .collect(),
        deployment_id: item.deployment_id,
        raised_at: item.created_at,
        sequence: item.alert_sequence,
        severity: item.top_severity,
        updated_at: item.updated_at,
    }
}

fn present_elsewhere(
    item: AlertStreamItem,
    bindings: &[ConnectedSiteBinding],
) -> ConnectedAlertElsewhere {
    let binding = bindings.iter().find(|binding| binding.site_id == item.site);
    ConnectedAlertElsewhere {
        alert_id: item.id,
        environment_url: binding.map(|binding| binding.env_url.clone()),
        project_id: binding.map(|binding| binding.project_id),
        project_name: binding.map(|binding| binding.project_name.clone()),
    }
}

/// List one environment's alerts without exposing details from other sites.
#[tracing::instrument(skip(app, db), fields(project_id))]
pub async fn list_connected_alerts(
    app: AppHandle,
    db: State<'_, Arc<Database>>,
    project_id: i64,
    environment_scope_key: String,
) -> Result<ConnectedAlertFeed, String> {
    if !crate::connected_service::is_configured() {
        return Ok(unavailable(AVAILABILITY_SERVICE_UNCONFIGURED));
    }
    let db_read = Arc::clone(&db);
    let env_read = environment_scope_key.clone();
    let site = run_blocking(move || db_read.get_connected_site(project_id, &env_read))
        .await?
        .map_err(sanitize_error)?;
    let Some(site) = site else {
        return Ok(unavailable(AVAILABILITY_SITE_NOT_CONNECTED));
    };
    // An unactivated binding may not have an installation token yet.
    let client = match installation_client(&app) {
        Ok(client) => client,
        Err(_) => return Ok(unavailable(AVAILABILITY_NO_INSTALLATION_TOKEN)),
    };

    let page = match client.list_alerts(ALERT_STREAM_PAGE_LIMIT).await {
        Ok(page) => page,
        // Suspended accounts expose the alert stream as unavailable.
        Err(error) if not_entitled(&error) => {
            return Ok(unavailable(AVAILABILITY_NOT_ENTITLED));
        }
        Err(error) => return Err(sanitize_error(error)),
    };
    let truncated = page.items.len() as u32 >= ALERT_STREAM_PAGE_LIMIT;

    let (mine, others): (Vec<AlertStreamItem>, Vec<AlertStreamItem>) = page
        .items
        .into_iter()
        .partition(|item| item.site == site.site_id);

    // Resolving site ids to projects only matters when the page carried an
    // alert from another site, which an account with one connected site never
    // does.
    let bindings = if others.is_empty() {
        Vec::new()
    } else {
        let db_bindings = Arc::clone(&db);
        run_blocking(move || db_bindings.connected_site_bindings())
            .await?
            .map_err(sanitize_error)?
    };

    // The service pages ascending by sequence; a timeline is read from the top.
    let mut alerts: Vec<ConnectedAlert> = mine.into_iter().map(present_alert).collect();
    alerts.reverse();

    Ok(ConnectedAlertFeed {
        alerts,
        availability: AVAILABILITY_READY.to_string(),
        elsewhere: others
            .into_iter()
            .map(|item| present_elsewhere(item, &bindings))
            .collect(),
        truncated,
    })
}

/// Return whether a stream refusal is an entitlement state rather than retryable I/O.
fn not_entitled(error: &ConnectedServiceError) -> bool {
    error.status == 403
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connected_alerts::{AlertCauseLine, AlertDeliveryCell};

    fn item(id: &str, site: &str) -> AlertStreamItem {
        AlertStreamItem {
            alert_sequence: 1,
            causes: vec![AlertCauseLine {
                count: 2,
                kind: "regression".into(),
                severity: Some("critical".into()),
            }],
            content_mode: Some("private".into()),
            created_at: "2026-08-10T12:00:00.000Z".into(),
            delivery: vec![AlertDeliveryCell {
                delivery_generation: 1,
                outcome: "sent".into(),
                target_id: "dst_1".into(),
                target_kind: "destination".into(),
            }],
            deployment_id: None,
            id: id.into(),
            site: site.into(),
            top_severity: Some("critical".into()),
            updated_at: None,
        }
    }

    #[test]
    fn a_presented_alert_keeps_the_delivery_record_that_says_someone_was_told() {
        let presented = present_alert(item("alr_1", "site_a"));
        assert_eq!(presented.delivery[0].target_kind, "destination");
        assert_eq!(presented.delivery[0].outcome, "sent");
        assert_eq!(presented.causes[0].count, 2);
        assert_eq!(presented.severity.as_deref(), Some("critical"));
    }

    #[test]
    fn an_alert_for_another_site_resolves_to_the_project_that_holds_it() {
        let bindings = vec![ConnectedSiteBinding {
            env_url: "https://staging.example.com".into(),
            project_id: 7,
            project_name: "Example".into(),
            site_id: "site_b".into(),
        }];
        let resolved = present_elsewhere(item("alr_2", "site_b"), &bindings);
        assert_eq!(resolved.project_id, Some(7));
        assert_eq!(resolved.project_name.as_deref(), Some("Example"));
        assert_eq!(
            resolved.environment_url.as_deref(),
            Some("https://staging.example.com")
        );
    }

    #[test]
    fn an_alert_for_a_site_this_machine_never_bound_names_no_project() {
        let resolved = present_elsewhere(item("alr_3", "site_c"), &[]);
        assert_eq!(resolved.project_id, None);
        assert_eq!(resolved.project_name, None);
    }

    #[test]
    fn an_unavailable_feed_is_empty_and_never_claims_truncation() {
        let feed = unavailable(AVAILABILITY_SITE_NOT_CONNECTED);
        assert_eq!(feed.availability, "site_not_connected");
        assert!(feed.alerts.is_empty());
        assert!(feed.elsewhere.is_empty());
        assert!(!feed.truncated);
    }

    #[test]
    fn only_a_forbidden_refusal_reads_as_an_entitlement_state() {
        let forbidden = ConnectedServiceError {
            code: "entitlement_suspended".into(),
            details: None,
            message: "This subscription is suspended.".into(),
            request_id: None,
            status: 403,
            retry_after: None,
        };
        assert!(not_entitled(&forbidden));
        assert!(!not_entitled(&ConnectedServiceError {
            status: 500,
            ..forbidden
        }));
    }
}
