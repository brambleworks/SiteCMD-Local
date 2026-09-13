//! Consent-gated, schema-validated telemetry egress to fixed endpoints.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::telemetry_schema::{
    sanitized_diagnostic, validate_deletion, validate_ingest, validate_registration,
    DiagnosticReport, TelemetryDeletionBody, TelemetryIngestBody, TelemetryRegistrationBody,
};
use super::CommandResult;

const USAGE_TELEMETRY_HOST: &str = "telemetry.sitecmd.com";
const SENTRY_INGEST_HOST: &str = "o4511662343127040.ingest.us.sentry.io";
const USAGE_REGISTER_PATH: &str = "/v1/register";
const USAGE_EVENTS_PATH: &str = "/v1/events";
const USAGE_DELETE_PATH: &str = "/v1/delete";
const TELEMETRY_CONSENT_FILENAME: &str = "telemetry-consent.json";
const TELEMETRY_CONSENT_VERSION: u8 = 1;

static DIAGNOSTIC_EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedTelemetryConsent {
    consent_version: u8,
    usage_analytics: bool,
    crash_reports: bool,
    updated_at: Option<String>,
}

impl Default for PersistedTelemetryConsent {
    fn default() -> Self {
        Self {
            consent_version: TELEMETRY_CONSENT_VERSION,
            usage_analytics: false,
            crash_reports: false,
            updated_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryConsentView {
    usage_analytics: bool,
    crash_reports: bool,
    consent_version: u8,
    updated_at: Option<String>,
}

impl From<&PersistedTelemetryConsent> for TelemetryConsentView {
    fn from(value: &PersistedTelemetryConsent) -> Self {
        Self {
            usage_analytics: value.usage_analytics,
            crash_reports: value.crash_reports,
            consent_version: value.consent_version,
            updated_at: value.updated_at.clone(),
        }
    }
}

/// Private, fail-closed authority for usage and crash telemetry consent.
pub struct TelemetryConsentState {
    path: PathBuf,
    value: Mutex<PersistedTelemetryConsent>,
    update_gate: tokio::sync::Mutex<()>,
}

impl TelemetryConsentState {
    pub fn load(app_data_dir: &Path) -> Result<Self, String> {
        let path = app_data_dir.join(TELEMETRY_CONSENT_FILENAME);
        crate::app_identity::validate_private_file_target(&path).map_err(|error| {
            super::sanitize_error(format!(
                "Could not validate telemetry consent state: {error}"
            ))
        })?;
        let value = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<PersistedTelemetryConsent>(&bytes)
                .ok()
                .filter(|value| value.consent_version == TELEMETRY_CONSENT_VERSION)
                .unwrap_or_else(|| {
                    tracing::warn!("Telemetry consent state was invalid and has been disabled");
                    PersistedTelemetryConsent::default()
                }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PersistedTelemetryConsent::default()
            }
            Err(error) => {
                return Err(super::sanitize_error(format!(
                    "Could not read telemetry consent state: {error}"
                )))
            }
        };
        Ok(Self {
            path,
            value: Mutex::new(value),
            update_gate: tokio::sync::Mutex::new(()),
        })
    }

    fn snapshot(&self) -> Result<PersistedTelemetryConsent, String> {
        self.value
            .lock()
            .map(|value| value.clone())
            .map_err(|_| "Telemetry consent state is unavailable".to_string())
    }

    fn persist(&self, value: PersistedTelemetryConsent) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|error| super::sanitize_error(format!("Could not encode consent: {error}")))?;
        crate::app_identity::write_private_file(&self.path, &bytes).map_err(|error| {
            super::sanitize_error(format!("Could not save telemetry consent: {error}"))
        })?;
        let mut current = self
            .value
            .lock()
            .map_err(|_| "Telemetry consent state is unavailable".to_string())?;
        *current = value;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetTelemetryConsentArgs {
    usage_analytics: bool,
    crash_reports: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TelemetryRequestArgs {
    UsageRegister {
        body: TelemetryRegistrationBody,
    },
    UsageEvents {
        body: TelemetryIngestBody,
        authorization: String,
    },
    UsageDelete {
        body: TelemetryDeletionRequest,
    },
    CrashReport {
        report: DiagnosticReport,
    },
}

/// What the renderer sends for a deletion. The secret that authorizes it is
/// read from the keychain here and never crosses IPC in either direction.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryDeletionRequest {
    subject_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryHttpResponse {
    status: u16,
    body: String,
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequiredConsent {
    None,
    Usage,
    Crash,
}

struct PreparedTelemetryRequest {
    url: Url,
    content_type: &'static str,
    body: Vec<u8>,
    authorization: Option<HeaderValue>,
    required_consent: RequiredConsent,
}

#[tauri::command]
pub fn get_telemetry_consent(
    state: tauri::State<'_, TelemetryConsentState>,
) -> Result<TelemetryConsentView, String> {
    let current = state.snapshot()?;
    Ok(TelemetryConsentView::from(&current))
}

#[tauri::command]
#[tracing::instrument(skip(app, state, args))]
pub async fn set_telemetry_consent(
    app: tauri::AppHandle,
    state: tauri::State<'_, TelemetryConsentState>,
    args: SetTelemetryConsentArgs,
) -> Result<TelemetryConsentView, String> {
    let _update_guard = state.update_gate.lock().await;
    let current = state.snapshot()?;
    let enables_usage = args.usage_analytics && !current.usage_analytics;
    let enables_crash = args.crash_reports && !current.crash_reports;
    if enables_usage || enables_crash {
        let channels = match (enables_usage, enables_crash) {
            (true, true) => "anonymous usage analytics and scrubbed crash reports",
            (true, false) => "anonymous usage analytics",
            (false, true) => "scrubbed crash reports",
            (false, false) => unreachable!(),
        };
        super::confirm_sensitive_action(
            app,
            "Enable Optional Telemetry",
            // Opting in is a grant the person just made, not something being
            // done to them, so the prompt confirms intent without the icon
            // that the destructive actions rely on to mean something.
            super::SensitiveActionTone::Notice,
            format!(
                "Allow SiteCMD to send {channels}? Usage data goes only to telemetry.sitecmd.com. Crash reports go only to SiteCMD's Sentry ingest project. Scan URLs, source code, credentials, and local file paths are excluded."
            ),
            "Enable",
        )
        .await
        .map_err(String::from)?;
    }

    let next = PersistedTelemetryConsent {
        consent_version: TELEMETRY_CONSENT_VERSION,
        usage_analytics: args.usage_analytics,
        crash_reports: args.crash_reports,
        updated_at: Some(Utc::now().to_rfc3339()),
    };
    state.persist(next.clone())?;
    crate::audit_log::record(
        "telemetry_consent_changed",
        serde_json::json!({
            "usage_analytics": next.usage_analytics,
            "crash_reports": next.crash_reports,
        }),
        "success",
    );
    Ok(TelemetryConsentView::from(&next))
}

/// The deletion secret, minted on first use. `delete_` plus 32 random bytes
/// as hex satisfies both this client's validator and the ingest service's,
/// which require the prefix and at least 32 body characters.
fn telemetry_delete_secret<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<Zeroizing<String>, String> {
    if let Some(existing) = crate::keyring::get_telemetry_delete_secret(app)? {
        return Ok(Zeroizing::new(existing));
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| super::sanitize_error(format!("OS randomness unavailable: {error}")))?;
    let minted = Zeroizing::new(format!("delete_{}", hex::encode(bytes.as_slice())));
    crate::keyring::store_telemetry_delete_secret(app, &minted)?;
    Ok(minted)
}

/// SHA-256 of the secret, as the ingest service stores it at registration.
fn delete_proof_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Hand the renderer the proof it sends with every event. The secret itself
/// stays in the keychain; only its hash crosses IPC.
#[tauri::command]
pub fn get_telemetry_delete_proof_hash(app: tauri::AppHandle) -> CommandResult<String> {
    Ok(delete_proof_hash(&telemetry_delete_secret(&app)?))
}

/// Forget the secret when the subject is reset. The next proof request mints
/// a fresh one, which is what a new anonymous identity means.
#[tauri::command]
pub fn clear_telemetry_delete_secret(app: tauri::AppHandle) -> CommandResult<()> {
    Ok(crate::keyring::delete_telemetry_delete_secret(&app)?)
}

/// Send one typed request after validating current backend consent.
#[tauri::command]
#[tracing::instrument(skip(app, state, args))]
pub async fn send_telemetry_request(
    app: tauri::AppHandle,
    state: tauri::State<'_, TelemetryConsentState>,
    args: TelemetryRequestArgs,
) -> Result<TelemetryHttpResponse, String> {
    let request = prepare_request(&app, args)?;
    require_consent(&state.snapshot()?, request.required_consent)?;
    if request.body.len() > crate::constants::TELEMETRY_REQUEST_MAX_BYTES {
        return Err("Telemetry payload exceeds the allowed size".to_string());
    }

    let mut outbound = crate::http_client::credentialed_service_client()
        .post(request.url)
        .header(CONTENT_TYPE, request.content_type)
        .body(request.body);
    if let Some(value) = request.authorization {
        outbound = outbound.header(AUTHORIZATION, value);
    }

    let response = outbound
        .send()
        .await
        .map_err(|error| super::sanitize_error(format!("Telemetry request failed: {error}")))?;
    let status = response.status().as_u16();
    let headers = response_headers(&response);
    let body = crate::http_client::read_text_limited(
        response,
        crate::constants::TELEMETRY_RESPONSE_MAX_BYTES,
        crate::constants::API_TIMEOUT_SHORT,
    )
    .await
    .map_err(|error| super::sanitize_error(format!("Telemetry response failed: {error}")))?;

    Ok(TelemetryHttpResponse {
        status,
        body,
        headers,
    })
}

fn prepare_request<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    args: TelemetryRequestArgs,
) -> Result<PreparedTelemetryRequest, String> {
    match args {
        TelemetryRequestArgs::UsageRegister { body } => {
            validate_registration(&body)?;
            prepared_usage_request(USAGE_REGISTER_PATH, &body, None, RequiredConsent::Usage)
        }
        TelemetryRequestArgs::UsageEvents {
            body,
            authorization,
        } => {
            validate_ingest(&body)?;
            let authorization = validate_authorization(authorization)?;
            prepared_usage_request(
                USAGE_EVENTS_PATH,
                &body,
                Some(authorization),
                RequiredConsent::Usage,
            )
        }
        TelemetryRequestArgs::UsageDelete { body } => {
            let body = TelemetryDeletionBody {
                subject_id: body.subject_id,
                delete_secret: telemetry_delete_secret(app)?.to_string(),
            };
            validate_deletion(&body)?;
            prepared_usage_request(USAGE_DELETE_PATH, &body, None, RequiredConsent::None)
        }
        TelemetryRequestArgs::CrashReport { report } => {
            let diagnostic = sanitized_diagnostic(&report)?;
            let (url, dsn) = configured_sentry_endpoint()?;
            let body = build_sentry_envelope(&diagnostic, &dsn)?;
            Ok(PreparedTelemetryRequest {
                url,
                content_type: "application/x-sentry-envelope",
                body,
                authorization: None,
                required_consent: RequiredConsent::Crash,
            })
        }
    }
}

fn prepared_usage_request<T: Serialize>(
    path: &str,
    body: &T,
    authorization: Option<HeaderValue>,
    required_consent: RequiredConsent,
) -> Result<PreparedTelemetryRequest, String> {
    let url = Url::parse(&format!("https://{USAGE_TELEMETRY_HOST}{path}"))
        .map_err(|_| "Telemetry endpoint configuration is invalid".to_string())?;
    validate_telemetry_target(&url)?;
    let body = serde_json::to_vec(body)
        .map_err(|error| super::sanitize_error(format!("Could not encode telemetry: {error}")))?;
    Ok(PreparedTelemetryRequest {
        url,
        content_type: "application/json",
        body,
        authorization,
        required_consent,
    })
}

fn require_consent(
    consent: &PersistedTelemetryConsent,
    required: RequiredConsent,
) -> Result<(), String> {
    let permitted = match required {
        RequiredConsent::None => true,
        RequiredConsent::Usage => consent.usage_analytics,
        RequiredConsent::Crash => consent.crash_reports,
    };
    if permitted {
        Ok(())
    } else {
        Err("This telemetry channel is disabled in SiteCMD privacy settings".to_string())
    }
}

fn validate_authorization(value: String) -> Result<HeaderValue, String> {
    if value.len() > crate::constants::TELEMETRY_AUTHORIZATION_MAX_BYTES
        || !value.starts_with("Bearer ")
        || value.len() == "Bearer ".len()
    {
        return Err("Telemetry authorization header is invalid".to_string());
    }
    HeaderValue::from_str(&value)
        .map_err(|_| "Telemetry authorization header is invalid".to_string())
}

fn configured_sentry_endpoint() -> Result<(Url, String), String> {
    let dsn = option_env!("VITE_SITECMD_SENTRY_DSN")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Crash reporting is not configured in this build".to_string())?;
    sentry_endpoint_from_dsn(dsn).map(|url| (url, dsn.to_string()))
}

fn sentry_endpoint_from_dsn(dsn: &str) -> Result<Url, String> {
    let parsed = Url::parse(dsn).map_err(|_| "Sentry DSN is invalid".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some(SENTRY_INGEST_HOST)
        || parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some_and(|port| port != 443)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed
            .username()
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Err("Sentry DSN is not an approved ingest configuration".to_string());
    }
    let project_id = parsed.path().trim_matches('/');
    if project_id.is_empty()
        || !project_id
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err("Sentry DSN project is invalid".to_string());
    }
    let mut url = Url::parse(&format!(
        "https://{SENTRY_INGEST_HOST}/api/{project_id}/envelope/"
    ))
    .map_err(|_| "Sentry endpoint configuration is invalid".to_string())?;
    url.query_pairs_mut()
        .append_pair("sentry_version", "7")
        .append_pair("sentry_key", parsed.username())
        .append_pair("sentry_client", "sitecmd-desktop/1");
    validate_telemetry_target(&url)?;
    Ok(url)
}

fn build_sentry_envelope(diagnostic: &serde_json::Value, dsn: &str) -> Result<Vec<u8>, String> {
    let event_id = diagnostic_event_id();
    let timestamp = Utc::now().to_rfc3339();
    let payload = serde_json::json!({
        "event_id": event_id,
        "timestamp": timestamp,
        "platform": "javascript",
        "level": "error",
        "logger": "sitecmd.desktop",
        "release": diagnostic["appVersion"],
        "environment": diagnostic["buildChannel"],
        "message": diagnostic["message"],
        "exception": {
            "values": [{
                "type": diagnostic["name"],
                "value": diagnostic["message"],
            }],
        },
        "tags": {
            "sitecmd.event": diagnostic["name"],
            "sitecmd.consent_version": TELEMETRY_CONSENT_VERSION.to_string(),
        },
        "extra": {
            "properties": diagnostic["properties"],
            "sanitized_stack": diagnostic["stack"],
        },
    });
    let payload = serde_json::to_vec(&payload)
        .map_err(|error| super::sanitize_error(format!("Could not encode diagnostic: {error}")))?;
    let envelope_header = serde_json::to_vec(&serde_json::json!({
        "event_id": event_id,
        "sent_at": timestamp,
        "dsn": dsn,
        "sdk": { "name": "sitecmd.desktop", "version": "1" },
    }))
    .map_err(|error| super::sanitize_error(format!("Could not encode diagnostic: {error}")))?;
    let item_header = serde_json::to_vec(&serde_json::json!({
        "type": "event",
        "content_type": "application/json",
        "length": payload.len(),
    }))
    .map_err(|error| super::sanitize_error(format!("Could not encode diagnostic: {error}")))?;

    let mut envelope =
        Vec::with_capacity(envelope_header.len() + item_header.len() + payload.len() + 3);
    envelope.extend(envelope_header);
    envelope.push(b'\n');
    envelope.extend(item_header);
    envelope.push(b'\n');
    envelope.extend(payload);
    envelope.push(b'\n');
    Ok(envelope)
}

fn diagnostic_event_id() -> String {
    let counter = DIAGNOSTIC_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let input = format!(
        "{}:{}:{}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::process::id(),
        counter
    );
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest).chars().take(32).collect()
}

fn validate_telemetry_target(url: &Url) -> Result<(), String> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
    {
        return Err("Telemetry endpoint is not allowed".to_string());
    }
    match url.host_str() {
        Some(USAGE_TELEMETRY_HOST)
            if url.query().is_none()
                && matches!(
                    url.path(),
                    USAGE_REGISTER_PATH | USAGE_EVENTS_PATH | USAGE_DELETE_PATH
                ) =>
        {
            Ok(())
        }
        Some(SENTRY_INGEST_HOST) => validate_sentry_target(url),
        _ => Err("Telemetry endpoint is not allowed".to_string()),
    }
}

fn validate_sentry_target(url: &Url) -> Result<(), String> {
    let segments: Vec<_> = url
        .path_segments()
        .ok_or_else(|| "Sentry endpoint path is not allowed".to_string())?
        .collect();
    let path_is_envelope = matches!(
        segments.as_slice(),
        ["api", project_id, "envelope"] | ["api", project_id, "envelope", ""]
            if !project_id.is_empty() && project_id.chars().all(|character| character.is_ascii_digit())
    );
    if !path_is_envelope {
        return Err("Sentry endpoint path is not allowed".to_string());
    }
    let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    if query.len() != 3
        || query.get("sentry_version").map(String::as_str) != Some("7")
        || !query
            .get("sentry_key")
            .is_some_and(|value| !value.is_empty() && value.len() <= 256)
        || !query
            .get("sentry_client")
            .is_some_and(|value| !value.is_empty() && value.len() <= 256)
    {
        return Err("Sentry endpoint query is not allowed".to_string());
    }
    Ok(())
}

fn response_headers(response: &reqwest::Response) -> BTreeMap<String, String> {
    ["content-type", "retry-after", "x-sentry-rate-limits"]
        .into_iter()
        .filter_map(|name| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_consent_is_required_for_each_upload_channel() {
        let disabled = PersistedTelemetryConsent::default();
        assert!(require_consent(&disabled, RequiredConsent::Usage).is_err());
        assert!(require_consent(&disabled, RequiredConsent::Crash).is_err());
        assert!(require_consent(&disabled, RequiredConsent::None).is_ok());

        let enabled = PersistedTelemetryConsent {
            usage_analytics: true,
            crash_reports: true,
            ..disabled
        };
        assert!(require_consent(&enabled, RequiredConsent::Usage).is_ok());
        assert!(require_consent(&enabled, RequiredConsent::Crash).is_ok());
    }

    #[test]
    fn persisted_consent_defaults_closed_and_rejects_unknown_fields() {
        let default = PersistedTelemetryConsent::default();
        assert!(!default.usage_analytics);
        assert!(!default.crash_reports);
        assert!(serde_json::from_str::<PersistedTelemetryConsent>(
            r#"{"consentVersion":1,"usageAnalytics":true,"crashReports":true,"endpoint":"bad"}"#
        )
        .is_err());
    }

    #[test]
    fn sentry_endpoint_is_derived_from_the_baked_dsn_only() {
        let endpoint =
            sentry_endpoint_from_dsn(&format!("https://publickey@{SENTRY_INGEST_HOST}/451"))
                .expect("valid configured DSN");
        assert_eq!(endpoint.host_str(), Some(SENTRY_INGEST_HOST));
        assert_eq!(endpoint.path(), "/api/451/envelope/");
        assert!(endpoint.as_str().contains("sentry_key=publickey"));

        for invalid in [
            "https://publickey@example.com/451".to_string(),
            format!("https://publickey@{SENTRY_INGEST_HOST}/not-a-project"),
            format!("https://publickey:secret@{SENTRY_INGEST_HOST}/451"),
        ] {
            assert!(sentry_endpoint_from_dsn(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn request_target_allowlist_rejects_endpoint_variants() {
        for invalid in [
            format!("http://{USAGE_TELEMETRY_HOST}{USAGE_EVENTS_PATH}"),
            format!("https://{USAGE_TELEMETRY_HOST}.example{USAGE_EVENTS_PATH}"),
            format!("https://{USAGE_TELEMETRY_HOST}:8443{USAGE_EVENTS_PATH}"),
            format!("https://user@{USAGE_TELEMETRY_HOST}{USAGE_EVENTS_PATH}"),
            format!("https://{USAGE_TELEMETRY_HOST}{USAGE_EVENTS_PATH}?next=bad"),
        ] {
            let url = Url::parse(&invalid).expect("test URL should parse");
            assert!(validate_telemetry_target(&url).is_err(), "{invalid}");
        }
    }

    #[test]
    fn the_deletion_secret_is_minted_once_and_its_proof_is_stable() {
        let _guard = crate::keyring::SECRET_TEST_GUARD
            .lock()
            .expect("secret test guard");
        let app = tauri::test::mock_app();
        let handle = app.handle();
        crate::keyring::delete_telemetry_delete_secret(handle).expect("clean slate");

        let first = telemetry_delete_secret(handle).expect("mint");
        let second = telemetry_delete_secret(handle).expect("reread");
        assert_eq!(*first, *second, "a second read must not mint again");
        assert!(first.starts_with("delete_"));
        assert_eq!(first.len(), "delete_".len() + 64);
        assert_eq!(delete_proof_hash(&first), delete_proof_hash(&second));

        crate::keyring::delete_telemetry_delete_secret(handle).expect("reset");
        let rotated = telemetry_delete_secret(handle).expect("mint again");
        assert_ne!(*first, *rotated, "a reset must mint a fresh secret");
    }

    #[test]
    fn a_deletion_request_carries_the_keychain_secret_not_a_renderer_value() {
        let _guard = crate::keyring::SECRET_TEST_GUARD
            .lock()
            .expect("secret test guard");
        let app = tauri::test::mock_app();
        let handle = app.handle();
        crate::keyring::delete_telemetry_delete_secret(handle).expect("clean slate");
        let secret = telemetry_delete_secret(handle).expect("mint");

        let request = prepare_request(
            handle,
            TelemetryRequestArgs::UsageDelete {
                body: TelemetryDeletionRequest {
                    subject_id: "scmd_12345678".into(),
                },
            },
        )
        .expect("prepared");
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json body");
        assert_eq!(body["subjectId"], "scmd_12345678");
        assert_eq!(body["deleteSecret"], secret.as_str());
        assert_eq!(request.required_consent, RequiredConsent::None);
    }

    #[test]
    fn diagnostic_envelope_contains_only_reconstructed_fields() {
        let diagnostic = serde_json::json!({
            "name": "frontend_error",
            "message": "scrubbed",
            "stack": ["at main"],
            "properties": {"page": "dashboard"},
            "appVersion": "1.2.3",
            "buildChannel": "production",
        });
        let envelope = build_sentry_envelope(
            &diagnostic,
            &format!("https://publickey@{SENTRY_INGEST_HOST}/451"),
        )
        .expect("diagnostic envelope");
        let text = String::from_utf8(envelope).expect("utf8 envelope");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        let item: serde_json::Value = serde_json::from_str(lines[1]).expect("item header");
        assert_eq!(item["type"], "event");
        let payload: serde_json::Value = serde_json::from_str(lines[2]).expect("event payload");
        assert!(payload.get("request").is_none());
        assert!(payload.get("user").is_none());
        assert_eq!(payload["extra"]["properties"]["page"], "dashboard");
    }
}
