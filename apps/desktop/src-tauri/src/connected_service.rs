//! Bounded authenticated HTTP contract for the connected service.

use reqwest::header::{HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sitecmd_engine::sync::{ClientGroupState, DesktopSubmission, DismissalPolicy};

pub(crate) mod autofix_jobs;
pub(crate) mod deployment_ordering;
#[cfg(test)]
pub(crate) mod test_double;

pub use autofix_jobs::{
    ClaimedFinding, ClaimedJob, Committer, FindingOutcomeReport, OperationToken, PullRequestReport,
    ResultReceipt, ResultReport,
};
pub use deployment_ordering::{
    CiDeploymentHead, ConnectedCurrentDeployment, ConnectedOrderingAuthority,
};

const CONNECTED_ENDPOINT: Option<&str> = option_env!("SITECMD_CONNECTED_ENDPOINT");
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

pub fn is_configured() -> bool {
    CONNECTED_ENDPOINT.is_some()
}

/// The stored scan scope, as state reports it. `None` on the state means no
/// scope has ever been PUT, which the bootstrap path reads as its cue to set
/// the initial one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectedScope {
    pub scope_revision: i64,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub check_families: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectedSiteState {
    pub phase: String,
    #[serde(default)]
    pub state_revision: i64,
    #[serde(default)]
    pub event_sequence: i64,
    #[serde(default)]
    pub current_deployment: Option<ConnectedCurrentDeployment>,
    #[serde(default)]
    pub ordering_authority: Option<ConnectedOrderingAuthority>,
    #[serde(default)]
    pub scope: Option<ConnectedScope>,
    #[serde(default)]
    pub scope_effective_route_count: i64,
    #[serde(default)]
    pub scope_route_cap: i64,
    #[serde(default)]
    pub scope_over_plan: bool,
    #[serde(default)]
    pub scope_over_plan_grace_expires_at: Option<String>,
    #[serde(default)]
    pub scope_overflow_count: i64,
    #[serde(default)]
    pub site_allowance_over_plan: bool,
    #[serde(default)]
    pub site_allowance_over_plan_grace_expires_at: Option<String>,
    /// Present only while the site is still waiting for its proof, which is
    /// what lets a desktop that was closed mid-setup show the customer the
    /// string they were told to publish.
    #[serde(default)]
    pub verification: Option<SiteChallenge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectedGroupState {
    pub check: String,
    pub state: String,
    pub state_revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectedGroupPage {
    #[serde(default, alias = "groups")]
    pub items: Vec<ConnectedGroupState>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SyncReceipt {
    #[serde(default)]
    pub event_sequence: i64,
    #[serde(default)]
    pub state_revision: i64,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MutationReceipt {
    #[serde(default)]
    pub event_sequence: i64,
    pub state_revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleGroup {
    pub check: String,
    pub state: String,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectedServiceError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
    pub details: Option<Value>,
}

impl ConnectedServiceError {
    pub fn is_stale_revision(&self) -> bool {
        self.status == StatusCode::CONFLICT.as_u16() && self.code == "stale_revision"
    }

    /// Read all stale groups from either the batch form or the single-entry
    /// shorthand. The service contract allows a batch to report more than one
    /// conflict; callers sending one entry still accept both shapes.
    pub fn stale_groups(&self, fallback_check: &str) -> Vec<StaleGroup> {
        let Some(details) = self.details.as_ref() else {
            return Vec::new();
        };
        if let Some(groups) = details.get("stale_groups").and_then(Value::as_array) {
            return groups
                .iter()
                .filter_map(|group| {
                    Some(StaleGroup {
                        check: group.get("check")?.as_str()?.to_string(),
                        state: group.get("current_state")?.as_str()?.to_string(),
                        revision: group.get("current_state_revision")?.as_i64()?,
                    })
                })
                .collect();
        }
        match (
            details.get("current_state").and_then(Value::as_str),
            details
                .get("current_state_revision")
                .and_then(Value::as_i64),
        ) {
            (Some(state), Some(revision)) => vec![StaleGroup {
                check: fallback_check.to_string(),
                state: state.to_string(),
                revision,
            }],
            _ => Vec::new(),
        }
    }
}

impl std::fmt::Display for ConnectedServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "connected service {}: {}",
            self.code, self.message
        )?;
        if let Some(request_id) = &self.request_id {
            write!(formatter, " (request {request_id})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConnectedServiceError {}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    details: Option<Value>,
    #[serde(default)]
    request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupMutationEntry {
    pub check: String,
    pub based_on_revision: i64,
    pub state: ClientGroupState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissal: Option<DismissalPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GroupMutationBatch<'a> {
    entries: &'a [GroupMutationEntry],
}

#[derive(Debug, Serialize)]
struct CreateSiteRequest<'a> {
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<&'a str>,
    fingerprint_key_commitment: &'a str,
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    method: &'a str,
}

#[derive(Debug, Serialize)]
struct ScopePutRequest<'a> {
    based_on_scope_revision: i64,
    routes: &'a [String],
    check_families: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ScopeReceipt {
    pub scope_revision: i64,
    #[serde(default)]
    pub event_sequence: i64,
}

#[derive(Debug, Serialize)]
struct MintCiTokenRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    repository: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    r#ref: Option<&'a str>,
}

/// Where a customer publishes the challenge, in the form they will copy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnsChallenge {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WellKnownChallenge {
    pub path: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SiteChallenge {
    pub challenge: String,
    pub dns: DnsChallenge,
    pub well_known: WellKnownChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreatedSite {
    pub id: String,
    pub phase: String,
    pub url: String,
    pub verification: SiteChallenge,
}

/// The service's answer to an erasure request: a job the caller can name and
/// the bearer that can read its receipt after everything else is gone.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ErasureStarted {
    pub job_id: String,
    pub status_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SiteVerification {
    pub phase: String,
    pub verified: bool,
}

/// The one moment a CI secret is readable. It is hashed before the service
/// stores it, so this response is not a copy of something recoverable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MintedCiToken {
    pub id: String,
    pub token: String,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub repository_id: Option<String>,
    pub site: String,
}

/// Repository policy, sent with the request because it lives in the
/// repository. A threshold stored server-side is a setting that silently
/// governs a repository nobody looking at the repository can see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatePolicy {
    pub severity_threshold: String,
    pub strict_detector_changes: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateRequest {
    pub schema_version: u16,
    pub site_id: String,
    pub snapshot: sitecmd_engine::sync::CodeSnapshot,
    pub policy: GatePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GateFinding {
    pub check: String,
    pub identity: String,
    pub severity: String,
    #[serde(default)]
    pub warned_because: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GateCounts {
    pub new: u32,
    pub failing: u32,
    pub warned: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GateVerdict {
    pub verdict: String,
    pub threshold: String,
    pub counts: GateCounts,
    #[serde(default)]
    pub new_findings: Vec<GateFinding>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl GateVerdict {
    /// Whether the merge should be blocked. Read from the service's own word
    /// rather than recomputed from the counts: two implementations of one
    /// verdict is two chances to disagree about whether a build passes.
    pub fn failed(&self) -> bool {
        self.verdict == "fail"
    }
}

/// Authenticated connected-service client. `Debug` never exposes its bearer.
pub struct ConnectedServiceClient {
    base_url: url::Url,
    authorization: Option<HeaderValue>,
    #[cfg(test)]
    allow_http_loopback: bool,
}

impl std::fmt::Debug for ConnectedServiceClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectedServiceClient")
            .field("base_url", &self.base_url)
            .field("authorization", &"[redacted]")
            .finish()
    }
}

impl ConnectedServiceClient {
    pub fn configured(token: &str) -> Result<Self, String> {
        let endpoint = CONNECTED_ENDPOINT.ok_or_else(|| {
            "no connected-service endpoint is configured in this build".to_string()
        })?;
        Self::for_endpoint(endpoint, Some(token), false)
    }

    /// A client for the origin the Action's `connect-origin` input names,
    /// which is also the OIDC audience the CLI requests. `None` for the claim,
    /// which carries the OIDC witness and no bearer.
    pub fn for_origin(origin: &str, token: Option<&str>) -> Result<Self, String> {
        Self::for_endpoint(origin, token, false)
    }

    #[cfg(test)]
    pub(crate) fn for_test_origin(origin: &str, token: Option<&str>) -> Result<Self, String> {
        Self::for_endpoint(origin, token, true)
    }

    /// Test client for an explicit endpoint.
    #[cfg(test)]
    pub(crate) fn for_test_endpoint(endpoint: &str, token: &str) -> Result<Self, String> {
        Self::for_endpoint(endpoint, Some(token), true)
    }

    fn for_endpoint(
        endpoint: &str,
        token: Option<&str>,
        allow_http_loopback: bool,
    ) -> Result<Self, String> {
        if token.is_some_and(|token| token.trim().is_empty()) {
            return Err("a connected-service token cannot be empty".into());
        }
        let mut base_url = url::Url::parse(endpoint.trim())
            .map_err(|error| format!("connected-service endpoint is invalid: {error}"))?;
        let allowed_scheme = base_url.scheme() == "https"
            || (allow_http_loopback
                && base_url.scheme() == "http"
                && crate::core::localhost::is_strict_localhost(&base_url));
        if !allowed_scheme
            || base_url.cannot_be_a_base()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || !matches!(base_url.path(), "" | "/")
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err("connected-service endpoint must be an HTTPS origin".into());
        }
        base_url.set_path("/");
        let authorization = match token {
            Some(token) => {
                let mut authorization =
                    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                        "connected-service token is not a valid header value".to_string()
                    })?;
                authorization.set_sensitive(true);
                Some(authorization)
            }
            None => None,
        };
        Ok(Self {
            base_url,
            authorization,
            #[cfg(test)]
            allow_http_loopback,
        })
    }

    pub(crate) fn url(&self, segments: &[&str]) -> Result<url::Url, ConnectedServiceError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                local_error(
                    "malformed_endpoint",
                    "connected-service endpoint cannot carry paths",
                )
            })?
            .extend(segments);
        Ok(url)
    }

    pub(crate) fn origin(&self) -> String {
        self.base_url.origin().ascii_serialization()
    }

    pub(crate) async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        url: url::Url,
        idempotency_key: Option<&str>,
        body: Option<String>,
    ) -> Result<T, ConnectedServiceError> {
        let (status, bytes) = self.send(method, url, idempotency_key, body, None).await?;
        parse_response(status, &bytes)
    }

    pub(crate) async fn request_with_github_oidc<T: DeserializeOwned>(
        &self,
        method: Method,
        url: url::Url,
        idempotency_key: Option<&str>,
        body: Option<String>,
        github_oidc_token: Option<&str>,
    ) -> Result<T, ConnectedServiceError> {
        let (status, bytes) = self
            .send(method, url, idempotency_key, body, github_oidc_token)
            .await?;
        parse_response(status, &bytes)
    }

    /// One wire exchange: the transport concerns without the body parse, for
    /// the routes that answer `204` and give a parser nothing to read.
    async fn send(
        &self,
        method: Method,
        url: url::Url,
        idempotency_key: Option<&str>,
        body: Option<String>,
        github_oidc_token: Option<&str>,
    ) -> Result<(StatusCode, Vec<u8>), ConnectedServiceError> {
        #[cfg(test)]
        let url_policy =
            if self.allow_http_loopback && crate::core::localhost::is_strict_localhost(&url) {
                crate::network_policy::UrlPolicy::Scan
            } else {
                crate::network_policy::UrlPolicy::ExternalCallback
            };
        #[cfg(not(test))]
        let url_policy = crate::network_policy::UrlPolicy::ExternalCallback;
        crate::network_policy::validate_url(url.as_str(), url_policy)
            .await
            .map_err(|_| {
                local_error("unsafe_endpoint", "connected-service endpoint was refused")
            })?;
        let is_local = crate::core::localhost::is_strict_localhost(&url);
        let mut request = if is_local {
            crate::http_client::localhost_client()
        } else {
            crate::http_client::credentialed_service_client()
        }
        .request(method, url)
        .header(CACHE_CONTROL, "no-store");
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }
        if let Some(token) = github_oidc_token {
            let mut token = HeaderValue::from_str(token).map_err(|_| {
                local_error(
                    "malformed_oidc_token",
                    "GitHub's OIDC token is not a valid header value",
                )
            })?;
            token.set_sensitive(true);
            request = request.header("X-GitHub-OIDC-Token", token);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request.send().await.map_err(|_| {
            local_error(
                "transport_failed",
                "the connected service could not be reached",
            )
        })?;
        let status = response.status();
        let bytes = crate::http_client::read_body_limited(
            response,
            MAX_RESPONSE_BYTES,
            crate::constants::API_TIMEOUT_SHORT,
        )
        .await
        .map_err(|_| {
            local_error(
                "response_failed",
                "the connected service response could not be read",
            )
        })?;
        Ok((status, bytes))
    }

    /// One exchange for the routes that answer `204` and give a parser
    /// nothing to read: success is success, anything else is the envelope.
    pub(crate) async fn no_content(
        &self,
        method: Method,
        url: url::Url,
    ) -> Result<(), ConnectedServiceError> {
        let (status, bytes) = self.send(method, url, None, None, None).await?;
        if status.is_success() {
            return Ok(());
        }
        Err(parse_error(status, &bytes))
    }

    /// Idempotently disconnect a site while retaining its state window.
    pub async fn delete_site(&self, site_id: &str) -> Result<(), ConnectedServiceError> {
        let url = self.url(&["v1", "sites", site_id])?;
        self.no_content(Method::DELETE, url).await
    }

    /// Permanently erase a site and return its one-time receipt token.
    pub async fn erase_site(&self, site_id: &str) -> Result<ErasureStarted, ConnectedServiceError> {
        let url = self.url(&["v1", "sites", site_id, "erase"])?;
        self.request(Method::POST, url, None, Some("{}".to_string()))
            .await
    }

    /// Create a pending site and its verification challenge.
    /// The fingerprint commitment is required at creation so the first code
    /// submission cannot establish a conflicting key.
    pub async fn create_site(
        &self,
        url: &str,
        alias: Option<&str>,
        fingerprint_key_commitment: &str,
    ) -> Result<CreatedSite, ConnectedServiceError> {
        let body = serde_json::to_string(&CreateSiteRequest {
            alias,
            fingerprint_key_commitment,
            url,
        })
        .map_err(|_| {
            local_error(
                "serialization_failed",
                "connected site request could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites"])?;
        self.request(Method::POST, url, None, Some(body)).await
    }

    /// Ask the service to verify the published ownership challenge.
    pub async fn verify_site(
        &self,
        site_id: &str,
        method: &str,
    ) -> Result<SiteVerification, ConnectedServiceError> {
        let body = serde_json::to_string(&VerifyRequest { method }).map_err(|_| {
            local_error(
                "serialization_failed",
                "connected verification request could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites", site_id, "verify"])?;
        self.request(Method::POST, url, None, Some(body)).await
    }

    /// Mint a CI credential for one site. The secret in the response is the
    /// only copy that will ever exist.
    pub async fn mint_ci_token(
        &self,
        site_id: &str,
        repository: Option<&str>,
        repository_id: Option<&str>,
        workflow_ref: Option<&str>,
        git_ref: Option<&str>,
    ) -> Result<MintedCiToken, ConnectedServiceError> {
        let body = serde_json::to_string(&MintCiTokenRequest {
            repository,
            repository_id,
            workflow_ref,
            r#ref: git_ref,
        })
        .map_err(|_| {
            local_error(
                "serialization_failed",
                "connected token request could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites", site_id, "tokens"])?;
        self.request(Method::POST, url, None, Some(body)).await
    }

    /// Ask for a verdict on a candidate branch. Nothing is persisted.
    pub async fn gate(
        &self,
        site_id: &str,
        request: &GateRequest,
    ) -> Result<GateVerdict, ConnectedServiceError> {
        let body = serde_json::to_string_pretty(request).map_err(|_| {
            local_error(
                "serialization_failed",
                "connected gate request could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites", site_id, "gate"])?;
        self.request(Method::POST, url, None, Some(body)).await
    }

    pub async fn state(&self, site_id: &str) -> Result<ConnectedSiteState, ConnectedServiceError> {
        let url = self.url(&["v1", "sites", site_id, "state"])?;
        self.request(Method::GET, url, None, None).await
    }

    /// Replace scope under an optimistic revision guard.
    /// Callers decide whether `stale_revision` satisfies bootstrap intent.
    pub async fn put_scope(
        &self,
        site_id: &str,
        based_on_scope_revision: i64,
        routes: &[String],
        check_families: &[String],
    ) -> Result<ScopeReceipt, ConnectedServiceError> {
        let body = serde_json::to_string(&ScopePutRequest {
            based_on_scope_revision,
            check_families,
            routes,
        })
        .map_err(|_| {
            local_error(
                "serialization_failed",
                "connected scope request could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites", site_id, "scope"])?;
        self.request(Method::PUT, url, None, Some(body)).await
    }

    pub async fn groups(
        &self,
        site_id: &str,
        cursor: Option<&str>,
    ) -> Result<ConnectedGroupPage, ConnectedServiceError> {
        let mut url = self.url(&["v1", "sites", site_id, "groups"])?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", "500");
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        self.request(Method::GET, url, None, None).await
    }

    pub async fn sync_desktop(
        &self,
        site_id: &str,
        idempotency_key: &str,
        submission: &DesktopSubmission,
    ) -> Result<SyncReceipt, ConnectedServiceError> {
        let exact_body = submission.render_for_inspection().map_err(|_| {
            local_error(
                "serialization_failed",
                "connected submission could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites", site_id, "sync", "desktop"])?;
        self.request(Method::POST, url, Some(idempotency_key), Some(exact_body))
            .await
    }

    pub async fn mutate_group(
        &self,
        site_id: &str,
        idempotency_key: &str,
        mutation: &GroupMutationEntry,
    ) -> Result<MutationReceipt, ConnectedServiceError> {
        let body = serde_json::to_string_pretty(&GroupMutationBatch {
            entries: std::slice::from_ref(mutation),
        })
        .map_err(|_| {
            local_error(
                "serialization_failed",
                "connected mutation could not be encoded",
            )
        })?;
        let url = self.url(&["v1", "sites", site_id, "mutations"])?;
        self.request(Method::POST, url, Some(idempotency_key), Some(body))
            .await
    }
}

pub(crate) fn local_error(code: &str, message: &str) -> ConnectedServiceError {
    ConnectedServiceError {
        status: 0,
        code: code.into(),
        message: message.into(),
        request_id: None,
        details: None,
    }
}

fn parse_response<T: DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
) -> Result<T, ConnectedServiceError> {
    if status.is_success() {
        return serde_json::from_slice(bytes).map_err(|_| ConnectedServiceError {
            status: status.as_u16(),
            code: "malformed_response".into(),
            message: "the connected service returned an invalid response".into(),
            request_id: None,
            details: None,
        });
    }
    Err(parse_error(status, bytes))
}

/// The service's error envelope, or the uniform refusal when there is none.
fn parse_error(status: StatusCode, bytes: &[u8]) -> ConnectedServiceError {
    let envelope = serde_json::from_slice::<ErrorEnvelope>(bytes).ok();
    let error = envelope.map(|envelope| envelope.error);
    ConnectedServiceError {
        status: status.as_u16(),
        code: error
            .as_ref()
            .map(|error| error.code.clone())
            .unwrap_or_else(|| "request_failed".into()),
        message: error
            .as_ref()
            .map(|error| error.message.clone())
            .unwrap_or_else(|| "the connected service refused the request".into()),
        request_id: error.as_ref().and_then(|error| error.request_id.clone()),
        details: error.and_then(|error| error.details),
    }
}

#[cfg(test)]
#[path = "connected_service_tests.rs"]
mod tests;
