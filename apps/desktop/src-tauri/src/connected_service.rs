//! Bounded authenticated HTTP contract for the connected service.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sitecmd_protocol::sync::wire::{Digest, Identifier, SeverityThreshold};
use zeroize::Zeroizing;

pub(crate) mod autofix_jobs;
pub(crate) mod deployment_ordering;
mod problem;
mod request_body;
mod request_url;
pub(crate) use request_body::{EmptyRequest, WireRequest, NO_BODY};
use request_url::RequestUrl;
#[cfg(test)]
pub(crate) mod test_double;

pub(crate) use problem::local_error;
use problem::parse_response;

pub use autofix_jobs::{
    ClaimedFinding, ClaimedJob, FindingOutcomeReport, PullRequestReport, ResultReport,
};
pub use deployment_ordering::CiDeploymentHead;

const CONNECTED_ENDPOINT: Option<&str> = option_env!("SITECMD_CONNECTED_ENDPOINT");
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(any(test, feature = "test-support"))]
pub(crate) static CLIENT_CONSTRUCTION_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectedServiceError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
    /// The whole problem object. Boxed because few refusals carry one and
    /// the error rides in every `Result` the client returns.
    pub details: Option<Box<Value>>,
    /// The seconds a refusal's `Retry-After` header names, such as the lease
    /// left on a `request_in_progress` key.
    pub retry_after: Option<u64>,
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

/// What a CI command answers when Connect says the account is inactive. It
/// names no origin, so a self-hosted Connect's users read the same sentence.
pub(crate) const ACCOUNT_INACTIVE_NOTICE: &str = "SiteCMD says this account is inactive, so nothing was sent. Renew it from the dashboard to resume.";

/// The same answer at a door whose request carried the person's data or that
/// followed a step that changed state, where something was sent.
pub(crate) const ACCOUNT_INACTIVE_RESULT_NOTICE: &str = "SiteCMD says this account is inactive, so this result was not recorded. Renew it from the dashboard to resume.";

/// The gate's answer. The gate records nothing even for an active account,
/// so its sentence names what did not happen, as the gate action's summary
/// does.
pub(crate) const ACCOUNT_INACTIVE_GATE_NOTICE: &str = "SiteCMD says this account is inactive, so the gate graded nothing. Renew it from the dashboard to resume.";

/// Connect answers every machine door of a read-only account with
/// `account_inactive`. A CI command stops on it with a notice and exit 0, so
/// the person's pipeline stays green.
pub(crate) fn is_account_inactive(error: &ConnectedServiceError) -> bool {
    error.code == "account_inactive"
}

/// What a CI command answers when Connect says the account is inactive:
/// `earlier`, what the command had already done, then `notice`, the sentence
/// true of the door that said so. Under GitHub Actions the sentence is also a
/// notice annotation, in the `::notice title=` form `sitecmd audit` uses.
pub(crate) fn inactive_output(earlier: &str, notice: &str, github_actions: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    if !earlier.is_empty() {
        lines.push(earlier.to_string());
    }
    lines.push(notice.to_string());
    if github_actions {
        lines.push(format!("::notice title=SiteCMD::{notice}"));
    }
    lines.join("\n")
}

/// Repository policy, sent with the request because it lives in the
/// repository. A threshold stored server-side is a setting that silently
/// governs a repository nobody looking at the repository can see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatePolicy {
    pub severity_threshold: SeverityThreshold,
    pub strict_detector_changes: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateRequest {
    pub schema_version: u16,
    pub site_id: Identifier,
    pub snapshot: sitecmd_protocol::sync::CodeSnapshot,
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

struct WireResponse {
    status: StatusCode,
    bytes: Zeroizing<Vec<u8>>,
    headers: HeaderMap,
}

impl WireResponse {
    fn check_status(
        &self,
        now: impl FnOnce() -> Option<jiff::Timestamp>,
    ) -> Result<(), ConnectedServiceError> {
        if self.status.is_success() {
            Ok(())
        } else {
            Err(problem::refusal(
                self.status,
                &self.headers,
                &self.bytes,
                now(),
            ))
        }
    }

    fn parse<T: DeserializeOwned>(&self) -> Result<T, ConnectedServiceError> {
        self.parse_at(|| Some(jiff::Timestamp::now()))
    }

    fn parse_at<T: DeserializeOwned>(
        &self,
        now: impl FnOnce() -> Option<jiff::Timestamp>,
    ) -> Result<T, ConnectedServiceError> {
        self.check_status(now)?;
        parse_response(self.status, &self.bytes)
    }
}

impl ConnectedServiceClient {
    pub fn configured(token: &str) -> Result<Self, String> {
        #[cfg(any(test, feature = "test-support"))]
        CLIENT_CONSTRUCTION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
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

    pub(crate) fn for_endpoint(
        endpoint: &str,
        token: Option<&str>,
        allow_http_loopback: bool,
    ) -> Result<Self, String> {
        #[cfg(any(test, feature = "test-support"))]
        CLIENT_CONSTRUCTION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        if token.is_some_and(|token| token.trim().is_empty()) {
            return Err("a connected-service token cannot be empty".into());
        }
        let mut base_url = url::Url::parse(endpoint.trim())
            .map_err(|error| format!("connected-service endpoint is invalid: {error}"))?;
        normalize_origin_host(&mut base_url)?;
        let allowed_scheme = base_url.scheme() == "https"
            || crate::core::localhost::loopback_endpoint_allowed(allow_http_loopback, &base_url);
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
                let bearer = Zeroizing::new(format!("Bearer {token}"));
                let mut authorization = HeaderValue::from_str(&bearer).map_err(|_| {
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

    pub(crate) fn url(&self, segments: &[&str]) -> Result<RequestUrl, ConnectedServiceError> {
        for segment in segments {
            Identifier::try_from(*segment).map_err(|_| {
                local_error(
                    "invalid_identifier",
                    "invalid connected request path identifier",
                )
            })?;
        }
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                local_error(
                    "malformed_endpoint",
                    "connected-service endpoint cannot carry paths",
                )
            })?
            .extend(segments);
        Ok(RequestUrl(url))
    }

    pub(crate) fn origin(&self) -> String {
        self.base_url.origin().ascii_serialization()
    }

    pub(crate) async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        url: RequestUrl,
        idempotency_key: Option<&Digest>,
        body: Option<&impl WireRequest>,
    ) -> Result<T, ConnectedServiceError> {
        self.send(method, url, idempotency_key, body, None, |_| {})
            .await?
            .parse()
    }

    pub(crate) async fn request_at<T: DeserializeOwned>(
        &self,
        method: Method,
        url: RequestUrl,
        idempotency_key: Option<&Digest>,
        now: impl FnOnce() -> jiff::Timestamp,
    ) -> Result<T, ConnectedServiceError> {
        self.send(method, url, idempotency_key, NO_BODY, None, |_| {})
            .await?
            .parse_at(|| Some(now()))
    }

    /// Observe the server date even if the GET is refused or the body cannot be read.
    pub(crate) async fn get_with_date<T: DeserializeOwned>(
        &self,
        url: RequestUrl,
        observe: impl FnOnce(Option<jiff::Timestamp>),
    ) -> Result<T, ConnectedServiceError> {
        let mut date = None;
        self.send(Method::GET, url, None, NO_BODY, None, |headers| {
            date = problem::response_date(headers);
            observe(date);
        })
        .await?
        .parse_at(|| date)
    }

    pub(crate) async fn request_with_github_oidc<T: DeserializeOwned>(
        &self,
        method: Method,
        url: RequestUrl,
        idempotency_key: Option<&Digest>,
        body: Option<&impl WireRequest>,
        github_oidc_token: Option<&str>,
    ) -> Result<T, ConnectedServiceError> {
        self.send(
            method,
            url,
            idempotency_key,
            body,
            github_oidc_token,
            |_| {},
        )
        .await?
        .parse()
    }

    /// One exchange for the routes that answer `204` and give a parser
    /// nothing to read: success is success, anything else is a refusal.
    pub(crate) async fn no_content(
        &self,
        method: Method,
        url: RequestUrl,
    ) -> Result<(), ConnectedServiceError> {
        self.send(method, url, None, NO_BODY, None, |_| {})
            .await?
            .check_status(|| Some(jiff::Timestamp::now()))
    }

    /// One bounded wire exchange with the configured origin.
    async fn send(
        &self,
        method: Method,
        url: RequestUrl,
        idempotency_key: Option<&Digest>,
        body: Option<&impl WireRequest>,
        github_oidc_token: Option<&str>,
        observe_headers: impl FnOnce(&HeaderMap),
    ) -> Result<WireResponse, ConnectedServiceError> {
        let url = url.0;
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
            crate::http_client::credentialed_loopback_client()
        } else {
            crate::http_client::credentialed_service_client()
        }
        .request(method, url)
        .header(CACHE_CONTROL, "no-store");
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key.as_str());
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
            let encoded = request_body::encode(body).map_err(|error| {
                local_error(
                    "serialization_failed",
                    &format!("connected request could not be encoded: {error}"),
                )
            })?;
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(encoded);
        }
        let response = request.send().await.map_err(|_| {
            local_error(
                "transport_failed",
                "the connected service could not be reached",
            )
        })?;
        let status = response.status();
        observe_headers(response.headers());
        let headers = response.headers().clone();
        let bytes = Zeroizing::new(
            crate::http_client::read_body_limited(
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
            })?,
        );
        Ok(WireResponse {
            status,
            bytes,
            headers,
        })
    }

    pub async fn gate(
        &self,
        site_id: &str,
        request: &GateRequest,
    ) -> Result<GateVerdict, ConnectedServiceError> {
        let url = self.url(&["v1", "sites", site_id, "gate"])?;
        self.request(Method::POST, url, None, Some(request)).await
    }
}

#[cfg(test)]
#[path = "connected_service_tests.rs"]
mod tests;

pub(crate) fn normalize_origin_host(url: &mut url::Url) -> Result<(), String> {
    if let Some(url::Host::Domain(host)) = url.host() {
        if let Some(host) = host.strip_suffix('.') {
            let host = host.to_owned();
            url.set_host(Some(&host))
                .map_err(|_| "connected-service endpoint host is invalid")?;
        }
    }
    Ok(())
}
