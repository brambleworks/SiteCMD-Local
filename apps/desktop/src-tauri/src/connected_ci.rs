//! Connected-service contracts for CI ordering, gates, deployments, and evidence.
//!
//! CI submissions omit local sequences and producer-supplied provenance. The
//! service assigns provenance and applies presence only; retries use idempotency.

use sitecmd_protocol::sync::wire::{
    AuthorityId, CommitSha, DeploymentTarget, GitRef, Identifier, OrderingKind, Timestamp,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sitecmd_protocol::sync::{CodeSnapshot, SCHEMA_VERSION};

use crate::connected_service::deployment_ordering::CiSubmissionAttestation;
use crate::connected_service::{local_error, ConnectedServiceClient, ConnectedServiceError};
use zeroize::Zeroizing;

/// Domain separator for the submission idempotency key, so the digest of a
/// payload can never be replayed as some other keyed value.
const IDEMPOTENCY_DOMAIN: &str = "sitecmd-ci-submission|v1|";

struct GitHubActionsOidcRequest {
    url: url::Url,
    bearer: Zeroizing<String>,
}

fn github_actions_oidc_request(
    submission_attestation: CiSubmissionAttestation,
    get_env: impl Fn(&str) -> Option<String>,
    audience: &str,
) -> Result<Option<GitHubActionsOidcRequest>, String> {
    if submission_attestation == CiSubmissionAttestation::Unattested {
        return Ok(None);
    }
    if get_env("GITHUB_ACTIONS").as_deref() != Some("true") {
        return Ok(None);
    }
    let endpoint = get_env("ACTIONS_ID_TOKEN_REQUEST_URL").ok_or_else(|| {
        "GitHub Actions cannot attest this submission. Grant the job `permissions: id-token: write`."
            .to_string()
    })?;
    let bearer = get_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok_or_else(|| {
        "GitHub Actions cannot attest this submission. Grant the job `permissions: id-token: write`."
            .to_string()
    })?;
    let mut url = url::Url::parse(&endpoint)
        .map_err(|_| "GitHub Actions supplied an invalid OIDC endpoint".to_string())?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https"
        || !(host == "actions.githubusercontent.com"
            || host.ends_with(".actions.githubusercontent.com"))
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("GitHub Actions supplied an unexpected OIDC endpoint".to_string());
    }
    if bearer.is_empty() || bearer.chars().any(char::is_control) {
        return Err("GitHub Actions supplied an invalid OIDC request token".to_string());
    }
    let retained_query: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(name, _)| name != "audience")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in retained_query {
            query.append_pair(&name, &value);
        }
        query.append_pair("audience", audience);
    }
    Ok(Some(GitHubActionsOidcRequest {
        url,
        bearer: Zeroizing::new(bearer),
    }))
}

#[derive(Deserialize)]
struct GitHubActionsOidcResponse {
    value: String,
}

/// Provider deployment ordering shared by publish and CI evidence paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishOrdering {
    /// Closed wire vocabulary validated before submission.
    pub kind: OrderingKind,
    pub authority_id: AuthorityId,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor_deployment_id: Option<Identifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentFacts {
    pub provider_deployment_id: Identifier,
    pub commit_sha: CommitSha,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<GitRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<DeploymentTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_sha: Option<CommitSha>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_created_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub published: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordering: Option<PublishOrdering>,
}

impl DeploymentFacts {
    /// Validate fields locally so CI errors identify the invalid argument.
    pub fn validate(&self) -> Result<(), String> {
        match (&self.ordering, self.published) {
            (None, false) => {}
            (None, true) => {
                return Err(
                    "--published requires --ordering-authority, --ordering-epoch, and exactly one of --publish-sequence or --predecessor-deployment-id"
                        .into(),
                )
            }
            (Some(_), false) => return Err("publish ordering requires --published".into()),
            (Some(ordering), true) => {
                if ordering.kind != "publish_sequence" {
                    return Err("deployment ordering kind must be publish_sequence".into());
                }
                if ordering.epoch == 0 {
                    return Err("--ordering-epoch must be at least 1".into());
                }
                if ordering.publish_sequence.is_some()
                    == ordering.predecessor_deployment_id.is_some()
                {
                    return Err(
                        "pass exactly one of --publish-sequence or --predecessor-deployment-id"
                            .into(),
                    );
                }
                if let Some(predecessor) = &ordering.predecessor_deployment_id {
                    if predecessor == &self.provider_deployment_id {
                        return Err(
                            "--predecessor-deployment-id cannot name the deployment itself".into(),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Deployment record accepted from either connected-service response.
/// `created` is nested here by submission responses and adjacent elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeploymentRecord {
    pub provider_deployment_id: String,
    pub commit_sha: String,
    /// `publish_sequence` is an ordered current-head candidate. Creation time
    /// only yields `creation_sequence`, which remains history-grade.
    pub ordering: String,
    /// Response form is the service's SQLite integer, not the request boolean.
    #[serde(default)]
    pub published: u8,
    #[serde(default)]
    pub authority_kind: Option<String>,
    #[serde(default)]
    pub authority_id: Option<String>,
    #[serde(default)]
    pub authority_epoch: Option<u64>,
    #[serde(default)]
    pub publish_sequence: Option<u64>,
    #[serde(default)]
    pub predecessor_deployment_id: Option<String>,
    #[serde(default)]
    pub immutable_facts_hash: Option<String>,
    #[serde(default)]
    pub created: Option<bool>,
}

/// The deployments door's answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeploymentReceipt {
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub current: bool,
    pub deployment: DeploymentRecord,
}

/// Submission receipt containing only facts explicitly returned by the service.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CiSubmissionReceipt {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub event_sequence: Option<i64>,
    #[serde(default)]
    pub deployment: Option<DeploymentRecord>,
}

impl CiSubmissionReceipt {
    /// Whether the embedded deployment was new to the service. A redelivered
    /// identity converges rather than erroring, so "not created" is success.
    pub fn created_deployment(&self) -> bool {
        self.deployment
            .as_ref()
            .and_then(|deployment| deployment.created)
            .unwrap_or(false)
    }
}

use sitecmd_protocol::manifest::ManifestDigest;
use sitecmd_protocol::sync::wire::{CheckId, Digest};
use sitecmd_protocol::sync::{CodeBasis, CodeVersions, WireCoverage};
use sitecmd_protocol::vocab::{IssueConfidence, Severity};

#[derive(Serialize, Deserialize)]
pub(crate) struct CiSubmission {
    schema_version: u16,
    site_id: Identifier,
    snapshot: CiCodeSnapshot,
    deployment: DeploymentFacts,
}
#[derive(Serialize, Deserialize)]
struct CiCodeSnapshot {
    pub observed_at: i64,
    pub versions: CodeVersions,
    pub manifest_digest: ManifestDigest,
    /// The commitment of the key these fingerprints were computed under, so a
    /// producer hashing under the wrong key for a claimed version fails
    /// visibly instead of corrupting identity matching in silence.
    pub key_commitment: Digest,
    pub code_basis: CodeBasis,
    pub coverage: WireCoverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<CiCodeOccurrence>,
}

#[derive(Serialize, Deserialize)]
struct CiCodeOccurrence {
    pub check: CheckId,
    pub location_hash: Digest,
    pub instance_count: u32,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<IssueConfidence>,
}

impl From<CodeSnapshot> for CiCodeSnapshot {
    fn from(s: CodeSnapshot) -> Self {
        Self {
            observed_at: s.observed_at,
            versions: s.versions,
            manifest_digest: s.manifest_digest,
            key_commitment: s.key_commitment,
            code_basis: s.code_basis,
            coverage: s.coverage,
            occurrences: s
                .occurrences
                .into_iter()
                .map(|o| CiCodeOccurrence {
                    check: o.check,
                    location_hash: o.location_hash,
                    instance_count: o.instance_count,
                    severity: o.severity,
                    confidence: o.confidence,
                })
                .collect(),
        }
    }
}

/// Render a CI submission without desktop-only occurrence provenance.
/// CI ordering comes from the embedded deployment, not a producer watermark.
pub fn ci_submission_body(
    site_id: &str,
    snapshot: &CodeSnapshot,
    deployment: &DeploymentFacts,
) -> Result<String, String> {
    let body = CiSubmission {
        schema_version: SCHEMA_VERSION,
        site_id: site_id
            .try_into()
            .map_err(|error| format!("site id: {error}"))?,
        snapshot: CiCodeSnapshot::from(snapshot.clone()),
        deployment: deployment.clone(),
    };
    serde_json::to_string_pretty(&body)
        .map_err(|error| format!("failed to encode the CI submission: {error}"))
}

/// Derive idempotency from the body so identical bytes replay and changed
/// payloads become new submissions.
pub fn ci_idempotency_key(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_DOMAIN.as_bytes());
    hasher.update(body.as_bytes());
    hex::encode(hasher.finalize())
}

/// Canonical CI submission path segments.
fn ci_sync_path(site_id: &str) -> [&str; 5] {
    ["v1", "sites", site_id, "sync", "ci"]
}

fn ci_deployments_path(site_id: &str) -> [&str; 4] {
    ["v1", "sites", site_id, "deployments"]
}

impl ConnectedServiceClient {
    /// Request GitHub's short-lived workload witness when this command is
    /// running inside Actions. A GitHub job without id-token permission fails
    /// visibly instead of silently downgrading a governing submission.
    pub async fn github_actions_oidc_token(
        &self,
        submission_attestation: CiSubmissionAttestation,
    ) -> Result<Option<Zeroizing<String>>, String> {
        let audience = self.origin();
        let Some(request) = github_actions_oidc_request(
            submission_attestation,
            |name| std::env::var(name).ok(),
            &audience,
        )?
        else {
            return Ok(None);
        };
        crate::network_policy::validate_url(
            request.url.as_str(),
            crate::network_policy::UrlPolicy::ExternalCallback,
        )
        .await
        .map_err(|_| "GitHub Actions supplied an unsafe OIDC endpoint".to_string())?;
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", request.bearer.as_str()))
                .map_err(|_| "GitHub Actions supplied an invalid OIDC request token".to_string())?;
        authorization.set_sensitive(true);
        let response = crate::http_client::credentialed_service_client()
            .get(request.url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(crate::constants::API_TIMEOUT_SHORT)
            .send()
            .await
            .map_err(|_| "GitHub's OIDC provider could not be reached".to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "GitHub's OIDC provider refused the token request ({})",
                response.status()
            ));
        }
        let response: GitHubActionsOidcResponse = crate::http_client::read_json_limited(
            response,
            crate::constants::GITHUB_OIDC_RESPONSE_MAX_BYTES,
            crate::constants::API_TIMEOUT_SHORT,
        )
        .await
        .map_err(|_| "GitHub's OIDC response could not be read".to_string())?;
        if response.value.is_empty() {
            return Err("GitHub's OIDC response did not contain a token".to_string());
        }
        Ok(Some(Zeroizing::new(response.value)))
    }

    /// Record a deployment without a code scan.
    /// Retries converge on deployment identity instead of an idempotency key.
    pub async fn record_ci_deployment(
        &self,
        site_id: &str,
        facts: &DeploymentFacts,
    ) -> Result<DeploymentReceipt, ConnectedServiceError> {
        let url = self.url(&ci_deployments_path(site_id))?;
        self.request(reqwest::Method::POST, url, None, Some(facts))
            .await
    }

    /// Submit the typed CI envelope, deriving idempotency from its wire bytes.
    pub async fn submit_ci_evidence(
        &self,
        site_id: &str,
        body: &str,
        github_oidc_token: Option<&str>,
    ) -> Result<CiSubmissionReceipt, ConnectedServiceError> {
        let submission: CiSubmission = serde_json::from_str(body)
            .map_err(|_| local_error("invalid_payload", "invalid CI submission"))?;
        let body = serde_json::to_string_pretty(&submission)
            .map_err(|_| local_error("invalid_payload", "invalid CI submission"))?;
        let url = self.url(&ci_sync_path(site_id))?;
        self.request_with_github_oidc(
            reqwest::Method::POST,
            url,
            Some(&ci_idempotency_key(&body).parse().expect("SHA-256 digest")),
            Some(&submission),
            github_oidc_token,
        )
        .await
    }
}

#[cfg(test)]
#[path = "connected_ci_tests.rs"]
mod tests;
