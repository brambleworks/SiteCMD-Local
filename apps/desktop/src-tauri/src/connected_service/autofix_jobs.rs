//! The fix-job doors of the connected service: claim, result, publish token
//! and issue token, in the same bounded transport as every other route.

use serde::{Deserialize, Serialize};
use sitecmd_protocol::sync::wire::ClaimPurpose;
use sitecmd_protocol::sync::wire::{
    CheckId, FindingIdentity, FindingOutcome, HeadSha, OutcomeCode, SitecmdBranch,
};

use super::{local_error, ConnectedServiceClient, ConnectedServiceError};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ClaimedFinding {
    pub check_id: String,
    pub identity: String,
    pub class: String,
    pub category: String,
    #[serde(default)]
    pub fallback_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Committer {
    pub name: String,
    pub email: String,
}

#[derive(Clone, Deserialize)]
pub struct ClaimedJob {
    pub job_id: String,
    pub attempt: u32,
    pub purpose: String,
    pub job_token: String,
    pub expires_at: String,
    pub base_sha: String,
    #[serde(deserialize_with = "deserialize_site_url")]
    pub site_url: String,
    pub repository: String,
    pub default_branch: String,
    pub agent: String,
    pub findings: Vec<ClaimedFinding>,
    #[serde(default)]
    pub opt_in_fixers: Vec<String>,
    #[serde(default)]
    pub committer: Option<Committer>,
}

fn deserialize_site_url<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let raw = String::deserialize(deserializer)?;
    let has_authority = raw
        .split_once("://")
        .is_some_and(|(_, rest)| !rest.starts_with('/'));
    if has_authority
        && !raw.contains(|ch: char| ch.is_whitespace() || ch.is_control() || ch == '\\')
        && url::Url::parse(&raw)
            .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
    {
        Ok(raw)
    } else {
        Err(serde::de::Error::custom(
            "expected an absolute HTTP or HTTPS site URL",
        ))
    }
}

impl std::fmt::Debug for ClaimedJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimedJob")
            .field("job_id", &self.job_id)
            .field("attempt", &self.attempt)
            .field("purpose", &self.purpose)
            .field("job_token", &"[redacted]")
            .field("base_sha", &self.base_sha)
            .field("findings", &self.findings)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingOutcomeReport {
    pub check_id: CheckId,
    pub identity: FindingIdentity,
    pub outcome: FindingOutcome,
}

impl FindingOutcomeReport {
    /// Invalid service-supplied identities stay in the runner's local output.
    pub(crate) fn new(check: &str, identity: &str, outcome: &str) -> Option<Self> {
        let parsed = || -> Result<Self, String> {
            Ok(Self {
                check_id: check.try_into()?,
                identity: identity.try_into()?,
                outcome: outcome.try_into()?,
            })
        };
        match parsed() {
            Ok(report) => Some(report),
            Err(error) => {
                eprintln!("Connected result omitted a finding: {error}");
                None
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PullRequestReport {
    pub number: u64,
    pub head_sha: HeadSha,
    pub branch: SitecmdBranch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResultReport {
    pub attempt: u32,
    pub outcome_code: OutcomeCode,
    pub token_revoked: bool,
    pub findings: Vec<FindingOutcomeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<PullRequestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_number: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ResultReceipt {
    pub job_id: String,
    pub state: String,
}

#[derive(Clone, Deserialize)]
pub struct OperationToken {
    pub token: String,
    pub expires_at: String,
}

impl std::fmt::Debug for OperationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationToken")
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Serialize)]
pub(super) struct ClaimRequest {
    purpose: ClaimPurpose,
}

fn job_path<'a>(job_id: &'a str, door: &'a str) -> [&'a str; 4] {
    ["v1", "fix-jobs", job_id, door]
}

#[derive(Serialize)]
pub(super) struct PublishTokenRequest {
    workflows_write: bool,
}

impl ConnectedServiceClient {
    /// Take one attempt at a fix job. The runner's OIDC token is the only
    /// credential the claim carries; the job token comes back in the answer.
    pub async fn claim_job(
        &self,
        job_id: &str,
        purpose: &str,
        github_oidc_token: &str,
    ) -> Result<ClaimedJob, ConnectedServiceError> {
        let url = self.url(&job_path(job_id, "claim"))?;
        let body = ClaimRequest {
            purpose: purpose
                .try_into()
                .map_err(|error: String| local_error("invalid_purpose", &error))?,
        };
        self.request_with_github_oidc(
            reqwest::Method::POST,
            url,
            None,
            Some(&body),
            Some(github_oidc_token),
        )
        .await
    }

    pub async fn report_job_result(
        &self,
        job_id: &str,
        report: &ResultReport,
    ) -> Result<ResultReceipt, ConnectedServiceError> {
        let url = self.url(&job_path(job_id, "result"))?;
        self.request(reqwest::Method::POST, url, None, Some(report))
            .await
    }

    pub async fn publish_token(
        &self,
        job_id: &str,
    ) -> Result<OperationToken, ConnectedServiceError> {
        let url = self.url(&job_path(job_id, "publish-token"))?;
        self.request(
            reqwest::Method::POST,
            url,
            None,
            Some(&PublishTokenRequest {
                workflows_write: false,
            }),
        )
        .await
    }

    pub async fn issue_token(&self, job_id: &str) -> Result<OperationToken, ConnectedServiceError> {
        let url = self.url(&job_path(job_id, "issue-token"))?;
        self.request(reqwest::Method::POST, url, None, super::NO_BODY)
            .await
    }
}

#[cfg(test)]
#[path = "autofix_jobs_tests.rs"]
mod tests;
