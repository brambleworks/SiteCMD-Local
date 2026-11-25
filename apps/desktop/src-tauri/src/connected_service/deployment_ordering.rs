//! Narrow transport contract for deployment-ordering setup and CI cursors.

use reqwest::Method;
use serde::Deserialize;

use super::{ConnectedServiceClient, ConnectedServiceError, NO_BODY};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectedOrderingAuthority {
    pub kind: String,
    pub authority_id: String,
    pub epoch: i64,
    #[serde(default)]
    pub current_deployment_id: Option<String>,
    #[serde(default)]
    pub publish_sequence: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiSubmissionAttestation {
    GithubOidc,
    Unattested,
}

fn legacy_submission_attestation() -> CiSubmissionAttestation {
    // Older connected-service deployments predate this discriminator and
    // always expected the CLI to request OIDC inside GitHub Actions. Preserve
    // that fail-loud behavior during a rolling service/client deployment.
    CiSubmissionAttestation::GithubOidc
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CiDeploymentHead {
    #[serde(default)]
    pub current_deployment_id: Option<String>,
    #[serde(default = "legacy_submission_attestation")]
    pub submission_attestation: CiSubmissionAttestation,
    #[serde(default)]
    pub ordering_authority: Option<ConnectedOrderingAuthority>,
}

impl ConnectedServiceClient {
    pub async fn ci_deployment_head(
        &self,
        site_id: &str,
    ) -> Result<CiDeploymentHead, ConnectedServiceError> {
        let url = self.url(&["v1", "sites", site_id, "deployment-head"])?;
        self.request(Method::GET, url, None, NO_BODY).await
    }
}
