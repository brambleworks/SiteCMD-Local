//! Wire types for the Connect CLI code flow.

use serde::{Deserialize, Deserializer, Serialize};
use sitecmd_protocol::sync::wire::{AuthorityId, DeviceCode, Digest, Identifier, RepositorySlug};
use sitecmd_protocol::sync::CodeSnapshot;
use zeroize::Zeroizing;

use crate::cli::credential_store::secret_serde;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeRequest {
    Login,
    Connect {
        url: AuthorityId,
        repository: RepositorySlug,
        commitment: Digest,
        rotate: bool,
    },
}

/// The code request as sent, with the build that asks for it.
#[derive(Serialize)]
pub struct CodeRequestBody {
    #[serde(flatten)]
    pub request: CodeRequest,
    pub client: CodeClient,
}

#[derive(Serialize)]
pub struct CodeClient {
    pub version: Identifier,
    pub os: Identifier,
}

#[derive(Serialize)]
pub struct PollTokenRequest {
    pub device_code: DeviceCode,
}

/// A connection's first code baseline: the checkout's snapshot for its site.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineRequest {
    pub schema_version: u16,
    pub site_id: Identifier,
    pub snapshot: CodeSnapshot,
}

#[derive(Serialize)]
pub struct ProvisionedRequest {
    pub token_revoked: bool,
}

/// Device authorization is never a CLI JSON output type.
/// ```compile_fail
/// // Bug: serializing authorization would expose the device secret.
/// use sitecmd_runtime::connected_codes::DeviceAuthorization;
/// fn output(value: &DeviceAuthorization) { let _ = serde_json::to_value(value); }
/// ```
#[derive(Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: DeviceCode,
    #[serde(deserialize_with = "display_text")]
    pub user_code: String,
    #[serde(deserialize_with = "verification_uri")]
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceAuthorization { [redacted] }")
    }
}

pub enum PollAnswer {
    Login {
        token: Zeroizing<String>,
        token_id: String,
        account_name: Option<String>,
    },
    Connect {
        connection_token: Zeroizing<String>,
        site_id: String,
        site_url: String,
        key_version: i64,
        repository: String,
    },
    AuthorizationPending,
    SlowDown {
        interval: u64,
    },
    AccessDenied,
    ExpiredToken,
    TokenLimitReached,
}

impl std::fmt::Debug for PollAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Login { .. } => "Login { [redacted] }",
            Self::Connect { .. } => "Connect { [redacted] }",
            Self::AuthorizationPending => "AuthorizationPending",
            Self::SlowDown { .. } => "SlowDown",
            Self::AccessDenied => "AccessDenied",
            Self::ExpiredToken => "ExpiredToken",
            Self::TokenLimitReached => "TokenLimitReached",
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireToken {
    Login {
        #[serde(with = "secret_serde")]
        token: Zeroizing<String>,
        token_id: String,
        #[serde(default, deserialize_with = "display_name")]
        account_name: Option<String>,
    },
    Connect {
        #[serde(with = "secret_serde")]
        connection_token: Zeroizing<String>,
        site_id: String,
        site_url: String,
        key_version: i64,
        repository: String,
    },
}

impl<'de> Deserialize<'de> for PollAnswer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match WireToken::deserialize(deserializer)? {
            WireToken::Login {
                token,
                token_id,
                account_name,
            } => Self::Login {
                token,
                token_id,
                account_name,
            },
            WireToken::Connect {
                connection_token,
                site_id,
                site_url,
                key_version,
                repository,
            } => Self::Connect {
                connection_token,
                site_id,
                site_url,
                key_version,
                repository,
            },
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    Applied,
    Bootstrapped,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineReceipt {
    pub status: BaselineStatus,
    pub key_version: i64,
}

/// GitHub secrets are never serializable CLI output.
/// ```compile_fail
/// // Bug: serializing a secrets response would expose its bearer.
/// use sitecmd_runtime::connected_codes::SecretsToken;
/// fn output(value: &SecretsToken) { let _ = serde_json::to_value(value); }
/// ```
#[derive(Deserialize)]
pub struct SecretsToken {
    #[serde(with = "secret_serde")]
    pub token: Zeroizing<String>,
    pub expires_at: String,
    pub repository: String,
}

impl std::fmt::Debug for SecretsToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretsToken { [redacted] }")
    }
}

/// Recorded secret writes and the workflow status reported by Connect.
#[derive(Deserialize)]
pub struct ProvisionedReceipt {
    pub provisioned: bool,
    pub workflow_state: String,
}

fn display_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let raw = String::deserialize(deserializer)?;
    Ok(super::errors::printable(&raw, 500))
}

fn display_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw
        .map(|text| super::errors::printable(&text, 500))
        .filter(|text| !text.is_empty()))
}

fn verification_uri<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let raw = String::deserialize(deserializer)?;
    let url =
        url::Url::parse(&raw).map_err(|_| serde::de::Error::custom("invalid verification URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || raw.chars().any(char::is_control)
    {
        return Err(serde::de::Error::custom(
            "verification URL must use HTTPS without user information or controls",
        ));
    }
    Ok(url.to_string())
}
