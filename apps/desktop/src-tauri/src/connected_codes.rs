//! CLI device authorization and one-use connection setup through Connect.

use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use reqwest::Method;
use serde::de::DeserializeOwned;
use sitecmd_protocol::sync::wire::{DeviceCode, Identifier};

use crate::connected_service::{
    local_error, ConnectedServiceClient, ConnectedServiceError, EmptyRequest, WireRequest,
};

mod errors;
mod types;
use errors::code_error;
pub(crate) use errors::printable;
pub use errors::CodeRefusal;
use types::CodeClient;
pub use types::{
    BaselineReceipt, BaselineRequest, BaselineStatus, CodeRequest, DeviceAuthorization, PollAnswer,
    ProvisionedReceipt, SecretsToken,
};
pub(crate) use types::{CodeRequestBody, PollTokenRequest, ProvisionedRequest};

impl ConnectedServiceClient {
    pub async fn request_code(
        &self,
        request: &CodeRequest,
    ) -> Result<DeviceAuthorization, ConnectedServiceError> {
        let build = |value: &str| {
            Identifier::try_from(value).map_err(|_| {
                local_error("serialization_failed", "code request could not be encoded")
            })
        };
        let body = CodeRequestBody {
            request: request.clone(),
            client: CodeClient {
                version: build(env!("CARGO_PKG_VERSION"))?,
                os: build(std::env::consts::OS)?,
            },
        };
        let client = self.code_flow_client(None)?;
        client.code_post(&["v1", "cli", "codes"], &body).await
    }

    pub async fn poll_token(
        &self,
        device_code: &DeviceCode,
    ) -> Result<PollAnswer, ConnectedServiceError> {
        let client = self.code_flow_client(None)?;
        let body = PollTokenRequest {
            device_code: device_code.clone(),
        };
        let url = client.url(&["v1", "cli", "token"])?;
        match client.request(Method::POST, url, None, Some(&body)).await {
            Ok(answer) => Ok(answer),
            Err(error) if error.status == 400 => match error.code.as_str() {
                "authorization_pending" => Ok(PollAnswer::AuthorizationPending),
                "slow_down" => {
                    let interval = error
                        .details
                        .as_ref()
                        .and_then(|body| body.get("interval"))
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| {
                            local_error(
                                "malformed_response",
                                "slow_down did not name a polling interval",
                            )
                        })?;
                    Ok(PollAnswer::SlowDown { interval })
                }
                "access_denied" => Ok(PollAnswer::AccessDenied),
                "expired_token" => Ok(PollAnswer::ExpiredToken),
                "token_limit_reached" => Ok(PollAnswer::TokenLimitReached),
                _ => Err(code_error(error)),
            },
            Err(error) => Err(code_error(error)),
        }
    }

    pub async fn connect_baseline(
        &self,
        connection_token: &str,
        body: &BaselineRequest,
    ) -> Result<BaselineReceipt, ConnectedServiceError> {
        self.code_flow_client(Some(connection_token))?
            .code_post(&["v1", "connect", "baseline"], body)
            .await
    }

    pub async fn connect_secrets_token(
        &self,
        connection_token: &str,
    ) -> Result<SecretsToken, ConnectedServiceError> {
        self.code_flow_client(Some(connection_token))?
            .code_post(&["v1", "connect", "secrets-token"], &EmptyRequest {})
            .await
    }

    pub async fn connect_secrets_provisioned(
        &self,
        connection_token: &str,
        token_revoked: bool,
    ) -> Result<ProvisionedReceipt, ConnectedServiceError> {
        let body = ProvisionedRequest { token_revoked };
        self.code_flow_client(Some(connection_token))?
            .code_post(&["v1", "connect", "secrets-provisioned"], &body)
            .await
    }

    pub async fn revoke_current_token(&self) -> Result<(), ConnectedServiceError> {
        let url = self.url(&["v1", "account", "tokens", "current"])?;
        self.no_content(Method::DELETE, url)
            .await
            .map_err(code_error)
    }

    fn code_flow_client(&self, token: Option<&str>) -> Result<Self, ConnectedServiceError> {
        Self::for_endpoint(&self.origin(), token, cfg!(test)).map_err(|_| {
            local_error(
                "invalid_credential",
                "code-flow credential or origin is invalid",
            )
        })
    }

    async fn code_post<T: DeserializeOwned>(
        &self,
        path: &[&str],
        body: &impl WireRequest,
    ) -> Result<T, ConnectedServiceError> {
        let url = self.url(path)?;
        self.request(Method::POST, url, None, Some(body))
            .await
            .map_err(code_error)
    }
}

/// Poll immediately, then obey Connect's interval and the authorization lifetime.
pub async fn wait_for_approval(
    client: &ConnectedServiceClient,
    authorization: &DeviceAuthorization,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
) -> Result<PollAnswer, String> {
    let started = Instant::now();
    wait_for_approval_with_clock(client, authorization, sleep, || started.elapsed()).await
}

async fn wait_for_approval_with_clock(
    client: &ConnectedServiceClient,
    authorization: &DeviceAuthorization,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
    clock: impl Fn() -> Duration,
) -> Result<PollAnswer, String> {
    wait_for_approval_until(client, authorization, sleep, clock, || false).await
}

pub(crate) async fn wait_for_approval_interruptible(
    client: &ConnectedServiceClient,
    authorization: &DeviceAuthorization,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
    interrupted: impl Fn() -> bool,
) -> Result<PollAnswer, String> {
    let started = Instant::now();
    wait_for_approval_until(
        client,
        authorization,
        sleep,
        || started.elapsed(),
        interrupted,
    )
    .await
}

async fn wait_for_approval_until(
    client: &ConnectedServiceClient,
    authorization: &DeviceAuthorization,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
    clock: impl Fn() -> Duration,
    interrupted: impl Fn() -> bool,
) -> Result<PollAnswer, String> {
    // allow-inline-duration: these durations are supplied by Connect's device-flow protocol.
    let lifetime = Duration::from_secs(authorization.expires_in);
    // allow-inline-duration: Connect specifies polling intervals in whole seconds.
    let mut interval = Duration::from_secs(authorization.interval.max(1));
    let mut elapsed = Duration::ZERO;
    loop {
        if interrupted() {
            return Err(String::new());
        }
        elapsed = elapsed.max(clock());
        if elapsed >= lifetime {
            return Ok(PollAnswer::ExpiredToken);
        }
        let remaining = lifetime.saturating_sub(elapsed);
        let polled = clock();
        let answer =
            tokio::time::timeout(remaining, client.poll_token(&authorization.device_code)).await;
        elapsed = elapsed.saturating_add(clock().saturating_sub(polled));
        let answer = match answer {
            Ok(answer) => {
                answer.map_err(|error| format!("code approval failed ({})", error.code))?
            }
            Err(_) => return Ok(PollAnswer::ExpiredToken),
        };
        match answer {
            PollAnswer::AuthorizationPending => {}
            PollAnswer::SlowDown {
                interval: requested,
            } => {
                // allow-inline-duration: the device-flow slow_down contract adds five seconds.
                interval = interval.saturating_add(Duration::from_secs(5));
                // allow-inline-duration: honor the minimum interval in Connect's slow_down answer.
                interval = interval.max(Duration::from_secs(requested));
            }
            answer => return Ok(answer),
        }
        elapsed = elapsed.max(clock());
        let remaining = lifetime.saturating_sub(elapsed);
        let delay = interval.min(remaining);
        let sleeping = clock();
        sleep(delay).await;
        elapsed = elapsed.saturating_add(delay.max(clock().saturating_sub(sleeping)));
    }
}

#[cfg(test)]
#[path = "connected_codes/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "connected_codes/refusal_tests.rs"]
mod refusal_tests;
