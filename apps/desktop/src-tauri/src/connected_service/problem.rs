//! Connect's refusals as the client reads them: RFC 9457 problem details, the
//! uniform refusal a body without them reads as, and the wait a refusal's
//! `Retry-After` names.

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

use super::ConnectedServiceError;

/// RFC 9457 problem details, the shape of every Connect refusal. `code` is what
/// callers branch on; `details` holds the whole object, so the members a
/// refusal adds (`stale_groups`, `reason`, ...) stay reachable.
#[derive(Deserialize)]
struct Problem {
    code: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    request_id: Option<String>,
}

pub(crate) fn local_error(code: &str, message: &str) -> ConnectedServiceError {
    ConnectedServiceError {
        status: 0,
        code: code.into(),
        message: message.into(),
        request_id: None,
        details: None,
        retry_after: None,
    }
}

pub(super) fn parse_response<T: DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
) -> Result<T, ConnectedServiceError> {
    if status.is_success() {
        return serde_json::from_slice(bytes).map_err(|_| ConnectedServiceError {
            status: status.as_u16(),
            ..local_error(
                "malformed_response",
                "the connected service returned an invalid response",
            )
        });
    }
    Err(parse_error(status, bytes))
}

/// The service's problem details, or the uniform refusal when there are none.
pub(super) fn parse_error(status: StatusCode, bytes: &[u8]) -> ConnectedServiceError {
    let value = serde_json::from_slice::<Value>(bytes).ok();
    let problem = value
        .as_ref()
        .and_then(|value| Problem::deserialize(value).ok());
    match problem {
        Some(problem) => ConnectedServiceError {
            status: status.as_u16(),
            code: problem.code,
            message: problem.detail,
            request_id: problem.request_id,
            details: value.map(Box::new),
            retry_after: None,
        },
        None => ConnectedServiceError {
            status: status.as_u16(),
            ..local_error(
                "request_failed",
                "the connected service refused the request",
            )
        },
    }
}

/// A refusal with the wait its `Retry-After` header names, in the
/// delay-seconds form Connect sends. The HTTP-date form, which Connect never
/// sends, and anything unreadable name no wait.
pub(super) fn refusal(
    status: StatusCode,
    headers: &HeaderMap,
    bytes: &[u8],
) -> ConnectedServiceError {
    let retry_after = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    ConnectedServiceError {
        retry_after,
        ..parse_error(status, bytes)
    }
}
