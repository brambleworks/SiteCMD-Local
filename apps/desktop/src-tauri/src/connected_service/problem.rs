//! Connect's refusals as the client reads them: RFC 9457 problem details, the
//! uniform refusal a body without them reads as, and the wait a refusal's
//! `Retry-After` names.

use reqwest::header::{HeaderMap, DATE, RETRY_AFTER};
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

/// A refusal with the wait its `Retry-After` header names.
pub(super) fn refusal(
    status: StatusCode,
    headers: &HeaderMap,
    bytes: &[u8],
    now: Option<jiff::Timestamp>,
) -> ConnectedServiceError {
    ConnectedServiceError {
        retry_after: retry_after(headers, now),
        ..parse_error(status, bytes)
    }
}

pub(super) fn response_date(headers: &HeaderMap) -> Option<jiff::Timestamp> {
    parse_http_date(headers.get(DATE)?.to_str().ok()?.trim())
}

fn parse_http_date(value: &str) -> Option<jiff::Timestamp> {
    jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(value)
        .ok()
}

fn retry_after(headers: &HeaderMap, now: Option<jiff::Timestamp>) -> Option<u64> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse().ok();
    }
    let timestamp = parse_http_date(value)?;
    let delay = std::time::Duration::try_from(timestamp.duration_since(now?)).unwrap_or_default();
    Some(delay.as_secs() + u64::from(delay.subsec_nanos() > 0))
}
