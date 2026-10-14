//! Desktop reqwest adapter for portable engine probe outcomes.
//!
//! Every typed `ProbeRequest` passes through here, so this is also where the
//! transport is kept honest for the origin and for the verdicts: at most
//! `PROBE_HOST_CONCURRENCY` probe requests are in flight to one origin at a
//! time, and a request that failed at the connection level before any
//! response arrived is retried once inside its own timeout budget. A request
//! that reads its answer as the server sent it goes through `probe_raw`, which
//! uses the client that decodes nothing.
//!
//! Three checks still call `reqwest` directly instead of building a
//! `ProbeRequest`, and `guardrail-probe-seam.test.mjs` holds the list to those
//! three so the next check cannot quietly add a fourth. None of them can
//! reproduce the burst this seam exists to prevent: `polish/css_fetch.rs` reads
//! the bodies it asks for, which is what returns the HTTP/2 frame budget the
//! burst exhausted; `performance/timing.rs` measures TTFB and must not have seam
//! queueing counted into the number it reports; and
//! `security/vulnerable_libraries.rs` queries the OSV API, not the scanned origin.

use std::time::{Duration, Instant};

use super::probe_slots::OriginSlot;
use sitecmd_engine::probe::{
    decode_probe_body, BodyLimit, BodyPolicy, ContentCoding, ProbeFailure, ProbeFailureClass,
    ProbeMeasure, ProbeMethod, ProbeOutcome, ProbeRequest, ProbeResponse, RedirectPolicy,
};

// The seam's tests read these through `use super::*`.
#[cfg(test)]
use {
    super::probe_slots::{lock_limiters, origin_key},
    std::sync::Arc,
};

/// GET one probe URL under the standard probe timeout and body cap, with
/// the common policies (follow redirects, 2xx body).
pub(crate) async fn probe_get(client: &reqwest::Client, url: &str) -> ProbeOutcome {
    probe(client, ProbeRequest::get(url)).await
}

/// Execute one probe request. `client` serves redirect-following requests;
/// `RedirectPolicy::None` swaps in the shared no-redirect client so a 3xx
/// classifies as the answer instead of being followed.
pub(crate) async fn probe(client: &reqwest::Client, request: ProbeRequest) -> ProbeOutcome {
    probe_with_timeout(client, request, None).await
}

/// Execute one probe request under an explicit timeout. Link probing uses a
/// longer budget for different-host destinations.
///
/// The origin slot is held for the whole exchange, body read included, so
/// "in flight" means what the origin sees: a request it has not finished
/// answering. Waiting for a slot does not count against the timeout; the
/// budget starts when the request is actually sent.
pub(crate) async fn probe_with_timeout(
    client: &reqwest::Client,
    request: ProbeRequest,
    timeout: Option<Duration>,
) -> ProbeOutcome {
    if request.coding == ContentCoding::Raw {
        // This client decodes what it reads, so a raw read through it would
        // answer the wrong question.
        return ProbeOutcome::Failure(ProbeFailure {
            class: ProbeFailureClass::Transport,
            detail: "a raw-coding probe cannot be read through a decoding client".into(),
        });
    }
    let client = match request.redirects {
        RedirectPolicy::Follow => client,
        RedirectPolicy::None => crate::http_client::no_redirect_client(),
    };
    exchange(client, request, timeout).await.0
}

/// Execute a request that reads the response as the server sent it, through
/// the client that decodes nothing, with the measure a counted body adds. That
/// client follows redirects, so a raw read that may not is refused unsent.
pub(crate) async fn probe_raw(
    is_strict_local: bool,
    request: ProbeRequest,
) -> (ProbeOutcome, Option<ProbeMeasure>) {
    if request.redirects == RedirectPolicy::None {
        let refused = ProbeFailure {
            class: ProbeFailureClass::Transport,
            detail: "a raw-coding probe follows its redirects".into(),
        };
        return (ProbeOutcome::Failure(refused), None);
    }
    let client = crate::http_client::no_decompress_client(is_strict_local);
    exchange(client, request, None).await
}

/// One exchange: the origin slot, the send with its one retry, and the answer
/// under the request's body policy, with the measure a counted body adds.
async fn exchange(
    client: &reqwest::Client,
    request: ProbeRequest,
    timeout: Option<Duration>,
) -> (ProbeOutcome, Option<ProbeMeasure>) {
    let _slot = OriginSlot::acquire(&request.url).await;
    let timeout = timeout.unwrap_or(crate::constants::CHECK_PROBE_TIMEOUT);
    let response = match send_with_one_retry(client, &request, timeout).await {
        Ok(response) => response,
        Err(error) => return (ProbeOutcome::Failure(failure_from_send_error(&error)), None),
    };
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let head = ProbeResponse {
        status,
        final_url,
        content_type,
        content_length,
        headers,
        body: None,
    };
    if request.body == BodyPolicy::Count {
        let sized = status >= 400 || status == 206 || head.content_length.is_some();
        let measure = counted_body(response, request.method, sized).await;
        return (ProbeOutcome::Response(head), measure);
    }
    let read_body = match (request.method, request.body) {
        (ProbeMethod::Head, _) | (_, BodyPolicy::None | BodyPolicy::Count) => false,
        (_, BodyPolicy::SuccessOnly) => (200..300).contains(&status),
        (_, BodyPolicy::Always) => true,
    };
    if !read_body {
        return (ProbeOutcome::Response(head), None);
    }
    let body_cap = match request.limit {
        BodyLimit::Probe => crate::constants::MAX_PROBE_BODY_SIZE,
        BodyLimit::Sitemap => crate::constants::MAX_SITEMAP_SIZE,
    };
    let outcome = match crate::http_client::read_body_limited(
        response,
        body_cap,
        crate::constants::CHECK_PROBE_TIMEOUT,
    )
    .await
    {
        Ok(bytes) => ProbeOutcome::Response(ProbeResponse {
            body: Some(decode_probe_body(bytes)),
            ..head
        }),
        // SuccessOnly consumers need the body as evidence; Always consumers
        // treat the status line as primary and degrade to an absent body.
        Err(error) => match request.body {
            BodyPolicy::Always => ProbeOutcome::Response(head),
            _ => ProbeOutcome::Failure(failure_from_body_error(error)),
        },
    };
    (outcome, None)
}

/// The bytes of a body its own headers do not size, counted and discarded
/// under the probe cap. A 206's Content-Range and a declared Content-Length
/// already answer, and an error status's body measures no asset.
async fn counted_body(
    response: reqwest::Response,
    method: ProbeMethod,
    sized: bool,
) -> Option<ProbeMeasure> {
    if method == ProbeMethod::Head || sized {
        return None;
    }
    match crate::http_client::read_body_limited(
        response,
        crate::constants::MAX_PROBE_BODY_SIZE,
        crate::constants::CHECK_PROBE_TIMEOUT,
    )
    .await
    {
        Ok(bytes) => Some(ProbeMeasure::counted(bytes.len() as u64, false)),
        Err(crate::http_client::BodyReadError::TooLarge { received_bytes, .. }) => {
            Some(ProbeMeasure::counted(received_bytes, true))
        }
        Err(_) => None,
    }
}

/// Send the request, and send it once more if the first attempt failed in a
/// way that says nothing about the origin's answer. Both attempts share one
/// `timeout` budget measured from the first send.
async fn send_with_one_retry(
    client: &reqwest::Client,
    request: &ProbeRequest,
    timeout: Duration,
) -> reqwest::Result<reqwest::Response> {
    let deadline = Instant::now() + timeout;
    let first_error = match send(client, request, timeout).await {
        Ok(response) => return Ok(response),
        Err(error) if send_failure_is_retryable(&error) => error,
        Err(error) => return Err(error),
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(first_error);
    }
    match send(client, request, remaining).await {
        Ok(response) => Ok(response),
        // A retry the first attempt left almost nothing of the budget can
        // only end by running out of it, so its timeout describes that
        // remainder rather than the origin. The connection failure is what was
        // actually observed there, and reporting the retry instead would
        // downgrade an observed reset to "timed out". A retry that did get a
        // fair share of the budget and still did not finish is a real
        // observation of the origin, and stays the answer.
        Err(second_error)
            if second_error.is_timeout() && !retry_had_a_fair_share(remaining, timeout) =>
        {
            Err(first_error)
        }
        Err(second_error) => Err(second_error),
    }
}

/// Whether a second attempt left `remaining` of a `timeout` budget was a fair
/// test of the origin. Half the budget is the line: above it the retry had
/// room to succeed or to prove the origin does not answer, below it the clock
/// was always going to run out first whatever the origin did.
fn retry_had_a_fair_share(remaining: Duration, timeout: Duration) -> bool {
    remaining * 2 >= timeout
}

async fn send(
    client: &reqwest::Client,
    request: &ProbeRequest,
    timeout: Duration,
) -> reqwest::Result<reqwest::Response> {
    let mut builder = match request.method {
        ProbeMethod::Get => client.get(&request.url),
        ProbeMethod::Head => client.head(&request.url),
    }
    .timeout(timeout);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    builder.send().await
}

/// Every probe is a GET or HEAD, so a second attempt is always safe; the
/// question is only whether it could answer differently. A connection that
/// was refused, reset, or torn down before a response arrived (an HTTP/2
/// GOAWAY takes every in-flight stream on the connection with it) can. A
/// timeout already spent the budget, a builder or redirect-policy error
/// would repeat exactly, and a host that did not resolve, or that the
/// resolver refused by policy, is not going to resolve on the second try.
fn send_failure_is_retryable(error: &reqwest::Error) -> bool {
    !(error.is_timeout()
        || error.is_builder()
        || error.is_redirect()
        || error.is_body()
        || error.is_decode()
        || dns_failure(error).is_some())
}

/// A resolver that answered "no address" is a fact about the host, not a
/// missing answer, so it carries its own class. A policy refusal stays
/// `Transport`: the name resolved and this runtime declined the address, which
/// says nothing about the host a verdict could report.
fn failure_from_send_error(error: &reqwest::Error) -> ProbeFailure {
    ProbeFailure {
        class: if error.is_timeout() {
            ProbeFailureClass::Timeout
        } else if dns_failure(error) == Some(DnsFailure::Unresolved) {
            ProbeFailureClass::DnsUnresolved
        } else {
            ProbeFailureClass::Transport
        },
        detail: error.to_string(),
    }
}

/// How name resolution failed, when it was resolution that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsFailure {
    /// The resolver returned no address for the host.
    Unresolved,
    /// The host resolved, but to an address the network policy refuses.
    Refused,
}

fn dns_failure(error: &reqwest::Error) -> Option<DnsFailure> {
    dns_failure_in_chain(error)
}

/// Walk the error chain for hyper-util's resolver wrapper. hyper-util does
/// not export its `ConnectError` type, but every resolver failure is wrapped
/// with the fixed message `dns error` (`ConnectError::dns`) around the
/// resolver's own `io::Error`, and `CachedDnsResolver` reports a policy
/// refusal as `PermissionDenied` and everything else as an ordinary lookup
/// failure.
fn dns_failure_in_chain(error: &(dyn std::error::Error + 'static)) -> Option<DnsFailure> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(layer) = current {
        if layer.to_string() == "dns error" {
            let refused = layer
                .source()
                .and_then(|cause| cause.downcast_ref::<std::io::Error>())
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied);
            return Some(if refused {
                DnsFailure::Refused
            } else {
                DnsFailure::Unresolved
            });
        }
        current = layer.source();
    }
    None
}

fn failure_from_body_error(error: crate::http_client::BodyReadError) -> ProbeFailure {
    use crate::http_client::BodyReadError;
    ProbeFailure {
        class: match &error {
            BodyReadError::TooLarge { .. } => ProbeFailureClass::BodyCapExceeded,
            BodyReadError::TimedOut { .. } => ProbeFailureClass::Timeout,
            BodyReadError::Transport(_) => ProbeFailureClass::Transport,
        },
        detail: error.to_string(),
    }
}

#[cfg(test)]
#[path = "probe_adapter_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "probe_adapter_raw_tests.rs"]
mod raw_tests;

/// The loopback origins the transport tests drive. Re-exported so the
/// open-redirect sweep test can reach them under the adapter's own path.
#[cfg(test)]
pub(crate) use tests::testing;
