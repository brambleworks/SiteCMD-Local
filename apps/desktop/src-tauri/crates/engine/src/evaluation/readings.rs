//! Private, compact verdict inputs from documents recorded alone.

use std::collections::HashMap;

use super::probes::{is_stylesheet_key, is_sweep_key, probe_key, ExecutedProbe};
use crate::checks::polish::{css_signal_counts, CssSignalCounts};
use crate::checks::security::directory_listing::body_indicates_listing;
use crate::checks::security::exposed_files::PROBE_SIGNATURE_SAMPLE_CHARS;
use crate::probe::{ProbeBody, ProbeFailure, ProbeOutcome, ProbeRequest, ProbeResponse};

fn success_body(response: &ProbeResponse) -> Option<&ProbeBody> {
    response
        .body
        .as_ref()
        .filter(|_| (200..300).contains(&response.status))
}

/// A sweep's verdict inputs, kept inside the engine and never serialized or logged.
/// The signature sample can contain sensitive content and must never enter a result.
pub struct SweepReading {
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub sample: Option<String>,
    pub listing: bool,
    pub failure: Option<ProbeFailure>,
}

/// Reduce one sweep answer without keeping its document, response headers or URL.
pub fn sweep_reading(outcome: &ProbeOutcome) -> SweepReading {
    match outcome {
        ProbeOutcome::Response(response) => SweepReading {
            status: Some(response.status),
            content_type: response.content_type.clone(),
            content_length: response.content_length,
            sample: success_body(response).map(|body| {
                body.text
                    .chars()
                    .take(PROBE_SIGNATURE_SAMPLE_CHARS)
                    .collect()
            }),
            listing: success_body(response).is_some_and(|body| body_indicates_listing(&body.text)),
            failure: None,
        },
        ProbeOutcome::Failure(failure) => SweepReading {
            status: None,
            content_type: None,
            content_length: None,
            sample: None,
            listing: false,
            failure: Some(failure.clone()),
        },
    }
}

/// Route-local readings keyed by the complete request, never serialized or logged.
#[derive(Default)]
pub struct Readings {
    sweeps: HashMap<String, SweepReading>,
    stylesheets: HashMap<String, Option<CssSignalCounts>>,
}

impl Readings {
    /// The reading of a recorded sweep, or `None` until it has answered.
    pub fn sweep(&self, request: &ProbeRequest) -> Option<&SweepReading> {
        self.sweeps.get(&probe_key(request))
    }

    /// Counts from a successful recorded stylesheet, including an empty body.
    pub fn stylesheet(&self, request: &ProbeRequest) -> Option<&CssSignalCounts> {
        self.stylesheets
            .get(&probe_key(request))
            .and_then(Option::as_ref)
    }

    /// Reduce a sweep or stylesheet to its reading and leave only a body-free answered marker.
    /// Other probes retain their existing outcome semantics.
    pub(super) fn absorb(&mut self, mut executed: ExecutedProbe) -> ExecutedProbe {
        let sweep = is_sweep_key(&executed.key);
        let stylesheet = is_stylesheet_key(&executed.key);
        if sweep {
            self.sweeps
                .insert(executed.key.clone(), sweep_reading(&executed.outcome));
        }
        if stylesheet {
            let counts = match &executed.outcome {
                ProbeOutcome::Response(response) => success_body(response).map(|body| {
                    css_signal_counts(&body.text, crate::checks::polish::CssTextKind::Stylesheet)
                }),
                _ => None,
            };
            self.stylesheets.insert(executed.key.clone(), counts);
        }
        if sweep || stylesheet {
            if let ProbeOutcome::Response(response) = &mut executed.outcome {
                response.body = None;
                response.headers = Vec::new();
                response.final_url = String::new();
            }
        }
        executed
    }
}

#[cfg(test)]
#[path = "readings_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "readings_stylesheets_tests.rs"]
mod stylesheet_tests;
