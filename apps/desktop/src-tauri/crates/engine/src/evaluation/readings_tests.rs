//! The reading store must discard documents while retaining bounded verdict inputs.

use super::Readings;
use crate::evaluation::{probe_key, ExecutedProbe};
use crate::probe::{decode_probe_body, BodyLimit, ProbeOutcome, ProbeRequest, ProbeResponse};

#[test]
fn a_sweep_entry_keeps_its_sample_and_drops_the_document() {
    // Storing the original outcome alongside its reading would retain the secret document.
    let request = ProbeRequest::get("https://example.com/probe").limit(BodyLimit::Sweep);
    let mut readings = Readings::default();
    assert!(readings.sweep(&request).is_none());
    let text = format!("{}tail-must-be-dropped", "é".repeat(4096));
    let kept = readings.absorb(ExecutedProbe::new(
        probe_key(&request),
        ProbeOutcome::Response(ProbeResponse {
            status: 200,
            final_url: request.url.clone(),
            content_type: Some("text/plain".into()),
            content_length: Some(text.len() as u64),
            headers: vec![("x-unneeded".into(), "discarded".into())],
            body: Some(decode_probe_body(text.as_bytes().to_vec())),
        }),
    ));
    let reading = readings
        .sweep(&request)
        .expect("reading stored by full key");
    assert_eq!(reading.sample.as_deref(), Some("é".repeat(4096).as_str()));
    assert_eq!(readings.sweeps.len(), 1);
    let ProbeOutcome::Response(response) = kept.outcome else {
        panic!("response");
    };
    assert!(response.body.is_none());
    assert!(response.headers.is_empty());
    assert!(response.final_url.is_empty());
    assert!(readings.sweep(&request.limit(BodyLimit::Probe)).is_none());
}
