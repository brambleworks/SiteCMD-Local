use super::*;
use crate::checks::polish::{css_signal_counts, stylesheet_request};
use crate::probe::{decode_probe_body, ProbeResponse};

#[test]
fn stylesheet_documents_are_reduced_and_replacements_do_not_keep_stale_counts() {
    // Keeping stylesheet bodies defeats recorded-alone memory bounds or stale reads prove a false finding.
    let mut readings = Readings::default();
    let request = stylesheet_request("https://example.com/a.css");
    let text = "a{background:linear-gradient(red,blue)}";
    for (status, body) in [
        (200, Some(text)),
        (404, Some(text)),
        (200, None),
        (200, Some("")),
    ] {
        let kept = readings.absorb(ExecutedProbe::new(
            probe_key(&request),
            ProbeOutcome::Response(ProbeResponse {
                status,
                final_url: request.url.clone(),
                content_type: Some("text/css".into()),
                content_length: None,
                headers: vec![("x-unneeded".into(), "discard".into())],
                body: body.map(|text| decode_probe_body(text.as_bytes().to_vec())),
            }),
        ));
        assert_eq!(
            readings.stylesheet(&request).copied(),
            body.filter(|_| status == 200).map(|text| css_signal_counts(
                text,
                crate::checks::polish::CssTextKind::Stylesheet
            ))
        );
        let ProbeOutcome::Response(response) = kept.outcome else {
            panic!("response")
        };
        assert!(response.body.is_none());
        assert!(response.headers.is_empty());
        assert!(response.final_url.is_empty());
    }
}
