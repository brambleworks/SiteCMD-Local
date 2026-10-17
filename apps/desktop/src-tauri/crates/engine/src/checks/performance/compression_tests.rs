use super::*;
use http::header::HeaderMap;

fn page_with_encoding(encoding: Option<&str>) -> PageContext {
    let mut headers = HeaderMap::new();
    if let Some(e) = encoding {
        headers.insert("content-encoding", e.parse().expect("static header"));
    }
    PageContext {
        evaluation_time: chrono::DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .expect("static test time")
            .with_timezone(&chrono::Utc),
        url: url::Url::parse("https://example.com").expect("static test url"),
        response_headers: headers,
        status_code: 200,
        body: String::new(),
        is_localhost: false,
        is_strict_localhost: false,
        http_version: Some("HTTP/2.0".to_string()),
        body_lower_cache: std::sync::OnceLock::new(),
    }
}

fn probe(http_status: u16, encoding: Option<&str>, vary: &str) -> EncodingProbe {
    EncodingProbe {
        http_status,
        encoding: encoding.map(String::from),
        vary: vary.into(),
    }
}

#[test]
fn header_fallback_detects_gzip() {
    let results = evaluate_compression_get(None, &page_with_encoding(Some("gzip")));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn header_fallback_detects_brotli_and_zstd() {
    for encoding in ["br", "zstd"] {
        let results = evaluate_compression_get(None, &page_with_encoding(Some(encoding)));
        assert_eq!(results[0].status, CheckStatus::Pass, "{encoding}");
    }
}

#[test]
fn header_fallback_lowercases_before_matching() {
    let results = evaluate_compression_get(None, &page_with_encoding(Some("GZIP")));
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn header_fallback_missing_encoding_is_inconclusive() {
    let results = evaluate_compression_get(None, &page_with_encoding(None));
    assert_eq!(results[0].status, CheckStatus::Skipped);
}

#[test]
fn header_fallback_identity_is_inconclusive() {
    let results = evaluate_compression_get(None, &page_with_encoding(Some("identity")));
    assert_eq!(results[0].status, CheckStatus::Skipped);
}

#[test]
fn header_fallback_reads_every_content_encoding_line() {
    // RFC 9110 section 5.3: gzip on a second line is part of the field's value,
    // as it is when one line lists both.
    let mut page = page_with_encoding(Some("identity"));
    page.response_headers
        .append("content-encoding", "gzip".parse().expect("static header"));
    let results = evaluate_compression_get(None, &page);
    assert_eq!(results[0].status, CheckStatus::Pass);
}

#[test]
fn non_2xx_probe_is_not_graded_as_the_page() {
    let results = evaluate_compression_get(Some(probe(405, None, "")), &page_with_encoding(None));
    assert_eq!(results[0].status, CheckStatus::Skipped);
    assert!(results[0].description.contains("HTTP 405"));
}

#[test]
fn head_probe_can_only_short_circuit_to_a_pass() {
    let mut approved = 0;
    for http_status in [200u16, 204, 301, 404, 500] {
        for encoding in [None, Some("br"), Some("gzip"), Some("identity")] {
            for vary in ["", "accept-encoding, cookie"] {
                let head = probe(http_status, encoding, vary);
                if let CompressionStep::Done(results) = evaluate_compression_head(Some(&head)) {
                    approved += 1;
                    assert_eq!(
                        results[0].status,
                        CheckStatus::Pass,
                        "HEAD probe approved for grading must Pass: \
                         status={http_status} encoding={encoding:?} vary={vary:?}"
                    );
                }
            }
        }
    }
    assert!(
        approved > 0,
        "the sweep must exercise at least one gradable HEAD probe"
    );
}

#[test]
fn signal_less_head_defers_to_get_instead_of_grading() {
    // A 2xx HEAD without Content-Encoding or Vary proves nothing; the step
    // must fall through to the GET probe.
    let head = probe(200, None, "");
    assert!(matches!(
        evaluate_compression_head(Some(&head)),
        CompressionStep::NeedsGet
    ));
}

#[test]
fn vary_only_head_defers_to_get_instead_of_passing() {
    let head = probe(200, None, "accept-encoding");
    assert!(matches!(
        evaluate_compression_head(Some(&head)),
        CompressionStep::NeedsGet
    ));
}

#[test]
fn a_failed_head_request_defers_to_get() {
    assert!(matches!(
        evaluate_compression_head(None),
        CompressionStep::NeedsGet
    ));
}

#[test]
fn uncompressed_get_fails() {
    // Fail is reserved for a confirmed 2xx GET with no compression
    // signal - the only path where absence is real evidence.
    let results = evaluate_compression_get(Some(probe(200, None, "")), &page_with_encoding(None));
    assert_eq!(results[0].status, CheckStatus::Fail);
}

#[test]
fn vary_only_uncompressed_get_fails_with_capability_copy() {
    let results = evaluate_compression_get(
        Some(probe(200, None, "accept-encoding, cookie")),
        &page_with_encoding(None),
    );
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert!(
        results[0].description.contains("only signals capability"),
        "copy must explain the Vary header honestly: {}",
        results[0].description
    );
}

#[test]
fn localhost_previews_skip_without_probing() {
    let result = localhost_skip_result();
    assert_eq!(result.status, CheckStatus::Skipped);
    assert_eq!(result.check_id, "performance.compression");
    assert_eq!(
        result.raw_data.as_ref().unwrap()["reason"],
        "localhost_preview_server"
    );
}

fn answered(status: u16, headers: &[(&str, &str)]) -> crate::probe::ProbeOutcome {
    crate::probe::ProbeOutcome::Response(crate::probe::ProbeResponse {
        status,
        final_url: String::new(),
        content_type: None,
        content_length: None,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        body: None,
    })
}

#[test]
fn the_head_and_the_get_offer_every_coding_and_read_no_body() {
    // Changing the codings, page URL or redirects breaks the raw probes.
    let url = url::Url::parse("https://example.com/blog/post?id=1").expect("url");
    let offered = (
        "accept-encoding".to_string(),
        "gzip, deflate, br, zstd".to_string(),
    );
    let head = head_request(&url);
    assert_eq!(head.url, url.as_str());
    assert_eq!(head.method, crate::probe::ProbeMethod::Head);
    assert_eq!(head.redirects, crate::probe::RedirectPolicy::Follow);
    assert_eq!(head.coding, crate::probe::ContentCoding::Raw);
    assert!(head.headers.contains(&offered));
    let get = get_request(&url);
    assert_eq!(get.url, url.as_str());
    assert_eq!(get.method, crate::probe::ProbeMethod::Get);
    assert_eq!(get.redirects, crate::probe::RedirectPolicy::Follow);
    assert_eq!(get.body, crate::probe::BodyPolicy::None);
    assert_eq!(get.coding, crate::probe::ContentCoding::Raw);
    assert!(get.headers.contains(&offered));
}

#[test]
fn an_answer_reads_its_coding_and_every_vary_line() {
    let probe = encoding_probe(&answered(
        200,
        &[
            ("content-encoding", "BR"),
            ("vary", "Cookie"),
            ("vary", "Accept-Encoding"),
        ],
    ))
    .expect("answered");
    assert_eq!(probe.http_status, 200);
    assert_eq!(probe.encoding.as_deref(), Some("br"));
    assert_eq!(probe.vary, "cookie, accept-encoding");
}

#[test]
fn a_request_with_no_answer_observed_nothing() {
    let failed = crate::probe::ProbeOutcome::Failure(crate::probe::ProbeFailure {
        class: crate::probe::ProbeFailureClass::Timeout,
        detail: "timeout".into(),
    });
    assert!(encoding_probe(&failed).is_none());
}

#[test]
fn a_vary_split_across_lines_still_names_the_coding_on_an_uncompressed_get() {
    let get = encoding_probe(&answered(
        200,
        &[("vary", "Cookie"), ("vary", "Accept-Encoding")],
    ));
    let results = evaluate_compression_get(get, &page_with_encoding(None));
    assert_eq!(results[0].status, CheckStatus::Fail);
    assert!(
        results[0].description.contains("Vary: Accept-Encoding"),
        "{}",
        results[0].description
    );
}

#[test]
fn a_zstd_answer_is_compressed() {
    let probe = encoding_probe(&answered(200, &[("content-encoding", "zstd")]));
    assert!(matches!(
        evaluate_compression_head(probe.as_ref()),
        CompressionStep::Done(_)
    ));
}
