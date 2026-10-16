use super::*;

#[test]
fn valid_utf8_decodes_verbatim() {
    let body = decode_probe_body("Contact: mailto:security@example.com\n".into());
    assert!(body.utf8_valid);
    assert_eq!(body.bytes, 37);
    assert!(body.text.starts_with("Contact:"));
}

#[test]
fn invalid_utf8_decodes_lossily_and_keeps_the_raw_length() {
    let body = decode_probe_body(vec![0x43, 0xFF, 0x44]);
    assert!(!body.utf8_valid);
    assert_eq!(body.bytes, 3);
    assert_eq!(body.text, "C\u{FFFD}D");
}

#[test]
fn html_shell_detected_by_content_type_or_markup() {
    assert!(looks_like_html_shell("text/html; charset=utf-8", ""));
    assert!(looks_like_html_shell(
        "text/plain",
        "  <!DOCTYPE html><html><head></head></html>"
    ));
    assert!(looks_like_html_shell("", "<html lang=\"en\"><body>"));
    assert!(!looks_like_html_shell(
        "text/plain",
        "User-agent: *\nDisallow:\n"
    ));
    assert!(!looks_like_html_shell("", ""));
}

#[test]
fn a_plain_request_writes_no_coding_and_no_timing() {
    let wire = serde_json::to_value(ProbeRequest::get("https://example.com/")).expect("serializes");
    assert!(
        wire.get("coding").is_none() && wire.get("timed").is_none(),
        "{wire}"
    );
}

#[test]
fn a_raw_timed_count_request_reads_back_as_written() {
    let request = ProbeRequest::get("https://example.com/a.png")
        .body(BodyPolicy::Count)
        .coding(ContentCoding::Raw)
        .timed(2);
    let wire = serde_json::to_value(&request).expect("serializes");
    assert_eq!(wire["body"], "count");
    assert_eq!(wire["coding"], "raw");
    assert_eq!(wire["timed"], 2);
    let back: ProbeRequest = serde_json::from_value(wire).expect("parses");
    assert_eq!(back.body, BodyPolicy::Count);
    assert_eq!(back.coding, ContentCoding::Raw);
    assert_eq!(back.timed, Some(2));
}

#[test]
fn a_measure_writes_only_what_was_measured() {
    assert_eq!(
        serde_json::to_value(ProbeMeasure::timed(42)).expect("serializes"),
        serde_json::json!({ "first_byte_ms": 42 })
    );
    assert_eq!(
        serde_json::to_value(ProbeMeasure::counted(10, false)).expect("serializes"),
        serde_json::json!({ "counted_bytes": 10 })
    );
    assert_eq!(
        serde_json::to_value(ProbeMeasure::counted(10, true)).expect("serializes"),
        serde_json::json!({ "counted_bytes": 10, "count_capped": true })
    );
}

#[test]
fn lossy_decoding_matches_standard_text_with_exact_capacity() {
    let mut samples = vec![
        b"User-agent: *\nDisallow: /private".to_vec(),
        br#""quoted" \\ path"#.to_vec(),
        b"first\r\nsecond\nthird\r".to_vec(),
        "caf\u{e9} \u{4e16}\u{754c} \u{1f680}".as_bytes().to_vec(),
        vec![0xff],
        vec![0xe2, 0x82],
        Vec::new(),
    ];
    samples.extend((0..32).map(|byte| vec![byte]));
    samples.push(vec![0xff; 2_097_152]);
    let mut excess_capacity = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        let decoded = decode_probe_body(sample.clone());
        assert_eq!(
            decoded.text,
            String::from_utf8_lossy(sample),
            "sample {index}"
        );
        assert_eq!(decoded.bytes, sample.len(), "sample {index}");
        assert_eq!(
            decoded.utf8_valid,
            std::str::from_utf8(sample).is_ok(),
            "sample {index}"
        );
        if !decoded.utf8_valid && decoded.text.capacity() != decoded.text.len() {
            excess_capacity.push((index, decoded.text.capacity(), decoded.text.len()));
        }
    }
    assert!(
        excess_capacity.is_empty(),
        "sample, capacity, length: {excess_capacity:?}"
    );
}
