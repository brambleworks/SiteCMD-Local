//! Tests payload measurement eligibility and checkout claims.

use super::*;

#[test]
fn browser_ttfb_uses_only_the_preserved_transport_observation() {
    let row = MeasurementRow {
        check_id: "performance.ttfb".into(),
        page_url: Some("https://example.com/".into()),
        raw_data: serde_json::json!({
            "measurement_source": "browser_navigation",
            "transport_ttfb_ms": 1_200,
            "ttfb_ms": 300,
        }),
    };

    assert_eq!(
        connected_measurement(&row),
        Some((1_200.0, MeasurementUnit::Milliseconds))
    );
}

#[test]
fn ttfb_without_provenance_is_not_guessed_into_the_transport_series() {
    let row = MeasurementRow {
        check_id: "performance.ttfb".into(),
        page_url: Some("https://example.com/".into()),
        raw_data: serde_json::json!({ "ttfb_ms": 1_200 }),
    };

    assert_eq!(connected_measurement(&row), None);
}

#[test]
fn a_stored_stack_without_other_labels_still_names_its_framework() {
    let run = RunMaterial {
        run_kind: ScanRunKind::Single,
        started_at: 0,
        coverage: ScanCoverageManifest {
            kind: ScanCoverageKind::Site,
            successful: true,
            page_urls: Vec::new(),
            checks: Vec::new(),
            exceptions: Vec::new(),
        },
        diagnostics: NormalizedRunDiagnostics {
            detected_stack: Some(r#"{"framework":"Next.js"}"#.into()),
            ..NormalizedRunDiagnostics::default()
        },
        stamp: sitecmd_engine::release::ReleaseStamp::current(
            "1.5.0",
            sitecmd_engine::release::ExecutionProfile::default(),
        ),
        measurements: Vec::new(),
        web_occurrence_keys: BTreeSet::new(),
    };
    assert_eq!(
        stack_facts(&[&run]),
        Some(StackFacts {
            framework: Some("Next.js".into()),
            framework_version: None
        })
    );
}

// The full SHA a clean checkout observes, and the abbreviations a pipeline
// legitimately states for it.
const OBSERVED_SHA: &str = "c0ffee1deadbeef0123456789abcdef012345678";

#[test]
fn an_abbreviated_commit_still_names_the_checkout_it_abbreviates() {
    assert!(names_the_same_commit("c0ffee1", OBSERVED_SHA));
    assert!(names_the_same_commit("c0ffee1deadbeef", OBSERVED_SHA));
    // Providers differ on case; hex does not.
    assert!(names_the_same_commit("C0FFEE1", OBSERVED_SHA));
}

#[test]
fn a_full_commit_still_names_the_checkout_it_equals() {
    assert!(names_the_same_commit(OBSERVED_SHA, OBSERVED_SHA));
    // Equality answers first and answers alone, so the abbreviation floor
    // below can never take back a checkout the stated commit exactly names.
    assert!(names_the_same_commit("abc123", "abc123"));
}

#[test]
fn a_different_commit_is_never_read_as_the_checkout() {
    assert!(!names_the_same_commit("c0ffee2", OBSERVED_SHA));
    assert!(!names_the_same_commit("deadbee", OBSERVED_SHA));
    assert!(!names_the_same_commit("c0ffee", OBSERVED_SHA));
    // The stated commit is longer than what was observed, so it cannot be an
    // abbreviation of it.
    assert!(!names_the_same_commit(
        &format!("{OBSERVED_SHA}0"),
        OBSERVED_SHA
    ));
    assert!(!names_the_same_commit("not-a-sha", OBSERVED_SHA));
}
