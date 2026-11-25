//! Tests checkout claims and omission of unencodable evidence.

use super::*;

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

#[test]
fn i5_i6_unencodable_pairs_do_not_refuse_the_entire_submission() {
    // One unencodable check ID can refuse all of the site's code evidence.
    let engine = sitecmd_engine_host::load().unwrap();
    let run = RunMaterial {
        execution_id: 1,
        observed_at: 0,
        based_on_event_sequence: 0,
        coverage: ScanCoverageManifest::declared(
            sitecmd_protocol::coverage::ScanCoverageKind::Project,
            Vec::new(),
            vec!["code_scan.bad id".into(), "code_scan.good-id".into()],
        ),
        diagnostics: NormalizedRunDiagnostics::default(),
        stamp: crate::core::engine_release::code_stamp(engine.info(), None),
    };
    let coverage = canonical_coverage(&[&run]);
    assert!(!coverage.complete);
    assert!(coverage.exceptions.iter().any(
        |e| e.reason == sitecmd_protocol::coverage::CoverageExceptionReason::SessionIncomplete
    ));
    assert_eq!(coverage.checks, ["code_scan.good-id"]);
    assert!(serde_json::to_string(&coverage).is_ok());
}

#[test]
fn i5_i6_omit_only_unencodable_occurrences() {
    // A bad check ID can prevent an otherwise valid code finding from being sent.
    let occurrence = |check: &str| ObservedOccurrence {
        identity: super::super::OccurrenceIdentity {
            source: ScanEvidenceSource::CodeScan,
            check_id: check.into(),
            location: OccurrenceLocation::File {
                rule: "hardcoded-secret".into(),
                path: "src/a.ts".into(),
            },
            instance_count: 1,
        },
        severity: sitecmd_protocol::vocab::Severity::High,
        confidence: sitecmd_protocol::vocab::IssueConfidence::Confirmed,
    };
    let key = ProjectFingerprintKey::from_bytes([7; 32]);
    let basis = ConnectedCodeBasis {
        commit_sha: None,
        kind: CodeBasisKind::Unknown,
    };
    let valid = code_occurrence(&occurrence("code_scan.hardcoded-secret"), &key, &basis);
    assert!(valid.is_some());
    assert!(serde_json::to_string(&valid.unwrap()).is_ok());
    assert!(code_occurrence(&occurrence("code_scan.bad id"), &key, &basis).is_none());
}
