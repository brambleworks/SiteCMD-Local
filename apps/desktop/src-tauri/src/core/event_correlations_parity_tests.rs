//! Cross-runtime parity for event correlation. Connect's port replays these
//! cases from its vendored copy.
//!
//! Regenerate with `cargo test -p sitecmd-runtime --lib core::event_correlations::parity_tests::regenerate -- --ignored`.

use serde::{Deserialize, Serialize};

use super::find_correlations;
use crate::core::parity_corpus_tests::{
    assert_printable_corpus, assert_replay_panics_for_case, compact_fields, visible_json,
};
use crate::core::scanner::ScanType;
use crate::db::{EventSeverity, EventSource, EventType, ScanSummary, SiteEvent};

const CORPUS: &str = include_str!("../../tests/fixtures/parity/event_correlations.json");
const BOUNDARIES: &str =
    include_str!("../../tests/fixtures/parity/event_correlations_boundaries.json");
const BOUNDARIES_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/event_correlations_boundaries.json"
);
const CORPUS_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/event_correlations.json"
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    #[allow(dead_code)]
    comment: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    events: Vec<CaseEvent>,
    scans: Vec<CaseScan>,
    expected: Option<Vec<ExpectedCorrelation>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseEvent {
    id: i64,
    event_type: EventType,
    severity: EventSeverity,
    occurred_at_ms: i64,
    title: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseScan {
    id: i64,
    url: String,
    overall_score: u32,
    timestamp: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExpectedCorrelation {
    source_event_id: i64,
    target_event_id: Option<i64>,
    correlation_type: String,
    confidence: String,
    description: String,
    source_timestamp: String,
    target_timestamp: Option<String>,
}

fn correlate(case: &Case) -> serde_json::Value {
    let events: Vec<SiteEvent> = case
        .events
        .iter()
        .map(|event| SiteEvent {
            id: event.id,
            project_id: 1,
            event_type: event.event_type.clone(),
            severity: event.severity.clone(),
            occurred_at_ms: event.occurred_at_ms,
            title: event.title.clone(),
            summary: String::new(),
            detail: None,
            source: EventSource::Internal,
            source_id: None,
            metadata: None,
            affected_check_ids: None,
        })
        .collect();
    let scans: Vec<ScanSummary> = case
        .scans
        .iter()
        .map(|scan| ScanSummary {
            id: scan.id,
            url: scan.url.clone(),
            mode: "full".into(),
            scan_type: ScanType::Health,
            overall_score: scan.overall_score,
            issues_total: 0,
            issues_critical: 0,
            issues_high: 0,
            issues_medium: 0,
            issues_low: 0,
            duration_ms: 0,
            timestamp: scan.timestamp.clone(),
            session_id: None,
            page_url: None,
        })
        .collect();
    serde_json::to_value(find_correlations(&events, &scans)).expect("correlations serialize")
}

fn replay(value: serde_json::Value) {
    let corpus: Corpus = serde_json::from_value(value.clone()).expect("corpus parses");
    assert!(!corpus.cases.is_empty(), "corpus has cases");
    let slots = value["cases"].as_array().expect("cases array");
    for (case, slot) in corpus.cases.iter().zip(slots) {
        if case.expected.is_none() {
            panic!(
                "case '{}' has no expected block; run the ignored `regenerate` test",
                case.name
            );
        }
        // Typed loading validates the schema; raw comparison preserves absent versus null keys.
        assert_eq!(correlate(case), slot["expected"], "{}", case.name);
    }
}

#[test]
fn golden_correlations_reproduce() {
    for source in [CORPUS, BOUNDARIES] {
        replay(serde_json::from_str(source).expect("corpus parses"));
    }
}

#[test]
fn missing_nullable_expected_keys_do_not_replay() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
    value["cases"]
        .as_array_mut()
        .expect("cases array")
        .truncate(1);
    value["cases"][0]["expected"][0]
        .as_object_mut()
        .expect("correlation object")
        .remove("targetEventId")
        .expect("nullable key exists");
    assert_replay_panics_for_case(
        || replay(value),
        "deploy_an_hour_before_a_twenty_point_drop_is_high",
    );
}

#[test]
fn misspelled_keys_fail_to_load() {
    let mut accepted = Vec::new();
    for (pointer, key) in [
        ("", "commment"),
        ("/cases/0", "evnets"),
        ("/cases/0/events/0", "occurred_at_m"),
        ("/cases/0/scans/0", "overall_scor"),
        ("/cases/0/expected/0", "sourceEventID"),
    ] {
        let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
        value.pointer_mut(pointer).expect("object exists")[key] = serde_json::Value::Null;
        match serde_json::from_value::<Corpus>(value) {
            Ok(_) => accepted.push(key),
            Err(error) => assert!(error.to_string().contains("unknown field"), "{error}"),
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted misspelled keys: {accepted:?}"
    );
}

#[test]
fn unusual_title_characters_stay_escaped() {
    let sources = format!("{CORPUS}{BOUNDARIES}");
    for escape in [r"\uFFFD", r"\uD83D\uDE00", r"\uD83D\uDE80"] {
        assert!(sources.contains(escape), "{escape}");
    }
    for character in ['\u{fffd}', '\u{1f600}', '\u{1f680}'] {
        assert!(!sources.contains(character), "{character:?}");
    }
}

#[test]
fn corpora_stay_escaped_and_within_their_file_budgets() {
    for (name, source) in [
        ("event_correlations.json", CORPUS),
        ("event_correlations_boundaries.json", BOUNDARIES),
    ] {
        assert_printable_corpus(name, source);
        assert!(
            source.lines().count() < 400,
            "{} lines",
            source.lines().count()
        );
    }
}

#[test]
#[ignore]
fn regenerate() {
    for (source, path) in [(CORPUS, CORPUS_PATH), (BOUNDARIES, BOUNDARIES_PATH)] {
        let mut value: serde_json::Value = serde_json::from_str(source).expect("corpus parses");
        let corpus: Corpus = serde_json::from_value(value.clone()).expect("corpus parses");
        let slots = value["cases"].as_array_mut().expect("cases array");
        for (slot, case) in slots.iter_mut().zip(&corpus.cases) {
            slot["expected"] = correlate(case);
        }
        let mut rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&value).expect("corpus serializes")
        );
        for slot in value["cases"].as_array().expect("cases array") {
            compact_fields(&mut rendered, slot, &["events", "scans", "expected"], 6);
        }
        // Escape Unicode and non-printable title characters so excerpt boundaries remain visible.
        std::fs::write(path, visible_json(&rendered)).expect("write correlation corpus");
    }
}
