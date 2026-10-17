//! Corpus schema and serialization checks for canonical ids and regressions.

use super::*;
use crate::core::parity_corpus_tests::{assert_printable_corpus, assert_replay_panics_for_case};

#[test]
fn stored_web_ids_resolve_to_themselves() {
    for mapping in SIGNAL_MAPPINGS {
        let chained = SIGNAL_MAPPINGS
            .iter()
            .any(|next| next.source == mapping.source && next.source_signal == mapping.check_id);
        assert!(
            !chained,
            "{} alias {} chains through {}",
            mapping.source, mapping.source_signal, mapping.check_id,
        );
        assert_eq!(
            resolve_check_id("web_scan", mapping.check_id),
            mapping.check_id,
            "{}",
            mapping.check_id
        );
    }
}

#[test]
fn every_alias_case_has_its_regenerated_name() {
    let corpus = corpus();
    for (source, signals) in alias_table() {
        for signal in signals.keys() {
            let case = corpus
                .canonical
                .iter()
                .find(|case| case.source == source && case.signal == *signal)
                .expect("every alias has a case");
            assert_eq!(
                case.name,
                alias_case_name(source, signal),
                "{source} {signal}"
            );
        }
    }
}

#[test]
fn unknown_current_labels_fail_to_load() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
    value["regressions"][0]["current"]["security.csp"] = serde_json::json!("severe");
    let error = match serde_json::from_value::<Corpus>(value) {
        Ok(_) => panic!("unknown current severity must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn missing_nullable_expected_keys_do_not_replay() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
    value["regressions"][2]["expected"]
        .as_object_mut()
        .expect("expected object")
        .remove("regressed")
        .expect("nullable key exists");
    assert_replay_panics_for_case(|| replay(value), "an_unchanged_or_better_check_does_not");
}

#[test]
fn misspelled_keys_fail_to_load() {
    for (pointer, key) in [
        ("", "commment"),
        ("/canonical/0", "sorce"),
        ("/code_issue_ids/0", "issueid"),
        ("/severities/0", "nmae"),
        ("/severities/0/rows/0", "severty"),
        ("/regressions/0", "piror"),
        ("/regressions/0/expected", "regresed"),
    ] {
        let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
        value.pointer_mut(pointer).expect("object exists")[key] = serde_json::Value::Null;
        let error = match serde_json::from_value::<Corpus>(value) {
            Ok(_) => panic!("{key} must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}

#[test]
fn corpora_stay_escaped_and_within_their_file_budgets() {
    for (name, source) in [
        ("work_item_projection.json", CORPUS),
        ("work_item_projection_boundaries.json", BOUNDARIES),
        ("check_aliases.json", ALIASES),
    ] {
        assert_printable_corpus(name, source);
        assert!(
            source.lines().count() < 400,
            "{} lines",
            source.lines().count()
        );
    }
}
