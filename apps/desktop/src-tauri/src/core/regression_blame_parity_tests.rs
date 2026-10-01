//! Cross-runtime parity for the regression-blame decision. Connect's port
//! replays these cases from its vendored copy.
//!
//! Regenerate with `cargo test -p sitecmd-runtime --lib core::regression_blame::parity_tests::regenerate -- --ignored`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{decide_blame, BlameAttribution, BlameDecision, BlameInput};
use crate::core::parity_corpus_tests::{assert_printable_corpus, compact_fields, visible_json};

const CORPUS: &str = include_str!("../../tests/fixtures/parity/regression_blame.json");
const CORPUS_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/regression_blame.json"
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
    input: BlameInput,
    unattributable: BTreeSet<String>,
    expected: Option<Expected>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    decision: Option<BlameDecision>,
}

/// Every check except those named by the case may be attributed to the deploy.
struct Withheld<'a>(&'a BTreeSet<String>);

impl BlameAttribution for Withheld<'_> {
    fn attributable(&self, check_id: &str) -> bool {
        !self.0.contains(check_id)
    }
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("regression_blame.json parses")
}

fn decide(case: &Case) -> Expected {
    Expected {
        decision: decide_blame(&case.input, &Withheld(&case.unattributable)),
    }
}

fn replay(value: serde_json::Value) {
    let corpus = serde_json::from_value::<Corpus>(value.clone()).expect("corpus parses");
    assert!(!corpus.cases.is_empty(), "corpus has cases");
    for (case, slot) in corpus.cases.iter().zip(value["cases"].as_array().unwrap()) {
        case.expected.as_ref().unwrap_or_else(|| {
            panic!(
                "case '{}' has no expected block; run the ignored `regenerate` test",
                case.name
            )
        });
        assert_eq!(
            serde_json::to_value(decide(case)).unwrap(),
            slot["expected"],
            "{}",
            case.name
        );
    }
}

#[test]
fn golden_decisions_reproduce() {
    replay(serde_json::from_str(CORPUS).unwrap());
}

#[test]
#[should_panic(expected = "no_listed_commits_blames_nothing")]
fn a_missing_nullable_decision_key_does_not_replay() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][2]["expected"]
        .as_object_mut()
        .unwrap()
        .remove("decision");
    replay(value);
}

#[test]
fn unusual_check_ids_stay_escaped() {
    for escape in [r"\uFFFD.check", r"\uD83D\uDE00.check"] {
        assert!(CORPUS.contains(escape), "{escape}");
    }
    for character in ['\u{fffd}', '\u{1f600}'] {
        assert!(!CORPUS.contains(character), "{character:?}");
    }
}

#[test]
fn corpus_stays_escaped_and_within_its_file_budget() {
    assert_printable_corpus("regression_blame.json", CORPUS);
    assert!(
        CORPUS.lines().count() < 400,
        "{} lines",
        CORPUS.lines().count()
    );
}

#[test]
fn misspelled_keys_fail_to_load() {
    for (pointer, key) in [
        ("", "commment"),
        ("/cases/0", "unattributabl"),
        ("/cases/0/expected", "decison"),
        ("/cases/0/input", "windwo"),
        ("/cases/0/input/window", "newset"),
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
#[ignore]
fn regenerate() {
    let mut value: serde_json::Value =
        serde_json::from_str(CORPUS).expect("regression_blame.json parses");
    let corpus = corpus();
    let slots = value["cases"].as_array_mut().expect("cases array");
    for (slot, case) in slots.iter_mut().zip(&corpus.cases) {
        slot["expected"] = serde_json::to_value(decide(case)).expect("decision serializes");
    }
    let mut rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("corpus serializes")
    );
    // Compact inputs and finding entries keep the corpus within its file budget.
    for slot in value["cases"].as_array().expect("cases array") {
        compact_fields(&mut rendered, slot, &["input", "unattributable"], 6);
        let decision = &slot["expected"]["decision"];
        if !decision.is_null() {
            compact_fields(
                &mut rendered,
                decision,
                &["new_issues", "fixed_check_ids"],
                10,
            );
        }
    }
    std::fs::write(CORPUS_PATH, visible_json(&rendered)).expect("write regression_blame.json");
}
