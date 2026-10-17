//! Cross-runtime parity for the fix brief. Connect's renderer replays these
//! cases, so the issue body the publish job renders here and the briefs
//! Connect renders cannot drift.
//!
//! Regenerate with `cargo test -p sitecmd-runtime --lib core::fix_brief::parity_tests::regenerate -- --ignored`.

use serde::Deserialize;

use super::{build_fix_brief_with_mode, BriefLocation, BriefMode, FixBriefInput, VerificationPath};
use crate::checks::Severity;
use crate::core::parity_corpus_tests::{
    assert_inputs_match_corpus, assert_printable_corpus, compact_fields, reset_inputs, visible_json,
};

#[path = "fix_brief_parity_cases_tests.rs"]
mod inputs;

const CORPUS: &str = include_str!("../../tests/fixtures/parity/fix_brief.json");
const CORPUS_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/fix_brief.json"
);
const BOUNDARIES: &str = include_str!("../../tests/fixtures/parity/fix_brief_boundaries.json");
const BOUNDARIES_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/fix_brief_boundaries.json"
);
const BOUNDARIES_COMMENT: &str = concat!(
    "Expected strings are written only by src/core/fix_brief_parity_tests.rs through its ignored regenerate test.",
    " fix_brief_boundaries.json holds literal text, location order and acceptance cases, with inputs written from src/core/fix_brief_parity_cases_tests.rs."
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
    mode: CaseMode,
    input: CaseInput,
    locations: Vec<BriefLocation>,
    expected: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CaseMode {
    Hosted {},
    RemoteMcp { verification: VerificationPath },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    attempt_id: String,
    check_id: String,
    title: String,
    severity: Severity,
    description: String,
    why_it_matters: Option<String>,
    manual_fix: Option<String>,
    url: String,
    detected_stack: Option<serde_json::Value>,
    previous_failure: Option<String>,
    occurrence_target: Option<BriefLocation>,
}

fn render(case: &Case) -> String {
    let input = FixBriefInput {
        attempt_id: case.input.attempt_id.clone(),
        check_id: case.input.check_id.clone(),
        title: case.input.title.clone(),
        severity: case.input.severity,
        description: case.input.description.clone(),
        why_it_matters: case.input.why_it_matters.clone(),
        // Connect keeps no raw evidence, so no parity case carries any.
        evidence: None,
        manual_fix: case.input.manual_fix.clone(),
        url: case.input.url.clone(),
        detected_stack: case.input.detected_stack.clone(),
        previous_failure: case.input.previous_failure.clone(),
        occurrence_target: case.input.occurrence_target.clone(),
    };
    let mode = match &case.mode {
        CaseMode::Hosted {} => BriefMode::Hosted,
        CaseMode::RemoteMcp { verification } => BriefMode::RemoteMcp(*verification),
    };
    build_fix_brief_with_mode(&input, &case.locations, mode)
}

#[test]
fn golden_briefs_reproduce_their_text() {
    for source in [CORPUS, BOUNDARIES] {
        let value: serde_json::Value = serde_json::from_str(source).expect("corpus parses");
        let corpus: Corpus = serde_json::from_value(value.clone()).expect("corpus parses");
        assert!(!corpus.cases.is_empty(), "corpus has cases");
        for (case, slot) in corpus
            .cases
            .iter()
            .zip(value["cases"].as_array().expect("cases array"))
        {
            case.expected.as_ref().unwrap_or_else(|| {
                panic!(
                    "case '{}' has no expected brief; run the ignored `regenerate` test",
                    case.name
                )
            });
            assert_eq!(
                serde_json::json!(render(case)),
                slot["expected"],
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn remote_acceptance_criteria_match_the_verification_path() {
    let corpora = [CORPUS, BOUNDARIES]
        .map(|source| serde_json::from_str::<Corpus>(source).expect("corpus parses"));
    for case in corpora.iter().flat_map(|corpus| &corpus.cases) {
        let CaseMode::RemoteMcp { verification } = case.mode else {
            continue;
        };
        let brief = render(case);
        let criteria = brief
            .split("\n## Acceptance criteria\n\n")
            .nth(1)
            .expect("acceptance criteria")
            .split("\n## When you are done")
            .next()
            .unwrap();
        match verification {
            VerificationPath::Submission => {
                assert!(
                    criteria.contains(&format!(
                    "SiteCMD accepts the fix when an authenticated code submission bound to this \
                     attempt, from your CI or the SiteCMD CLI, no longer reports the `{}` finding.",
                    case.input.check_id
                )),
                    "{}: {criteria}",
                    case.name
                );
                assert!(
                    criteria.contains("records the result as self-attested"),
                    "{criteria}"
                );
                assert!(!criteria.contains("re-run"), "{criteria}");
            }
            VerificationPath::Observation => {
                assert!(
                    criteria.contains(&format!(
                    "SiteCMD accepts the fix only once visitors' page loads under a build of the \
                     commit that carries the fix no longer raise the `{}` finding.",
                    case.input.check_id
                )),
                    "{}: {criteria}",
                    case.name
                );
                assert!(
                    criteria.contains("A clean audit does not count."),
                    "{criteria}"
                );
                assert!(!criteria.contains("re-run"), "{criteria}");
            }
            VerificationPath::TargetedScan => {
                assert!(criteria.contains("SiteCMD will re-run"), "{criteria}");
            }
        }
    }
}

#[test]
fn invisible_excerpt_characters_are_visible_in_the_corpus() {
    for excerpt in [r"\u00A0\u2003\t", r"\u0085", r"\uFEFF"] {
        assert!(CORPUS.contains(&format!("\"{excerpt}\"")), "{excerpt}");
    }
}

#[test]
fn corpora_stay_escaped_and_within_their_file_budgets() {
    for (name, source) in [
        ("fix_brief.json", CORPUS),
        ("fix_brief_boundaries.json", BOUNDARIES),
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
fn misspelled_keys_fail_to_load() {
    for source in [CORPUS, BOUNDARIES] {
        for (pointer, key) in [
            ("", "commment"),
            ("/cases/0", "loactions"),
            ("/cases/0/input", "checkid"),
            ("/cases/0/mode", "verification"),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(source).expect("corpus parses");
            value.pointer_mut(pointer).expect("object exists")[key] = serde_json::Value::Null;
            let error = match serde_json::from_value::<Corpus>(value) {
                Ok(_) => panic!("{key} must be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
        let value: serde_json::Value = serde_json::from_str(source).expect("corpus parses");
        for mut case in value["cases"]
            .as_array()
            .expect("cases array")
            .iter()
            .cloned()
        {
            case["mode"]["verificaton"] = serde_json::Value::Null;
            let error = match serde_json::from_value::<Case>(case) {
                Ok(_) => panic!("verificaton must be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }
}

#[test]
fn rust_inputs_match_their_corpora() {
    assert_inputs_match_corpus(CORPUS, Vec::new());
    assert_inputs_match_corpus(BOUNDARIES, inputs::cases());
}

#[test]
#[ignore]
fn regenerate() {
    for (source, path, inputs) in [
        (CORPUS, CORPUS_PATH, Vec::new()),
        (BOUNDARIES, BOUNDARIES_PATH, inputs::cases()),
    ] {
        let mut value: serde_json::Value = serde_json::from_str(source).expect("corpus parses");
        reset_inputs(&mut value, inputs);
        if path == BOUNDARIES_PATH {
            value["comment"] = serde_json::json!(BOUNDARIES_COMMENT);
        }
        let corpus: Corpus = serde_json::from_value(value.clone()).expect("corpus parses");
        let slots = value["cases"].as_array_mut().expect("cases array");
        for (slot, case) in slots.iter_mut().zip(&corpus.cases) {
            slot["expected"] = serde_json::Value::String(render(case));
        }
        let mut rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&value).expect("corpus serializes")
        );
        // Pretty inputs and compact metadata keep the corpus within its file budget.
        for slot in value["cases"].as_array().expect("cases array") {
            compact_fields(&mut rendered, slot, &["mode", "locations"], 6);
        }
        std::fs::write(path, visible_json(&rendered)).expect("write brief corpus");
    }
}
