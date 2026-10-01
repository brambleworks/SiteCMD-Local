//! Cross-runtime parity for canonical check ids and regression comparisons.
//! Canonicalization takes producer signals and issue ids.
//!
//! Regenerate with `cargo test -p sitecmd-runtime --lib core::work_item_projection::parity_tests::regenerate -- --ignored`.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::{current_web_severities, regressed_check_ids};
use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};
use crate::core::code_scan::canonical_code_check_id;
use crate::core::correlation::resolve_check_id;
use crate::core::correlation::signal_mapping::{SignalMapping, SIGNAL_MAPPINGS};
#[path = "work_item_projection_corpus_tests.rs"]
mod corpus_tests;

use crate::core::parity_corpus_tests::{compact_fields, visible_json};

const CORPUS: &str = include_str!("../../tests/fixtures/parity/work_item_projection.json");
const BOUNDARIES: &str =
    include_str!("../../tests/fixtures/parity/work_item_projection_boundaries.json");
const ALIASES: &str = include_str!("../../tests/fixtures/parity/check_aliases.json");
const CORPUS_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/work_item_projection.json"
);
const BOUNDARIES_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/work_item_projection_boundaries.json"
);
const ALIASES_PATH: &str = concat!(
    env!("SITECMD_SOURCE_ROOT"),
    "/tests/fixtures/parity/check_aliases.json"
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    #[allow(dead_code)]
    comment: String,
    canonical: Vec<CanonicalCase>,
    code_issue_ids: Vec<CodeIdCase>,
    severities: Vec<SeverityCase>,
    regressions: Vec<RegressionCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCase {
    name: String,
    source: String,
    signal: String,
    expected: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeIdCase {
    name: String,
    issue_id: String,
    expected: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeverityCase {
    name: String,
    rows: Vec<Row>,
    expected: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    check_id: String,
    status: CheckStatus,
    severity: Severity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegressionCase {
    name: String,
    current: BTreeMap<String, Severity>,
    prior: BTreeMap<String, String>,
    expected: Option<Regressed>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Regressed {
    regressed: Option<Vec<String>>,
}

type AliasTable = BTreeMap<&'static str, BTreeMap<&'static str, &'static str>>;

fn alias_table_from(mappings: &[SignalMapping]) -> AliasTable {
    let mut table = BTreeMap::from([
        ("code_scan", BTreeMap::new()),
        ("web_scan", BTreeMap::new()),
    ]);
    for mapping in mappings {
        if let Some(signals) = table.get_mut(mapping.source) {
            signals
                .entry(mapping.source_signal)
                .or_insert(mapping.check_id);
        }
    }
    table
}

fn alias_table() -> AliasTable {
    alias_table_from(SIGNAL_MAPPINGS)
}

fn alias_case_name(source: &str, signal: &str) -> String {
    let signal: String = signal
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{source}_{signal}_uses_its_canonical_alias")
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("work_item_projection.json parses")
}

fn severities(case: &SeverityCase) -> BTreeMap<String, String> {
    let results: Vec<CheckResult> = case
        .rows
        .iter()
        .map(|row| CheckResult {
            check_id: row.check_id.clone(),
            category: ScanCategory::Seo,
            title: String::new(),
            description: String::new(),
            status: row.status,
            severity: row.severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        })
        .collect();
    current_web_severities(&results)
        .into_iter()
        .map(|(id, label)| (id, label.to_string()))
        .collect()
}

fn regressed(case: &RegressionCase) -> Regressed {
    let current: HashMap<String, &'static str> = case
        .current
        .iter()
        .map(|(id, severity)| (id.clone(), severity.as_str()))
        .collect();
    let prior: HashMap<String, String> = case.prior.clone().into_iter().collect();
    Regressed {
        regressed: regressed_check_ids(&current, &prior),
    }
}

fn compare<T>(actual: impl Serialize, expected: &Option<T>, slot: &serde_json::Value, name: &str) {
    assert!(expected.is_some(), "{name} needs regeneration");
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        slot["expected"],
        "{name}"
    );
}

fn replay(value: serde_json::Value) {
    let corpus: Corpus = serde_json::from_value(value.clone()).expect("corpus parses");
    for (case, slot) in corpus
        .canonical
        .iter()
        .zip(value["canonical"].as_array().unwrap())
    {
        compare(
            resolve_check_id(&case.source, &case.signal),
            &case.expected,
            slot,
            &case.name,
        );
    }
    for (case, slot) in corpus
        .code_issue_ids
        .iter()
        .zip(value["code_issue_ids"].as_array().unwrap())
    {
        compare(
            canonical_code_check_id(&case.issue_id),
            &case.expected,
            slot,
            &case.name,
        );
    }
    for (case, slot) in corpus
        .severities
        .iter()
        .zip(value["severities"].as_array().unwrap())
    {
        compare(severities(case), &case.expected, slot, &case.name);
    }
    for (case, slot) in corpus
        .regressions
        .iter()
        .zip(value["regressions"].as_array().unwrap())
    {
        compare(regressed(case), &case.expected, slot, &case.name);
    }
}

#[test]
fn the_alias_file_is_the_signal_table() {
    let file: serde_json::Value = serde_json::from_str(ALIASES).expect("check_aliases.json parses");
    assert_eq!(
        file,
        serde_json::to_value(alias_table()).unwrap(),
        "run the ignored `regenerate` test"
    );
}

#[test]
fn every_alias_has_a_canonical_case() {
    let corpus = corpus();
    let aliases: BTreeMap<String, BTreeMap<String, String>> =
        serde_json::from_str(ALIASES).expect("aliases parse");
    for (source, signals) in aliases {
        for (signal, canonical) in signals {
            assert_eq!(
                resolve_check_id(&source, &signal),
                canonical,
                "{source} {signal}"
            );
            assert!(
                corpus
                    .canonical
                    .iter()
                    .any(|case| case.source == source && case.signal == signal),
                "{source} {signal} has no canonical case; run the ignored `regenerate` test"
            );
        }
    }
}

#[test]
fn duplicate_aliases_keep_the_first_mapping_per_source() {
    let mappings = [
        SignalMapping {
            source: "web_scan",
            source_signal: "same",
            check_id: "first",
        },
        SignalMapping {
            source: "web_scan",
            source_signal: "same",
            check_id: "last",
        },
        SignalMapping {
            source: "code_scan",
            source_signal: "same",
            check_id: "code",
        },
        SignalMapping {
            source: "psi",
            source_signal: "outside",
            check_id: "excluded",
        },
    ];
    let table = alias_table_from(&mappings);
    assert_eq!(
        table,
        BTreeMap::from([
            ("code_scan", BTreeMap::from([("same", "code")])),
            ("web_scan", BTreeMap::from([("same", "first")])),
        ])
    );
}

#[test]
fn golden_projection_cases_reproduce() {
    for source in [CORPUS, BOUNDARIES] {
        replay(serde_json::from_str(source).expect("corpus parses"));
    }
}

fn fill(value: &mut serde_json::Value) {
    let corpus: Corpus = serde_json::from_value(value.clone()).expect("corpus parses");
    for (slot, case) in value["canonical"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(&corpus.canonical)
    {
        slot["expected"] = serde_json::json!(resolve_check_id(&case.source, &case.signal));
    }
    for (slot, case) in value["code_issue_ids"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(&corpus.code_issue_ids)
    {
        slot["expected"] = serde_json::json!(canonical_code_check_id(&case.issue_id));
    }
    for (slot, case) in value["severities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(&corpus.severities)
    {
        slot["expected"] = serde_json::to_value(severities(case)).unwrap();
    }
    for (slot, case) in value["regressions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(&corpus.regressions)
    {
        slot["expected"] = serde_json::to_value(regressed(case)).unwrap();
    }
}

fn write_corpus(value: &serde_json::Value, path: &str) {
    let mut rendered = format!("{}\n", serde_json::to_string_pretty(value).unwrap());
    for slot in value["severities"].as_array().unwrap() {
        compact_fields(&mut rendered, slot, &["rows", "expected"], 6);
    }
    for slot in value["regressions"].as_array().unwrap() {
        compact_fields(&mut rendered, slot, &["current", "prior", "expected"], 6);
    }
    std::fs::write(path, visible_json(&rendered)).expect("write corpus");
}

#[test]
#[ignore]
fn regenerate() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("corpus parses");
    for (source, signals) in alias_table() {
        for signal in signals.keys() {
            let cases = value["canonical"].as_array_mut().unwrap();
            if !cases
                .iter()
                .any(|case| case["source"] == source && case["signal"] == *signal)
            {
                cases.push(
                    serde_json::json!({ "name": alias_case_name(source, signal), "source": source, "signal": signal, "expected": null }),
                );
            }
        }
    }
    fill(&mut value);
    write_corpus(&value, CORPUS_PATH);
    let mut boundaries: serde_json::Value =
        serde_json::from_str(BOUNDARIES).expect("corpus parses");
    fill(&mut boundaries);
    write_corpus(&boundaries, BOUNDARIES_PATH);
    let aliases = format!(
        "{}\n",
        serde_json::to_string_pretty(&alias_table()).unwrap()
    );
    std::fs::write(ALIASES_PATH, visible_json(&aliases)).expect("write check_aliases.json");
}
