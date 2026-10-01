//! Cross-runtime severity fixtures: the engine's policy, pinned case by case.
//! Connect replays the same corpus through the scorer artifact.
//!
//! Regenerate with `cargo test -p sitecmd-engine --test golden_severity -- --ignored regenerate`.

use serde::Deserialize;
use sitecmd_engine::severity_policy::{apply, SeverityAnswer, SeverityRequest, WebSeverityInput};
use sitecmd_engine::vocab::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

const CORPUS: &str = include_str!("../fixtures/severity/golden.json");

#[derive(Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    comment: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    request: SeverityRequest,
    expected: Option<SeverityAnswer>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("golden.json parses")
}

fn answer(name: &str) -> SeverityAnswer {
    let corpus = corpus();
    let case = corpus
        .cases
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("case '{name}' present"));
    apply(&case.request)
}

fn replay(value: serde_json::Value) {
    let slots = value["cases"].as_array().expect("cases array");
    assert!(!slots.is_empty(), "corpus has cases");
    for slot in slots {
        let case: Case = serde_json::from_value(slot.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", slot["name"]));
        case.expected.as_ref().unwrap_or_else(|| {
            panic!(
                "case '{}' has no expected block; run the ignored `regenerate` test",
                case.name
            )
        });
        assert_eq!(
            serde_json::to_value(apply(&case.request)).unwrap(),
            slot["expected"],
            "{}",
            case.name
        );
    }
    let _: Corpus = serde_json::from_value(value).expect("corpus parses");
}

#[test]
fn golden_cases_reproduce_their_answers() {
    replay(serde_json::from_str(CORPUS).unwrap());
}

#[test]
fn headline_grades_match_the_policy() {
    use Severity::{Critical, High, Low, Medium};
    assert_eq!(answer("pass_and_skipped_rows_are_low").web, vec![Low, Low]);
    assert_eq!(
        answer("critical_survives_only_where_the_policy_allows_it").web,
        vec![Critical, High, Critical]
    );
    assert_eq!(
        answer("a_warn_never_carries_critical").web,
        vec![Medium, High]
    );
    assert_eq!(
        answer("broken_links_escalate_at_three").web,
        vec![High, Medium, Medium]
    );
    assert_eq!(
        answer("polish_and_axe_signals_take_their_own_grades").web,
        vec![Medium, Medium, Low, High]
    );
    assert_eq!(
        answer("fixed_grades_replace_the_emitted_one").web,
        vec![Medium, Low, Low, Medium]
    );
    assert_eq!(
        answer("an_unknown_web_check_keeps_its_grade_below_critical").web,
        vec![High, High]
    );
    assert_eq!(
        answer("code_rules_take_their_registered_policy").code,
        vec![Critical, High, Medium, Low, Medium]
    );
    assert_eq!(
        answer("an_unregistered_code_rule_passes_through_below_critical").code,
        vec![High, Medium, Critical]
    );
    assert_eq!(
        answer("meta_conflicts_keep_high_and_raise_low_to_medium").web,
        vec![High, Medium]
    );
    assert_eq!(
        answer("axe_findings_keep_medium_and_low").web,
        vec![Medium, Low]
    );
    assert_eq!(
        answer("risk_rules_without_a_fixed_grade_keep_the_emitted_severity_below_critical").code,
        vec![High, Medium, Low]
    );
}

#[test]
fn the_input_carries_a_broken_link_count_only_for_broken_links() {
    let result = |check_id: &str| CheckResult {
        check_id: check_id.to_string(),
        category: ScanCategory::Seo,
        title: String::new(),
        description: String::new(),
        status: CheckStatus::Fail,
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({ "broken": [1, 2, 3, 4] })),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    };
    assert_eq!(
        WebSeverityInput::of(&result("seo.broken_links")).broken_count,
        Some(4)
    );
    assert_eq!(
        WebSeverityInput::of(&result("seo.title")).broken_count,
        None
    );
}

#[test]
fn requests_default_to_empty_collections() {
    let request: SeverityRequest = serde_json::from_str("{}").unwrap();
    assert!(request.web.is_empty());
    assert!(request.code.is_empty());
    assert_eq!(
        serde_json::to_value(apply(&request)).unwrap(),
        serde_json::json!({ "web": [], "code": [] })
    );
}

#[test]
fn requests_reject_unknown_fields_at_every_input_boundary() {
    for value in [
        serde_json::json!({ "extra": true }),
        serde_json::json!({ "web": [{ "check_id": "seo.title", "status": "fail", "severity": "high", "raw_data": {} }] }),
        serde_json::json!({ "code": [{ "rule": "dependency-advisory", "severity": "medium", "path": "app.ts" }] }),
    ] {
        let error = serde_json::from_value::<SeverityRequest>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}

#[test]
fn requests_reject_unknown_vocabulary_and_out_of_range_counts() {
    for value in [
        serde_json::json!({ "web": [{ "check_id": "seo.title", "status": "unknown", "severity": "high" }] }),
        serde_json::json!({ "web": [{ "check_id": "seo.title", "status": "fail", "severity": "unknown" }] }),
        serde_json::json!({ "code": [{ "rule": "dependency-advisory", "severity": "unknown" }] }),
    ] {
        assert!(serde_json::from_value::<SeverityRequest>(value).is_err());
    }
    for count in [
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(4294967296_u64),
        serde_json::json!("3"),
    ] {
        let value = serde_json::json!({ "check_id": "seo.broken_links", "status": "fail", "severity": "medium", "broken_count": count });
        assert!(serde_json::from_value::<WebSeverityInput>(value).is_err());
    }
    for count in [0, u32::MAX] {
        let value = serde_json::json!({ "check_id": "seo.broken_links", "status": "fail", "severity": "medium", "broken_count": count });
        let input: WebSeverityInput = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(input.broken_count, Some(count));
        assert_eq!(serde_json::to_value(input).unwrap(), value);
    }
}

#[test]
#[ignore]
fn regenerate() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).expect("golden.json parses");
    let corpus = corpus();
    let slots = value["cases"].as_array_mut().expect("cases array");
    for (slot, case) in slots.iter_mut().zip(&corpus.cases) {
        slot["expected"] = serde_json::to_value(apply(&case.request)).expect("answer serializes");
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/severity/golden.json");
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("corpus serializes")
    );
    std::fs::write(path, rendered).expect("write golden.json");
}

#[test]
#[should_panic(expected = "pass_and_skipped_rows_are_low")]
fn missing_answer_keys_name_the_case() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][0]["expected"]
        .as_object_mut()
        .unwrap()
        .remove("code");
    replay(value);
}

#[test]
#[should_panic(expected = "pass_and_skipped_rows_are_low")]
fn an_extra_null_answer_member_does_not_replay() {
    let mut value: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    value["cases"][0]["expected"]["extra"] = serde_json::Value::Null;
    replay(value);
}
