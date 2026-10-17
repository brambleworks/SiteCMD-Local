//! Evaluation answers the document's stack and a severity input for each verdict.

use serde::Deserialize;
use sitecmd_engine::evaluation::{evaluate, EvaluationRequest, PageArtifact};
use sitecmd_engine::severity_policy::WebSeverityInput;
use sitecmd_engine::stack::DetectedStack;

const STACK_CORPUS: &str = include_str!("../fixtures/stack/golden.json");
const CHECKS_CORPUS: &str = include_str!("../fixtures/checks/golden.json");

#[derive(Deserialize)]
struct StackCase {
    name: String,
    page: PageArtifact,
    expected: Option<DetectedStack>,
}

#[derive(Deserialize)]
struct PageCase {
    name: String,
    page: PageArtifact,
}

#[derive(Deserialize)]
struct Cases<T> {
    cases: Vec<T>,
}

fn request(page: PageArtifact) -> EvaluationRequest {
    EvaluationRequest {
        page,
        resolver_facts: None,
        vulnerability_facts: None,
        tls_facts: None,
        probe_outcomes: None,
        browser_facts: None,
    }
}

fn replay_stack(value: serde_json::Value) {
    let slots = value["cases"].as_array().expect("cases array");
    assert!(!slots.is_empty());
    for slot in slots {
        let case: StackCase = serde_json::from_value(slot.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", slot["name"]));
        assert!(
            case.expected.is_some(),
            "{} needs an expected stack",
            case.name
        );
        let response = evaluate(&request(case.page)).expect("corpus pages evaluate");
        assert_eq!(
            serde_json::to_value(response.stack).unwrap(),
            slot["expected"],
            "{}",
            case.name
        );
    }
}

#[test]
fn the_evaluation_answers_the_stack_its_page_shows() {
    replay_stack(serde_json::from_str(STACK_CORPUS).unwrap());
}

#[test]
#[should_panic(expected = "vercel_headers")]
fn removing_a_nullable_server_key_names_the_case() {
    let mut value: serde_json::Value = serde_json::from_str(STACK_CORPUS).unwrap();
    value["cases"][2]["expected"]
        .as_object_mut()
        .unwrap()
        .remove("server");
    replay_stack(value);
}

#[test]
#[should_panic(expected = "wordpress_paths")]
fn null_is_not_an_absent_stack_field() {
    let mut value: serde_json::Value = serde_json::from_str(STACK_CORPUS).unwrap();
    value["cases"][0]["expected"]["server"] = serde_json::Value::Null;
    replay_stack(value);
}

#[test]
fn every_verdict_has_its_severity_input_beside_it() {
    let corpus: Cases<PageCase> =
        serde_json::from_str(CHECKS_CORPUS).expect("checks corpus parses");
    assert!(!corpus.cases.is_empty());
    for case in corpus.cases {
        let response = evaluate(&request(case.page)).expect("corpus pages evaluate");
        assert_eq!(
            response.severity_inputs.len(),
            response.results.len(),
            "{}",
            case.name
        );
        for (input, result) in response.severity_inputs.iter().zip(&response.results) {
            assert_eq!(input, &WebSeverityInput::of(result), "{}", case.name);
        }
    }
}
