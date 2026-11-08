//! Build a page from each case's body and URL, answer each planned probe with
//! the case's recorded response for that final URL or a 404, and stop after
//! 24 rounds.

use serde_json::{json, Value};
use sitecmd_engine::evaluation::{probe_key, ExecutedProbe, PageArtifact, RouteSession};
use sitecmd_engine::probe::{ProbeOutcome, ProbeResponse};

fn outcomes(value: &Value, answers: &mut Vec<ProbeOutcome>) {
    if let Ok(answer) = serde_json::from_value::<ProbeOutcome>(value.clone()) {
        answers.push(answer);
    } else {
        match value {
            Value::Object(fields) => fields.values().for_each(|v| outcomes(v, answers)),
            Value::Array(items) => items.iter().for_each(|v| outcomes(v, answers)),
            _ => {}
        }
    }
}

pub fn probe_corpus_keys(corpus: &str) -> Vec<Value> {
    let corpus: Value = serde_json::from_str(corpus).expect("probe corpus");
    corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(case_rounds)
        .collect()
}

fn case_rounds(case: &Value) -> Value {
    let input = &case["input"];
    let url = input["page_url"]
        .as_str()
        .or(input["base"].as_str())
        .unwrap_or("https://example.com/");
    let page: PageArtifact = serde_json::from_value(json!({
        "url": url,
        "requested_url": input["start_url"].as_str(),
        "status_code": 200,
        "headers": [],
        "body": input["page_body"].as_str().or(input["body"].as_str()).unwrap_or(""),
        "is_localhost": input["page_is_local"].as_bool().unwrap_or(false),
        "evaluation_time": input["evaluation_time"].as_str().unwrap_or("2026-10-30T00:00:00Z")
    }))
    .expect("corpus page");
    let mut route = RouteSession::open(page).expect("route");
    let mut answers = Vec::new();
    outcomes(input, &mut answers);
    let mut rounds = Vec::new();
    for _ in 0..24 {
        let probes = route.plan().probes;
        if probes.is_empty() {
            return json!({"name": case["name"], "rounds": rounds});
        }
        rounds.push(
            probes
                .iter()
                .map(|probe| {
                    assert_eq!(probe.key, probe_key(&probe.request));
                    json!({
                        "key": probe.key,
                        "request": serde_json::to_string(&probe.request).expect("request bytes")
                    })
                })
                .collect::<Vec<_>>(),
        );
        route.record(Some(
            probes
                .into_iter()
                .map(|probe| {
                    let outcome = answers
                        .iter()
                        .find(|answer| {
                            matches!(answer,
                                ProbeOutcome::Response(response)
                                    if response.final_url == probe.request.url
                            )
                        })
                        .cloned()
                        .unwrap_or_else(|| {
                            ProbeOutcome::Response(ProbeResponse {
                                status: 404,
                                final_url: probe.request.url,
                                content_type: None,
                                content_length: None,
                                headers: Vec::new(),
                                body: None,
                            })
                        });
                    ExecutedProbe::new(probe.key, outcome)
                })
                .collect(),
        ));
    }
    panic!("{}: probes did not finish", case["name"]);
}
