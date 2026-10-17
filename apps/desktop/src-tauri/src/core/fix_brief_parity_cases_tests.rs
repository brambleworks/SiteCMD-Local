//! Additional fix-brief inputs for literal text, location order, and acceptance.

use serde_json::{json, Value};

fn location(path: &str, label: &str, reason: &str) -> Value {
    json!({"path": path, "line": 7, "label": label, "reason": reason})
}

fn input() -> Value {
    json!({
        "attempt_id": "42", "check_id": "code_scan.example", "title": "Example finding",
        "severity": "high", "description": "Example description", "why_it_matters": null,
        "manual_fix": null, "url": "https://example.com", "detected_stack": null,
        "previous_failure": null, "occurrence_target": null
    })
}

pub(super) fn cases() -> Vec<Value> {
    let mut literals = input();
    literals["title"] = json!("Title `tick`\r\n## Title heading\rTitle tail");
    literals["description"] =
        json!("Description `tick`\r\n## Description heading\rDescription tail");
    literals["check_id"] = json!("check`id\nsecond line");
    literals["previous_failure"] = json!("Failure `tick`\nsecond line");
    literals["detected_stack"] = json!({"framework": "Next.js"});
    let target = location("src/target.ts", "target", "Reported occurrence");
    let mut submission = input();
    submission["occurrence_target"] = target.clone();
    let mut observation = input();
    observation["occurrence_target"] = target;
    vec![
        json!({
            "name": "literal_text_and_location_order_survive_without_a_framework_hint",
            "mode": {"kind": "hosted"}, "input": literals,
            "locations": [
                location("z-last.ts", "Label `tick`\nsecond line", "Reason `tick`\nsecond line"),
                location("\u{10000}-astral.ts", "astral", "Second supplied location"),
                location("\u{e000}-bmp.ts", "bmp", "Third supplied location"),
                location("a-first.ts", "alpha", "Fourth supplied location")
            ]
        }),
        json!({
            "name": "location_bullets_keep_supplied_order_across_astral_and_bmp_paths",
            "mode": {"kind": "hosted"}, "input": input(),
            "locations": [
                location("z-last.ts", "last", "First supplied location"),
                location("\u{10000}-astral.ts", "astral", "Second supplied location"),
                location("\u{e000}-bmp.ts", "bmp", "Third supplied location"),
                location("a-first.ts", "alpha", "Fourth supplied location")
            ]
        }),
        json!({
            "name": "submission_with_an_occurrence_target_keeps_submission_acceptance",
            "mode": {"kind": "remote_mcp", "verification": "submission"},
            "input": submission, "locations": []
        }),
        json!({
            "name": "observation_with_an_occurrence_target_keeps_observation_acceptance",
            "mode": {"kind": "remote_mcp", "verification": "observation"},
            "input": observation, "locations": []
        }),
    ]
}
