//! Additional regression-blame inputs for check identity and active findings.

use serde_json::{json, Value};

fn issue(check_id: &str, severity: &str, title: &str) -> Value {
    json!({"check_id": check_id, "severity": severity, "title": title})
}

fn case(name: &str, score: i64, issues: Vec<Value>, active: &[&str], withheld: &[&str]) -> Value {
    json!({
        "name": name,
        "input": {
            "scan_kind": "code", "previous_score": 90, "current_score": score,
            "current_issues": issues, "active_check_ids": active, "engine_release": "1.5.0",
            "window": {
                "newest": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
                "oldest": "0f1e2d3c4b5a69788796a5b4c3d2e1f00a1b2c3d", "listed": 3, "total": 3
            }
        },
        "unattributable": withheld
    })
}

pub(super) fn cases() -> Vec<Value> {
    vec![
        case(
            "prototype_named_checks_keep_their_highest_severity_findings",
            86,
            vec![
                issue("constructor", "low", "Constructor low"),
                issue("constructor", "high", "Constructor high"),
                issue("__proto__", "medium", "Prototype medium"),
                issue("__proto__", "critical", "Prototype critical"),
            ],
            &[],
            &[],
        ),
        case(
            "an_active_check_still_present_is_not_counted_as_fixed",
            80,
            vec![
                issue("code_scan.existing", "high", "Existing finding"),
                issue("code_scan.new", "high", "New finding"),
            ],
            &["code_scan.existing"],
            &[],
        ),
        case(
            "two_new_high_findings_below_five_points_take_the_plural_title",
            86,
            vec![
                issue("code_scan.first", "high", "First finding"),
                issue("code_scan.second", "high", "Second finding"),
            ],
            &[],
            &[],
        ),
        case(
            "two_occurrences_of_one_changed_check_count_as_one_held_back_finding",
            80,
            vec![
                issue("code_scan.new", "high", "New finding"),
                issue("code_scan.changed", "low", "Changed check low"),
                issue("code_scan.changed", "high", "Changed check high"),
            ],
            &[],
            &["code_scan.changed"],
        ),
        case(
            "an_active_changed_check_is_not_counted_as_held_back",
            80,
            vec![
                issue("code_scan.new", "high", "New finding"),
                issue("code_scan.changed", "high", "Existing changed check"),
            ],
            &["code_scan.changed"],
            &["code_scan.changed"],
        ),
        case(
            "a_score_rise_keeps_a_negative_drop_and_names_the_new_high_finding",
            94,
            vec![issue("code_scan.new", "high", "New finding")],
            &[],
            &[],
        ),
    ]
}
