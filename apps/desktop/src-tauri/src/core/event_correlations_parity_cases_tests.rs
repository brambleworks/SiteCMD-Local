//! Additional event-correlation inputs with precision and direction boundaries.

use serde_json::{json, Value};

fn event(id: i64, kind: &str, severity: &str, timestamp: &str, title: &str) -> Value {
    json!({
        "id": id, "event_type": kind, "severity": severity, "title": title,
        "occurred_at_ms": chrono::DateTime::parse_from_rfc3339(timestamp)
            .expect("event timestamp parses").timestamp_millis()
    })
}

fn scan(id: i64, score: u32, timestamp: &str, url: &str) -> Value {
    json!({"id": id, "overall_score": score, "timestamp": timestamp, "url": url})
}

fn pair(name: &str, event: Value, timestamp: &str, newer: u32, older: u32) -> Value {
    json!({
        "name": name, "events": [event], "scans": [
            scan(2, newer, timestamp, "https://example.com"),
            scan(1, older, "2023-12-31T11:00:00Z", "https://example.com")
        ]
    })
}

fn deploy_pair(name: &str, deploy: &str, timestamp: &str, newer: u32, older: u32) -> Value {
    pair(
        name,
        event(1, "deploy", "info", deploy, "v1.2.3 deployed"),
        timestamp,
        newer,
        older,
    )
}

pub(super) fn boundaries() -> Vec<Value> {
    let precise_scan = "2024-01-01T13:00:00.0000005Z";
    vec![
        deploy_pair(
            "a_drop_two_hours_and_five_hundred_nanoseconds_is_medium",
            "2024-01-01T11:00:00Z",
            precise_scan,
            70,
            90,
        ),
        deploy_pair(
            "a_drop_twenty_four_hours_and_five_hundred_nanoseconds_does_not_correlate",
            "2023-12-31T13:00:00Z",
            precise_scan,
            70,
            90,
        ),
        pair(
            "an_anomaly_five_hundred_nanoseconds_before_thirteen_hours_is_medium",
            event(
                2,
                "analytics",
                "warning",
                "2024-01-02T02:00:00Z",
                "Traffic anomaly",
            ),
            precise_scan,
            70,
            90,
        ),
        json!({
            "name": "submillisecond_scan_times_choose_the_newer_scan_over_the_lower_id",
            "events": [event(1, "deploy", "info", "2024-01-01T12:00:00Z", "v1.2.3 deployed")],
            "scans": [
                scan(2, 70, "2024-01-01T13:00:00.0000001Z", "https://example.com"),
                scan(9, 60, "2024-01-01T13:00:00.0000009Z", "https://other.example.com"),
                scan(1, 90, "2024-01-01T11:00:00Z", "https://example.com"),
                scan(8, 90, "2024-01-01T11:00:00Z", "https://other.example.com")
            ]
        }),
        deploy_pair(
            "a_unicode_minus_offset_is_read_as_thirteen_hundred_utc",
            "2024-01-01T12:00:00Z",
            "2024-01-01T11:00:00\u{2212}02:00",
            70,
            90,
        ),
        deploy_pair(
            "a_leading_zero_fraction_past_nine_digits_inside_twenty_four_hours_is_low",
            "2023-12-31T13:00:00.050Z",
            "2024-01-01T13:00:00.0123456789Z",
            70,
            90,
        ),
        deploy_pair(
            "a_resolution_exactly_two_hours_is_high",
            "2024-01-01T11:00:00Z",
            "2024-01-01T13:00:00Z",
            90,
            70,
        ),
        deploy_pair(
            "a_resolution_two_hours_and_a_millisecond_is_medium",
            "2024-01-01T11:00:00Z",
            "2024-01-01T13:00:00.001Z",
            90,
            70,
        ),
        deploy_pair(
            "a_resolution_exactly_twenty_four_hours_is_low",
            "2023-12-31T13:00:00Z",
            "2024-01-01T13:00:00Z",
            90,
            70,
        ),
        deploy_pair(
            "a_resolution_twenty_four_hours_and_a_millisecond_does_not_correlate",
            "2023-12-31T13:00:00Z",
            "2024-01-01T13:00:00.001Z",
            90,
            70,
        ),
        deploy_pair(
            "a_resolution_at_the_deploy_instant_is_high",
            "2024-01-01T13:00:00Z",
            "2024-01-01T13:00:00Z",
            90,
            70,
        ),
        deploy_pair(
            "a_resolution_before_the_deploy_does_not_correlate",
            "2024-01-01T13:00:00Z",
            "2024-01-01T12:59:59.999Z",
            90,
            70,
        ),
    ]
}

pub(super) fn main_cases() -> Vec<Value> {
    vec![
        pair(
            "an_anomaly_five_hours_before_a_regression_is_medium",
            event(
                2,
                "analytics",
                "warning",
                "2024-01-01T08:00:00Z",
                "Traffic anomaly",
            ),
            "2024-01-01T13:00:00Z",
            70,
            90,
        ),
        pair(
            "an_anomaly_thirteen_hours_before_a_regression_is_low",
            event(
                2,
                "analytics",
                "warning",
                "2024-01-01T00:00:00Z",
                "Traffic anomaly",
            ),
            "2024-01-01T13:00:00Z",
            70,
            90,
        ),
        pair(
            "an_anomaly_forty_nine_hours_before_a_regression_does_not_correlate",
            event(
                2,
                "analytics",
                "warning",
                "2023-12-30T12:00:00Z",
                "Traffic anomaly",
            ),
            "2024-01-01T13:00:00Z",
            70,
            90,
        ),
        pair(
            "an_anomaly_beside_a_twenty_point_improvement_does_not_correlate",
            event(
                2,
                "analytics",
                "warning",
                "2024-01-01T14:00:00Z",
                "Traffic anomaly",
            ),
            "2024-01-01T13:00:00Z",
            90,
            70,
        ),
        json!({
            "name": "one_anomaly_keeps_the_newer_regressions_thirty_point_description",
            "events": [event(2, "analytics", "warning", "2024-01-01T14:00:00Z", "Traffic anomaly")],
            "scans": [
                scan(2, 70, "2024-01-01T13:00:00Z", "https://example.com"),
                scan(1, 90, "2024-01-01T11:00:00Z", "https://example.com"),
                scan(4, 50, "2024-01-01T20:00:00Z", "https://other.example.com"),
                scan(3, 80, "2024-01-01T18:00:00Z", "https://other.example.com")
            ]
        }),
        json!({
            "name": "info_uptime_does_not_explain_a_traffic_drop",
            "events": [
                event(1, "uptime", "info", "2024-01-01T12:00:00Z", "Site is up"),
                event(2, "analytics", "warning", "2024-01-01T13:00:00Z", "Traffic drop")
            ],
            "scans": []
        }),
    ]
}
