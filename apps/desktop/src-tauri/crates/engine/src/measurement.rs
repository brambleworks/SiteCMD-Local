//! Shared measurement extraction for local diagnostics and connected numeric samples.
//! Centralizing both forms prevents runtime-specific series from diverging.

use serde_json::Value;
use std::sync::LazyLock;

use crate::browser::CoreWebVitals;
use crate::manifest::{capability_manifest, CapabilityManifest, HostedLane, MeasurementUnit};

static MANIFEST: LazyLock<CapabilityManifest> = LazyLock::new(capability_manifest);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ObservedMeasurement {
    pub check: &'static str,
    pub value: f64,
    pub unit: MeasurementUnit,
}

fn observed(
    check: &'static str,
    value: Option<f64>,
    producing_lane: HostedLane,
) -> Option<ObservedMeasurement> {
    let value = value.filter(|value| value.is_finite() && *value >= 0.0)?;
    let entry = MANIFEST.entry(check)?;
    if entry.hosted != producing_lane {
        return None;
    }
    let unit = entry.measurement_unit?;
    Some(ObservedMeasurement { check, value, unit })
}

/// Extract every metric one browser navigation actually observed.
pub fn from_browser_vitals(vitals: &CoreWebVitals) -> Vec<ObservedMeasurement> {
    [
        observed("performance.lcp", vitals.lcp_ms, HostedLane::Browser),
        observed("performance.cls", vitals.cls, HostedLane::Browser),
        observed("performance.fcp", vitals.fcp_ms, HostedLane::Browser),
        observed("performance.ttfb", vitals.ttfb_ms, HostedLane::Browser),
        observed(
            "performance.long_task_blocking",
            vitals.observed_long_task_blocking_ms,
            HostedLane::Browser,
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Extract the connected sample carried by one local diagnostic result.
pub fn from_result_raw_data(check: &str, raw: &Value) -> Option<(f64, MeasurementUnit)> {
    let value = match check {
        "performance.cls" => raw.get("cls")?.as_f64(),
        "performance.ttfb" => raw.get("ttfb_ms")?.as_f64(),
        "performance.lcp" | "performance.fcp" | "performance.long_task_blocking" => {
            raw.get("value")?.as_f64()
        }
        _ => None,
    }?;
    let entry = MANIFEST.entry(check)?;
    let unit = entry.measurement_unit?;
    (value.is_finite() && value >= 0.0).then_some((value, unit))
}

/// The sample one probe-lane result row carries, under its check: only for a
/// check whose manifest lane is the probe lane, so a browser timing graded
/// into a row is never counted a second time.
pub fn from_probe_row(row: &crate::vocab::CheckResult) -> Option<(String, f64, MeasurementUnit)> {
    let entry = MANIFEST.entry(&row.check_id)?;
    if entry.hosted != HostedLane::ProbeAdapter {
        return None;
    }
    let (value, unit) = from_result_raw_data(&row.check_id, row.raw_data.as_ref()?)?;
    Some((row.check_id.clone(), value, unit))
}

/// A route's numeric samples: what its browser navigation observed, then the
/// timings its probe-lane rows graded.
pub fn route_samples(
    vitals: Option<&CoreWebVitals>,
    probe_rows: &[crate::vocab::CheckResult],
) -> Vec<crate::evaluation::EvaluationMeasurement> {
    let browser = vitals
        .map(from_browser_vitals)
        .unwrap_or_default()
        .into_iter()
        .map(|sample| (sample.check.to_string(), sample.value, sample.unit));
    browser
        .chain(probe_rows.iter().filter_map(from_probe_row))
        .map(|(check, value, unit)| crate::evaluation::EvaluationMeasurement { check, value, unit })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_result_units_come_from_the_manifest() {
        assert_eq!(
            from_result_raw_data("performance.lcp", &serde_json::json!({ "value": 123.0 })),
            Some((123.0, MeasurementUnit::Milliseconds))
        );
        assert_eq!(
            from_result_raw_data("performance.cls", &serde_json::json!({ "cls": 0.04 })),
            Some((0.04, MeasurementUnit::Ratio))
        );
    }

    #[test]
    fn invalid_or_unknown_values_are_not_samples() {
        assert_eq!(
            from_result_raw_data("performance.lcp", &serde_json::json!({ "value": -1.0 })),
            None
        );
        assert_eq!(
            from_result_raw_data("performance.unknown", &serde_json::json!({ "value": 1.0 })),
            None
        );
    }

    #[test]
    fn browser_samples_never_relabel_probe_measurements() {
        let samples = from_browser_vitals(&CoreWebVitals {
            lcp_ms: Some(1_200.0),
            cls: None,
            fcp_ms: None,
            ttfb_ms: Some(320.0),
            observed_long_task_blocking_ms: None,
            js_errors: vec![],
            js_error_count: None,
        });

        assert!(samples
            .iter()
            .any(|sample| sample.check == "performance.lcp"));
        assert!(samples
            .iter()
            .all(|sample| sample.check != "performance.ttfb"));
    }

    fn row(check: &str, raw: serde_json::Value) -> crate::vocab::CheckResult {
        crate::vocab::CheckResult {
            check_id: check.into(),
            category: crate::vocab::ScanCategory::Performance,
            title: String::new(),
            description: String::new(),
            status: crate::vocab::CheckStatus::Pass,
            severity: crate::vocab::Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: Some(raw),
            confidence: crate::vocab::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    }

    #[test]
    fn a_probe_timing_row_is_a_sample() {
        assert_eq!(
            from_probe_row(&row(
                "performance.ttfb",
                serde_json::json!({ "ttfb_ms": 120 })
            )),
            Some((
                "performance.ttfb".to_string(),
                120.0,
                MeasurementUnit::Milliseconds
            ))
        );
    }

    #[test]
    fn a_browser_measurement_row_is_no_probe_sample() {
        assert_eq!(
            from_probe_row(&row(
                "performance.lcp",
                serde_json::json!({ "value": 900.0 })
            )),
            None
        );
        assert_eq!(
            from_probe_row(&row("performance.compression", serde_json::json!({}))),
            None
        );
    }

    #[test]
    fn a_route_counts_its_timing_once_whichever_lanes_reported_one() {
        // Reversed samples or a duplicate browser TTFB change the complete
        // ordered list.
        let vitals = CoreWebVitals {
            lcp_ms: Some(1_200.0),
            cls: None,
            fcp_ms: None,
            ttfb_ms: Some(320.0),
            observed_long_task_blocking_ms: None,
            js_errors: vec![],
            js_error_count: None,
        };
        let samples = route_samples(
            Some(&vitals),
            &[row(
                "performance.ttfb",
                serde_json::json!({ "ttfb_ms": 120 }),
            )],
        );
        assert_eq!(
            samples,
            vec![
                crate::evaluation::EvaluationMeasurement {
                    check: "performance.lcp".into(),
                    value: 1_200.0,
                    unit: MeasurementUnit::Milliseconds,
                },
                crate::evaluation::EvaluationMeasurement {
                    check: "performance.ttfb".into(),
                    value: 120.0,
                    unit: MeasurementUnit::Milliseconds,
                },
            ]
        );
    }
}
