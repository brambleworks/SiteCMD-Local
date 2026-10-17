//! Merges browser-layer verdicts into desktop scan results and rescoring.

use crate::core::analysis_types::{AxeReport, CoreWebVitals};
use crate::core::scanner::ScanResult;
use crate::scoring::calculator;
use sitecmd_engine::checks::accessibility::axe;
use sitecmd_engine::checks::performance::{browser_vitals, ttfb};

/// Append axe and Core Web Vitals results, then recalculate scores.
/// Missing axe output preserves first-party accessibility findings.
#[tracing::instrument(skip(result, axe_report, cwv))]
pub fn append_webview_results(
    result: &mut ScanResult,
    axe_report: Option<&AxeReport>,
    cwv: Option<&CoreWebVitals>,
) {
    if let Some(report) = axe_report {
        // axe supersedes a heuristic only when that rule reached a verdict on
        // this page; incomplete rules preserve existing coverage.
        let superseded = axe::superseded_first_party_check_ids(report);
        result
            .issues
            .retain(|issue| !superseded.contains(&issue.check_id.as_str()));
        result.issues.extend(axe::evaluate_axe_report(report));
    }
    if let Some(cwv) = cwv {
        let transport_ttfb = result
            .issues
            .iter()
            .find(|issue| issue.check_id == "performance.ttfb")
            .and_then(|issue| issue.raw_data.as_ref())
            .filter(|raw| {
                raw.get("measurement_source")
                    .and_then(serde_json::Value::as_str)
                    == Some(ttfb::HTTP_PROBE_SOURCE)
            })
            .and_then(|raw| raw.get("ttfb_ms"))
            .cloned();
        if cwv.ttfb_ms.is_some() {
            // The browser navigation sample includes the page's real redirect,
            // connection, and response path. It supersedes the preliminary HTTP
            // probe so one server-response problem cannot appear or score twice.
            result
                .issues
                .retain(|issue| issue.check_id != "performance.ttfb");
        }
        let mut browser_results = browser_vitals::evaluate_core_web_vitals(cwv);
        if let Some(transport_ttfb) = transport_ttfb {
            if let Some(raw) = browser_results
                .iter_mut()
                .find(|issue| issue.check_id == "performance.ttfb")
                .and_then(|issue| issue.raw_data.as_mut())
                .and_then(serde_json::Value::as_object_mut)
            {
                // Keep the browser value for local scoring and preserve the HTTP
                // observation separately for connected transport evidence.
                raw.insert("transport_ttfb_ms".into(), transport_ttfb);
            }
        }
        result.issues.extend(browser_results);
    }

    super::finalize_check_results(&mut result.issues);

    let (score, cats) = calculator::calculate_scores_with_identity(&result.issues, |issue| {
        crate::core::correlation::web_scan_check_id(&issue.check_id)
            .unwrap_or(issue.check_id.as_str())
    });
    result.overall_score = score;
    result.categories = cats;
}

#[cfg(test)]
#[path = "webview_results_tests.rs"]
mod tests;
