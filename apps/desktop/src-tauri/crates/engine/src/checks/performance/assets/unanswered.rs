//! The rows a sample states when none of the requests a verdict reads was
//! answered: a transport failure is not an observation about the site, so a
//! byte sum, a size or a cache verdict read off it would grade nothing.

use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};

/// One row declining to grade, for `requests` sampled requests that all went
/// unanswered.
fn declined(
    check_id: &str,
    title: &str,
    noun: &str,
    outcome: &str,
    requests: usize,
) -> CheckResult {
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Performance,
        title: title.into(),
        description: format!(
            "{requests} sampled {noun} request{} went unanswered, so {outcome}.",
            if requests == 1 { "" } else { "s" }
        ),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(
            serde_json::json!({ "reason": "sample_unanswered", "unanswered": requests }),
        ),
        confidence: IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

pub(super) fn weight_unmeasured(requests: usize) -> CheckResult {
    declined(
        "performance.asset_weight",
        "Sampled asset byte sum not measured",
        "asset",
        "no asset bytes were measured",
        requests,
    )
}

pub(super) fn heavy_unmeasured(requests: usize) -> CheckResult {
    declined(
        "performance.images.heavy",
        "Sampled image transfer size not measured",
        "image",
        "no image size was measured",
        requests,
    )
}

pub(super) fn caching_unassessed(requests: usize) -> CheckResult {
    declined(
        "performance.asset_caching",
        "Static asset caching not assessed",
        "asset",
        "no cache header was read",
        requests,
    )
}
