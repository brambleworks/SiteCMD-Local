//! Canonical severity-policy finalization for assembled web results.

use crate::checks::CheckResult;

pub fn finalize_check_results(results: &mut [CheckResult]) {
    crate::core::severity_policy::normalize_check_results(results);
}

#[cfg(test)]
mod tests {
    use super::finalize_check_results;
    use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};

    fn result(check_id: &str, status: CheckStatus, severity: Severity) -> CheckResult {
        CheckResult {
            check_id: check_id.to_string(),
            category: ScanCategory::Seo,
            title: String::new(),
            description: String::new(),
            status,
            severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    }

    #[test]
    fn finalize_applies_severity_policy_in_both_directions() {
        let mut results = vec![
            // Policy pins the applicability-dependent privacy-link heuristic
            // to Medium even when the check module wrote Low.
            result(
                "compliance.privacy_policy",
                CheckStatus::Fail,
                Severity::Low,
            ),
            // Policy demotes a heuristic title-length warning even when the
            // producer supplied its missing-title severity.
            result("seo.title", CheckStatus::Warn, Severity::High),
        ];

        finalize_check_results(&mut results);

        assert_eq!(results[0].severity, Severity::Medium);
        assert_eq!(results[1].severity, Severity::Medium);
    }
}
