//! The desktop's and CLI's severity chokepoints.
//!
//! The policy is the engine's (`sitecmd_engine::severity_policy`), the code the
//! hosted runner's artifact and Connect run too. This module applies it where
//! scan results are assembled.

use sitecmd_engine::severity_policy::{self as policy, WebSeverityInput};

use crate::checks::{CheckResult, Severity};
use crate::core::code_scan::CodeIssue;

pub use sitecmd_engine::severity_policy::polish_signal_severity;

pub fn normalize_check_results(results: &mut [CheckResult]) {
    for result in results {
        result.severity = normalized_web_issue_severity(result);
    }
}

pub fn normalize_code_issues(issues: &mut [CodeIssue]) {
    for issue in issues {
        issue.severity = normalized_code_issue_severity(issue);
    }
}

pub fn normalized_web_issue_severity(result: &CheckResult) -> Severity {
    policy::normalized_web_severity(&WebSeverityInput::of(result))
}

pub fn normalized_code_issue_severity(issue: &CodeIssue) -> Severity {
    policy::normalized_code_severity(&issue.id, issue.severity)
}

/// Apply registry severity and the Critical eligibility clamp before the
/// advisory-class cap.
#[cfg(test)]
pub(crate) fn policy_clamped_code_severity(issue: &CodeIssue) -> Severity {
    policy::policy_clamped_code_severity(&issue.id, issue.severity)
}

#[cfg(test)]
fn web_policy_severity(result: &CheckResult) -> Option<Severity> {
    policy::web_policy_severity(&WebSeverityInput::of(result))
}

#[cfg(test)]
fn code_policy_severity(issue: &CodeIssue) -> Option<Severity> {
    policy::code_policy_severity(&issue.id, issue.severity)
}

#[cfg(test)]
#[path = "severity_policy_tests.rs"]
mod tests;
