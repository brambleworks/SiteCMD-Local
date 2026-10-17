//! The severity policy: the grade a finding carries once SiteCMD's rules for
//! its check are applied to the grade its producer emitted.
//!
//! One implementation for every runtime. The CLI and the desktop link it
//! natively; the hosted runner's artifact and Connect reach it through the
//! engine-wasm `severity_apply` export, and Connect applies it to hosted scan
//! findings, which arrive with the engine's unnormalized grade.

mod web;

use serde::{Deserialize, Serialize};

use crate::code_rules::{descriptor_for_issue_id, RuleClass};
use crate::vocab::{CheckResult, CheckStatus, Severity};

pub use web::{polish_signal_severity, web_policy_severity};

/// One web verdict as the policy reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSeverityInput {
    pub check_id: String,
    pub status: CheckStatus,
    pub severity: Severity,
    /// How many broken links `seo.broken_links` reported: the one raw fact the
    /// policy reads, so the only one that travels. Absent for every other check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broken_count: Option<u32>,
}

impl WebSeverityInput {
    pub fn of(result: &CheckResult) -> Self {
        let broken_count = (result.check_id == "seo.broken_links")
            .then(|| {
                let broken = result.raw_data.as_ref()?.get("broken")?.as_array()?;
                Some(u32::try_from(broken.len()).unwrap_or(u32::MAX))
            })
            .flatten();
        Self {
            check_id: result.check_id.clone(),
            status: result.status,
            severity: result.severity,
            broken_count,
        }
    }
}

/// One code finding as the policy reads it. `rule` is the producer rule; a
/// full `<rule>:<path>` issue id resolves to the same rule.
/// The policy takes producer rules, never stored canonical ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeSeverityInput {
    pub rule: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityRequest {
    #[serde(default)]
    pub web: Vec<WebSeverityInput>,
    #[serde(default)]
    pub code: Vec<CodeSeverityInput>,
}

/// The policy's grade for each input, in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityAnswer {
    pub web: Vec<Severity>,
    pub code: Vec<Severity>,
}

pub fn apply(request: &SeverityRequest) -> SeverityAnswer {
    SeverityAnswer {
        web: request.web.iter().map(normalized_web_severity).collect(),
        code: request
            .code
            .iter()
            .map(|input| normalized_code_severity(&input.rule, input.severity))
            .collect(),
    }
}

pub fn normalized_web_severity(input: &WebSeverityInput) -> Severity {
    if matches!(input.status, CheckStatus::Pass | CheckStatus::Skipped) {
        return Severity::Low;
    }
    let severity = web_policy_severity(input).unwrap_or(input.severity);
    if severity == Severity::Critical && !web_check_allows_critical(&input.check_id) {
        return Severity::High;
    }
    // A Warn is an advisory; it never carries Critical weight in the score.
    // Checks that mean Critical must Fail.
    if severity == Severity::Critical && matches!(input.status, CheckStatus::Warn) {
        return Severity::High;
    }
    severity
}

pub fn normalized_code_severity(rule: &str, severity: Severity) -> Severity {
    let severity = policy_clamped_code_severity(rule, severity);
    // Advisory rules describe recommendations rather than proven exposure, so
    // the central policy caps them at Medium.
    if is_advisory_rule(rule) {
        cap_at_medium(severity)
    } else {
        severity
    }
}

/// Apply registry severity and the Critical eligibility clamp before the
/// advisory-class cap.
pub fn policy_clamped_code_severity(rule: &str, severity: Severity) -> Severity {
    let severity = code_policy_severity(rule, severity).unwrap_or(severity);
    if severity == Severity::Critical && !code_rule_allows_critical(rule) {
        Severity::High
    } else {
        severity
    }
}

/// The registry's severity for a code rule. `None` preserves the emitted
/// severity for an uncatalogued rule.
pub fn code_policy_severity(rule: &str, severity: Severity) -> Option<Severity> {
    let descriptor = descriptor_for_issue_id(rule)?;
    Some(descriptor.policy_severity.unwrap_or(severity))
}

fn is_advisory_rule(rule: &str) -> bool {
    descriptor_for_issue_id(rule).is_some_and(|descriptor| descriptor.class == RuleClass::Advisory)
}

fn code_rule_allows_critical(rule: &str) -> bool {
    descriptor_for_issue_id(rule).is_some_and(|descriptor| descriptor.allows_critical)
}

/// Clamp a severity down to Medium (Critical/High -> Medium; Medium/Low kept).
fn cap_at_medium(severity: Severity) -> Severity {
    match severity {
        Severity::Critical | Severity::High => Severity::Medium,
        other => other,
    }
}

fn web_check_allows_critical(check_id: &str) -> bool {
    matches!(
        check_id,
        "security.ssl.expiry"
            | "security.ssl.hostname"
            | "security.ssl.chain"
            | "security.https_enforcement"
            | "security.insecure_form"
    ) || check_id.starts_with("security.exposed_files")
}
