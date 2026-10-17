//! Enumerable source of truth for code-scan checks and their policy metadata.
//!
//! The table itself is the engine's (`sitecmd_engine::code_rules`), so the
//! severity policy reads the same rules wherever it runs. Counts and canonical
//! ids stay here, beside the scan that emits the rules.

pub use sitecmd_engine::code_rules::{
    descriptor, descriptor_for_issue_id, CodeCheckDescriptor, CodeScanPhase, RuleClass, CODE_CHECKS,
};

use super::types::CodeScanDomain;

/// Canonical code check IDs shared by release inventory and coverage claims.
pub fn registered_code_check_ids() -> impl Iterator<Item = String> {
    CODE_CHECKS
        .iter()
        .map(|check| super::canonical_code_check_id(check.slug))
}

/// Honest count of distinct first-party code-scan checks.
pub fn code_check_count() -> usize {
    CODE_CHECKS.len()
}

/// Count of first-party code-scan checks in one domain.
pub fn code_check_count_for_domain(domain: CodeScanDomain) -> usize {
    CODE_CHECKS
        .iter()
        .filter(|check| check.domain == domain)
        .count()
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod registry_tests;
