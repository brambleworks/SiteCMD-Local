use std::collections::HashSet;

use super::{descriptor, descriptor_for_issue_id, CodeScanDomain, RuleClass, CODE_CHECKS};
use crate::vocab::Severity;

#[test]
fn a_full_issue_id_resolves_to_its_rule() {
    let rule = descriptor_for_issue_id("js-command-injection:app/api/run/route.ts")
        .expect("the rule is registered");
    assert_eq!(rule.slug, "js-command-injection");
    assert_eq!(rule.policy_severity, Some(Severity::Critical));
    assert!(rule.allows_critical);
    assert_eq!(rule.class, RuleClass::Risk);
}

#[test]
fn an_unregistered_rule_has_no_descriptor() {
    assert!(descriptor("dependency-advisory").is_none());
    assert!(descriptor_for_issue_id("dependency-advisory:package.json").is_none());
}

#[test]
fn every_slug_is_unique_and_colon_free() {
    let mut seen = HashSet::new();
    for rule in CODE_CHECKS {
        assert!(!rule.slug.contains(':'), "{}", rule.slug);
        assert!(seen.insert(rule.slug), "duplicate {}", rule.slug);
    }
}

#[test]
fn the_domain_keeps_its_wire_names() {
    for (domain, wire) in [
        (CodeScanDomain::Database, "database"),
        (CodeScanDomain::AiSafety, "ai-safety"),
        (CodeScanDomain::Security, "security"),
        (CodeScanDomain::Architecture, "architecture"),
        (CodeScanDomain::Operations, "operations"),
        (CodeScanDomain::SupplyChain, "supply-chain"),
        (CodeScanDomain::AiScaffolding, "ai-scaffolding"),
    ] {
        assert_eq!(domain.as_str(), wire);
        assert_eq!(
            serde_json::to_string(&domain).unwrap(),
            format!("\"{wire}\"")
        );
        assert_eq!(wire.parse::<CodeScanDomain>().unwrap(), domain);
    }
}
