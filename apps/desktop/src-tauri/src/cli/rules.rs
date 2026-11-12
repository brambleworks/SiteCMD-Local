//! Read-only inventory of the rules used by Code Scan.

use crate::checks::Severity;
use crate::core::code_scan::{canonical_code_check_id, registry::CODE_CHECKS, CodeScanDomain};
use serde::Serialize;
use sitecmd_engine::severity_policy::normalized_code_severity;
use std::fmt::Write;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SeveritySource {
    Fixed,
    PerFinding,
}

impl SeveritySource {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::PerFinding => "per_finding",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    producer_rule_id: &'static str,
    check_id: String,
    domain: CodeScanDomain,
    default_severity: Option<Severity>,
    severity_source: SeveritySource,
}

#[derive(Serialize)]
struct Inventory<'a> {
    version: &'a str,
    rules: Vec<Rule>,
}

/// Render the audit registry with canonical identities and effective policy grades.
pub fn render(json: bool, version: &str) -> Result<String, String> {
    let mut rules: Vec<_> = CODE_CHECKS
        .iter()
        .map(|rule| Rule {
            producer_rule_id: rule.slug,
            check_id: canonical_code_check_id(rule.slug),
            domain: rule.domain,
            default_severity: rule
                .policy_severity
                .map(|severity| normalized_code_severity(rule.slug, severity)),
            severity_source: if rule.policy_severity.is_some() {
                SeveritySource::Fixed
            } else {
                SeveritySource::PerFinding
            },
        })
        .collect();
    rules.sort_unstable_by_key(|rule| rule.producer_rule_id);
    let inventory = Inventory { version, rules };
    if json {
        return serde_json::to_string_pretty(&inventory)
            .map_err(|error| format!("Could not serialize Code Scan rules: {error}"));
    }

    let mut output =
        String::from("producerRuleId\tcheckId\tdomain\tdefaultSeverity\tseveritySource\n");
    for rule in inventory.rules {
        let _ = writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            rule.producer_rule_id,
            rule.check_id,
            rule.domain,
            rule.default_severity
                .map(|severity| severity.as_str())
                .unwrap_or("null"),
            rule.severity_source.as_str()
        );
    }
    Ok(output.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::code_scan::CodeIssue;
    use crate::core::severity_policy::normalized_code_issue_severity;

    #[test]
    fn fixed_rule_inventory_grades_match_normalized_findings_for_every_emitted_grade() {
        let inventory: serde_json::Value =
            serde_json::from_str(&render(true, "test").unwrap()).unwrap();
        for rule in CODE_CHECKS
            .iter()
            .filter(|rule| rule.policy_severity.is_some())
        {
            let entry = inventory["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["producerRuleId"] == rule.slug)
                .unwrap();
            assert_eq!(entry["severitySource"], "fixed", "{}", rule.slug);
            for severity in ["critical", "high", "medium", "low"] {
                let issue: CodeIssue = serde_json::from_value(serde_json::json!({
                    "id": format!("{}:src/fixture.ts", rule.slug),
                    "checkId": canonical_code_check_id(rule.slug),
                    "category": rule.category,
                    "severity": severity,
                    "title": "", "description": "",
                    "relativePath": "src/fixture.ts", "absolutePath": ""
                }))
                .unwrap();
                assert_eq!(
                    entry["defaultSeverity"],
                    normalized_code_issue_severity(&issue).as_str(),
                    "{} at {severity}",
                    rule.slug
                );
            }
        }
    }
}
