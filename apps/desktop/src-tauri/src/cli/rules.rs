//! Read-only inventory of the rules used by Code Scan.

use crate::core::scan_types::Severity;
use serde::Serialize;
use sitecmd_protocol::vocab::Category;
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
struct Rule<'a> {
    producer_rule_id: &'a str,
    check_id: &'a str,
    category: Category,
    default_severity: Option<Severity>,
    severity_source: SeveritySource,
}

#[derive(Serialize)]
struct Inventory<'a> {
    version: &'a str,
    rules: Vec<Rule<'a>>,
}

/// Render the audit registry with canonical identities and effective policy grades.
pub fn render(json: bool, version: &str) -> Result<String, String> {
    let engine = sitecmd_engine_host::load().map_err(|error| error.to_string())?;
    let mut rules: Vec<_> = engine
        .info()
        .code_rules
        .iter()
        .map(|rule| Rule {
            producer_rule_id: &rule.id,
            check_id: &rule.check_id,
            category: rule.category,
            default_severity: rule.default_severity,
            severity_source: if rule.default_severity.is_some() {
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
        String::from("producerRuleId\tcheckId\tcategory\tdefaultSeverity\tseveritySource\n");
    for rule in inventory.rules {
        let _ = writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            rule.producer_rule_id,
            rule.check_id,
            rule.category.key(),
            rule.default_severity
                .map(|severity| severity.as_str())
                .unwrap_or("null"),
            rule.severity_source.as_str()
        );
    }
    Ok(output.trim_end().to_string())
}
