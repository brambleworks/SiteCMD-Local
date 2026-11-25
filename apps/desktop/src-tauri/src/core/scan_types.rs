//! Shared Web Scan results and profile vocabulary.

use serde::{Deserialize, Serialize};
use sitecmd_protocol::score::CategoryScore;
pub use sitecmd_protocol::vocab::{
    Category, CheckResult, CheckStatus, IssueConfidence, ScanType, Severity,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub url: String,
    pub mode: String, // "live" | "predeploy"
    pub scan_type: ScanType,
    pub overall_score: u32,
    pub categories: Vec<CategoryScore>,
    pub issues: Vec<CheckResult>,
    /// Score gains aligned to actionable issues in scan order.
    #[serde(skip)]
    pub fix_points: Vec<u32>,
    pub detected_stack: Option<serde_json::Value>,
    pub duration_ms: u64,
    pub timestamp: String,
}

/// Failed and warning results in scan order, omitting covered summaries.
pub fn actionable(results: &[CheckResult]) -> impl Iterator<Item = &CheckResult> {
    results.iter().filter(|result| {
        !result.covered && matches!(result.status, CheckStatus::Fail | CheckStatus::Warn)
    })
}

#[cfg(test)]
mod scan_type_tests {
    use super::*;

    #[test]
    fn actionable_results_are_failures_and_warnings() {
        // A covered summary can be counted as a second finding.
        let results = [
            ("covered", CheckStatus::Fail, true),
            ("fail", CheckStatus::Fail, false),
            ("warn", CheckStatus::Warn, false),
            ("pass", CheckStatus::Pass, false),
            ("not_applicable", CheckStatus::NotApplicable, false),
            ("skipped", CheckStatus::Skipped, false),
        ]
        .map(|(check_id, status, covered)| CheckResult {
            check_id: check_id.into(),
            status,
            covered,
            category: Some(Category::Seo),
            title: check_id.into(),
            description: "fixture".into(),
            severity: Severity::High,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: IssueConfidence::Confirmed,
            confidence_reason: None,
            skip_reason: (status == CheckStatus::Skipped)
                .then_some(sitecmd_protocol::vocab::SkipReason::Unreachable),
            why_it_matters: None,
        });
        assert_eq!(
            actionable(&results)
                .map(|result| result.check_id.as_str())
                .collect::<Vec<_>>(),
            ["fail", "warn"],
        );
    }
    use std::collections::BTreeSet;

    fn variant_set<const N: usize>(all: [&'static str; N]) -> BTreeSet<&'static str> {
        all.into_iter().collect()
    }

    fn constraint_values<'a>(definition: &'a str, marker: &str) -> BTreeSet<&'a str> {
        definition
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing scan_executions.{marker} constraint"))
            .1
            .split_once('(')
            .expect("CHECK IN list")
            .1
            .split_once(')')
            .expect("CHECK list body")
            .0
            .split(',')
            .map(|value| value.trim().trim_matches('\''))
            .collect()
    }

    /// Keep enum vocabularies synchronized with schema CHECK constraints.
    #[test]
    fn scan_type_vocabularies_match_schema_check_constraints() {
        // A later migration can change the installed web_focus constraint.
        let conn = crate::db::test_helpers::migrated_conn();
        let definition: String = conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'scan_executions'",
                [],
                |row| row.get(0),
            )
            .expect("read migrated scan_executions schema");
        let scan_variants = variant_set(ScanType::ALL.map(|s| s.as_str()));
        assert_eq!(
            constraint_values(&definition, "web_focus IN"),
            scan_variants,
            "ScanType variants and scan_executions.web_focus disagree"
        );
    }

    #[test]
    fn scan_types_round_trip_and_reject_unknown_values() {
        for scan_type in ScanType::ALL {
            assert_eq!(scan_type.to_string().parse::<ScanType>(), Ok(scan_type));
            let json = serde_json::to_string(&scan_type).expect("serialize");
            assert_eq!(json, format!("\"{}\"", scan_type.as_str()));
            let back: ScanType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, scan_type);
        }
        assert!("full".parse::<ScanType>().is_err());
        assert!("code".parse::<ScanType>().is_err());
        assert!(serde_json::from_str::<ScanType>("\"code\"").is_err());
        assert!(serde_json::from_str::<ScanType>("\"full\"").is_err());
        assert_eq!(ScanType::default(), ScanType::Health);
    }
}
