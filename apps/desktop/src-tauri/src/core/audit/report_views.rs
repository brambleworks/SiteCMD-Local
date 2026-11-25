use serde::{Deserialize, Serialize};
use sitecmd_protocol::engine_abi::EngineInfo;
use sitecmd_protocol::skipped_scopes::CodeScanSkippedScopes;
use sitecmd_protocol::vocab::{IssueConfidence, Severity};

use super::{code_producer_rule_id, CodeIssue, CodeScanReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CodeIssueView {
    pub id: String,
    /// Stable producer rule used for rule-specific presentation such as fix
    /// guides. This is deliberately separate from both canonical identity and
    /// occurrence location, so frontend consumers never parse either ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_rule_id: Option<String>,
    /// Rule-level canonical check_id; lets the frontend
    /// address a code issue like a web issue's check_id.
    #[serde(default)]
    pub check_id: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub relative_path: String,
    pub absolute_path: String,
    pub line: Option<u32>,
    pub evidence: Option<String>,
    pub why_now: Option<String>,
    pub likely_fix: Option<String>,
    #[serde(default)]
    pub confidence: IssueConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_reason: Option<String>,
    pub verify_hint: Option<String>,
}

impl CodeIssueView {
    pub(crate) fn new(issue: &CodeIssue, rules: &EngineInfo) -> Result<Self, &'static str> {
        let rule = super::rule_for_issue(issue, rules)?;
        debug_assert!(
            issue.check_id.is_empty() || issue.check_id == rule.check_id,
            "Code issue check_id must match its producer rule"
        );
        Ok(Self {
            id: issue.id.clone(),
            producer_rule_id: Some(code_producer_rule_id(&issue.id).to_string()),
            check_id: rule.check_id.clone(),
            category: rule.category.key().into(),
            severity: issue.severity,
            title: issue.title.clone(),
            description: issue.description.clone(),
            relative_path: issue.relative_path.clone(),
            absolute_path: issue.absolute_path.clone(),
            line: issue.line,
            evidence: issue.evidence.clone(),
            why_now: issue.why_now.clone(),
            likely_fix: issue.likely_fix.clone(),
            confidence: issue.confidence,
            confidence_reason: issue.confidence_reason.clone(),
            verify_hint: issue.verify_hint.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CodeScanReportView {
    pub checked_at: String,
    pub framework: Option<String>,
    pub issue_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub issues: Vec<CodeIssueView>,
    #[serde(default)]
    pub skipped_scopes: CodeScanSkippedScopes,
}

impl CodeScanReportView {
    pub(crate) fn new(report: &CodeScanReport, rules: &EngineInfo) -> Result<Self, &'static str> {
        Ok(Self {
            checked_at: report.checked_at.clone(),
            framework: report.framework.clone(),
            issue_count: report.issue_count,
            critical_count: report.critical_count,
            high_count: report.high_count,
            medium_count: report.medium_count,
            low_count: report.low_count,
            issues: report
                .issues
                .iter()
                .map(|issue| CodeIssueView::new(issue, rules))
                .collect::<Result<_, _>>()?,
            skipped_scopes: report.skipped_scopes.clone(),
        })
    }
}

macro_rules! report_formats {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum CodeScanReportFormat { $($variant),+ }

        impl CodeScanReportFormat {
            pub const ALL: &'static [(Self, &'static str)] = &[$((Self::$variant, $name)),+];
        }
    };
}

report_formats! {
    Summary => "summary",
    Json => "json",
    Markdown => "markdown",
    Review => "review",
    Github => "github",
    Sarif => "sarif",
}

#[cfg(test)]
mod tests {
    use super::super::CodeScanDomain;
    use super::*;
    use sitecmd_protocol::engine_abi::CodeRuleInfo;
    use sitecmd_protocol::vocab::Category;

    fn rules() -> EngineInfo {
        let rule = |id: &str, category: Category, domain| CodeRuleInfo {
            id: id.into(),
            title: id.into(),
            domain,
            default_severity: None,
            check_id: format!("code_scan.{id}"),
            category,
            rationale: None,
        };
        EngineInfo {
            module_version: "example".into(),
            abi_version: sitecmd_protocol::engine_abi::ENGINE_ABI_VERSION,
            manifest_digest: "0000000000000000".try_into().unwrap(),
            code_rules: vec![rule(
                "supply_chain_typosquat",
                Category::Security,
                CodeScanDomain::Security,
            )],
            local_checks: vec![],
        }
    }

    fn sample_issue(id: &str) -> CodeIssue {
        CodeIssue {
            id: id.to_string(),
            check_id: rules()
                .code_rule(code_producer_rule_id(id))
                .unwrap()
                .check_id
                .clone(),
            category: "supply-chain".to_string(),
            severity: Severity::High,
            title: "Sample".to_string(),
            description: "Sample".to_string(),
            relative_path: "src/index.ts".to_string(),
            absolute_path: "/tmp/src/index.ts".to_string(),
            line: Some(1),
            evidence: None,
            why_now: None,
            likely_fix: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            verify_hint: None,
        }
    }

    fn report_from_issues(issues: Vec<CodeIssue>) -> CodeScanReport {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        for issue in &issues {
            match issue.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
            }
        }
        CodeScanReport {
            skipped_scopes: Default::default(),
            checked_at: "2026-06-02T00:00:00Z".to_string(),
            framework: None,
            issue_count: issues.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            issues,
        }
    }

    #[test]
    fn code_issue_view_carries_check_id_from_issue() {
        // CodeIssueView is the report payload the CLI prints as JSON; it
        // must mirror the rule's canonical check_id verbatim.
        let issue = sample_issue("supply_chain_typosquat");
        let view = CodeIssueView::new(&issue, &rules()).unwrap();
        assert_eq!(view.check_id, issue.check_id);
        assert_eq!(
            view.producer_rule_id.as_deref(),
            Some("supply_chain_typosquat")
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json.get("checkId").and_then(|v| v.as_str()),
            Some("code_scan.supply_chain_typosquat")
        );
    }

    #[test]
    fn code_issue_view_names_the_rules_category_and_no_domain() {
        // Code findings show a second list of domains and emit categories beside the ten.
        let json = serde_json::to_value(
            CodeIssueView::new(&sample_issue("supply_chain_typosquat"), &rules()).unwrap(),
        )
        .unwrap();
        assert_eq!(json["category"], "security");
        assert!(json.get("domain").is_none());
    }

    #[test]
    fn code_issue_view_backfills_empty_check_id() {
        let mut issue = sample_issue("supply_chain_typosquat");
        issue.check_id = String::new();
        let view = CodeIssueView::new(&issue, &rules()).unwrap();
        assert_eq!(view.check_id, "code_scan.supply_chain_typosquat");
    }

    #[test]
    fn issue_and_report_views_backfill_empty_check_id() {
        let mut issue = sample_issue("supply_chain_typosquat");
        issue.check_id = String::new();

        let borrowed = CodeIssueView::new(&issue, &rules()).unwrap();
        assert_eq!(borrowed.check_id, "code_scan.supply_chain_typosquat");

        let report = report_from_issues(vec![issue]);
        let report_view = CodeScanReportView::new(&report, &rules()).unwrap();
        assert_eq!(
            report_view.issues[0].check_id,
            "code_scan.supply_chain_typosquat"
        );
    }

    #[test]
    fn ai_scaffolding_domain_string_round_trips() {
        assert_eq!(CodeScanDomain::AiScaffolding.as_str(), "ai-scaffolding");
        assert_eq!(
            "ai-scaffolding".parse::<CodeScanDomain>().unwrap(),
            CodeScanDomain::AiScaffolding
        );
    }
}
