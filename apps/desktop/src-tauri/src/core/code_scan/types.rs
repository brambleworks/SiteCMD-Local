use crate::checks::{IssueConfidence, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ts_rs::TS;

#[cfg(test)]
use super::validate_canonical_check_id;
use super::{canonical_code_check_id, code_producer_rule_id};

// Internal pre-domain shape: never crosses the IPC boundary (the wire always
// carries CodeIssueView, the domain-tagged superset, via db::CodeScanResult /
// db::CodeScanReportPayload). Not exported to TS; the frontend aliases
// CodeIssue = CodeIssueView.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeIssue {
    pub id: String,
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
    pub source_excerpt: Option<String>,
    pub evidence: Option<String>,
    pub why_now: Option<String>,
    pub likely_fix: Option<String>,
    #[serde(default)]
    pub confidence: IssueConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_reason: Option<String>,
    pub verify_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum CodeScanDomain {
    Database,
    AiSafety,
    Security,
    Architecture,
    Operations,
    SupplyChain,
    AiScaffolding,
}

impl CodeScanDomain {
    /// Stable wire and display value. Must remain log-free because `Display`
    /// can run while the logger holds a non-reentrant writer lock.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::AiSafety => "ai-safety",
            Self::Security => "security",
            Self::Architecture => "architecture",
            Self::Operations => "operations",
            Self::SupplyChain => "supply-chain",
            Self::AiScaffolding => "ai-scaffolding",
        }
    }
}

impl std::fmt::Display for CodeScanDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CodeScanDomain {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "database" => Ok(Self::Database),
            "ai-safety" => Ok(Self::AiSafety),
            "security" => Ok(Self::Security),
            "architecture" => Ok(Self::Architecture),
            "operations" => Ok(Self::Operations),
            "supply-chain" => Ok(Self::SupplyChain),
            "ai-scaffolding" => Ok(Self::AiScaffolding),
            _ => Err(format!("Unknown code scan domain: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct CodeIssueView {
    pub id: String,
    /// Stable producer rule used for rule-specific presentation such as fix
    /// guides. This is deliberately separate from both canonical identity and
    /// occurrence location, so frontend consumers never parse either ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub producer_rule_id: Option<String>,
    /// Rule-level canonical check_id; lets the frontend
    /// address a code issue like a web issue's check_id.
    #[serde(default)]
    pub check_id: String,
    pub category: String,
    pub domain: CodeScanDomain,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub relative_path: String,
    pub absolute_path: String,
    pub line: Option<u32>,
    pub source_excerpt: Option<String>,
    pub evidence: Option<String>,
    pub why_now: Option<String>,
    pub likely_fix: Option<String>,
    #[serde(default)]
    pub confidence: IssueConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub confidence_reason: Option<String>,
    pub verify_hint: Option<String>,
}

/// Work-item fields required by grouped badge counts.
#[derive(Debug, Clone)]
pub struct CodeIssueCountKey {
    pub check_id: String,
    pub domain: CodeScanDomain,
    pub severity: Severity,
    pub title: String,
}

/// Resolve canonical identity from the producer occurrence.
fn resolve_code_view_check_id(check_id: String, id: &str) -> String {
    let canonical = canonical_code_check_id(id);
    debug_assert!(
        check_id.is_empty() || check_id == canonical,
        "Code issue check_id must match its producer rule"
    );
    canonical
}

impl CodeIssueView {
    #[tracing::instrument(skip(issue, domain))]
    pub fn from_issue_with_domain(issue: CodeIssue, domain: CodeScanDomain) -> Self {
        let check_id = resolve_code_view_check_id(issue.check_id, &issue.id);
        Self {
            producer_rule_id: Some(code_producer_rule_id(&issue.id).to_string()),
            id: issue.id,
            check_id,
            category: issue.category,
            domain,
            severity: issue.severity,
            title: issue.title,
            description: issue.description,
            relative_path: issue.relative_path,
            absolute_path: issue.absolute_path,
            line: issue.line,
            source_excerpt: issue.source_excerpt,
            evidence: issue.evidence,
            why_now: issue.why_now,
            likely_fix: issue.likely_fix,
            confidence: issue.confidence,
            confidence_reason: issue.confidence_reason,
            verify_hint: issue.verify_hint,
        }
    }
}

impl From<&CodeIssue> for CodeIssueView {
    fn from(issue: &CodeIssue) -> Self {
        Self {
            id: issue.id.clone(),
            producer_rule_id: Some(code_producer_rule_id(&issue.id).to_string()),
            check_id: resolve_code_view_check_id(issue.check_id.clone(), &issue.id),
            category: issue.category.clone(),
            domain: code_issue_domain(issue),
            severity: issue.severity,
            title: issue.title.clone(),
            description: issue.description.clone(),
            relative_path: issue.relative_path.clone(),
            absolute_path: issue.absolute_path.clone(),
            line: issue.line,
            source_excerpt: issue.source_excerpt.clone(),
            evidence: issue.evidence.clone(),
            why_now: issue.why_now.clone(),
            likely_fix: issue.likely_fix.clone(),
            confidence: issue.confidence,
            confidence_reason: issue.confidence_reason.clone(),
            verify_hint: issue.verify_hint.clone(),
        }
    }
}

impl From<CodeIssue> for CodeIssueView {
    fn from(issue: CodeIssue) -> Self {
        let domain = code_issue_domain(&issue);
        Self::from_issue_with_domain(issue, domain)
    }
}

/// Summary of nested repositories and ignored trees pruned by the code walker.
/// A capped sample lets the UI explain unexpectedly small scans.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct CodeScanSkippedScopes {
    /// Directories skipped because they are a separate nested git repository
    /// (a benchmark clone, a vendored checkout, a submodule or worktree).
    pub nested_repositories: usize,
    /// Directories skipped because the project's own `.gitignore` excludes them
    /// (build output, codegen, third-party working trees).
    pub gitignored_directories: usize,
    /// A small, capped sample of the skipped top-level directory names (relative
    /// to the scan root), for a "skipped: foo, bar,..." note. Not exhaustive.
    pub sample_names: Vec<String>,
}

/// Cap on `sample_names` so a pathological tree can never balloon the report.
pub const MAX_SKIPPED_SAMPLE_NAMES: usize = 12;

impl CodeScanSkippedScopes {
    /// Total directories the walker refused to descend into.
    pub fn total(&self) -> usize {
        self.nested_repositories + self.gitignored_directories
    }

    /// Record a pruned directory, keeping the sample list bounded.
    pub fn record_nested_repository(&mut self, name: String) {
        self.nested_repositories += 1;
        self.push_sample(name);
    }

    pub fn record_gitignored_directory(&mut self, name: String) {
        self.gitignored_directories += 1;
        self.push_sample(name);
    }

    fn push_sample(&mut self, name: String) {
        if name.is_empty() || self.sample_names.len() >= MAX_SKIPPED_SAMPLE_NAMES {
            return;
        }
        self.sample_names.push(name);
    }
}

// Internal report shapes: neither crosses IPC. The engine builds CodeScanReport
// (bare issues), converts to CodeScanReportView, then to db::CodeScanReportPayload
// (the only code-scan report type that reaches the frontend). Not exported to TS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeScanReport {
    pub checked_at: String,
    pub framework: Option<String>,
    pub issue_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub issues: Vec<CodeIssue>,
    #[serde(default)]
    pub skipped_scopes: CodeScanSkippedScopes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeScanReportView {
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

impl From<&CodeScanReport> for CodeScanReportView {
    fn from(report: &CodeScanReport) -> Self {
        Self {
            checked_at: report.checked_at.clone(),
            framework: report.framework.clone(),
            issue_count: report.issue_count,
            critical_count: report.critical_count,
            high_count: report.high_count,
            medium_count: report.medium_count,
            low_count: report.low_count,
            issues: report.issues.iter().map(CodeIssueView::from).collect(),
            skipped_scopes: report.skipped_scopes.clone(),
        }
    }
}

#[tracing::instrument(skip(report))]
pub fn score_report(report: &CodeScanReport) -> u32 {
    // Score deduplicated rule rows; report counts retain per-file semantics.
    let check_ids: Vec<String> = report
        .issues
        .iter()
        .map(|issue| canonical_code_check_id(&issue.id))
        .collect();
    let rows = crate::scoring::dedup::dedup_score_rows(report.issues.iter().zip(&check_ids).map(
        |(issue, check_id)| {
            // Severity and confidence come from the same finding.
            let weight = crate::scoring::dedup::confidence_weight(Some(issue.confidence));
            crate::scoring::dedup::ScoreFinding {
                check_id,
                category: issue.category.as_str(),
                severity: issue.severity,
                cap_confidence: issue.confidence.can_trigger_score_cap(),
                weight,
                full_weight_critical: issue.severity == Severity::Critical && weight >= 1.0,
                identity: None,
            }
        },
    ));
    let counts = crate::scoring::dedup::severity_counts(&rows);
    // Effective (confidence-weighted) counts feed the curve; the report's own
    // critical_count..low_count fields keep raw per-file display semantics.
    crate::scoring::calculator::health_score_from_severity(
        counts.eff_critical,
        counts.eff_high,
        counts.eff_medium,
        counts.eff_low,
        counts.has_full_weight_critical,
        counts.has_cap_eligible,
    )
}

/// Returns the registry-defined issue domain, with a deterministic category
/// fallback for uncatalogued or future check ids.
#[tracing::instrument(skip(issue))]
pub fn code_issue_domain(issue: &CodeIssue) -> CodeScanDomain {
    if let Some(descriptor) = crate::core::code_scan::registry::descriptor_for_issue_id(&issue.id) {
        return descriptor.domain;
    }
    fallback_code_issue_domain(&issue.category)
}

/// Category-driven domain for an id the registry does not catalog. Kept in sync
/// with the emit-site category vocabulary so uncatalogued findings still land in
/// a sensible domain.
fn fallback_code_issue_domain(category: &str) -> CodeScanDomain {
    match category {
        "ai-scaffolding" => CodeScanDomain::AiScaffolding,
        "ai-safety" => CodeScanDomain::AiSafety,
        "data" | "database" => CodeScanDomain::Database,
        "security" => CodeScanDomain::Security,
        "supply-chain" => CodeScanDomain::SupplyChain,
        "operations" => CodeScanDomain::Operations,
        _ => CodeScanDomain::Architecture,
    }
}

pub fn code_scan_domain_rank(domain: CodeScanDomain) -> usize {
    match domain {
        CodeScanDomain::Database => 0,
        CodeScanDomain::AiSafety => 1,
        CodeScanDomain::Security => 2,
        CodeScanDomain::Architecture => 3,
        CodeScanDomain::Operations => 4,
        CodeScanDomain::SupplyChain => 5,
        CodeScanDomain::AiScaffolding => 6,
    }
}

#[tracing::instrument(skip(issues))]
pub fn summarize_code_scan_domain(issues: &[CodeIssue]) -> Option<(CodeScanDomain, usize)> {
    let mut counts = HashMap::new();
    for issue in issues {
        *counts.entry(code_issue_domain(issue)).or_insert(0usize) += 1;
    }

    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|(domain_a, count_a), (domain_b, count_b)| {
        count_b
            .cmp(count_a)
            .then_with(|| code_scan_domain_rank(*domain_a).cmp(&code_scan_domain_rank(*domain_b)))
    });
    ranked.into_iter().next()
}

pub(crate) fn code_scan_domain_label(domain: CodeScanDomain) -> &'static str {
    match domain {
        CodeScanDomain::Database => "Database Analysis",
        CodeScanDomain::AiSafety => "AI Safety",
        CodeScanDomain::Security => "Security",
        CodeScanDomain::Architecture => "Architecture",
        CodeScanDomain::Operations => "Operations",
        CodeScanDomain::SupplyChain => "Dependencies",
        CodeScanDomain::AiScaffolding => "AI Setup",
    }
}

pub fn severity_rank(severity: &Severity) -> u8 {
    severity.sort_rank()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeScanReportFormat {
    Summary,
    Json,
    Markdown,
    Review,
    Github,
    Sarif,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{IssueConfidence, Severity};

    fn sample_issue(id: &str) -> CodeIssue {
        CodeIssue {
            id: id.to_string(),
            check_id: canonical_code_check_id(id),
            category: "supply-chain".to_string(),
            severity: Severity::High,
            title: "Sample".to_string(),
            description: "Sample".to_string(),
            relative_path: "src/index.ts".to_string(),
            absolute_path: "/tmp/src/index.ts".to_string(),
            line: Some(1),
            source_excerpt: None,
            evidence: None,
            why_now: None,
            likely_fix: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            verify_hint: None,
        }
    }

    #[test]
    fn code_scan_check_id_resolves_to_source_dot_signal() {
        let id = "supply_chain_typosquat";
        let resolved = canonical_code_check_id(id);
        assert_eq!(resolved, "code_scan.supply_chain_typosquat");
    }

    #[test]
    fn code_identity_is_rule_level_before_location_is_attached() {
        let first = canonical_code_check_id("hardcoded-secret:src/a.ts");
        let second = canonical_code_check_id("hardcoded-secret:src/b.ts");
        assert_eq!(first, "code_scan.hardcoded-secret");
        assert_eq!(first, second);
        assert_eq!(
            code_producer_rule_id("hardcoded-secret:src/a.ts"),
            "hardcoded-secret"
        );
    }

    #[test]
    fn runtime_boundaries_reject_path_bearing_code_identity() {
        assert!(validate_canonical_check_id("code_scan.hardcoded-secret").is_ok());
        assert!(validate_canonical_check_id("security.csp").is_ok());
        let error = validate_canonical_check_id("code_scan.hardcoded-secret:src/env.ts")
            .expect_err("legacy location-bearing ids must stop at migration");
        assert!(error.contains("structured occurrence target"));
    }

    #[test]
    fn code_issue_serializes_check_id_as_camel_case() {
        // The frontend addresses code issues by checkId; pin the serde rename so
        // the camelCase key the TS CodeIssue interface expects keeps shipping.
        let issue = sample_issue("supply_chain_typosquat");
        let json = serde_json::to_value(&issue).unwrap();
        assert_eq!(
            json.get("checkId").and_then(|v| v.as_str()),
            Some("code_scan.supply_chain_typosquat")
        );
        assert!(
            json.get("check_id").is_none(),
            "check_id must serialize as checkId, not snake_case"
        );
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

    fn issue_with_severity(id: &str, severity: Severity) -> CodeIssue {
        let mut issue = sample_issue(id);
        issue.severity = severity;
        issue
    }

    #[test]
    fn score_report_uses_the_shared_health_model() {
        let one_critical = report_from_issues(vec![issue_with_severity(
            "rule-a:src/a.ts",
            Severity::Critical,
        )]);
        assert_eq!(score_report(&one_critical), 85);
        let one_high =
            report_from_issues(vec![issue_with_severity("rule-a:src/a.ts", Severity::High)]);
        assert_eq!(score_report(&one_high), 91);

        // A Critical cap-class finding with explicit High confidence still
        // force-caps in the red.
        let exploitable = report_from_issues(vec![issue_with_severity(
            "js-command-injection:src/a.ts",
            Severity::Critical,
        )]);
        assert!(
            score_report(&exploitable) <= 49,
            "an exploitable finding must cap the code score in the red"
        );
    }

    #[test]
    fn score_report_scores_deduped_rules_not_per_file_counts() {
        // One canonical rule deducts once regardless of file count.
        let multi_file = report_from_issues(vec![
            issue_with_severity("rule-a:src/a.ts", Severity::High),
            issue_with_severity("rule-a:src/b.ts", Severity::High),
            issue_with_severity("rule-a:src/c.ts", Severity::High),
        ]);
        let single_file =
            report_from_issues(vec![issue_with_severity("rule-a:src/a.ts", Severity::High)]);
        assert_eq!(score_report(&multi_file), score_report(&single_file));

        let distinct_rules = report_from_issues(vec![
            issue_with_severity("rule-a:src/a.ts", Severity::High),
            issue_with_severity("rule-b:src/a.ts", Severity::High),
            issue_with_severity("rule-c:src/a.ts", Severity::High),
        ]);
        assert!(
            score_report(&distinct_rules) < score_report(&multi_file),
            "distinct rules must keep deducting"
        );
    }

    #[test]
    fn canonical_identity_rewrite_is_score_invariant() {
        let mut legacy = report_from_issues(vec![
            issue_with_severity("rule-a:src/a.ts", Severity::High),
            issue_with_severity("rule-a:src/b.ts", Severity::Critical),
            issue_with_severity("rule-b:src/c.ts", Severity::Medium),
        ]);
        for issue in &mut legacy.issues {
            issue.check_id = format!("code_scan.{}", issue.id);
        }
        let mut canonical = legacy.clone();
        for issue in &mut canonical.issues {
            issue.check_id = canonical_code_check_id(&issue.id);
        }

        assert_eq!(
            score_report(&legacy),
            score_report(&canonical),
            "moving location out of canonical identity must not move the SiteCMD Score"
        );
    }

    #[test]
    fn score_report_row_severity_is_the_max_across_files() {
        // The canonical row keeps the highest severity across files.
        let mixed = report_from_issues(vec![
            issue_with_severity("rule-a:src/a.ts", Severity::Low),
            issue_with_severity("rule-a:src/z.ts", Severity::Critical),
        ]);
        let one_critical = report_from_issues(vec![issue_with_severity(
            "rule-a:src/z.ts",
            Severity::Critical,
        )]);
        assert_eq!(score_report(&mixed), score_report(&one_critical));
        assert_eq!(score_report(&mixed), 85);
    }

    #[test]
    fn needs_review_exploitable_does_not_cap_the_code_score() {
        let mut issue = issue_with_severity("js-command-injection:src/a.ts", Severity::Critical);
        issue.confidence = IssueConfidence::NeedsReview;
        let report = report_from_issues(vec![issue]);
        assert_eq!(score_report(&report), 92);
    }

    #[test]
    fn noncritical_cap_class_issue_does_not_cap_even_at_high_confidence() {
        let mut issue = issue_with_severity("python-command-injection:src/a.py", Severity::High);
        issue.confidence = IssueConfidence::High;
        let report = report_from_issues(vec![issue]);
        assert_eq!(score_report(&report), 91);
    }

    #[test]
    fn code_issue_view_carries_check_id_from_issue() {
        // CodeIssueView is the report payload the frontend actually receives; it
        // must mirror the source CodeIssue check_id verbatim.
        let issue = sample_issue("supply_chain_typosquat");
        let view = CodeIssueView::from(&issue);
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
    fn code_issue_view_backfills_empty_check_id() {
        let mut issue = sample_issue("supply_chain_typosquat");
        issue.check_id = String::new();
        let view = CodeIssueView::from_issue_with_domain(issue, CodeScanDomain::Security);
        assert_eq!(view.check_id, "code_scan.supply_chain_typosquat");
    }

    #[test]
    fn borrowed_code_issue_view_and_report_backfill_empty_check_id() {
        let mut issue = sample_issue("supply_chain_typosquat");
        issue.check_id = String::new();

        let borrowed = CodeIssueView::from(&issue);
        assert_eq!(borrowed.check_id, "code_scan.supply_chain_typosquat");

        let report = report_from_issues(vec![issue]);
        let report_view = CodeScanReportView::from(&report);
        assert_eq!(
            report_view.issues[0].check_id,
            "code_scan.supply_chain_typosquat"
        );
    }

    #[test]
    fn ai_scaffolding_category_routes_to_ai_scaffolding_domain() {
        // An issue stamped with the ai-scaffolding category must route to the
        // dedicated domain, NOT AiSafety, even though both are "AI". The id does
        // not start with "ai-", so the AiSafety id-prefix branch must not catch it.
        let mut issue = sample_issue("agent-instructions-stub:CLAUDE.md");
        issue.category = "ai-scaffolding".to_string();
        assert_eq!(code_issue_domain(&issue), CodeScanDomain::AiScaffolding);
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
