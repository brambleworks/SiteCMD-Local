//! Converts scan evidence into persistent work items and regression comparisons.

use crate::checks::{CheckResult, CheckStatus, Severity};
use crate::core::code_scan::{code_issue_domain, CodeIssue};
use crate::db::work_items::{WorkItemInput, WorkItemMetadata};
use crate::db::{Database, DbError};
use std::collections::HashMap;
use std::sync::Arc;

/// Convert a code issue into a stable, upsertable work item.
/// Framework detection is passed in once per scan for specific fix prompts.
pub fn code_issue_to_work_item_input(
    issue: &CodeIssue,
    project_id: i64,
    env_url: &str,
    code_scan_id: i64,
    now_ms: i64,
    framework: Option<&'static str>,
) -> WorkItemInput {
    let file = issue.relative_path.as_str();
    let line = issue.line.map(|l| l.to_string()).unwrap_or_default();
    let severity = issue.severity;
    // Resolve the producer rule before location is attached. Path and line are
    // occurrence evidence, never lifecycle identity.
    let producer_rule = crate::core::code_scan::code_producer_rule_id(&issue.id);
    let check_id = crate::core::code_scan::canonical_code_check_id(&issue.id);
    let fix_prompt = Some(crate::ai::build_code_fix_prompt_with_framework(
        issue,
        framework.unwrap_or("not detected"),
    ));
    WorkItemInput {
        project_id,
        env_url: env_url.to_string(),
        source: "code_scan".to_string(),
        signal_id: format!("code_scan:{}:{}:{}", issue.id, file, line),
        check_id,
        category: "code_quality".to_string(),
        severity,
        title: issue.title.clone(),
        description: issue.description.clone(),
        detail_json: Some(
            serde_json::to_string(issue).expect("CodeIssue serialization is infallible"), // allow-expect: CodeIssue contains only JSON-safe data.
        ),
        scan_ref: Some(code_scan_id),
        page_url: None,
        fix_prompt,
        // Code guidance recovery reads the full CodeIssue from detail_json
        // above (why_now/likely_fix included), so the columns stay NULL here.
        manual_fix: None,
        why_it_matters: None,
        observed_at: now_ms,
        metadata: WorkItemMetadata {
            confidence: Some(issue.confidence),
            confidence_reason: issue.confidence_reason.clone(),
            domain: Some(code_issue_domain(issue)),
            relative_path: Some(issue.relative_path.clone()),
            line: issue.line,
            check_status: None,
            producer_check_id: Some(producer_rule.to_string()),
            producer_fix_prompt: None,
            producer_category: None,
        },
    }
}

/// Return check IDs that worsened since the previous scan for this environment.
/// `None` means no regressions.
pub fn compute_regressed_check_ids_from_map(
    db: &Arc<Database>,
    env_url: &str,
    current_scan_id: i64,
    current_severities: &HashMap<String, &'static str>,
    source: &str,
) -> Result<Option<Vec<String>>, DbError> {
    if current_severities.is_empty() {
        return Ok(None);
    }

    let prior = db.get_prior_scan_check_severities(env_url, current_scan_id, source)?;

    let mut regressed: Vec<String> = current_severities
        .iter()
        .filter(|(cid, current_sev)| {
            let prior_rank = prior
                .get(*cid)
                .map(|s| Severity::impact_rank_for_label(s))
                .unwrap_or(0);
            Severity::impact_rank_for_label(current_sev) > prior_rank
        })
        .map(|(cid, _)| cid.clone())
        .collect();

    if regressed.is_empty() {
        return Ok(None);
    }

    regressed.sort(); // deterministic ordering for tests
    Ok(Some(regressed))
}

/// Compute regressed check_ids from a web_scan `ScanResult` issues slice.
pub fn compute_regressed_check_ids(
    db: &Arc<Database>,
    env_url: &str,
    current_scan_id: i64,
    current_issues: &[CheckResult],
    source: &str,
) -> Result<Option<Vec<String>>, DbError> {
    let mut current_severities: HashMap<String, &'static str> = HashMap::new();
    for issue in current_issues
        .iter()
        .filter(|issue| !matches!(issue.status, CheckStatus::Pass | CheckStatus::Skipped))
    {
        let canonical = crate::core::correlation::resolve_check_id("web_scan", &issue.check_id);
        let severity = issue.severity.as_str();
        current_severities
            .entry(canonical)
            .and_modify(|stored| {
                if Severity::impact_rank_for_label(severity)
                    > Severity::impact_rank_for_label(stored)
                {
                    *stored = severity;
                }
            })
            .or_insert(severity);
    }
    compute_regressed_check_ids_from_map(db, env_url, current_scan_id, &current_severities, source)
}

/// Convert a result into a page-scoped work-item occurrence.
pub fn check_result_to_work_item_input(
    cr: &CheckResult,
    project_id: i64,
    env_url: &str,
    scan_ref: i64,
    now_ms: i64,
    detected_stack: Option<&serde_json::Value>,
) -> WorkItemInput {
    check_result_to_scoped_work_item_input(
        cr,
        project_id,
        env_url,
        env_url,
        scan_ref,
        now_ms,
        detected_stack,
    )
}

pub fn check_result_to_page_work_item_input(
    cr: &CheckResult,
    project_id: i64,
    env_url: &str,
    page_url: &str,
    scan_ref: i64,
    now_ms: i64,
    detected_stack: Option<&serde_json::Value>,
) -> WorkItemInput {
    check_result_to_scoped_work_item_input(
        cr,
        project_id,
        env_url,
        page_url,
        scan_ref,
        now_ms,
        detected_stack,
    )
}

fn check_result_to_scoped_work_item_input(
    cr: &CheckResult,
    project_id: i64,
    env_url: &str,
    page_url: &str,
    scan_ref: i64,
    now_ms: i64,
    detected_stack: Option<&serde_json::Value>,
) -> WorkItemInput {
    let category = match cr.category {
        crate::checks::ScanCategory::Config => "compliance",
        _ => cr.category.as_str(),
    };
    let severity = cr.severity;
    let fix_prompt = if matches!(cr.status, CheckStatus::Fail | CheckStatus::Warn) {
        Some(crate::ai::build_fix_prompt(cr, page_url, detected_stack))
    } else {
        None
    };
    let canonical_check_id = crate::core::correlation::resolve_check_id("web_scan", &cr.check_id);
    WorkItemInput {
        project_id,
        env_url: env_url.to_string(),
        source: "web_scan".to_string(),
        // Keep raw signal identity; canonicalization belongs at grouping time.
        signal_id: format!("web_scan:{}:{}", cr.check_id, page_url),
        check_id: canonical_check_id,
        category: category.to_string(),
        severity,
        title: cr.title.clone(),
        description: cr.description.clone(),
        detail_json: cr.raw_data.as_ref().map(|value| {
            serde_json::to_string(value).expect("Value is valid JSON") // allow-expect: serde_json::Value cannot contain invalid JSON.
        }),
        scan_ref: Some(scan_ref),
        page_url: Some(page_url.to_string()),
        fix_prompt,
        manual_fix: cr.manual_fix.clone(),
        why_it_matters: cr.why_it_matters.clone(),
        observed_at: now_ms,
        // Web checks have no file/domain; confidence still feeds the score's
        // exploitable-cap gate.
        metadata: WorkItemMetadata {
            confidence: Some(cr.confidence),
            check_status: Some(cr.status),
            confidence_reason: cr.confidence_reason.clone(),
            producer_check_id: Some(cr.check_id.clone()),
            producer_fix_prompt: cr.fix_prompt.clone(),
            producer_category: Some(cr.category),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{CheckResult, CheckStatus, IssueConfidence, ScanCategory, Severity};
    use crate::core::scanner::ScanResult;
    use crate::db::test_helpers::temp_db_arc;
    use crate::db::work_items::WorkItemInput;

    fn make_check_result(check_id: &str, sev: Severity, status: CheckStatus) -> CheckResult {
        CheckResult {
            check_id: check_id.to_string(),
            category: ScanCategory::Performance,
            severity: sev,
            status,
            title: format!("Check {}", check_id),
            description: "test".to_string(),
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    }

    fn make_work_item_input(
        check_id: &str,
        severity: &str,
        scan_id: i64,
        project_id: i64,
    ) -> WorkItemInput {
        WorkItemInput {
            project_id,
            env_url: "https://example.com".to_string(),
            source: "web_scan".to_string(),
            signal_id: format!("web_scan:{}:https://example.com", check_id),
            check_id: check_id.to_string(),
            category: "performance".to_string(),
            severity: severity.parse().expect("valid severity"),
            title: format!("Check {}", check_id),
            description: "test".to_string(),
            detail_json: None,
            scan_ref: Some(scan_id),
            page_url: Some("https://example.com".to_string()),
            fix_prompt: None,
            manual_fix: None,
            why_it_matters: None,
            observed_at: 1_000,
            metadata: WorkItemMetadata::default(),
        }
    }

    fn make_scan_result(score: u32, ts: &str) -> ScanResult {
        ScanResult {
            page_signals: None,
            site_facts: None,
            url: "https://example.com".to_string(),
            mode: "full".to_string(),
            scan_type: crate::core::scanner::ScanType::Health,
            overall_score: score,
            categories: vec![],
            issues: vec![],
            detected_stack: None,
            duration_ms: 1000,
            timestamp: ts.to_string(),
        }
    }

    #[test]
    fn scan_completion_stamps_regressed_check_ids() {
        let td = temp_db_arc();
        let db = td.db.clone();
        let project_id = db
            .upsert_project("test", "/tmp/test-regress", None)
            .unwrap();
        let site_id = db.get_or_create_site("https://example.com").unwrap();

        // Prior scan with lcp at medium.
        let mut prior_result = make_scan_result(80, "2025-01-01T00:00:00Z");
        prior_result.issues = vec![make_check_result(
            "performance.lcp",
            Severity::Medium,
            CheckStatus::Fail,
        )];
        let prior_id = db.save_scan(site_id, &prior_result).unwrap();
        db.upsert_work_items_diff(
            "web_scan",
            project_id,
            "https://example.com",
            vec![make_work_item_input(
                "performance.lcp",
                "medium",
                prior_id,
                project_id,
            )],
            1_000,
        )
        .unwrap();

        // Current scan: lcp worsened to high.
        let current_result = make_scan_result(70, "2025-01-02T00:00:00Z");
        let current_id = db.save_scan(site_id, &current_result).unwrap();

        let current_issues = vec![make_check_result(
            "performance.lcp",
            Severity::High,
            CheckStatus::Fail,
        )];

        let regressed = compute_regressed_check_ids(
            &db,
            "https://example.com",
            current_id,
            &current_issues,
            "web_scan",
        )
        .expect("compare prior scan");

        assert_eq!(
            regressed,
            Some(vec!["performance.lcp".to_string()]),
            "lcp worsened from medium to high - should appear in regressed set"
        );
    }

    #[test]
    fn scan_completion_no_check_ids_when_nothing_regressed() {
        let td = temp_db_arc();
        let db = td.db.clone();
        let project_id = db
            .upsert_project("test", "/tmp/test-no-regress", None)
            .unwrap();
        let site_id = db.get_or_create_site("https://example.com").unwrap();

        // Prior scan with lcp at high.
        let mut prior_result = make_scan_result(70, "2025-01-01T00:00:00Z");
        prior_result.issues = vec![make_check_result(
            "performance.lcp",
            Severity::High,
            CheckStatus::Fail,
        )];
        let prior_id = db.save_scan(site_id, &prior_result).unwrap();
        db.upsert_work_items_diff(
            "web_scan",
            project_id,
            "https://example.com",
            vec![make_work_item_input(
                "performance.lcp",
                "high",
                prior_id,
                project_id,
            )],
            1_000,
        )
        .unwrap();

        // Current scan: lcp still at high - no regression.
        let current_result = make_scan_result(70, "2025-01-02T00:00:00Z");
        let current_id = db.save_scan(site_id, &current_result).unwrap();

        let current_issues = vec![make_check_result(
            "performance.lcp",
            Severity::High,
            CheckStatus::Fail,
        )];

        let regressed = compute_regressed_check_ids(
            &db,
            "https://example.com",
            current_id,
            &current_issues,
            "web_scan",
        )
        .expect("compare prior scan");

        assert_eq!(
            regressed, None,
            "lcp stayed at high - no regression - should be None"
        );
    }

    #[test]
    fn scan_completion_compares_web_aliases_by_canonical_check_id() {
        let td = temp_db_arc();
        let db = td.db.clone();
        let project_id = db
            .upsert_project("test", "/tmp/test-alias-no-regress", None)
            .unwrap();
        let site_id = db.get_or_create_site("https://example.com").unwrap();

        let mut prior_result = make_scan_result(70, "2025-01-01T00:00:00Z");
        prior_result.issues = vec![make_check_result(
            "security.csp",
            Severity::High,
            CheckStatus::Fail,
        )];
        let prior_id = db.save_scan(site_id, &prior_result).unwrap();
        db.upsert_work_items_diff(
            "web_scan",
            project_id,
            "https://example.com",
            vec![make_work_item_input(
                "security.csp",
                "high",
                prior_id,
                project_id,
            )],
            1_000,
        )
        .unwrap();

        let current_id = db
            .save_scan(site_id, &make_scan_result(70, "2025-01-02T00:00:00Z"))
            .unwrap();
        let current_issues = vec![make_check_result(
            "security.headers.csp",
            Severity::High,
            CheckStatus::Fail,
        )];

        assert_eq!(
            compute_regressed_check_ids(
                &db,
                "https://example.com",
                current_id,
                &current_issues,
                "web_scan",
            )
            .expect("compare prior scan"),
            None,
            "an unchanged alias must compare with its canonical persisted group"
        );
    }
}
