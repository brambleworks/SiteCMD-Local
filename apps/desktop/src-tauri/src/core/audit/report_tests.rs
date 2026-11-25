use super::session_host::{report::native_report, SessionReport};
use super::{list_project, published_issue, CodeIssue, ProjectListing};
use sitecmd_protocol::engine_abi::{AuditFailure, AuditIssue, AuditReport};
use sitecmd_protocol::vocab::{IssueConfidence, Severity};

fn populated_issue() -> CodeIssue {
    CodeIssue {
        id: "example-rule:src/lib.rs:23".into(),
        check_id: "code_scan.example-rule".into(),
        category: "security".into(),
        severity: Severity::High,
        title: "Finding title".into(),
        description: "Finding description".into(),
        relative_path: "src/lib.rs".into(),
        absolute_path: "/workspace/src/lib.rs".into(),
        line: Some(23),
        evidence: Some("Observed value".into()),
        why_now: Some("Finding impact".into()),
        likely_fix: Some("Suggested change".into()),
        confidence: IssueConfidence::Confirmed,
        confidence_reason: Some("Observed directly".into()),
        verify_hint: Some("Run the check again".into()),
    }
}

fn report_with_issue() -> (tempfile::TempDir, ProjectListing, SessionReport) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(root.path().join("src/lib.rs"), "fn main() {}").unwrap();
    let listing = list_project(root.path()).unwrap();
    let mut issue = populated_issue();
    issue.id = "standin.rule:src/lib.rs:23".into();
    issue.check_id = "code_scan.standin.rule".into();
    let report = SessionReport {
        report: AuditReport {
            checked_at: "1970-01-01T00:00:00+00:00".into(),
            framework: None,
            issue_count: 1,
            critical_count: 0,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
            issues: vec![AuditIssue::try_from(issue).unwrap()],
            skipped_scopes: Default::default(),
            coverage: vec![],
        },
        files: vec![],
    };
    (root, listing, report)
}

#[test]
fn an_issue_with_an_unlisted_rule_is_refused() {
    // A module answer the host prints without checking.
    let (_root, listing, report) = report_with_issue();
    let mut info = sitecmd_engine_host::load().unwrap().info().clone();
    info.code_rules.clear();
    assert_eq!(
        native_report(report, &listing, 0, &info).unwrap_err(),
        AuditFailure::AnalysisFailed("The engine reported an unknown Code Scan rule.".into())
    );
}

#[test]
fn an_issue_whose_check_id_differs_from_its_rule_is_refused() {
    // A module answer the host prints without checking.
    let (_root, listing, mut report) = report_with_issue();
    let mut info = sitecmd_engine_host::load().unwrap().info().clone();
    let mut rule = info.code_rules[0].clone();
    rule.id = report.report.issues[0].rule_id.clone();
    rule.check_id = report.report.issues[0].check_id.clone();
    info.code_rules = vec![rule];
    report.report.issues[0].check_id = "code_scan.example-rule".into();
    assert_eq!(
        native_report(report, &listing, 0, &info).unwrap_err(),
        AuditFailure::AnalysisFailed("The engine reported an inconsistent Code Scan rule.".into())
    );
}

#[test]
fn published_issue_takes_category_and_rationale_from_engine_info() {
    // A module answer the host prints without checking.
    let issue = populated_issue();
    let mut info = sitecmd_engine_host::load().unwrap().info().clone();
    let rule = &mut info.code_rules[0];
    rule.id = "example-rule".into();
    rule.check_id = issue.check_id.clone();
    rule.category = sitecmd_protocol::vocab::Category::Email;
    rule.rationale = Some("Module rationale.".into());
    let published = published_issue(&issue, &info).unwrap();
    assert_eq!(published.category, "email");
    assert_eq!(published.description, "Module rationale.");
}
