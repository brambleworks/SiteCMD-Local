//! Export `ScanResult` data into `.sitecmd/` JSON, issue guidance, and preventive rules.

use std::path::Path;

use crate::core::scan_types::ScanResult;

mod artifacts;
mod fix_prompts;
mod issues_json;
mod issues_markdown;
mod labels;
mod rules_markdown;

use artifacts::build_last_scan_json;
pub(super) use artifacts::write_file;
use fix_prompts::enrich_with_fix_prompts;
use issues_json::build_issues_json;
use issues_markdown::build_issues_md;
pub use labels::verify_hint;
use rules_markdown::build_rules_md;
pub(super) use rules_markdown::render_rules_md;

/// Write the complete scan artifact set under `.sitecmd/`.
pub fn export_scan(sitecmd_dir: &Path, result: &ScanResult) -> Result<(), String> {
    let sanitized = enrich_with_fix_prompts(result.clone())?;
    std::fs::create_dir_all(sitecmd_dir)
        .map_err(|e| format!("failed to create {}: {}", sitecmd_dir.display(), e))?;

    write_file(
        sitecmd_dir,
        "last-scan.json",
        &build_last_scan_json(&sanitized)?,
    )?;
    write_file(sitecmd_dir, "issues.md", &build_issues_md(&sanitized))?;
    write_file(sitecmd_dir, "issues.json", &build_issues_json(&sanitized)?)?;
    write_file(sitecmd_dir, "rules.md", &build_rules_md(&sanitized))?;

    Ok(())
}

pub(super) fn export_native_scan(sitecmd_dir: &Path, scan: &ScanResult) {
    if super::hosted::report::read_artifact(sitecmd_dir).is_ok() {
        return;
    }
    if let Err(e) = export_scan(sitecmd_dir, scan) {
        eprintln!("Warning: failed to export scan results: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan_types::ScanResult;
    use crate::core::scan_types::{Category, CheckResult, CheckStatus, Severity};
    use sitecmd_protocol::score::CategoryScore;

    #[test]
    fn scan_result_preserves_stored_and_exported_json() {
        // Bug: Renaming scan fields breaks saved scans and their issues.json exports.
        let stored = serde_json::json!({
            "url": "https://example.com/",
            "mode": "live",
            "scanType": "security",
            "overallScore": 98,
            "categories": [{
                "category": "security",
                "score": 98,
                "issuesTotal": 0,
                "issuesCritical": 0,
                "issuesHigh": 0,
                "issuesMedium": 0,
                "issuesLow": 0,
                "issuesPassed": 1
            }],
            "issues": [],
            "detectedStack": null,
            "durationMs": 17,
            "timestamp": "2026-11-21T12:00:00Z"
        });
        let result: ScanResult = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&build_last_scan_json(&result).unwrap())
                .unwrap(),
            stored,
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&build_issues_json(&result).unwrap())
                .unwrap(),
            serde_json::json!({
                "url": "https://example.com/",
                "score": 98,
                "scan_type": "security",
                "detected_stack": {},
                "scanned_at": "2026-11-21T12:00:00Z",
                "recoverable_points": 0,
                "issues": [],
                "categories": [{"key": "security", "name": "Security", "score": 98, "issues": 0}],
            }),
        );
    }

    fn make_check_result(
        check_id: &str,
        title: &str,
        category: Category,
        severity: Severity,
        status: CheckStatus,
    ) -> CheckResult {
        CheckResult {
            covered: false,
            check_id: check_id.to_string(),
            category: Some(category),
            title: title.to_string(),
            description: format!("Description for {}", check_id),
            status,
            severity,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::core::scan_types::IssueConfidence::High,
            confidence_reason: None,
            skip_reason: None,
            why_it_matters: None,
        }
    }

    fn make_category_score(category: Category, score: u32) -> CategoryScore {
        CategoryScore {
            category,
            score,
            issues_total: 0,
            issues_critical: 0,
            issues_high: 0,
            issues_medium: 0,
            issues_low: 0,
            issues_passed: 0,
        }
    }

    fn make_scan_result(issues: Vec<CheckResult>) -> ScanResult {
        ScanResult {
            url: "https://example.com".to_string(),
            mode: "live".to_string(),
            scan_type: crate::core::scan_types::ScanType::Health,
            overall_score: 67,
            categories: vec![
                make_category_score(Category::Security, 45),
                make_category_score(Category::Performance, 80),
            ],
            fix_points: vec![0; issues.len()],
            issues,
            detected_stack: Some(serde_json::json!({
                "summary": "Next.js / Vercel",
                "framework": "Next.js",
            })),
            duration_ms: 1200,
            timestamp: "2024-01-15T10:30:00Z".to_string(),
        }
    }

    #[test]
    fn issues_json_omits_unused_points_basis() {
        // issues.json emits an unused explanation field outside its supported shape.
        let result = make_scan_result(vec![]);
        let json: serde_json::Value =
            serde_json::from_str(&build_issues_json(&result).unwrap()).unwrap();
        assert!(json.get("points_basis").is_none());
    }

    #[test]
    fn issues_json_names_categories_by_key_and_label() {
        // issues.json names a category by an old word.
        let spf = make_check_result(
            "security.dns.spf",
            "SPF",
            Category::Email,
            Severity::High,
            CheckStatus::Fail,
        );
        let mut result = make_scan_result(vec![spf]);
        result.categories = vec![
            make_category_score(Category::Email, 88),
            make_category_score(Category::DomainHttps, 90),
        ];
        let json: serde_json::Value =
            serde_json::from_str(&build_issues_json(&result).expect("issues JSON"))
                .expect("valid JSON");
        assert_eq!(json["issues"][0]["category"], "email");
        assert_eq!(json["categories"][0]["key"], "domain_https");
        assert_eq!(json["categories"][0]["name"], "Domain and HTTPS");
        assert_eq!(json["categories"][1]["key"], "email");
        assert_eq!(json["categories"][1]["name"], "Email");
    }

    #[test]
    fn issues_md_header_contains_url_and_score() {
        let result = make_scan_result(vec![]);
        let md = build_issues_md(&result);

        assert!(md.contains("https://example.com"), "should contain URL");
        assert!(md.contains("67/100"), "should contain score");
        assert!(
            md.contains("Next.js / Vercel"),
            "should contain stack summary"
        );
        assert!(md.contains("2024-01-15"), "should contain timestamp");
    }

    #[test]
    fn issues_md_empty_when_no_failures() {
        let result = make_scan_result(vec![make_check_result(
            "security.headers.csp",
            "CSP Header",
            Category::Security,
            Severity::Critical,
            CheckStatus::Pass,
        )]);
        let md = build_issues_md(&result);

        assert!(md.contains("No issues found"), "should say no issues");
        assert!(!md.contains("### 1."), "should not have issue entries");
    }

    #[test]
    fn issues_json_is_valid_json() {
        let issues = vec![make_check_result(
            "security.headers.csp",
            "CSP Header Missing",
            Category::Security,
            Severity::Critical,
            CheckStatus::Fail,
        )];
        let result = make_scan_result(issues);
        let json_str = build_issues_json(&result).expect("should produce valid JSON string");

        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should parse as JSON");

        assert_eq!(parsed["score"], 67);
        assert_eq!(parsed["url"], "https://example.com");
        assert!(!parsed["issues"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rules_md_contains_security_rules() {
        let issues = vec![make_check_result(
            "security.headers.csp",
            "CSP Header Missing",
            Category::Security,
            Severity::Critical,
            CheckStatus::Fail,
        )];
        let result = make_scan_result(issues);
        let md = build_rules_md(&result);

        assert!(md.contains("## Security"), "should have Security section");
        assert!(
            md.contains("Content-Security-Policy"),
            "should contain CSP rule"
        );
    }

    #[test]
    fn rules_md_preserves_context_instead_of_turning_findings_into_absolutes() {
        let issues = vec![
            make_check_result(
                "security.headers.csp",
                "CSP Header Missing",
                Category::Security,
                Severity::High,
                CheckStatus::Fail,
            ),
            make_check_result(
                "security.headers.hsts",
                "HSTS Header Missing",
                Category::DomainHttps,
                Severity::High,
                CheckStatus::Fail,
            ),
            make_check_result(
                "security.headers.x_frame_options",
                "Clickjacking protection missing",
                Category::Security,
                Severity::Medium,
                CheckStatus::Fail,
            ),
            make_check_result(
                "seo.title",
                "Page title needs review",
                Category::Seo,
                Severity::Low,
                CheckStatus::Warn,
            ),
            make_check_result(
                "seo.meta_description",
                "Meta description needs review",
                Category::Seo,
                Severity::Low,
                CheckStatus::Warn,
            ),
            make_check_result(
                "accessibility.image_alt",
                "Image alternative text needs review",
                Category::Accessibility,
                Severity::Medium,
                CheckStatus::Fail,
            ),
        ];

        let md = build_rules_md(&make_scan_result(issues));

        assert!(
            !md.contains("Always include"),
            "rules must stay contextual: {md}"
        );
        assert!(
            !md.contains("50-60"),
            "title length is not a fixed rule: {md}"
        );
        assert!(
            !md.contains("120-160"),
            "snippet length is not a fixed rule: {md}"
        );
        assert!(
            md.contains("report-only") && md.contains("tailor"),
            "CSP rollout context missing: {md}"
        );
        assert!(
            md.contains("subdomain") && md.contains("rollout"),
            "HSTS rollout context missing: {md}"
        );
        assert!(
            md.contains("embedding requirements"),
            "framing policy must reflect product needs: {md}"
        );
        assert!(
            md.contains("rendered width"),
            "title guidance should reflect display behavior: {md}"
        );
        assert!(
            md.contains("rewrite"),
            "snippet guidance must disclose search-engine rewriting: {md}"
        );
        assert!(
            md.contains("empty alt"),
            "decorative-image behavior must be preserved: {md}"
        );
    }

    #[test]
    fn generic_rules_do_not_convert_a_missing_title_into_an_universal_requirement() {
        let issue = make_check_result(
            "config.print_stylesheet",
            "Missing optional integration marker",
            Category::Polish,
            Severity::Low,
            CheckStatus::Warn,
        );

        let md = build_rules_md(&make_scan_result(vec![issue]));

        assert!(md.contains("Review finding: Missing optional integration marker"));
        assert!(!md.contains("Always include optional integration marker"));
    }

    #[test]
    fn verify_hint_for_security_header() {
        let hint = verify_hint("security.headers.csp", "https://example.com");
        assert!(
            hint.starts_with("curl -sI"),
            "should be a curl command, got: {}",
            hint
        );
        assert!(hint.contains("https://example.com"), "should contain URL");
    }

    #[test]
    fn verify_hint_fallback() {
        let hint = verify_hint("seo.meta_description", "https://example.com");
        assert_eq!(hint, "sitecmd scan --diff");
    }

    #[test]
    fn every_tier_exports_complete_fix_guidance() {
        let mut issue = make_check_result(
            "security.headers.csp",
            "CSP Header Missing",
            Category::Security,
            Severity::Critical,
            CheckStatus::Fail,
        );
        issue.fix_prompt = Some("Add a CSP header.".into());
        issue.manual_fix = Some("Set Content-Security-Policy in the server config.".into());

        let dir = tempfile::tempdir().expect("temp dir");
        export_scan(dir.path(), &make_scan_result(vec![issue]))
            .expect("free export should succeed");
        let md = std::fs::read_to_string(dir.path().join("issues.md")).expect("issues.md");

        assert!(md.contains("Set Content-Security-Policy in the server config."));
    }

    #[test]
    fn export_scan_writes_complete_last_scan_json() {
        let mut issue = make_check_result(
            "security.headers.csp",
            "CSP Header Missing",
            Category::Security,
            Severity::Critical,
            CheckStatus::Fail,
        );
        issue.fix_prompt = Some("Add a CSP header.".into());
        issue.manual_fix = Some("Set Content-Security-Policy in the server config.".into());
        issue.raw_data = Some(serde_json::json!({ "header": null }));

        let dir = tempfile::tempdir().expect("temp dir");
        export_scan(dir.path(), &make_scan_result(vec![issue]))
            .expect("free export should succeed");

        let stored = std::fs::read_to_string(dir.path().join("last-scan.json"))
            .expect("last-scan.json should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&stored).expect("last-scan.json should parse");

        assert_eq!(parsed["issues"][0]["fixPrompt"], "Add a CSP header.");
        assert_eq!(
            parsed["issues"][0]["manualFix"],
            "Set Content-Security-Policy in the server config."
        );
        assert!(!parsed["issues"][0]["rawData"].is_null());
    }

    #[test]
    fn export_scan_writes_a_module_prompt_for_a_finding_without_one() {
        // Export can drop module guidance when the original finding has no prompt.
        let issue = make_check_result(
            "standin.rule",
            "Sample finding",
            Category::Reliability,
            Severity::Critical,
            CheckStatus::Fail,
        );

        let result = make_scan_result(vec![issue]);
        let expected =
            crate::core::fixes::one_fix_text(sitecmd_protocol::engine_abi::FixTextTarget::Web {
                issue: Box::new(result.issues[0].clone()),
                url: result.url.clone(),
                detected_stack: result.detected_stack.clone(),
            })
            .expect("module prompt");
        assert!(!expected.is_empty());
        let dir = tempfile::tempdir().expect("temp dir");
        export_scan(dir.path(), &result).expect("core export should succeed");

        let stored = std::fs::read_to_string(dir.path().join("last-scan.json"))
            .expect("last-scan.json should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&stored).expect("last-scan.json should parse");

        let stored_issue = &parsed["issues"][0];
        assert_eq!(stored_issue["fixPrompt"], expected);
        assert_eq!(stored_issue["title"], result.issues[0].title);
    }
}
