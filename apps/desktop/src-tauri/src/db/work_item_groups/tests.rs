use crate::checks::Severity;
use crate::core::types_work_items::IssueStatus;
use crate::db::test_helpers::{temp_db, TestDb};
use crate::db::work_items::WorkItemInput;
use crate::db::work_items::WorkItemMetadata;
use crate::db::IssueLifecycle;

fn test_db() -> TestDb {
    let db = temp_db();
    db.upsert_project("test", "https://example.com", None)
        .expect("insert test project");
    db
}

#[test]
fn grouped_read_returns_empty_when_no_work_items() {
    let db = test_db();
    let groups = db.get_work_items_grouped(1, None, 1_000).unwrap();
    assert!(groups.is_empty());
}

#[test]
fn grouped_read_deduplicates_by_check_id() {
    let db = test_db();
    let project_id = db
        .upsert_project("Group Test", "/tmp/group-test", Some("nextjs"))
        .expect("upsert project");

    let web_input = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.render_blocking:https://example.com".into(),
        check_id: "performance.render_blocking".into(),
        category: "performance".into(),
        severity: Severity::Medium,
        title: "Render-blocking resources".into(),
        description: "Eliminate render-blocking resources".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    let psi_input = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "psi".into(),
        signal_id: "psi:render-blocking:https://example.com/home".into(),
        check_id: "performance.render_blocking".into(),
        category: "performance".into(),
        severity: Severity::High,
        title: "Render-blocking resources".into(),
        description: "Eliminate render-blocking resources".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![web_input],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff(
        "psi",
        project_id,
        "https://example.com",
        vec![psi_input],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();

    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(g.check_id, "performance.render_blocking");
    assert_eq!(g.instances.len(), 2);
    assert_eq!(g.sources, vec!["psi", "web_scan"]);
    assert_eq!(g.severity, Severity::High);
}

#[test]
fn grouped_read_applies_snoozed_status_and_expires_at_now() {
    let db = test_db();
    let project_id = db
        .upsert_project("Snooze Expiry Test", "/tmp/snooze-expiry", Some("nextjs"))
        .expect("upsert project");

    let input = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:security.csp:https://example.com".into(),
        check_id: "security.csp".into(),
        category: "security".into(),
        severity: Severity::High,
        title: "CSP missing".into(),
        description: "Add a Content Security Policy header".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![input],
        1_000,
    )
    .unwrap();

    db.set_issue_state(
        project_id,
        "https://example.com",
        "security.csp",
        IssueLifecycle::Snoozed { until: 500 },
        100,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].status, IssueStatus::New);
}

#[test]
fn get_inactive_check_ids_returns_only_paused_issues() {
    let db = test_db();
    let project_id = db
        .upsert_project("Inactive Set Test", "/tmp/inactive-set", Some("nextjs"))
        .expect("upsert project");

    let make = |check_id: &str, title: &str| WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: format!("web_scan:{check_id}:https://example.com"),
        check_id: check_id.into(),
        category: "security".into(),
        severity: Severity::High,
        title: title.into(),
        description: "desc".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![
            make("a.active", "Active"),
            make("b.blocked", "Blocked"),
            make("c.ignored", "Ignored"),
        ],
        1_000,
    )
    .unwrap();

    db.set_issue_state(
        project_id,
        "https://example.com",
        "b.blocked",
        IssueLifecycle::Blocked { reason: None },
        100,
    )
    .unwrap();
    db.set_issue_state(
        project_id,
        "https://example.com",
        "c.ignored",
        IssueLifecycle::Ignored,
        100,
    )
    .unwrap();

    db.reset_operation_count();
    let mut inactive = db
        .get_inactive_check_ids(project_id, Some("https://example.com"), 2_000)
        .unwrap();
    inactive.sort();

    assert_eq!(
        inactive,
        vec!["b.blocked".to_string(), "c.ignored".to_string()]
    );
    assert_eq!(
        db.operation_count(),
        2,
        "inactive IDs should read work items and lifecycle state without correlation enrichment"
    );
}

#[test]
fn grouped_read_keeps_environment_specific_issue_state_separate() {
    let db = test_db();
    let project_id = db
        .upsert_project(
            "Env Scoped Group Test",
            "/tmp/env-group-test",
            Some("nextjs"),
        )
        .expect("upsert project");

    let prod_input = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:security.csp:https://example.com".into(),
        check_id: "security.csp".into(),
        category: "security".into(),
        severity: Severity::High,
        title: "CSP missing".into(),
        description: "Add a Content Security Policy header".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let staging_input = WorkItemInput {
        env_url: "https://staging.example.com".into(),
        signal_id: "web_scan:security.csp:https://staging.example.com".into(),
        observed_at: 2_000,
        ..prod_input.clone()
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![prod_input],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://staging.example.com",
        vec![staging_input],
        2_000,
    )
    .unwrap();

    db.set_issue_state(
        project_id,
        "https://example.com",
        "security.csp",
        IssueLifecycle::Ignored,
        3_000,
    )
    .unwrap();
    db.set_issue_state(
        project_id,
        "https://staging.example.com",
        "security.csp",
        IssueLifecycle::Blocked {
            reason: Some("waiting on deploy".to_string()),
        },
        4_000,
    )
    .unwrap();

    let prod_groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 5_000)
        .expect("load prod groups");
    let staging_groups = db
        .get_work_items_grouped(project_id, Some("https://staging.example.com"), 5_000)
        .expect("load staging groups");
    let project_wide_groups = db
        .get_work_items_grouped(project_id, None, 5_000)
        .expect("load project-wide groups");

    assert_eq!(prod_groups.len(), 1);
    assert_eq!(prod_groups[0].status, IssueStatus::Ignored);

    assert_eq!(staging_groups.len(), 1);
    assert_eq!(staging_groups[0].status, IssueStatus::Blocked);
    assert_eq!(
        staging_groups[0].block_reason.as_deref(),
        Some("waiting on deploy")
    );

    assert_eq!(project_wide_groups.len(), 1);
    assert_eq!(project_wide_groups[0].status, IssueStatus::New);
    assert_eq!(project_wide_groups[0].instances.len(), 2);
}

#[test]
fn grouped_read_impact_score_sorts_descending() {
    let db = test_db();
    let project_id = db
        .upsert_project("Sort Test", "/tmp/sort-test", Some("nextjs"))
        .expect("upsert project");

    let low_item = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:polish.font-display:https://example.com".into(),
        check_id: "polish.font-display".into(),
        category: "polish".into(),
        severity: Severity::Low,
        title: "Font display".into(),
        description: "Use font-display swap".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let med_item = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.ttfb:https://example.com".into(),
        check_id: "performance.ttfb".into(),
        category: "performance".into(),
        severity: Severity::Medium,
        title: "TTFB".into(),
        description: "Reduce server response time".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let high_item = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:security.https:https://example.com".into(),
        check_id: "security.https".into(),
        category: "security".into(),
        severity: Severity::Critical,
        title: "HTTPS not enforced".into(),
        description: "Enforce HTTPS for all traffic".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![low_item, med_item, high_item],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();

    assert_eq!(groups.len(), 3);
    for i in 0..groups.len() - 1 {
        assert!(groups[i].impact_score >= groups[i + 1].impact_score);
    }
    assert_eq!(groups[0].check_id, "security.https");
}

#[test]
fn grouped_read_populates_likely_causes_when_cause_is_active() {
    let db = test_db();
    seed_active_core_license(&db);
    let project_id = 1;

    let compression = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.compression:https://example.com".into(),
        check_id: "performance.compression".into(),
        category: "performance".into(),
        severity: Severity::Medium,
        title: "Missing compression".into(),
        description: "Enable gzip or brotli".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let lcp = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.lcp:https://example.com".into(),
        check_id: "performance.lcp".into(),
        category: "performance".into(),
        severity: Severity::High,
        title: "Slow LCP".into(),
        description: "LCP exceeds 2.5s".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![compression, lcp],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();
    let lcp_group = groups
        .iter()
        .find(|g| g.check_id == "performance.lcp")
        .expect("lcp group");
    assert!(lcp_group
        .likely_causes
        .iter()
        .any(|c| c.check_id == "performance.compression"));
}

#[test]
fn grouped_read_does_not_populate_causes_when_cause_is_inactive() {
    let db = test_db();
    seed_active_core_license(&db);
    let project_id = 1;

    let lcp = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.lcp:https://example.com".into(),
        check_id: "performance.lcp".into(),
        category: "performance".into(),
        severity: Severity::High,
        title: "Slow LCP".into(),
        description: "LCP exceeds 2.5s".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![lcp],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();
    let lcp_group = groups
        .iter()
        .find(|g| g.check_id == "performance.lcp")
        .expect("lcp group");
    assert!(lcp_group.likely_causes.is_empty());
}

#[test]
fn cross_source_canonical_check_id_produces_one_group() {
    use crate::core::correlation::resolve_check_id;

    let db = test_db();
    let project_id = 1;

    let check_id_web = "performance.cache_headers".to_string();
    let check_id_psi = resolve_check_id("psi", "uses-long-cache-ttl");
    let check_id_cf = resolve_check_id("cloudflare", "cache-hit-low");

    assert_eq!(check_id_web, check_id_psi);
    assert_eq!(check_id_psi, check_id_cf);

    let mk = |source: &str, check_id: &str, signal_id: &str| WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: source.into(),
        signal_id: signal_id.into(),
        check_id: check_id.into(),
        category: "performance".into(),
        severity: Severity::Medium,
        title: "Cache headers".into(),
        description: "Missing long cache-control".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![mk(
            "web_scan",
            &check_id_web,
            "web_scan:performance.cache_headers:https://example.com",
        )],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff(
        "psi",
        project_id,
        "https://example.com",
        vec![mk(
            "psi",
            &check_id_psi,
            "psi:uses-long-cache-ttl:https://example.com/home",
        )],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff(
        "cloudflare",
        project_id,
        "https://example.com",
        vec![mk(
            "cloudflare",
            &check_id_cf,
            "cloudflare:cache-hit-low:example.com",
        )],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].check_id, "performance.cache_headers");
    assert_eq!(groups[0].sources, vec!["cloudflare", "psi", "web_scan"]);
    assert_eq!(groups[0].instances.len(), 3);
}

#[test]
fn get_pages_with_issues_only_returns_findings_tied_to_real_pages() {
    let db = test_db();
    let project_id = 1;

    let page_item = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.lcp:https://example.com/pricing".into(),
        check_id: "performance.lcp".into(),
        category: "performance".into(),
        severity: Severity::High,
        title: "Slow LCP".into(),
        description: "/pricing is slow".into(),
        detail_json: None,
        scan_ref: None,
        page_url: Some("https://example.com/pricing".into()),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let mut duplicate_page_item = page_item.clone();
    duplicate_page_item.signal_id =
        "web_scan:performance.lcp:https://example.com/pricing#hero".into();
    let blocked_page_item = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:security.headers:https://example.com/pricing".into(),
        check_id: "security.headers".into(),
        category: "security".into(),
        severity: Severity::Critical,
        title: "Security headers missing".into(),
        description: "Headers are missing on /pricing".into(),
        detail_json: None,
        scan_ref: None,
        page_url: Some("https://example.com/pricing".into()),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let wide_item = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "updates".into(),
        signal_id: "updates:vulnerability:npm:lodash".into(),
        check_id: "dependencies.vulnerability".into(),
        category: "dependencies".into(),
        severity: Severity::Critical,
        title: "CVE".into(),
        description: "".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![page_item, duplicate_page_item, blocked_page_item],
        1_000,
    )
    .unwrap();
    db.upsert_work_items_diff(
        "updates",
        project_id,
        "https://example.com",
        vec![wide_item],
        1_000,
    )
    .unwrap();
    db.set_issue_state(
        project_id,
        "https://example.com",
        "security.headers",
        IssueLifecycle::Blocked {
            reason: Some("Accepted risk".into()),
        },
        1_000,
    )
    .unwrap();

    let pages = db
        .get_pages_with_issues(project_id, "https://example.com", 1_000)
        .unwrap();
    assert_eq!(pages.len(), 1);
    assert!(pages.iter().all(|page| page.page_url != "__project_wide__"));
    let pricing = pages
        .iter()
        .find(|p| p.page_url == "https://example.com/pricing")
        .expect("/pricing page");
    assert_eq!(pricing.max_severity, Severity::High);
    assert_eq!(pricing.issue_count, 1);
}

#[test]
fn get_work_items_grouped_for_page_filters_to_that_page() {
    let db = test_db();
    let project_id = 1;

    let on_pricing = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.lcp:https://example.com/pricing".into(),
        check_id: "performance.lcp".into(),
        category: "performance".into(),
        severity: Severity::Medium,
        title: "Slow LCP on /pricing".into(),
        description: "".into(),
        detail_json: None,
        scan_ref: None,
        page_url: Some("https://example.com/pricing".into()),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    let on_blog = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.lcp:https://example.com/blog".into(),
        check_id: "performance.lcp".into(),
        category: "performance".into(),
        severity: Severity::High,
        title: "Slow LCP on /blog".into(),
        description: "".into(),
        detail_json: None,
        scan_ref: None,
        page_url: Some("https://example.com/blog".into()),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![on_blog, on_pricing],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped_for_page(
            project_id,
            "https://example.com",
            "https://example.com/pricing",
            1_000,
        )
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].instances.len(), 1);
    assert_eq!(groups[0].severity, Severity::Medium);
    assert_eq!(groups[0].title, "Slow LCP on /pricing");
    assert_eq!(
        groups[0].instances[0].page_url.as_deref(),
        Some("https://example.com/pricing")
    );

    db.set_issue_state(
        project_id,
        "https://example.com",
        "performance.lcp",
        IssueLifecycle::Blocked {
            reason: Some("Accepted risk".into()),
        },
        1_000,
    )
    .unwrap();
    let blocked_groups = db
        .get_work_items_grouped_for_page(
            project_id,
            "https://example.com",
            "https://example.com/pricing",
            1_000,
        )
        .unwrap();
    assert!(blocked_groups.is_empty());
}

#[test]
fn grouped_read_populates_suggested_integrations_when_not_connected() {
    let db = test_db();
    seed_active_core_license(&db);
    let project_id = 1;

    let lcp = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:performance.lcp:https://example.com".into(),
        check_id: "performance.lcp".into(),
        category: "performance".into(),
        severity: Severity::High,
        title: "Slow LCP".into(),
        description: "".into(),
        detail_json: None,
        scan_ref: None,
        page_url: Some("https://example.com".into()),
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![lcp],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();
    let lcp_group = groups
        .iter()
        .find(|g| g.check_id == "performance.lcp")
        .unwrap();
    assert!(!lcp_group.suggested_integrations.is_empty());
    assert!(lcp_group.suggested_integrations.len() <= 2);
}

#[test]
fn get_work_items_grouped_for_page_project_wide_returns_null_page_rows() {
    let db = test_db();
    let project_id = 1;

    let wide = WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "updates".into(),
        signal_id: "updates:vulnerability:npm:foo".into(),
        check_id: "dependencies.vulnerability".into(),
        category: "dependencies".into(),
        severity: Severity::High,
        title: "CVE".into(),
        description: "".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };
    db.upsert_work_items_diff(
        "updates",
        project_id,
        "https://example.com",
        vec![wide],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped_for_page(
            project_id,
            "https://example.com",
            "__project_wide__",
            1_000,
        )
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].check_id, "dependencies.vulnerability");
}

#[test]
fn unenriched_grouping_yields_the_same_score_as_the_enriched_pass() {
    let db = test_db();
    let project_id = db
        .upsert_project("Score Parity", "/tmp/score-parity", Some("nextjs"))
        .expect("upsert project");
    let env = "https://example.com";

    let item = |source: &str, signal: &str, check_id: &str, severity: &str| WorkItemInput {
        project_id,
        env_url: env.into(),
        source: source.into(),
        signal_id: signal.into(),
        check_id: check_id.into(),
        category: "security".into(),
        severity: severity.parse().expect("valid severity"),
        title: "t".into(),
        description: "d".into(),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    };

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        env,
        vec![
            item("web_scan", "web:csp", "security.csp", "critical"),
            item("web_scan", "web:hsts", "security.hsts", "high"),
            item("web_scan", "web:title", "seo.title", "medium"),
        ],
        1_000,
    )
    .unwrap();
    // A multi-location code rule must dedupe to one display row in the score.
    db.upsert_work_items_diff(
        "code_scan",
        project_id,
        env,
        vec![
            item("code_scan", "code:a", "code_scan.n-plus-one-query", "high"),
            item("code_scan", "code:b", "code_scan.n-plus-one-query", "high"),
        ],
        1_000,
    )
    .unwrap();

    // Block one issue so the active-status filter is exercised in both paths.
    db.set_issue_state(
        project_id,
        env,
        "security.hsts",
        IssueLifecycle::Blocked { reason: None },
        2_000,
    )
    .unwrap();

    let now = 3_000;
    let enriched = db
        .get_work_items_grouped(project_id, Some(env), now)
        .unwrap();

    db.reset_operation_count();
    let unenriched = db
        .get_active_issue_groups(project_id, Some(env), now)
        .unwrap();
    assert_eq!(
        db.operation_count(),
        2,
        "unenriched grouping must skip the enrichment DB work"
    );

    let enriched_score = crate::scoring::calculator::compute_current_score(&enriched, now);
    let unenriched_score = crate::scoring::calculator::compute_current_score(&unenriched, now);

    assert_eq!(
        unenriched_score.overall, enriched_score.overall,
        "unenriched and enriched groups must yield the same overall score"
    );
    assert_eq!(
        unenriched_score.critical_count,
        enriched_score.critical_count
    );
    assert_eq!(unenriched_score.high_count, enriched_score.high_count);
    assert_eq!(unenriched_score.medium_count, enriched_score.medium_count);
    assert_eq!(unenriched_score.low_count, enriched_score.low_count);

    // Sanity: the seed produces a non-trivial score (csp critical active, the
    // 2-location code rule counted once as high, seo.title medium; hsts blocked).
    assert_eq!(unenriched_score.critical_count, 1);
    assert_eq!(unenriched_score.high_count, 1);
    assert_eq!(unenriched_score.medium_count, 1);
}

// Seed a currently-valid Core license row so `get_effective_tier` resolves
// Core (temp_db has no license row, so the default effective tier is Free).
fn seed_active_core_license(db: &TestDb) {
    use crate::licensing::config::Tier;
    use crate::licensing::store::{self, LicenseState};

    let state = LicenseState {
        license_key: "test-key".into(),
        instance_id: "inst-123".into(),
        variant_id: 42,
        tier: Tier::Core,
        status: "active".into(),
        last_validated_at: chrono::Utc::now().to_rfc3339(),
        activated_at: chrono::Utc::now().to_rfc3339(),
        expires_at: None,
    };
    db.execute(move |conn| store::save(conn, &state).expect("save license"))
        .expect("db worker");
}

fn detail_bearing_input(project_id: i64, detail_json: &str) -> WorkItemInput {
    WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: "web_scan".into(),
        signal_id: "web_scan:security.csp:https://example.com".into(),
        check_id: "security.csp".into(),
        category: "security".into(),
        severity: Severity::High,
        title: "CSP missing".into(),
        description: "Add a Content Security Policy header".into(),
        detail_json: Some(detail_json.into()),
        scan_ref: None,
        page_url: None,
        fix_prompt: Some("Generated agent prompt".into()),
        manual_fix: Some("Manual fix guide".into()),
        why_it_matters: Some("Impact explanation".into()),
        observed_at: 1_000,
        metadata: WorkItemMetadata {
            confidence_reason: Some("Confirmed from response headers".into()),
            producer_fix_prompt: Some("Producer prompt".into()),
            ..WorkItemMetadata::default()
        },
    }
}

#[test]
fn grouped_read_serves_free_tier_the_complete_instances() {
    let db = test_db();
    let project_id = 1;
    let detail = r#"{"confidence":"confirmed","header":"content-security-policy"}"#;

    let mut compression = detail_bearing_input(project_id, detail);
    compression.signal_id = "web_scan:performance.compression:https://example.com".into();
    compression.check_id = "performance.compression".into();
    compression.category = "performance".into();
    compression.title = "Missing compression".into();

    let mut lcp = detail_bearing_input(project_id, detail);
    lcp.signal_id = "web_scan:performance.lcp:https://example.com".into();
    lcp.check_id = "performance.lcp".into();
    lcp.category = "performance".into();
    lcp.title = "Slow LCP".into();

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![detail_bearing_input(project_id, detail), compression, lcp],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();

    assert_eq!(groups.len(), 3);
    let detail_group = groups
        .iter()
        .find(|group| group.check_id == "security.csp")
        .expect("detail-bearing group");
    assert!(
        detail_group.instances[0].detail_json.is_some(),
        "the free workbench serves complete detail_json through the unified read path"
    );
    assert_eq!(
        detail_group.instances[0].why_it_matters.as_deref(),
        Some("Impact explanation")
    );
    assert_eq!(
        detail_group.instances[0].confidence_reason.as_deref(),
        Some("Confirmed from response headers")
    );
}

#[test]
fn grouped_read_preserves_all_guidance_fields() {
    let db = test_db();
    let project_id = 1;
    let detail = r#"{"confidence":"confirmed","header":"content-security-policy"}"#;

    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![detail_bearing_input(project_id, detail)],
        1_000,
    )
    .unwrap();

    let groups = db
        .get_work_items_grouped(project_id, Some("https://example.com"), 1_000)
        .unwrap();

    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].instances[0].detail_json.as_deref(),
        Some(detail),
        "the unified read keeps detail_json"
    );
    assert_eq!(
        groups[0].instances[0].fix_prompt.as_deref(),
        Some("Generated agent prompt")
    );
    assert_eq!(
        groups[0].instances[0].producer_fix_prompt.as_deref(),
        Some("Producer prompt")
    );
    assert_eq!(
        groups[0].instances[0].manual_fix.as_deref(),
        Some("Manual fix guide")
    );
}

#[test]
fn score_reads_do_not_depend_on_subscription_tier() {
    use crate::scoring::calculator::compute_current_score;

    let db = test_db();
    let project_id = 1;
    let env = "https://example.com";

    let input = WorkItemInput {
        project_id,
        env_url: env.into(),
        source: "code_scan".into(),
        signal_id: "code_scan:hardcoded-secret:src/env.ts".into(),
        check_id: "code_scan.hardcoded-secret".into(),
        category: "security".into(),
        severity: Severity::Critical,
        title: "Hardcoded secret".into(),
        description: "Secret committed to source".into(),
        detail_json: Some("{}".into()),
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata {
            confidence: Some(crate::checks::IssueConfidence::NeedsReview),
            ..Default::default()
        },
    };
    db.upsert_work_items_diff("code_scan", project_id, env, vec![input], 1_000)
        .unwrap();

    let now = 2_000;

    // The grouped presentation read sees the promoted confidence too.
    let grouped = db
        .get_work_items_grouped(project_id, Some(env), now)
        .unwrap();
    let grouped_score = compute_current_score(&grouped, now);
    assert!(
        !grouped_score.exploitable_capped,
        "confidence is a promoted column; presentation enrichment must not affect the cap"
    );

    // The actual score read path, at Free tier and then at Core tier.
    let free_groups = db
        .get_active_issue_groups(project_id, Some(env), now)
        .unwrap();
    let free_score = compute_current_score(&free_groups, now);

    seed_active_core_license(&db);
    let core_groups = db
        .get_active_issue_groups(project_id, Some(env), now)
        .unwrap();
    let core_score = compute_current_score(&core_groups, now);

    assert_eq!(
        free_score.overall, core_score.overall,
        "the score must not depend on subscription tier"
    );
    assert_eq!(free_score.exploitable_capped, core_score.exploitable_capped);
    assert_eq!(free_score.critical_count, core_score.critical_count);
    assert!(
        !free_score.exploitable_capped,
        "a needs_review finding must not trigger the exploitable cap on any tier"
    );
    assert_eq!(
        free_score.overall, 92.0,
        "one needs_review critical deducts at half weight (B2), not capped"
    );
}

// Keep the generated MCP impact-score model synchronized with Rust.
#[test]
fn impact_score_json_is_in_sync_with_mcp_copy() {
    use std::collections::BTreeMap;

    use crate::checks::Severity;
    use crate::db::work_item_groups::{
        compute_impact_score, impact_score_from_penalty, IMPACT_BASE_MULTIPLIER,
        IMPACT_CATEGORY_WEIGHTS, IMPACT_DEFAULT_CATEGORY_WEIGHT, IMPACT_EXTRA_SOURCE_BONUS,
    };
    use crate::scoring::calculator::group_severity_penalty;

    // MCP-only: the JS side reads free-form severity strings from SQLite and
    // needs a default penalty for unknowns; typed Rust cannot see one.
    const IMPACT_DEFAULT_SEVERITY_PENALTY: f64 = 0.0;

    #[derive(serde::Serialize)]
    struct GridRow {
        severity: &'static str,
        category: &'static str,
        source_count: usize,
        score: f64,
    }

    #[derive(serde::Serialize)]
    struct Manifest {
        _generated: &'static str,
        severity_penalties: BTreeMap<&'static str, f64>,
        default_severity_penalty: f64,
        category_weights: BTreeMap<&'static str, f64>,
        default_category_weight: f64,
        base_multiplier: f64,
        extra_source_bonus_per_source: f64,
        grid: Vec<GridRow>,
    }

    let severities: Vec<&'static str> = Severity::ALL
        .iter()
        .map(|s| s.as_str())
        .chain(std::iter::once("unknown"))
        .collect();
    let categories: Vec<&'static str> = IMPACT_CATEGORY_WEIGHTS
        .iter()
        .map(|(label, _)| *label)
        .chain(std::iter::once("unknown"))
        .collect();

    let mut grid = Vec::new();
    for severity in &severities {
        for category in &categories {
            for source_count in [1usize, 3] {
                let score = match severity.parse::<Severity>() {
                    Ok(sev) => compute_impact_score(sev, category, source_count),
                    Err(_) => impact_score_from_penalty(
                        IMPACT_DEFAULT_SEVERITY_PENALTY,
                        category,
                        source_count,
                    ),
                };
                grid.push(GridRow {
                    severity,
                    category,
                    source_count,
                    score,
                });
            }
        }
    }

    let manifest = Manifest {
        _generated: "GENERATED by db::work_item_groups::tests::impact_score_json_is_in_sync_with_mcp_copy. Do not edit by hand: change db/work_item_groups.rs, run cargo test, commit the diff.",
        severity_penalties: Severity::ALL
            .iter()
            .map(|s| (s.as_str(), group_severity_penalty(*s)))
            .collect(),
        default_severity_penalty: IMPACT_DEFAULT_SEVERITY_PENALTY,
        category_weights: IMPACT_CATEGORY_WEIGHTS.iter().copied().collect(),
        default_category_weight: IMPACT_DEFAULT_CATEGORY_WEIGHT,
        base_multiplier: IMPACT_BASE_MULTIPLIER,
        extra_source_bonus_per_source: IMPACT_EXTRA_SOURCE_BONUS,
        grid,
    };

    let expected = serde_json::to_string_pretty(&manifest).expect("serialize impact_score") + "\n";

    let manifest_dir = std::path::PathBuf::from(env!("SITECMD_SOURCE_ROOT"));
    let json_path = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("apps root")
        .join("mcp-server")
        .join("src")
        .join("impact_score.json");

    let actual = std::fs::read_to_string(&json_path).unwrap_or_default();
    if actual != expected {
        std::fs::write(&json_path, &expected).expect("write impact_score.json");
        panic!(
            "apps/mcp-server/src/impact_score.json was stale (rewrote it). \
             Review the diff with `git diff apps/mcp-server/src/impact_score.json` and commit."
        );
    }
}
