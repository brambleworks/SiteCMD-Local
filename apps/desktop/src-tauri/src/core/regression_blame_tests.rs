//! Regression attribution tests.

#[path = "regression_blame_trace_tests.rs"]
mod trace_tests;

use crate::checks::Severity;
use crate::db::work_items::WorkItemMetadata;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;
use crate::db::alerts::AlertFilter;
use crate::db::test_helpers::{temp_db, TestDb};
use crate::db::work_items::WorkItemInput;

// Isolated temporary Git repository.
struct TestRepo {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for TestRepo {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

// Init a git repo in a tempdir + create one commit per (message, date)
// entry with pinned author/committer dates so window assertions are
// deterministic.
fn make_repo(name: &str, commits: &[(&str, &str)]) -> TestRepo {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    let isolated = path.join("isolated_home");
    fs::create_dir_all(&isolated).expect("home");
    let env = [
        ("HOME", isolated.to_string_lossy().to_string()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_string()),
        ("GIT_CONFIG_SYSTEM", "/dev/null".to_string()),
    ];

    let run = |args: &[&str], extra_env: &[(&str, &str)]| {
        Command::new("git")
            .args(args)
            .current_dir(&path)
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .envs(extra_env.iter().copied())
            .output()
            .expect("git command")
    };

    run(&["init", "-q", "-b", "main"], &[]);
    run(&["config", "user.email", "test@example.com"], &[]);
    run(&["config", "user.name", "Test User"], &[]);
    run(&["config", "commit.gpgsign", "false"], &[]);

    for (index, (message, date)) in commits.iter().enumerate() {
        let file = path.join(format!("file_{}_{}.txt", name, index + 1));
        fs::write(&file, format!("contents {}\n", index + 1)).expect("write");
        run(&["add", "."], &[]);
        run(
            &["commit", "-q", "-m", message],
            &[("GIT_AUTHOR_DATE", *date), ("GIT_COMMITTER_DATE", *date)],
        );
    }

    TestRepo { path, _dir: dir }
}

fn test_project(db: &TestDb) -> i64 {
    db.upsert_project("blame-test", "/tmp/sitecmd-regression-blame-test", None)
        .expect("project")
}

fn fixture_execution(db: &TestDb, project_id: i64, key: &str) -> i64 {
    db.admit_scan_execution(
        crate::core::scan_execution::NewScanExecution {
            project_id: Some(project_id),
            environment_id: None,
            environment_url: Some("https://example.com".into()),
            environment_scope_key: "https://example.com".into(),
            requested_mode: crate::core::scan_execution::ScanExecutionMode::Web,
            web_focus: Some(crate::core::scanner::ScanType::Health),
            trigger: crate::core::scan_execution::ScanTrigger::Manual,
            admission_class: crate::core::scan_execution::ScanAdmissionClass::GeneralScan,
            idempotency_key: key.into(),
            request_fingerprint: format!("v1:{key}"),
            now_ms: 100,
            web_status: Some(crate::core::scan_execution::ScanComponentStatus::Planned),
            web_detail: None,
            code_status: None,
            code_detail: None,
        },
        900,
    )
    .expect("execution")
    .execution
    .id
}

// Insert a run row carrying the given provenance.
fn insert_fixture_run(
    db: &TestDb,
    execution_id: i64,
    run_id: i64,
    engine_release: String,
    manifest_digest: String,
) {
    let execution_profile = serde_json::to_string(&crate::core::engine_release::execution_profile(
        crate::core::engine_release::ObservedSurface::Web,
        Some("health"),
        false,
        None,
    ))
    .expect("profile json");
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO scan_runs (
                id, execution_id, environment_scope_key, source, run_kind,
                status, started_at, timestamp_text, coverage_kind,
                engine_release, manifest_digest, canonicalizer,
                crawl_profile, execution_profile_json
             ) VALUES (
                ?1, ?2, 'https://example.com', 'web_scan', 'single',
                'complete', ?1, '2026-06-10T00:00:00Z', 'site',
                ?3, ?4, 1, 1, ?5
             )",
            rusqlite::params![
                run_id,
                execution_id,
                engine_release,
                manifest_digest,
                execution_profile,
            ],
        )
        .expect("insert fixture run");
    })
    .expect("fixture run");
}

// Stamp fixture runs so blame tests exercise attribution rather than refusal.
fn stamp_fixture_runs(db: &TestDb, project_id: i64, run_ids: &[i64]) {
    db.record_current_engine_release(0)
        .expect("record inventory");
    let execution_id = fixture_execution(db, project_id, "blame-fixture");
    let stamp = crate::core::engine_release::stamp(
        crate::core::engine_release::ObservedSurface::Web,
        Some("health"),
        false,
        None,
    );
    for run_id in run_ids {
        insert_fixture_run(
            db,
            execution_id,
            *run_id,
            stamp.engine_release.clone(),
            stamp.manifest_digest.clone(),
        );
    }
}

// Stamp one run as an OLDER build produced it: the current inventory, minus
// the checks that build did not have, plus the ones it had and this one
// dropped.
fn stamp_run_under_older_build(
    db: &TestDb,
    project_id: i64,
    run_id: i64,
    without: &[&str],
    with: &[&str],
) {
    const OLDER_RELEASE: &str = "1.4.0";
    const OLDER_DIGEST: &str = "00000000older000";
    let without: Vec<String> = without.iter().map(|id| id.to_string()).collect();
    let with: Vec<String> = with.iter().map(|id| id.to_string()).collect();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO engine_releases (
                engine_release, manifest_digest, manifest_schema, canonicalizer,
                crawl_profile, recorded_at
             ) VALUES (?1, ?2, 1, 1, 1, 0)",
            rusqlite::params![OLDER_RELEASE, OLDER_DIGEST],
        )
        .expect("older release row");
        for (check_id, entry) in crate::core::engine_release::CURRENT_INVENTORY.iter() {
            if without.iter().any(|omitted| omitted == check_id) {
                continue;
            }
            conn.execute(
                "INSERT INTO engine_release_checks (
                    engine_release, manifest_digest, check_id, contract,
                    compare_on, family
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    OLDER_RELEASE,
                    OLDER_DIGEST,
                    check_id,
                    entry.contract,
                    serde_json::to_string(&entry.compare_on).expect("compare_on json"),
                    i64::from(entry.family),
                ],
            )
            .expect("older inventory row");
        }
        for check_id in &with {
            conn.execute(
                "INSERT INTO engine_release_checks (
                    engine_release, manifest_digest, check_id, contract,
                    compare_on, family
                 ) VALUES (?1, ?2, ?3, 'retiredcontract', '[]', 0)",
                rusqlite::params![OLDER_RELEASE, OLDER_DIGEST, check_id],
            )
            .expect("retired inventory row");
        }
    })
    .expect("older inventory");
    let execution_id = fixture_execution(db, project_id, "blame-fixture-older");
    insert_fixture_run(
        db,
        execution_id,
        run_id,
        OLDER_RELEASE.to_string(),
        OLDER_DIGEST.to_string(),
    );
}

fn previous_scan() -> PreviousScan {
    PreviousScan {
        scan_id: 41,
        overall_score: 92,
        timestamp: "2026-06-08T00:00:00Z".into(),
    }
}

fn snapshot_with(previous: Option<PreviousScan>, active: &[&str]) -> BlameSnapshot {
    BlameSnapshot {
        previous,
        active_check_ids: active.iter().map(|id| id.to_string()).collect(),
    }
}

fn issue(check_id: &str, severity: &str) -> CurrentIssue {
    CurrentIssue {
        check_id: check_id.to_string(),
        title: format!("Title for {check_id}"),
        severity: severity.parse().expect("valid severity"),
    }
}

// BlameContext with the end-to-end defaults; tests vary the path.
fn ctx<'a>(
    db: &'a Database,
    project_id: i64,
    issues: &'a [CurrentIssue],
    project_path: Option<&'a str>,
) -> BlameContext<'a> {
    BlameContext {
        db,
        project_id,
        env_url: "https://example.com",
        scan_kind: "web",
        scan_id: 42,
        current_score: 84,
        current_timestamp: "2026-06-10T00:00:00Z",
        current_issues: issues,
        project_path,
    }
}

#[test]
fn should_blame_requires_new_issues_and_commits() {
    assert!(!should_blame(15, 0, 3, false), "no new issues, no blame");
    assert!(!should_blame(15, 2, 0, true), "no commits, no blame");
    assert!(should_blame(5, 1, 1, false), "drop at threshold fires");
    assert!(!should_blame(4, 1, 1, false), "drop below threshold skips");
    assert!(
        should_blame(0, 1, 1, true),
        "critical/high fires without drop"
    );
}

#[test]
fn blame_severity_matches_spec() {
    assert_eq!(blame_severity(8, true), "critical");
    assert_eq!(blame_severity(20, false), "critical");
    assert_eq!(blame_severity(19, false), "warn");
}

const DETAIL_FIXTURE: &str = r#"{"alert_type":"deploy_regression","scan_kind":"web","scan_id":42,"regression_id":7,"previous_score":92,"current_score":84,"score_drop":8,"new_issues":[{"check_id":"security.csp-header","title":"Missing Content-Security-Policy header"},{"check_id":"seo.meta-description","title":"Missing meta description"}],"fixed_count":1,"detector_changed_count":0,"engine_release":"1.5.4","commit_from":"aaa1111111","commit_to":"bbb2222222","commit_count":3,"commits":[{"hash":"bbb2222222","short_hash":"bbb2222","message":"Ship the redesign","author":"Kyle","date":"2026-06-09T12:00:00-05:00"}],"url":"https://example.com","destination":"issues"}"#;

#[test]
fn detail_json_matches_the_frontend_parity_fixture() {
    let commits_json = r#"[{"hash":"bbb2222222","short_hash":"bbb2222","message":"Ship the redesign","author":"Kyle","date":"2026-06-09T12:00:00-05:00"}]"#;
    let csp = CurrentIssue {
        check_id: "security.csp-header".into(),
        title: "Missing Content-Security-Policy header".into(),
        severity: Severity::High,
    };
    let meta = CurrentIssue {
        check_id: "seo.meta-description".into(),
        title: "Missing meta description".into(),
        severity: Severity::Medium,
    };
    let new_issues: Vec<&CurrentIssue> = vec![&csp, &meta];

    let detail = build_detail_json(DetailArgs {
        scan_kind: "web",
        scan_id: 42,
        regression_id: 7,
        previous_score: 92,
        current_score: 84,
        score_drop: 8,
        new_issues: &new_issues,
        fixed_count: 1,
        detector_changed_count: 0,
        engine_release: Some("1.5.4"),
        commit_from: "aaa1111111",
        commit_to: "bbb2222222",
        commit_count: 3,
        commits_json,
        env_url: "https://example.com",
    });

    let actual: serde_json::Value = serde_json::from_str(&detail).expect("detail parses");
    let expected: serde_json::Value = serde_json::from_str(DETAIL_FIXTURE).expect("fixture parses");
    assert_eq!(actual, expected);
}

#[test]
fn emit_creates_regression_row_and_alert_end_to_end() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo(
        "e2e",
        &[
            ("before window", "2026-06-01T10:00:00Z"),
            ("breaks csp", "2026-06-09T10:00:00Z"),
            ("breaks seo", "2026-06-09T11:00:00Z"),
        ],
    );
    stamp_fixture_runs(&db, project_id, &[41, 42]);
    let snapshot = snapshot_with(Some(previous_scan()), &["polish.alt-text", "old.fixed-now"]);
    let issues = vec![
        issue("security.csp-header", "high"),
        issue("polish.alt-text", "low"),
    ];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
        .expect("blame notice");

    let row = db
        .get_regression_by_scan("web", 42)
        .expect("get")
        .expect("row exists");
    assert_eq!(row.prev_scan_id, 41);
    assert_eq!(row.commit_count, 2);
    let introduced = db.get_regression_check_ids(row.id).expect("check ids");
    assert_eq!(introduced, vec!["security.csp-header".to_string()]);
    let fixed: Vec<String> =
        serde_json::from_str(&row.fixed_check_ids_json).expect("fixed json parses");
    assert_eq!(fixed, vec!["old.fixed-now".to_string()]);

    let alerts = db
        .get_alerts(project_id, AlertFilter::Unread, None)
        .expect("alerts");
    assert_eq!(alerts.len(), 1, "exactly one deploy-regression alert");
    assert!(alerts[0].alert_id.starts_with("deploy-regression:web:"));
    assert!(notice.body.contains("2 commits"));
}

#[test]
fn emit_skips_when_no_commits_in_window() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("ancient", &[("ancient commit", "2026-01-01T10:00:00Z")]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![issue("security.csp-header", "high")];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot);

    assert!(notice.is_none(), "no commits in window means no blame");
    assert!(db.get_regression_by_scan("web", 42).expect("get").is_none());
}

#[test]
fn emit_fires_with_no_license_state_at_all() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("free", &[("in window", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[41, 42]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![issue("security.csp-header", "critical")];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
        .expect("blame fires with no entitlement anywhere in sight");

    assert!(db.get_regression_by_scan("web", 42).expect("get").is_some());
    assert!(notice.body.contains("commit"));
}

#[test]
fn emit_skips_without_previous_scan_or_project_path() {
    let db = temp_db();
    let project_id = test_project(&db);
    let issues = vec![issue("security.csp-header", "critical")];

    let no_previous = snapshot_with(None, &[]);
    assert!(
        emit_regression_blame(ctx(&db.db, project_id, &issues, Some("/tmp")), &no_previous,)
            .is_none(),
        "no previous scan means no window to blame",
    );

    let with_previous = snapshot_with(Some(previous_scan()), &[]);
    assert!(
        emit_regression_blame(ctx(&db.db, project_id, &issues, None), &with_previous,).is_none(),
        "no project path means no repo to read",
    );
}

#[test]
fn stored_commits_are_capped_but_count_is_true() {
    let db = temp_db();
    let project_id = test_project(&db);
    let messages: Vec<String> = (1..=25).map(|i| format!("in-window commit {i}")).collect();
    let entries: Vec<(&str, &str)> = messages
        .iter()
        .map(|message| (message.as_str(), "2026-06-09T10:00:00Z"))
        .collect();
    let repo = make_repo("capped", &entries);
    stamp_fixture_runs(&db, project_id, &[41, 42]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![issue("security.csp-header", "high")];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot);
    assert!(notice.is_some(), "25 in-window commits must produce blame");

    let row = db
        .get_regression_by_scan("web", 42)
        .expect("get")
        .expect("row exists");
    assert_eq!(row.commit_count, 25, "true window count survives the cap");
    let stored: Vec<serde_json::Value> =
        serde_json::from_str(&row.commits_json).expect("commits json parses");
    assert_eq!(stored.len(), STORED_COMMITS_MAX);
}

fn work_item(project_id: i64, source: &str, check_id: &str) -> WorkItemInput {
    WorkItemInput {
        project_id,
        env_url: "https://example.com".into(),
        source: source.into(),
        signal_id: format!("{source}:{check_id}"),
        check_id: check_id.into(),
        category: "security".into(),
        severity: Severity::High,
        title: format!("Title for {check_id}"),
        description: format!("Description for {check_id}"),
        detail_json: None,
        scan_ref: None,
        page_url: None,
        fix_prompt: None,
        manual_fix: None,
        why_it_matters: None,
        observed_at: 1_000,
        metadata: WorkItemMetadata::default(),
    }
}

#[test]
fn capture_snapshot_filters_by_source_and_env() {
    let db = temp_db();
    let project_id = test_project(&db);
    db.upsert_work_items_diff(
        "web_scan",
        project_id,
        "https://example.com",
        vec![work_item(project_id, "web_scan", "security.csp-header")],
        1_000,
    )
    .expect("seed web work item");
    db.upsert_work_items_diff(
        "code_scan",
        project_id,
        "https://example.com",
        vec![work_item(
            project_id,
            "code_scan",
            "code_scan.sql-injection",
        )],
        1_000,
    )
    .expect("seed code work item");

    let snapshot = capture_snapshot(&db.db, project_id, "https://example.com/", "web_scan", None)
        .expect("capture active work items");

    let expected: HashSet<String> = ["security.csp-header".to_string()].into_iter().collect();
    assert_eq!(
        snapshot.active_check_ids, expected,
        "snapshot must keep only the requested source's check_ids",
    );
}

#[test]
fn emit_dedups_code_findings_and_uses_singular_commit_copy() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("dedup", &[("single deploy", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[41, 42]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let duplicate = |title: &str, severity: &str| CurrentIssue {
        check_id: "code_scan.sql-injection".to_string(),
        title: title.to_string(),
        severity: severity.parse().expect("valid severity"),
    };
    let issues = vec![
        duplicate("SQL injection in search", "medium"),
        duplicate("SQL injection in login", "critical"),
        duplicate("SQL injection in export", "high"),
        issue("code_scan.hardcoded-secret", "medium"),
    ];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(
        BlameContext {
            scan_kind: "code",
            ..ctx(&db.db, project_id, &issues, Some(&path))
        },
        &snapshot,
    )
    .expect("blame notice");

    let row = db
        .get_regression_by_scan("code", 42)
        .expect("get")
        .expect("row exists");
    let introduced = db.get_regression_check_ids(row.id).expect("check ids");
    assert_eq!(
        introduced
            .iter()
            .filter(|id| id.as_str() == "code_scan.sql-injection")
            .count(),
        1,
        "introduced check_ids carry the duplicated check_id exactly once",
    );

    let alerts = db
        .get_alerts(project_id, AlertFilter::Unread, None)
        .expect("alerts");
    assert_eq!(alerts.len(), 1, "exactly one deploy-regression alert");
    assert_eq!(
        alerts[0].severity, "critical",
        "highest duplicate severity drives the alert severity",
    );
    let detail: serde_json::Value =
        serde_json::from_str(alerts[0].detail_json.as_deref().expect("detail json"))
            .expect("detail parses");
    let new_issues = detail["new_issues"].as_array().expect("new_issues array");
    assert_eq!(
        new_issues.len(),
        2,
        "three sql-injection findings collapse to one detail entry",
    );
    let sql_injection = new_issues
        .iter()
        .find(|entry| entry["check_id"] == "code_scan.sql-injection")
        .expect("sql-injection entry");
    assert_eq!(
        sql_injection["title"], "SQL injection in login",
        "dedup keeps the critical instance's title",
    );
    assert!(
        notice.body.contains("after 1 commit on"),
        "singular commit copy expected, got: {}",
        notice.body,
    );
}

#[test]
fn a_check_the_previous_build_could_not_produce_is_not_blamed_on_the_deploy() {
    // The release added `security.headers.cross_origin`. Its first appearance is the
    // scanner learning to look, not a commit breaking something.
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("new-check", &[("unrelated change", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[42]);
    stamp_run_under_older_build(&db, project_id, 41, &["security.headers.cross_origin"], &[]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![issue("security.headers.cross_origin", "high")];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot);

    assert!(
        notice.is_none(),
        "a finding only the newer build could produce must not be attributed to a commit"
    );
    assert!(db.get_regression_by_scan("web", 42).expect("get").is_none());
}

#[test]
fn a_finding_from_an_unchanged_check_is_still_blamed_alongside_a_new_one() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("mixed", &[("breaks csp", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[42]);
    stamp_run_under_older_build(&db, project_id, 41, &["security.headers.cross_origin"], &[]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![
        issue("security.headers.csp", "high"),
        issue("security.headers.cross_origin", "high"),
    ];
    let path = repo.to_string_lossy().to_string();

    emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
        .expect("blame notice");

    let row = db
        .get_regression_by_scan("web", 42)
        .expect("get")
        .expect("row exists");
    let introduced = db.get_regression_check_ids(row.id).expect("check ids");
    assert_eq!(
        introduced,
        vec!["security.headers.csp".to_string()],
        "only the check both builds had is laid at the deploy's door"
    );
    let alerts = db
        .get_alerts(project_id, AlertFilter::Unread, None)
        .expect("alerts");
    assert!(
        alerts[0]
            .description
            .contains("not attributed to these commits"),
        "the copy must explain the finding it held back, got: {}",
        alerts[0].description,
    );
}

#[test]
fn a_retired_check_is_not_counted_as_a_fix_the_deploy_earned() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("retired", &[("breaks csp", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[42]);
    stamp_run_under_older_build(&db, project_id, 41, &[], &["seo.retired-check"]);
    let snapshot = snapshot_with(
        Some(previous_scan()),
        &["seo.retired-check", "security.headers.hsts"],
    );
    let issues = vec![issue("security.headers.csp", "high")];
    let path = repo.to_string_lossy().to_string();

    emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
        .expect("blame notice");

    let row = db
        .get_regression_by_scan("web", 42)
        .expect("get")
        .expect("row exists");
    let fixed: Vec<String> =
        serde_json::from_str(&row.fixed_check_ids_json).expect("fixed json parses");
    assert_eq!(
        fixed,
        vec!["security.headers.hsts".to_string()],
        "a check this build no longer runs stopped reporting; nobody fixed it"
    );
}

#[test]
fn an_unstamped_previous_run_withholds_attribution_entirely() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("unstamped", &[("breaks csp", "2026-06-09T10:00:00Z")]);
    // Only the current run is stamped, which is exactly the state of the first
    // scan after an upgrade - the moment a new check is most likely to appear.
    stamp_fixture_runs(&db, project_id, &[42]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![issue("security.headers.csp", "critical")];
    let path = repo.to_string_lossy().to_string();

    let notice = emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot);

    assert!(
        notice.is_none(),
        "a run produced by a build nobody can name is not a baseline to accuse a commit against"
    );
}

#[test]
fn an_id_no_build_ever_registered_is_attributed_as_before() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("foreign", &[("breaks something", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[41, 42]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![issue("security.csp-header", "critical")];
    let path = repo.to_string_lossy().to_string();

    emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
        .expect("blame notice");

    let row = db
        .get_regression_by_scan("web", 42)
        .expect("get")
        .expect("row exists");
    let introduced = db.get_regression_check_ids(row.id).expect("check ids");
    assert_eq!(introduced, vec!["security.csp-header".to_string()]);
    let alerts = db
        .get_alerts(project_id, AlertFilter::Unread, None)
        .expect("alerts");
    assert!(
        !alerts[0]
            .description
            .contains("not attributed to these commits"),
        "nothing was held back, so the copy must not claim otherwise"
    );
}

#[test]
fn the_detail_dossier_records_what_was_held_back_and_the_release_that_did_it() {
    let db = temp_db();
    let project_id = test_project(&db);
    let repo = make_repo("dossier", &[("breaks csp", "2026-06-09T10:00:00Z")]);
    stamp_fixture_runs(&db, project_id, &[42]);
    stamp_run_under_older_build(&db, project_id, 41, &["security.headers.cross_origin"], &[]);
    let snapshot = snapshot_with(Some(previous_scan()), &[]);
    let issues = vec![
        issue("security.headers.csp", "high"),
        issue("security.headers.cross_origin", "high"),
    ];
    let path = repo.to_string_lossy().to_string();

    emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
        .expect("blame notice");

    let alerts = db
        .get_alerts(project_id, AlertFilter::Unread, None)
        .expect("alerts");
    let detail: serde_json::Value =
        serde_json::from_str(alerts[0].detail_json.as_deref().expect("detail json"))
            .expect("detail parses");
    assert_eq!(detail["detector_changed_count"], 1);
    assert_eq!(detail["engine_release"], env!("CARGO_PKG_VERSION"));
}
