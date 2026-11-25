//! Connected bootstrap projection tests.

use super::*;
use crate::core::audit::{CodeIssue, CodeScanReport};
use crate::core::normalized_scan::{normalize_code_scan_with_provenance, ScanEvidenceSource};
use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionClass, ScanComponentStatus, ScanExecutionMode, ScanTrigger,
};
use crate::core::scan_types::CheckStatus;
use crate::core::scan_types::ScanType;
use crate::db::test_helpers::{code_batch, code_execution, temp_db, TestDb};
use crate::db::ConnectedSubmissionRequest;
use sitecmd_protocol::sync::ProjectFingerprintKey;

const SITE: &str = "https://example.com";

fn seeded() -> (TestDb, i64) {
    let db = temp_db();
    let project_id = db
        .upsert_project("Bootstrap", "/tmp/bootstrap", Some("nextjs"))
        .expect("upsert project");
    (db, project_id)
}

const FIRST: &str = "code_scan.hardcoded-secret";
const SECOND: &str = "code_scan.n-plus-one-query";

fn persist_code(db: &TestDb, project_id: i64, key: &str, checks: &[(&str, CheckStatus)]) {
    let execution_id = code_execution(db, project_id, SITE, key);
    db.persist_normalized_scan_run(code_batch(project_id, execution_id, SITE, checks))
        .expect("persist code scan");
}

fn code_issue(id: &str, path: &str, line: u32, severity: Severity) -> CodeIssue {
    CodeIssue {
        id: format!("{id}:{path}:{line}"),
        check_id: String::new(),
        category: "code_quality".parse().expect("fixture identifier"),
        severity,
        title: id.into(),
        description: "detail".parse().expect("fixture identifier"),
        relative_path: path.into(),
        absolute_path: format!("/tmp/bootstrap/{path}"),
        line: Some(line),
        evidence: None,
        why_now: None,
        likely_fix: None,
        confidence: IssueConfidence::NeedsReview,
        confidence_reason: None,
        verify_hint: None,
    }
}

// One instance the scanner is sure about, for the collapse rule.
fn confirmed(issue: CodeIssue) -> CodeIssue {
    CodeIssue {
        confidence: IssueConfidence::Confirmed,
        ..issue
    }
}

fn code_scan(db: &TestDb, project_id: i64, key: &str, scope_key: &str, issues: Vec<CodeIssue>) {
    code_scan_with_commit(db, project_id, key, scope_key, issues, Some("abc1234"));
}

fn code_scan_with_commit(
    db: &TestDb,
    project_id: i64,
    key: &str,
    scope_key: &str,
    issues: Vec<CodeIssue>,
    commit_sha: Option<&str>,
) {
    let execution_id = code_execution(db, project_id, scope_key, key);
    let report = CodeScanReport {
        checked_at: "2026-08-06T00:00:00Z".parse().expect("fixture identifier"),
        framework: Some("nextjs".parse().expect("fixture identifier")),
        issue_count: issues.len(),
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        issues,
        skipped_scopes: Default::default(),
    };
    let mut batch = normalize_code_scan_with_provenance(
        &report,
        execution_id,
        project_id,
        None,
        scope_key.to_string(),
        "/tmp/bootstrap".parse().expect("fixture identifier"),
        10,
        100,
        Some(crate::core::code_provenance::CodeCheckoutProvenance::default()),
    )
    .expect("normalize code");
    batch.diagnostics.code_commit_sha = commit_sha.map(str::to_string);
    batch.diagnostics.code_tree_clean = Some(true);
    db.persist_normalized_scan_run(batch).expect("persist code");
}

fn group<'a>(set: &'a BootstrapSet, check_id: &str) -> Option<&'a BootstrapGroup> {
    set.groups.iter().find(|group| group.check_id == check_id)
}

fn evidence(set: &BootstrapSet, source: ScanEvidenceSource) -> Option<&SourceEvidence> {
    set.evidence.iter().find(|found| found.source == source)
}

#[test]
fn an_untouched_active_issue_is_declared_without_ever_having_a_lifecycle_row() {
    let (db, project_id) = seeded();
    persist_code(&db, project_id, "untouched", &[(FIRST, CheckStatus::Fail)]);

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    let found = group(&set, FIRST).expect("group present");
    assert_eq!(
        found.state,
        BootstrapState::Active,
        "the overlay is an override table; absence is the ordinary case, not a gap"
    );
    assert_eq!(found.sources, vec![ScanEvidenceSource::CodeScan]);
    assert!(found.last_known_occurrences.is_empty());
}

#[test]
fn a_terminal_group_whose_findings_are_gone_survives_as_a_row() {
    let (db, project_id) = seeded();
    seed_state(
        &db,
        project_id,
        SITE,
        FIRST,
        ("blocked", None, Some("intended"), None),
        4_000,
    )
    .expect("block");

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    let found = group(&set, FIRST).expect("row-only group survives");
    assert_eq!(
        found.state,
        BootstrapState::Blocked {
            reason: Some("intended".parse().expect("fixture identifier"))
        },
        "a dismissal the projection can no longer see is exactly what the \
         service has to be told, or it will alert on it"
    );
    assert_eq!(found.state_changed_at, 4_000);
}

#[test]
fn a_scan_fixed_group_nobody_decided_about_is_not_revived() {
    let (db, project_id) = seeded();
    persist_code(&db, project_id, "present", &[(FIRST, CheckStatus::Fail)]);
    persist_code(&db, project_id, "absent", &[(FIRST, CheckStatus::Pass)]);

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    assert!(
        group(&set, FIRST).is_none(),
        "the resolved row is history; declaring it would report a fix as an \
         open issue the user has to look at again"
    );
}

#[test]
fn the_stored_state_travels_rather_than_the_effective_one() {
    let (db, project_id) = seeded();
    seed_state(
        &db,
        project_id,
        SITE,
        SECOND,
        ("snoozed", Some(1_000), None, None),
        900,
    )
    .expect("snooze");

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    assert_eq!(
        group(&set, SECOND).expect("group").state,
        BootstrapState::Snoozed { until: 1_000 },
        "the server evaluates snooze expiry at read time; collapsing it here \
         would discard the policy and read as a reopening nobody decided"
    );
}

#[test]
fn a_regression_is_readable_here_even_though_nothing_can_declare_one() {
    let (db, project_id) = seeded();
    persist_code(&db, project_id, "seen", &[(FIRST, CheckStatus::Fail)]);
    seed_state(
        &db,
        project_id,
        SITE,
        FIRST,
        ("verified", None, None, Some(VerifiedBy::LocalScan)),
        2_000,
    )
    .expect("verify");
    // Seeing it again after a scan proved it gone is the regression.
    persist_code(&db, project_id, "again", &[(FIRST, CheckStatus::Fail)]);

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    assert_eq!(
        group(&set, FIRST).expect("group").state,
        BootstrapState::Regressed,
        "reading a regression is what a producer must do; declaring one is \
         what it must not, which is why only the read vocabulary has it"
    );
}

#[test]
fn a_snoozed_row_with_no_deadline_stops_the_derivation() {
    let (db, project_id) = seeded();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO project_issue_states
                (project_id, env_url, check_id, status, last_status_changed_at)
             VALUES (?1, ?2, ?3, 'snoozed', 1000)",
            rusqlite::params![project_id, SITE, SECOND],
        )
    })
    .expect("execute")
    .expect("raw insert");

    let error = db
        .derive_bootstrap_set(project_id, SITE)
        .expect_err("an undeclarable dismissal must stop the submission");
    assert!(
        error.to_string().contains("no deadline"),
        "every repair invents a decision the user did not make: got {error}"
    );
}

#[test]
fn only_a_group_awaiting_verification_carries_the_places_to_look() {
    let (db, project_id) = seeded();
    let execution_id = code_execution(&db, project_id, SITE, "history");
    let mut batch = code_batch(
        project_id,
        execution_id,
        SITE,
        &[(FIRST, CheckStatus::Fail), (SECOND, CheckStatus::Fail)],
    );
    batch.findings[0].relative_path = Some("src/a.ts".into());
    batch.findings[0].occurrence_id = "code_scan:hardcoded-secret:src/a.ts:1".into();
    let mut second_occurrence = batch.findings[0].clone();
    second_occurrence.relative_path = Some("src/b.ts".into());
    second_occurrence.occurrence_id = "code_scan:hardcoded-secret:src/b.ts:1".into();
    batch.findings.push(second_occurrence);
    db.persist_normalized_scan_run(batch).unwrap();

    seed_state(
        &db,
        project_id,
        SITE,
        FIRST,
        ("verified", None, None, Some(VerifiedBy::UserClaim)),
        5_000,
    )
    .expect("claim fixed");

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    let claimed = group(&set, FIRST).expect("claimed group");
    assert_eq!(
        claimed
            .last_known_occurrences
            .iter()
            .map(|occurrence| &occurrence.location)
            .collect::<Vec<_>>(),
        [
            &OccurrenceLocation::File {
                rule: "hardcoded-secret".into(),
                path: "src/a.ts".into()
            },
            &OccurrenceLocation::File {
                rule: "hardcoded-secret".into(),
                path: "src/b.ts".into()
            },
        ],
    );
    let untouched = group(&set, SECOND).expect("active group");
    assert!(
        untouched.last_known_occurrences.is_empty(),
        "an active group is not awaiting verification and has nothing to prove absent"
    );
}

#[test]
fn a_group_whose_history_aged_out_declares_no_places_to_look() {
    let (db, project_id) = seeded();
    seed_state(
        &db,
        project_id,
        SITE,
        FIRST,
        ("verified", None, None, Some(VerifiedBy::LocalScan)),
        5_000,
    )
    .expect("verify");

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    let found = group(&set, FIRST).expect("group");
    assert!(
        found.last_known_occurrences.is_empty(),
        "omitting is honest; a guessed location would have the verifier prove \
         absence somewhere the issue never was"
    );
    assert!(found.sources.is_empty());
}

#[test]
fn standin_a_verified_group_recovers_its_source_from_the_scan_that_last_saw_it() {
    // Verifying a group can hide the stored source and last known occurrence.
    let (db, project_id) = seeded();
    let scope_key = format!("project:{project_id}");
    code_scan(
        &db,
        project_id,
        "code-history",
        &scope_key,
        vec![code_issue(
            "standin.rule",
            "src/db.ts",
            12,
            Severity::Medium,
        )],
    );
    let engine = sitecmd_engine_host::load().unwrap();
    let check_id = &engine.info().code_rule("standin.rule").unwrap().check_id;
    seed_state(
        &db,
        project_id,
        &scope_key,
        check_id,
        ("verified", None, None, Some(VerifiedBy::UserClaim)),
        6_000,
    )
    .expect("claim fixed");

    let set = db
        .derive_bootstrap_set(project_id, &scope_key)
        .expect("derive");
    let found = group(&set, check_id).expect("group");
    assert_eq!(
        found.sources,
        vec![ScanEvidenceSource::CodeScan],
        "a code-only project keys its rows the way the lifecycle overlay does, \
         and the scan that last saw the group still names its scanner"
    );
    assert_eq!(found.last_known_occurrences.len(), 1);
    assert_eq!(
        found.last_known_occurrences[0].location,
        OccurrenceLocation::File {
            rule: "standin.rule".parse().expect("fixture identifier"),
            path: "src/db.ts".parse().expect("fixture identifier"),
        }
    );
}

#[test]
fn standin_code_instances_in_one_file_collapse_and_keep_their_count() {
    // Grouping a file's findings can lose multiplicity, severity, or confidence.
    let (db, project_id) = seeded();
    let scope_key = format!("project:{project_id}");
    code_scan(
        &db,
        project_id,
        "collapse",
        &scope_key,
        vec![
            code_issue("standin.rule", "src/db.ts", 12, Severity::Low),
            confirmed(code_issue(
                "standin.rule",
                "src/db.ts",
                48,
                Severity::Critical,
            )),
            code_issue("standin.rule", "src/api.ts", 7, Severity::Low),
        ],
    );

    let set = db
        .derive_bootstrap_set(project_id, &scope_key)
        .expect("derive");
    let code = evidence(&set, ScanEvidenceSource::CodeScan).expect("code evidence");
    let occurrences = &code.occurrences;
    assert_eq!(
        occurrences.len(),
        2,
        "two findings in one file are one occurrence once the line is dropped"
    );
    let db_file = occurrences
        .iter()
        .find(|occurrence| {
            occurrence.identity.location
                == OccurrenceLocation::File {
                    rule: "standin.rule".parse().expect("fixture identifier"),
                    path: "src/db.ts".parse().expect("fixture identifier"),
                }
        })
        .expect("collapsed occurrence");
    assert_eq!(
        db_file.identity.instance_count, 2,
        "multiplicity is preserved as a count rather than lost with the line"
    );
    assert_eq!(
        db_file.severity,
        Severity::Critical,
        "the occurrence holds an instance this severe, so the strongest is the true one"
    );
    assert_eq!(
        db_file.confidence,
        IssueConfidence::Confirmed,
        "both facts are existential: one instance the scanner is sure about \
         makes the occurrence one the scanner is sure about"
    );
}

#[test]
fn newer_evidence_replaces_older_evidence_of_the_same_source() {
    let (db, project_id) = seeded();
    persist_code(&db, project_id, "first", &[(FIRST, CheckStatus::Fail)]);
    persist_code(
        &db,
        project_id,
        "second",
        &[(FIRST, CheckStatus::Fail), (SECOND, CheckStatus::Fail)],
    );

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    let code = evidence(&set, ScanEvidenceSource::CodeScan).expect("code evidence");
    assert_eq!(code.run_ids.len(), 1);
    assert_eq!(
        code.occurrences.len(),
        2,
        "a snapshot is one scan's observation, and the newest scan is the one \
         whose coverage the service will evaluate"
    );
}

#[test]
fn code_evidence_stays_in_its_environment_scope() {
    // A code scan in another environment can replace the current scope's evidence.
    let (db, project_id) = seeded();
    let scopes = [
        (format!("project:{project_id}"), FIRST),
        (SITE.into(), SECOND),
    ];
    let runs = scopes.map(|(scope, check)| {
        let execution_id = code_execution(&db, project_id, &scope, check);
        let batch = code_batch(
            project_id,
            execution_id,
            &scope,
            &[(check, CheckStatus::Fail)],
        );
        let run_id = db.persist_normalized_scan_run(batch).unwrap();
        (scope, run_id, check)
    });

    for (scope, run_id, check) in runs {
        let set = db.derive_bootstrap_set(project_id, &scope).unwrap();
        let code = evidence(&set, ScanEvidenceSource::CodeScan).expect("code evidence");
        assert_eq!(code.run_ids, [run_id], "{scope}");
        assert_eq!(code.occurrences.len(), 1, "{scope}");
        assert_eq!(code.occurrences[0].identity.check_id, check, "{scope}");
    }
}

#[test]
fn evidence_carries_the_watermark_its_scan_was_taken_against() {
    let (db, project_id) = seeded();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO connected_site_watermarks (project_id, env_url, event_sequence, pulled_at)
             VALUES (?1, ?2, 42, 100)",
            rusqlite::params![project_id, SITE],
        )
    })
    .unwrap()
    .unwrap();
    persist_code(&db, project_id, "after-pull", &[(FIRST, CheckStatus::Fail)]);

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    assert_eq!(
        evidence(&set, ScanEvidenceSource::CodeScan)
            .expect("code evidence")
            .based_on_event_sequence,
        42,
        "the basis is captured on the execution when the scan starts looking"
    );
}

#[test]
fn deriving_what_would_be_sent_does_not_require_a_connection() {
    let (db, project_id) = seeded();
    persist_code(
        &db,
        project_id,
        "unconnected",
        &[(FIRST, CheckStatus::Fail)],
    );

    let set = db.derive_bootstrap_set(project_id, SITE).expect("derive");
    assert_eq!(set.groups.len(), 1);
    assert!(
        db.get_connected_site(project_id, SITE)
            .expect("read binding")
            .is_none(),
        "a preview computable only after connecting would arrive too late to \
         inform the decision to connect"
    );
}

#[test]
fn an_environment_is_required() {
    let (db, project_id) = seeded();
    let error = db
        .derive_bootstrap_set(project_id, "")
        .expect_err("no environment, no site");
    assert!(error.to_string().contains("environment is required"));
}

#[test]
fn connected_code_basis_comes_from_the_persisted_scan_checkout() {
    let (db, project_id) = seeded();
    let scope_key = format!("project:{project_id}");
    code_scan(
        &db,
        project_id,
        "scan-provenance",
        &scope_key,
        vec![code_issue("standin.rule", "src/db.ts", 12, Severity::Low)],
    );
    let key = ProjectFingerprintKey::from_bytes([3_u8; 32]);
    let request = |deployed_commit: &str| ConnectedSubmissionRequest {
        site_id: "site_scan_provenance".parse().expect("fixture identifier"),
        submission_sequence: 1,
        include_groups: false,
        fingerprint_key: Some(key.clone()),
        fingerprint_key_version: 1,
        deployed_commit: Some(deployed_commit.into()),
    };

    let different_head = db
        .build_connected_submission(project_id, &scope_key, request("def4567"))
        .expect("build from stored scan provenance")
        .snapshots
        .code
        .expect("code snapshot");
    assert_eq!(
        different_head.code_basis.commit_sha.as_deref(),
        Some("abc1234")
    );
    assert_eq!(
        different_head.code_basis.kind,
        sitecmd_protocol::sync::CodeBasisKind::Unknown
    );

    let matching_head = db
        .build_connected_submission(project_id, &scope_key, request("abc1234"))
        .expect("build exact stored scan provenance")
        .snapshots
        .code
        .expect("code snapshot");
    assert_eq!(
        matching_head.code_basis.commit_sha.as_deref(),
        Some("abc1234")
    );
    assert_eq!(
        matching_head.code_basis.kind,
        sitecmd_protocol::sync::CodeBasisKind::ExactCheckout
    );
}

#[test]
fn a_non_git_code_scan_still_emits_presence_with_an_explicit_unknown_basis() {
    let (db, project_id) = seeded();
    let scope_key = format!("project:{project_id}");
    code_scan_with_commit(
        &db,
        project_id,
        "non-git-provenance",
        &scope_key,
        vec![code_issue("standin.rule", "src/db.ts", 12, Severity::Low)],
        None,
    );

    let snapshot = db
        .build_connected_submission(
            project_id,
            &scope_key,
            ConnectedSubmissionRequest {
                site_id: "site_non_git".parse().expect("fixture identifier"),
                submission_sequence: 1,
                include_groups: false,
                fingerprint_key: Some(ProjectFingerprintKey::from_bytes([4_u8; 32])),
                fingerprint_key_version: 1,
                deployed_commit: Some("def4567".parse().expect("fixture identifier")),
            },
        )
        .expect("build non-git snapshot")
        .snapshots
        .code
        .expect("code findings are retained without git");

    assert_eq!(
        snapshot.code_basis.kind,
        sitecmd_protocol::sync::CodeBasisKind::Unknown
    );
    assert_eq!(snapshot.code_basis.commit_sha, None);
    assert!(!snapshot.occurrences.is_empty());
    assert!(snapshot
        .occurrences
        .iter()
        .all(|occurrence| occurrence.provenance.commit_sha.is_none()));
    let wire = serde_json::to_value(snapshot).expect("wire snapshot");
    assert!(wire["code_basis"]["commit_sha"].is_null());
    assert!(wire["occurrences"][0]["provenance"]["commit_sha"].is_null());
}

#[path = "connected_payload_omission_tests.rs"]
mod omission_tests;

fn seed_state(
    db: &TestDb,
    project_id: i64,
    env_url: &str,
    check_id: &str,
    (status, snooze_until, block_reason, verified_by): (
        &'static str,
        Option<i64>,
        Option<&'static str>,
        Option<VerifiedBy>,
    ),
    now_ms: i64,
) -> Result<(), crate::db::DbError> {
    let check_id = check_id.to_owned();
    let env_url = env_url.to_owned();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO project_issue_states
                (project_id, env_url, check_id, status, snooze_until, block_reason,
                 verified_by, last_status_changed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                project_id,
                env_url,
                check_id,
                status,
                snooze_until,
                block_reason,
                verified_by.map(VerifiedBy::as_str),
                now_ms
            ],
        )?;
        Ok(())
    })?
}

fn legacy_web_execution(db: &TestDb, project_id: i64) -> i64 {
    db.admit_scan_execution(
        NewScanExecution {
            project_id: Some(project_id),
            environment_id: None,
            environment_url: Some(SITE.into()),
            environment_scope_key: SITE.into(),
            requested_mode: ScanExecutionMode::Web,
            web_focus: Some(ScanType::Health),
            trigger: ScanTrigger::Manual,
            admission_class: ScanAdmissionClass::GeneralScan,
            idempotency_key: "legacy-web".into(),
            request_fingerprint: "v1:legacy-web".into(),
            now_ms: 100,
            web_status: Some(ScanComponentStatus::Planned),
            web_detail: None,
            code_status: None,
            code_detail: None,
        },
        900,
    )
    .expect("admit execution")
    .execution
    .id
}

fn legacy_web_run(db: &TestDb, project_id: i64) -> i64 {
    let execution_id = legacy_web_execution(db, project_id);
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO scan_runs (
                execution_id, project_id, environment_scope_key, source, run_kind, status,
                started_at, completed_at, timestamp_text, duration_ms, coverage_kind,
                coverage_json, diagnostics_json, detail_state, engine_release, manifest_digest, canonicalizer, crawl_profile
             ) VALUES (?1, ?2, ?3, 'web_scan', 'single', 'complete', 100, 110, '2024-01-01',
                       10, 'page', ?4, '{}', 'exact', '2.0.0', ?5, 1, 1)",
            params![
                execution_id, project_id, SITE,
                r#"{"kind":"page","successful":true,"pageUrls":[],"checks":[],"exceptions":[]}"#,
                "a".repeat(16),
            ],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    })
    .unwrap()
    .unwrap()
}

fn legacy_web_finding(db: &TestDb, project_id: i64, check_id: &'static str) {
    let run_id = legacy_web_run(db, project_id);
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO scan_findings (
                 run_id, ordinal, occurrence_id, source, canonical_check_id, producer_check_id,
                 category, producer_category, verdict, severity, confidence,
                 title, description, location_kind
             ) VALUES (?1, 0, 'legacy', 'web_scan', ?2, ?2, 'security', 'security',
                       'fail', 'high', 'confirmed', ?2, ?2, 'site')",
            params![run_id, check_id],
        )
    })
    .unwrap()
    .unwrap();
}

#[test]
fn an_override_with_only_a_stored_web_finding_is_omitted() {
    // An override can leak web evidence after its work item has been removed.
    let (db, project_id) = seeded();
    legacy_web_finding(&db, project_id, "security.headers.csp");
    seed_state(
        &db,
        project_id,
        SITE,
        "security.headers.csp",
        ("ignored", None, None, None),
        120,
    )
    .unwrap();

    let set = db.derive_bootstrap_set(project_id, SITE).unwrap();
    assert!(set.groups.is_empty());
}

#[test]
fn an_override_shared_by_code_and_web_findings_is_retained() {
    // A legacy web finding can hide the override on a check also found by code.
    let (db, project_id) = seeded();
    legacy_web_finding(&db, project_id, FIRST);
    persist_code(
        &db,
        project_id,
        "shared-override",
        &[(FIRST, CheckStatus::Fail)],
    );
    db.execute(move |conn| {
        conn.execute("DELETE FROM work_items WHERE project_id = ?1", [project_id])
    })
    .unwrap()
    .unwrap();
    seed_state(
        &db,
        project_id,
        SITE,
        FIRST,
        ("ignored", None, None, None),
        120,
    )
    .unwrap();

    let set = db.derive_bootstrap_set(project_id, SITE).unwrap();
    let shared = group(&set, FIRST).expect("shared override");
    assert_eq!(shared.state, BootstrapState::Ignored);
    assert_eq!(shared.state_changed_at, 120);
}

#[test]
fn stored_web_rows_never_reach_a_submission() {
    // A desktop-era web run can enter a connected submission from local storage.
    let (db, project_id) = seeded();
    legacy_web_run(&db, project_id);
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO work_items (
                 project_id, env_url, source, signal_id, check_id, category, severity,
                 title, description, first_seen_at, last_seen_at
             ) VALUES (?1, ?2, 'web_scan', 'legacy', 'security.headers.csp', 'security',
                       'high', 'CSP', 'CSP', 100, 110)",
            params![project_id, SITE],
        )
        .unwrap();
    })
    .unwrap();
    seed_state(
        &db,
        project_id,
        SITE,
        "security.headers.csp",
        ("verified", None, None, Some(VerifiedBy::UserClaim)),
        120,
    )
    .unwrap();
    let request = ConnectedSubmissionRequest {
        site_id: "site_local".into(),
        submission_sequence: 1,
        include_groups: true,
        fingerprint_key: None,
        fingerprint_key_version: 1,
        deployed_commit: None,
    };
    let submission = db
        .build_connected_submission(project_id, SITE, request.clone())
        .unwrap();
    assert!(submission.snapshots.web.is_none());
    assert!(submission.groups.unwrap().entries.is_empty());
    let submission = db
        .build_connected_submission(
            project_id,
            SITE,
            ConnectedSubmissionRequest {
                include_groups: false,
                ..request
            },
        )
        .unwrap();
    assert!(submission.snapshots.web.is_none());
}

#[test]
fn standin_desktop_submission_counts_distinct_same_line_findings() {
    // Distinct same-line findings can collapse or keep an untrusted check ID.
    // Merging distinct same-line findings undercounts what the service grades.
    let (db, project_id) = seeded();
    let scope_key = format!("project:{project_id}");
    let mut issue = code_issue("standin.rule", "src/db.ts", 12, Severity::Low);
    issue.check_id = "code_scan.untrusted-check".into();
    let distinct = ["second", "third"].map(|name| CodeIssue {
        id: format!("standin.rule:{name}:src/db.ts:12"),
        ..issue.clone()
    });
    let issues = [issue.clone(), issue].into_iter().chain(distinct).collect();
    code_scan(&db, project_id, "canonical", &scope_key, issues);

    let request = ConnectedSubmissionRequest {
        site_id: "site_fixture".into(),
        submission_sequence: 1,
        include_groups: false,
        fingerprint_key: Some(ProjectFingerprintKey::from_bytes(
            [7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN],
        )),
        fingerprint_key_version: 1,
        deployed_commit: None,
    };
    let snapshot = db
        .build_connected_submission(project_id, &scope_key, request.clone())
        .unwrap()
        .snapshots
        .code
        .unwrap();
    assert_eq!(snapshot.occurrences.len(), 1);
    assert_eq!(
        snapshot.occurrences[0].check.as_str(),
        "code_scan.standin.rule"
    );
    assert_eq!(snapshot.occurrences[0].instance_count, 3);

    let unknown = CodeScanReport {
        checked_at: "2026-08-06T00:00:00Z".into(),
        framework: None,
        issue_count: 1,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 1,
        issues: vec![code_issue(
            "unregistered-fixture-rule",
            "src/db.ts",
            48,
            Severity::Low,
        )],
        skipped_scopes: Default::default(),
    };
    let error = db
        .save_code_scan_with_provenance(
            project_id,
            None,
            "/tmp/bootstrap".into(),
            &unknown,
            10,
            crate::core::code_provenance::CodeCheckoutProvenance::default(),
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The engine reported an unknown Code Scan rule."
    );
    let after_refusal = db
        .build_connected_submission(project_id, &scope_key, request.clone())
        .unwrap()
        .snapshots
        .code
        .unwrap();
    assert_eq!(after_refusal, snapshot);

    db.execute(|conn| {
        conn.execute(
            "UPDATE scan_findings SET producer_check_id = ?1 WHERE canonical_check_id = ?2",
            params!["unregistered-fixture-rule", "code_scan.standin.rule"],
        )
    })
    .unwrap()
    .unwrap();
    let error = db
        .build_connected_submission(project_id, &scope_key, request)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The engine reported an unknown Code Scan rule."
    );
}
