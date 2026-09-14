//! Tests for `db::fix_attempts`.

use super::FixAttemptTarget;
use crate::db::test_helpers::{insert_test_work_item, insert_test_work_item_at, temp_db};

#[test]
fn create_replaces_existing_active_attempt() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");

    let first = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("first attempt");
    let second = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "cursor",
            2_000,
        )
        .expect("second attempt");
    assert_ne!(first, second, "a new attempt gets a fresh row");

    let latest = db
        .get_latest_fix_attempt(project_id, "https://example.com", "security.csp")
        .expect("latest")
        .expect("row exists");
    assert_eq!(latest.id, second);
    assert_eq!(latest.status, "briefed");
    assert_eq!(latest.agent_tool, "cursor");

    let first_row = db
        .get_fix_attempt(first)
        .expect("get first")
        .expect("first row exists");
    assert_eq!(
        first_row.status, "canceled",
        "the superseded attempt is canceled, not left active"
    );
    assert_eq!(first_row.updated_at, 2_000);
}

#[test]
fn different_occurrence_targets_remain_independently_active() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let first = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret",
            "codex",
            FixAttemptTarget::occurrence("src/a.ts".into(), Some(10)),
            1_000,
        )
        .expect("first target");
    let second = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret",
            "codex",
            FixAttemptTarget::occurrence("src/b.ts".into(), Some(20)),
            2_000,
        )
        .expect("second target");

    assert_ne!(first, second);
    assert_eq!(
        db.list_fix_attempts_in_status(&["briefed"])
            .expect("active attempts")
            .len(),
        2,
        "a sibling target must not cancel the first occurrence"
    );
}

#[test]
fn different_lines_in_the_same_file_remain_independently_active() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let first = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret",
            "codex",
            FixAttemptTarget::occurrence("src/a.ts".into(), Some(10)),
            1_000,
        )
        .expect("first occurrence");
    let second = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret",
            "codex",
            FixAttemptTarget::occurrence("src/a.ts".into(), Some(18)),
            2_000,
        )
        .expect("second occurrence");

    assert_ne!(first, second);
    assert_eq!(
        db.get_fix_attempt(first)
            .expect("first query")
            .expect("first row")
            .status,
        "briefed"
    );
    assert_eq!(
        db.list_fix_attempts_in_status(&["briefed"])
            .expect("active attempts")
            .len(),
        2
    );

    let first_latest = db
        .get_latest_fix_attempt_for_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret",
            FixAttemptTarget::occurrence("src/a.ts".into(), Some(10)),
        )
        .expect("first target lookup")
        .expect("first target row");
    let second_latest = db
        .get_latest_fix_attempt_for_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret",
            FixAttemptTarget::occurrence("src/a.ts".into(), Some(18)),
        )
        .expect("second target lookup")
        .expect("second target row");

    assert_eq!(first_latest.id, first);
    assert_eq!(second_latest.id, second);
}

#[test]
fn fix_attempts_reject_path_bearing_canonical_ids() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let error = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.hardcoded-secret:src/env.ts",
            "codex",
            FixAttemptTarget::occurrence("src/env.ts".into(), Some(10)),
            1_000,
        )
        .expect_err("the location belongs only in the structured target");
    assert!(error.to_string().contains("is not canonical"));
}

#[test]
fn status_transitions_and_terminal_fields() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let id = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create");

    db.update_fix_attempt_brief(id, "# Add a Content-Security-Policy header", 1_100)
        .expect("brief");
    db.set_fix_attempt_status(
        id,
        "verify_requested",
        Some("Added the header"),
        None,
        1_200,
    )
    .expect("verify_requested");
    db.set_fix_attempt_status(id, "verifying", None, None, 1_300)
        .expect("verifying");
    db.set_fix_attempt_status(
        id,
        "verify_failed",
        None,
        Some("header still missing"),
        1_400,
    )
    .expect("verify_failed");

    let row = db.get_fix_attempt(id).expect("get").expect("row exists");
    assert_eq!(row.status, "verify_failed");
    assert_eq!(row.brief_md, "# Add a Content-Security-Policy header");
    assert_eq!(
        row.agent_summary.as_deref(),
        Some("Added the header"),
        "None on later transitions must preserve the earlier summary"
    );
    assert_eq!(row.failure_detail.as_deref(), Some("header still missing"));
    assert_eq!(
        row.verify_started_at,
        Some(1_300),
        "verify_started_at is stamped when verifying begins"
    );
    assert_eq!(row.updated_at, 1_400);
}

#[test]
fn status_machine_rejects_invalid_transitions() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let id = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create");

    let unknown = db
        .set_fix_attempt_status(id, "totally_bogus", None, None, 1_100)
        .expect_err("unknown status must be rejected");
    assert_eq!(
        unknown.to_string(),
        "unknown fix attempt status: totally_bogus"
    );

    db.set_fix_attempt_status(id, "verify_failed", None, Some("nope"), 1_200)
        .expect("verify_failed");

    let resurrect = db
        .set_fix_attempt_status(id, "verifying", None, None, 1_300)
        .expect_err("terminal rows must not be resurrected");
    assert_eq!(
        resurrect.to_string(),
        format!("fix attempt {id} is 'verify_failed'; cannot transition to 'verifying'")
    );

    db.set_fix_attempt_status(id, "verify_failed", None, None, 1_400)
        .expect("re-setting the same terminal status is idempotent");
    let row = db.get_fix_attempt(id).expect("get").expect("row exists");
    assert_eq!(row.status, "verify_failed");
    assert_eq!(
        row.updated_at, 1_200,
        "the idempotent no-op must not rewrite the row"
    );

    let missing_status = db
        .set_fix_attempt_status(9_999, "verifying", None, None, 1_500)
        .expect_err("nonexistent id must error");
    assert_eq!(missing_status.to_string(), "no fix attempt with id 9999");

    let missing_brief = db
        .update_fix_attempt_brief(9_999, "# brief", 1_500)
        .expect_err("nonexistent id must error");
    assert_eq!(missing_brief.to_string(), "no fix attempt with id 9999");
}

#[test]
fn normalization_joins_equivalent_env_urls() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");

    let messy = db
        .create_fix_attempt(
            project_id,
            "https://Example.COM/",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create with messy url");

    let latest = db
        .get_latest_fix_attempt(project_id, "https://example.com", "security.csp")
        .expect("latest")
        .expect("the clean form must find the messy-form attempt");
    assert_eq!(latest.id, messy);
    assert_eq!(latest.env_url, "https://example.com");

    let clean = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "cursor",
            2_000,
        )
        .expect("create with clean url");
    assert_ne!(clean, messy);

    let messy_row = db
        .get_fix_attempt(messy)
        .expect("get messy")
        .expect("messy row exists");
    assert_eq!(
        messy_row.status, "canceled",
        "the clean-form attempt must cancel the messy-form attempt"
    );
}

#[test]
fn expire_stale_attempts_only_touches_active_rows() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");

    let verified = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create verified");
    db.set_fix_attempt_status(verified, "verified", None, None, 1_500)
        .expect("mark verified");

    let active = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "seo.title",
            "claude-code",
            1_000,
        )
        .expect("create active");

    let expired = db.expire_stale_fix_attempts(2_000, 3_000).expect("expire");
    assert_eq!(expired, 1, "only the active stale row is expired");

    let verified_row = db
        .get_fix_attempt(verified)
        .expect("get verified")
        .expect("verified row exists");
    assert_eq!(
        verified_row.status, "verified",
        "terminal rows must not be expired"
    );

    let active_row = db
        .get_fix_attempt(active)
        .expect("get active")
        .expect("active row exists");
    assert_eq!(active_row.status, "expired");
    assert_eq!(active_row.updated_at, 3_000);
}

#[test]
fn canonical_group_activity_uses_exact_identity() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    insert_test_work_item(
        &db,
        project_id,
        "https://example.com",
        "code_scan.sql-injection",
    )
    .expect("insert test work item");

    assert!(db
        .is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "code_scan.sql-injection",
            "group",
            None,
            None,
        )
        .expect("exact group query"));
    assert!(
        !db.is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "security.csp",
            "group",
            None,
            None,
        )
        .expect("plain query"),
        "a check_id with no matching row must report inactive"
    );

    // Env-url normalization must match the sibling queries: a messy form
    // of the same env keys to the same rows.
    assert!(db
        .is_fix_attempt_target_active(
            project_id,
            "https://Example.COM/",
            "code_scan.sql-injection",
            "group",
            None,
            None,
        )
        .expect("messy env query"));
}

// fix_attempt_watcher is desktop-gated, so this test only compiles when
// the default `desktop` feature is enabled (it still runs under default).
#[test]
fn canonical_group_activity_does_not_match_longer_rule_names() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");

    insert_test_work_item(
        &db,
        project_id,
        "https://example.com",
        "code_scan.sensitive-authz",
    )
    .expect("insert test work item");
    assert!(
        !db.is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "code_scan.sensitive-auth",
            "group",
            None,
            None,
        )
        .expect("authz-only query"),
        "sensitive-auth patterns must not match a sensitive-authz row"
    );

    // Once a sensitive-auth row exists in some file, the same bare-rule
    // patterns do report it active.
    insert_test_work_item(
        &db,
        project_id,
        "https://example.com",
        "code_scan.sensitive-auth",
    )
    .expect("insert test work item");
    assert!(db
        .is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "code_scan.sensitive-auth",
            "group",
            None,
            None,
        )
        .expect("auth row query"));
}

#[test]
fn occurrence_activity_scopes_attempts_to_their_structured_file_target() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    insert_test_work_item_at(
        &db,
        project_id,
        "https://example.com",
        "code_scan.external-call-retry",
        Some("src/pages/api/latest-release.ts"),
        Some(12),
    )
    .expect("insert sibling work item");

    assert!(
        !db.is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "code_scan.external-call-retry",
            "occurrence",
            Some("src/pages/api/contact.ts"),
            Some(20),
        )
        .expect("sibling-only query"),
        "a sibling file failing the same rule must not keep this attempt failing"
    );

    // The dispatched file's own unresolved row is what keeps it active.
    insert_test_work_item_at(
        &db,
        project_id,
        "https://example.com",
        "code_scan.external-call-retry",
        Some("src/pages/api/contact.ts"),
        Some(20),
    )
    .expect("insert own-file work item");
    assert!(db
        .is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "code_scan.external-call-retry",
            "occurrence",
            Some("src/pages/api/contact.ts"),
            Some(20),
        )
        .expect("own-file query"));

    assert!(
        !db.is_fix_attempt_target_active(
            project_id,
            "https://example.com",
            "code_scan.external-call-retry",
            "occurrence",
            Some("src/pages/api/contact.ts"),
            Some(99),
        )
        .expect("shifted-line query"),
        "another line in the same file is a separate occurrence"
    );
}

#[test]
fn occurrence_activity_survives_line_only_movement() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    insert_test_work_item_at(
        &db,
        project_id,
        "https://example.com",
        "code_scan.unsafe-html",
        Some("src/view.tsx"),
        Some(20),
    )
    .expect("insert occurrence");
    let id = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.unsafe-html",
            "codex",
            FixAttemptTarget::occurrence("src/view.tsx".into(), Some(20)),
            1_000,
        )
        .expect("create attempt");
    let attempt = db
        .get_fix_attempt(id)
        .expect("query attempt")
        .expect("attempt row");
    assert_eq!(attempt.target_occurrence_count, Some(1));

    db.execute(move |conn| {
        conn.execute(
            "UPDATE work_items SET line = 99 WHERE project_id = ?1",
            rusqlite::params![project_id],
        )
        .map_err(|error| error.to_string())
    })
    .expect("database worker")
    .expect("move line");

    assert!(
        db.is_fix_attempt_active(&attempt)
            .expect("line-shifted activity"),
        "moving an unchanged finding must not verify the attempt"
    );
}

#[test]
fn clearing_one_occurrence_does_not_wait_for_its_sibling() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    insert_test_work_item_at(
        &db,
        project_id,
        "https://example.com",
        "code_scan.unsafe-html",
        Some("src/view.tsx"),
        Some(20),
    )
    .expect("insert first occurrence");
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO work_items
                (project_id, env_url, source, signal_id, check_id, category, severity,
                 title, description, first_seen_at, last_seen_at, resolved_at,
                 relative_path, line)
             VALUES (?1, 'https://example.com', 'code_scan', 'second-unsafe-html',
                     'code_scan.unsafe-html', 'security', 'high', 'unsafe html',
                     'unsafe html', 1000, 1000, NULL, 'src/view.tsx', 40)",
            rusqlite::params![project_id],
        )
        .map_err(|error| error.to_string())
    })
    .expect("database worker")
    .expect("insert second occurrence");
    let id = db
        .create_fix_attempt_with_target(
            project_id,
            "https://example.com",
            "code_scan.unsafe-html",
            "codex",
            FixAttemptTarget::occurrence("src/view.tsx".into(), Some(20)),
            1_000,
        )
        .expect("create attempt");
    let attempt = db
        .get_fix_attempt(id)
        .expect("query attempt")
        .expect("attempt row");
    assert_eq!(attempt.target_occurrence_count, Some(2));

    db.execute(move |conn| {
        conn.execute(
            "UPDATE work_items SET resolved_at = 2000
             WHERE project_id = ?1 AND line = 20",
            rusqlite::params![project_id],
        )
        .map_err(|error| error.to_string())
    })
    .expect("database worker")
    .expect("resolve target");

    assert!(
        !db.is_fix_attempt_active(&attempt)
            .expect("remaining activity"),
        "a separate occurrence must not keep the repaired target active"
    );
}

#[test]
fn list_attempts_in_status_filters() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");

    let _briefed = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create briefed");
    let requested = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "seo.title",
            "claude-code",
            1_100,
        )
        .expect("create requested");
    db.set_fix_attempt_status(requested, "verify_requested", None, None, 1_200)
        .expect("flip to verify_requested");

    let rows = db
        .list_fix_attempts_in_status(&["verify_requested"])
        .expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, requested);
    assert_eq!(rows[0].status, "verify_requested");
}

// The MCP server stamps brief_fetched_at out-of-process; this pins that the
// desktop read paths (shared column list + positional mapper) round-trip
// the stamp instead of silently misaligning a later column.
#[test]
fn brief_fetched_stamp_round_trips_through_every_read_path() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let id = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create");

    let fresh = db.get_fix_attempt(id).expect("get").expect("row exists");
    assert_eq!(fresh.brief_fetched_at, None, "unfetched briefs carry None");

    // Same statement shape the MCP get_fix_brief tool runs.
    db.execute(move |conn| {
        conn.execute(
            "UPDATE fix_attempts
             SET brief_fetched_at = ?2, updated_at = ?2
             WHERE id = ?1 AND brief_fetched_at IS NULL",
            rusqlite::params![id, 1_500_i64],
        )
        .map_err(|e| e.to_string())
    })
    .expect("db worker")
    .expect("stamp");

    let stamped = db.get_fix_attempt(id).expect("get").expect("row exists");
    assert_eq!(stamped.brief_fetched_at, Some(1_500));
    assert_eq!(stamped.created_at, 1_000, "neighbor columns stay aligned");
    assert_eq!(stamped.updated_at, 1_500);

    let latest = db
        .get_latest_fix_attempt(project_id, "https://example.com", "security.csp")
        .expect("latest")
        .expect("row exists");
    assert_eq!(latest.brief_fetched_at, Some(1_500));

    let listed = db.list_fix_attempts_in_status(&["briefed"]).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].brief_fetched_at, Some(1_500));
}

#[test]
fn count_metered_fix_attempts_refunds_only_verify_failed() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let window_start = 1_000_000;
    // Distinct check_ids keep every attempt clear of the one-active-row
    // unique index and of create's supersede-cancel path.
    let create = |check_id: &str, created_at: i64| {
        db.create_fix_attempt(
            project_id,
            "https://example.com",
            check_id,
            "claude-code",
            created_at,
        )
        .expect("create attempt")
    };

    let pre_window = create("security.csp", 900_000);
    db.set_fix_attempt_status(pre_window, "verified", None, None, window_start + 70)
        .expect("pre-window verified");

    let _stale = create("seo.title", window_start);
    let _briefed = create("seo.description", window_start + 10);
    let requested = create("perf.lcp", window_start + 20);
    db.set_fix_attempt_status(
        requested,
        "verify_requested",
        None,
        None,
        window_start + 120,
    )
    .expect("verify_requested");
    let verifying = create("security.headers", window_start + 30);
    db.set_fix_attempt_status(
        verifying,
        "verify_requested",
        None,
        None,
        window_start + 130,
    )
    .expect("verifying: request");
    db.set_fix_attempt_status(verifying, "verifying", None, None, window_start + 230)
        .expect("verifying: start");
    let verified = create("seo.canonical", window_start + 40);
    db.set_fix_attempt_status(verified, "verified", None, None, window_start + 140)
        .expect("verified");
    let failed = create("accessibility.contrast", window_start + 50);
    db.set_fix_attempt_status(
        failed,
        "verify_failed",
        None,
        Some("still broken"),
        window_start + 150,
    )
    .expect("verify_failed");
    let canceled = create("seo.robots", window_start + 60);
    db.cancel_fix_attempt_if_active(canceled, window_start + 160)
        .expect("canceled");
    let expired = db
        .expire_stale_fix_attempts(window_start + 5, window_start + 400)
        .expect("expire");
    assert_eq!(expired, 1, "exactly the stale attempt expires");
    assert_eq!(
        super::ALL_FIX_ATTEMPT_STATUSES.len(),
        7,
        "new status: decide its allowance refund policy and extend this test"
    );

    assert_eq!(
        db.count_metered_fix_attempts(window_start).unwrap(),
        6,
        "in-window: 7 attempts minus the verify_failed refund"
    );
    assert_eq!(db.count_metered_fix_attempts(0).unwrap(), 7);
}

#[test]
fn touch_fix_attempt_refreshes_updated_at_only() {
    let db = temp_db();
    let project_id = db
        .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
        .expect("upsert");
    let id = db
        .create_fix_attempt(
            project_id,
            "https://example.com",
            "security.csp",
            "claude-code",
            1_000,
        )
        .expect("create");

    db.touch_fix_attempt(id, 9_999).expect("touch");

    let row = db.get_fix_attempt(id).expect("get").expect("row");
    assert_eq!(row.updated_at, 9_999);
    assert_eq!(
        row.status, "briefed",
        "the heartbeat must not transition status"
    );
    assert_eq!(row.created_at, 1_000, "created_at is untouched");
}
