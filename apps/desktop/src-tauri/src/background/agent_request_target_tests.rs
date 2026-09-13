use super::*;
use crate::db::test_helpers::temp_db;

const ENV_URL: &str = "https://example.com";
const CHECK_ID: &str = "code_scan.unsafe-html";
const FILE: &str = "web/logic.js";

fn seed_code_occurrences(db: &Database) -> i64 {
    let project_id = db
        .upsert_project("Agent Target", "/tmp/agent-target", None)
        .unwrap();
    db.execute(move |conn| {
        for line in [241, 346] {
            conn.execute(
                "INSERT INTO work_items
                 (project_id, env_url, source, signal_id, check_id, category, severity,
                  title, description, first_seen_at, last_seen_at, relative_path, line)
                 VALUES (?1, ?2, 'code_scan', ?3, ?4, 'security', 'high', ?3, ?3, 1000, 1000, ?5, ?6)",
                rusqlite::params![project_id, ENV_URL, format!("{FILE}:{line}"), CHECK_ID, FILE, line],
            )?;
        }
        Ok::<_, rusqlite::Error>(())
    }).unwrap().unwrap();
    project_id
}

fn queue_target(db: &Database, project_id: i64, path: &str, line: Option<u32>) -> AgentRequestRow {
    let path = path.to_string();
    db.execute(move |conn| {
        conn.execute(
            "INSERT INTO agent_requests
             (kind, project_id, env_url, check_id, agent_tool, created_at, updated_at,
              target_relative_path, target_line)
             VALUES ('start_fix', ?1, ?2, ?3, 'codex', 1000, 1000, ?4, ?5)",
            rusqlite::params![project_id, ENV_URL, CHECK_ID, path, line],
        )
    })
    .unwrap()
    .unwrap();
    db.list_agent_requests_in_status("requested")
        .unwrap()
        .remove(0)
}

#[test]
fn selected_occurrence_survives_the_queue_and_appears_in_the_brief() {
    let db = temp_db();
    let project_id = seed_code_occurrences(&db);
    let request = queue_target(&db, project_id, FILE, Some(346));
    let result = fulfil_start_fix(&db, &request, 2000).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&result).unwrap();
    let attempt = db
        .get_fix_attempt(payload["attempt_id"].as_i64().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(attempt.target_relative_path.as_deref(), Some(FILE));
    assert_eq!(attempt.target_line, Some(346));
    assert!(attempt.brief_md.contains("web/logic.js:346"));
}

#[test]
fn an_issue_ignored_after_queueing_cannot_open_a_fix_attempt() {
    let db = temp_db();
    let project_id = seed_code_occurrences(&db);
    let request = queue_target(&db, project_id, FILE, Some(346));
    db.set_issue_state(
        project_id,
        ENV_URL,
        CHECK_ID,
        crate::db::IssueLifecycle::Ignored,
        1500,
    )
    .unwrap();
    assert!(fulfil_start_fix(&db, &request, 2000).is_err());
    assert!(db
        .list_fix_attempts_in_status(&["briefed"])
        .unwrap()
        .is_empty());
}

#[test]
fn a_changed_occurrence_never_falls_back_to_its_sibling() {
    for change in [
        "UPDATE work_items SET resolved_at = 1500 WHERE line = 346",
        "UPDATE work_items SET line = 347 WHERE line = 346",
        "UPDATE work_items SET relative_path = 'other.js' WHERE line = 346",
        "UPDATE work_items SET env_url = 'https://other.test' WHERE line = 346",
        "UPDATE work_items SET source = 'web_scan' WHERE line = 346",
    ] {
        let db = temp_db();
        let project_id = seed_code_occurrences(&db);
        let request = queue_target(&db, project_id, FILE, Some(346));
        db.execute(move |conn| conn.execute(change, []))
            .unwrap()
            .unwrap();
        let error = fulfil_start_fix(&db, &request, 2000).unwrap_err();
        assert!(
            error.contains("No open Code Scan occurrence"),
            "{change}: {error}"
        );
        assert!(db
            .list_fix_attempts_in_status(&["briefed"])
            .unwrap()
            .is_empty());
    }
}

#[test]
fn a_file_level_target_does_not_select_a_numbered_occurrence() {
    let db = temp_db();
    let project_id = seed_code_occurrences(&db);
    let request = queue_target(&db, project_id, FILE, None);
    assert!(fulfil_start_fix(&db, &request, 2000).is_err());
    db.execute(|conn| conn.execute("UPDATE work_items SET line = NULL WHERE line = 346", []))
        .unwrap()
        .unwrap();
    let result = fulfil_start_fix(&db, &request, 2000).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&result).unwrap();
    let attempt = db
        .get_fix_attempt(payload["attempt_id"].as_i64().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(attempt.target_relative_path.as_deref(), Some(FILE));
    assert_eq!(attempt.target_line, None);
}

#[test]
fn mapped_code_rules_keep_the_selected_producer_and_location() {
    let db = temp_db();
    let project_id = seed_code_occurrences(&db);
    queue_target(&db, project_id, FILE, Some(346));
    db.execute(|conn| {
        conn.execute_batch(
            "UPDATE work_items SET check_id = 'security.hsts', producer_check_id = 'hsts_missing';
         UPDATE agent_requests SET check_id = 'security.hsts';",
        )
    })
    .unwrap()
    .unwrap();
    let request = db
        .list_agent_requests_in_status("requested")
        .unwrap()
        .remove(0);
    let result = fulfil_start_fix(&db, &request, 2000).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&result).unwrap();
    let attempt = db
        .get_fix_attempt(payload["attempt_id"].as_i64().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(attempt.check_id, "security.hsts");
    assert_eq!(attempt.producer_rule.as_deref(), Some("hsts_missing"));
    assert_eq!(attempt.target_line, Some(346));
}

#[test]
fn a_new_repository_suppression_blocks_the_queued_target() {
    let db = temp_db();
    let project_id = seed_code_occurrences(&db);
    let request = queue_target(&db, project_id, FILE, Some(346));
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".sitecmd")).unwrap();
    std::fs::write(
        root.path().join(".sitecmd/config.json"),
        r#"{
        "version": 1,
        "url": "https://example.com",
        "name": "Suppressed project",
        "code_scan": {"suppressions": [
            {"match": {"rule": "code_scan.unsafe-html", "path": "web/logic.js"}, "reason": "Intentional example"}
        ]}
    }"#,
    )
    .unwrap();
    let path = root.path().to_string_lossy().into_owned();
    db.execute(move |conn| {
        conn.execute(
            "UPDATE projects SET path = ?1 WHERE id = ?2",
            rusqlite::params![path, project_id],
        )
    })
    .unwrap()
    .unwrap();
    let error = fulfil_start_fix(&db, &request, 2000).unwrap_err();
    assert!(error.contains("suppressed"), "{error}");
    assert!(db
        .list_fix_attempts_in_status(&["briefed"])
        .unwrap()
        .is_empty());
}
