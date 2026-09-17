//! Agent fix-attempt commands and MCP brief persistence.

use std::sync::Arc;

use tauri::State;

use crate::core::fix_brief::{build_fix_brief, build_kickoff_prompt, BriefLocation, FixBriefInput};
use crate::db::{Database, FixAttemptRow, FixAttemptTarget};

use super::fix_attempt_guidance::stored_issue_guidance;
use super::issues::require_issue_env_url;
use super::run_blocking;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn date_at_ms(timestamp_ms: i64) -> chrono::NaiveDate {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms)
        .map(|timestamp| timestamp.date_naive())
        .unwrap_or_else(|| chrono::Utc::now().date_naive())
}

fn reject_suppressed_code_occurrence(
    db: &Database,
    project_id: i64,
    env_url: &str,
    check_id: &str,
    target: &FixAttemptTarget,
    now: i64,
) -> Result<(), String> {
    let Some(relative_path) = target.relative_path.as_deref() else {
        return Ok(());
    };
    let Some(project_path) = db
        .get_project_path_result(project_id)
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let project_root = std::path::Path::new(&project_path);
    if !project_root.join(".sitecmd/config.json").is_file() {
        return Ok(());
    }
    let items = db
        .get_active_work_items(project_id, Some(env_url))
        .map_err(|error| error.to_string())?;
    let Some(item) = items.iter().find(|item| {
        item.source == "code_scan"
            && item.check_id == check_id
            && item.metadata.relative_path.as_deref() == Some(relative_path)
            && item.metadata.line == target.line
    }) else {
        return Ok(());
    };
    let fingerprint = item
        .detail_json
        .as_deref()
        .map(serde_json::from_str::<crate::core::code_scan::CodeIssue>)
        .transpose()
        .map_err(|error| format!("Could not read the stored Code Scan finding: {error}"))?
        .map(|issue| crate::cli::audit_suppressions::issue_fingerprint(&issue));
    let suppression = crate::cli::audit_suppressions::active_project_suppression(
        project_root,
        check_id,
        relative_path,
        fingerprint.as_deref(),
        date_at_ms(now),
    )?;
    if let Some(suppression) = suppression {
        let expiry = suppression
            .expires
            .map(|date| format!(" through {date}"))
            .unwrap_or_default();
        return Err(format!(
            "This Code Scan finding is suppressed by .sitecmd/config.json{expiry}: {}. Run Code Scan again to refresh the issue list.",
            suppression.reason
        ));
    }
    Ok(())
}

#[derive(Debug, serde::Serialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct FixAttemptDto {
    pub id: i64,
    pub status: String,
    pub agent_tool: String,
    pub agent_summary: Option<String>,
    pub failure_detail: Option<String>,
    pub kickoff_prompt: String,
    /// Ms epoch when the agent first pulled the brief through MCP; the
    /// handoff modal uses it to show "agent picked up the brief".
    pub brief_fetched_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct CreateFixAttemptArgs {
    pub project_id: i64,
    pub env_url: Option<String>,
    pub check_id: String,
    /// Typed so an invalid agent token is rejected at the IPC boundary;
    /// the kebab-case serde token is what lands in fix_attempts.agent_tool.
    pub agent_tool: crate::core::agent_tools::AgentTool,
    pub title: String,
    /// Typed like agent_tool: an unknown severity is rejected at the IPC
    /// boundary instead of flowing into the fix brief as free text.
    pub severity: crate::checks::Severity,
    pub description: String,
    pub why_it_matters: Option<String>,
    #[ts(type = "unknown")]
    pub evidence: Option<serde_json::Value>,
    pub manual_fix: Option<String>,
    pub url: String,
    #[ts(type = "unknown")]
    pub detected_stack: Option<serde_json::Value>,
    pub code_locations: Option<Vec<BriefLocation>>,
    pub previous_failure: Option<String>,
}

fn attempt_dto(row: FixAttemptRow, title: &str) -> FixAttemptDto {
    FixAttemptDto {
        id: row.id,
        status: row.status,
        agent_tool: row.agent_tool,
        agent_summary: row.agent_summary,
        failure_detail: row.failure_detail,
        kickoff_prompt: build_kickoff_prompt(row.id, title),
        brief_fetched_at: row.brief_fetched_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// Core create flow, separated from the Tauri `State` wrapper so tests can
/// exercise it against a `temp_db` (the brief-parity tests live in
/// `fix_attempt_guidance`, hence `pub(super)`).
pub(crate) fn create_fix_attempt_inner(
    db: &Database,
    args: CreateFixAttemptArgs,
    now: i64,
) -> Result<FixAttemptDto, String> {
    let CreateFixAttemptArgs {
        project_id,
        env_url,
        check_id,
        agent_tool,
        title,
        severity,
        description,
        why_it_matters,
        evidence,
        manual_fix,
        url,
        detected_stack,
        code_locations,
        previous_failure,
    } = args;
    let env_url = require_issue_env_url(env_url)?;
    crate::core::code_scan::validate_canonical_check_id(&check_id)?;
    // A mapped Code rule may intentionally share a Web canonical id (for
    // example hsts_missing -> security.hsts). The structured location, not
    // the canonical id prefix, determines whether this is an occurrence fix.
    let occurrence_target = match code_locations.as_deref() {
        Some([location]) => Some(location.clone()),
        _ => None,
    };
    let attempt_target = match occurrence_target.as_ref() {
        Some(location) => FixAttemptTarget::occurrence(location.path.clone(), location.line),
        _ => FixAttemptTarget::group(),
    };
    reject_suppressed_code_occurrence(db, project_id, &env_url, &check_id, &attempt_target, now)?;

    // Code-scan issues carry their own locations; web-scan issues fall back
    // to the static fix-location hints resolved against the linked project.
    let locations: Vec<BriefLocation> = match code_locations {
        Some(locations) if !locations.is_empty() => locations,
        _ => {
            let project_path = db.get_project_path(project_id);
            crate::core::correlation::resolve_fix_locations(&check_id, project_path.as_deref())
                .into_iter()
                .map(|location| BriefLocation {
                    label: location.label,
                    path: location.relative_path,
                    line: None,
                    reason: location.reason,
                    start_line: None,
                    end_line: None,
                    excerpt: None,
                })
                .collect()
        }
    };

    // Callers may omit guidance fields the stored scan already carries; fill
    // from the store. Args that arrive complete are never overwritten.
    let (why_it_matters, evidence, manual_fix) =
        if why_it_matters.is_none() || evidence.is_none() || manual_fix.is_none() {
            let stored = stored_issue_guidance(db, project_id, &env_url, &check_id)?;
            (
                why_it_matters.or(stored.why_it_matters),
                evidence.or(stored.evidence),
                manual_fix.or(stored.manual_fix),
            )
        } else {
            (why_it_matters, evidence, manual_fix)
        };

    let id = db.create_fix_attempt_with_target(
        project_id,
        &env_url,
        &check_id,
        agent_tool.as_str(),
        attempt_target,
        now,
    )?;
    let input = FixBriefInput {
        attempt_id: id,
        check_id,
        title: title.clone(),
        severity,
        description,
        why_it_matters,
        evidence,
        manual_fix,
        url,
        detected_stack,
        previous_failure,
        occurrence_target,
    };
    let brief = build_fix_brief(&input, &locations);
    if let Err(err) = db.update_fix_attempt_brief(id, &brief, now) {
        // Best effort: never leave a live attempt with an empty brief behind.
        let _ = db.cancel_fix_attempt_if_active(id, now);
        return Err(err.into());
    }
    let row = db
        .get_fix_attempt(id)?
        .ok_or_else(|| format!("fix attempt {id} missing right after creation"))?;
    Ok(attempt_dto(row, &title))
}

#[tauri::command]
#[tracing::instrument(
    skip(db, args),
    fields(project_id = args.project_id, check_id = %args.check_id, agent_tool = args.agent_tool.as_str())
)]
pub async fn create_fix_attempt(
    db: State<'_, Arc<Database>>,
    args: CreateFixAttemptArgs,
) -> Result<FixAttemptDto, String> {
    let now = now_ms();
    let db = (*db).clone();
    run_blocking(move || create_fix_attempt_inner(&db, args, now)).await?
}

/// Latest attempt for one issue regardless of status, so the dossier can show
/// in-flight or failed attempts. `None` when the issue has no env yet.
#[tauri::command]
#[tracing::instrument(skip(db, env_url, title), fields(project_id, check_id = %check_id))]
pub async fn get_fix_attempt_for_issue(
    db: State<'_, Arc<Database>>,
    project_id: i64,
    env_url: Option<String>,
    check_id: String,
    title: String,
    target_relative_path: Option<String>,
    target_line: Option<u32>,
) -> Result<Option<FixAttemptDto>, String> {
    let Ok(env_url) = require_issue_env_url(env_url) else {
        return Ok(None);
    };
    let target = match target_relative_path {
        Some(path) => FixAttemptTarget::occurrence(path, target_line),
        None => FixAttemptTarget::group(),
    };
    let db = (*db).clone();
    let row = run_blocking(move || {
        db.get_latest_fix_attempt_for_target(project_id, &env_url, &check_id, target)
    })
    .await??;
    Ok(row.map(|row| attempt_dto(row, &title)))
}

/// Cancel an active attempt; terminal attempts are unchanged.
#[tauri::command]
#[tracing::instrument(skip(db), fields(attempt_id))]
pub async fn cancel_fix_attempt(
    db: State<'_, Arc<Database>>,
    attempt_id: i64,
) -> Result<(), String> {
    let db = (*db).clone();
    run_blocking(move || db.cancel_fix_attempt_if_active(attempt_id, now_ms()))
        .await?
        .map_err(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_helpers::temp_db;

    fn base_args(project_id: i64) -> CreateFixAttemptArgs {
        CreateFixAttemptArgs {
            project_id,
            env_url: Some("https://example.com".to_string()),
            check_id: "security.csp".to_string(),
            agent_tool: crate::core::agent_tools::AgentTool::ClaudeCode,
            title: "Missing Content-Security-Policy".to_string(),
            severity: crate::checks::Severity::High,
            description: "The site does not send a Content-Security-Policy header.".to_string(),
            why_it_matters: Some("Without CSP, injected scripts run unrestricted.".to_string()),
            evidence: None,
            manual_fix: None,
            url: "https://example.com".to_string(),
            detected_stack: None,
            code_locations: None,
            previous_failure: None,
        }
    }

    #[test]
    fn brief_for_web_issue_uses_fix_locations_fallback() {
        let db = temp_db();
        // The fix-location resolver only returns files that exist, so give
        // the linked project a real candidate file for security.csp.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("vercel.json"), "{}").expect("write vercel.json");
        let project_path = dir.path().to_str().expect("utf8 path").to_string();
        let project_id = db
            .upsert_project("Fix Loop", &project_path, Some("nextjs"))
            .expect("upsert");

        let resolved =
            crate::core::correlation::resolve_fix_locations("security.csp", Some(&project_path));
        assert!(
            !resolved.is_empty(),
            "security.csp must resolve at least one location"
        );
        let expected_path = resolved[0].relative_path.clone();

        let dto =
            create_fix_attempt_inner(&db, base_args(project_id), 1_000).expect("create attempt");
        assert_eq!(dto.status, "briefed");
        assert!(dto
            .kickoff_prompt
            .contains(&format!("attempt_id={}", dto.id)));

        let row = db
            .get_fix_attempt(dto.id)
            .expect("get")
            .expect("row exists");
        assert!(row.brief_md.contains("## Where to look"));
        assert!(
            row.brief_md.contains(&expected_path),
            "brief must mention the resolved path {expected_path}, got:\n{}",
            row.brief_md
        );
    }

    #[test]
    fn cancel_on_terminal_attempt_is_a_no_op() {
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
        db.set_fix_attempt_status(id, "verify_requested", None, None, 1_100)
            .expect("verify_requested");
        db.set_fix_attempt_status(id, "verifying", None, None, 1_200)
            .expect("verifying");
        db.set_fix_attempt_status(id, "verified", None, None, 1_300)
            .expect("verified");

        db.cancel_fix_attempt_if_active(id, 1_400)
            .expect("canceling a terminal attempt must be a no-op, not an error");

        let row = db.get_fix_attempt(id).expect("get").expect("row exists");
        assert_eq!(
            row.status, "verified",
            "cancel must not overwrite a terminal status"
        );
    }

    #[test]
    fn empty_code_locations_fall_back_to_resolver() {
        let db = temp_db();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("vercel.json"), "{}").expect("write vercel.json");
        let project_path = dir.path().to_str().expect("utf8 path").to_string();
        let project_id = db
            .upsert_project("Fix Loop", &project_path, Some("nextjs"))
            .expect("upsert");

        let resolved =
            crate::core::correlation::resolve_fix_locations("security.csp", Some(&project_path));
        assert!(
            !resolved.is_empty(),
            "security.csp must resolve at least one location"
        );
        let expected_path = resolved[0].relative_path.clone();

        let mut args = base_args(project_id);
        args.code_locations = Some(vec![]);
        let dto = create_fix_attempt_inner(&db, args, 1_000).expect("create attempt");

        let row = db
            .get_fix_attempt(dto.id)
            .expect("get")
            .expect("row exists");
        assert!(
            row.brief_md.contains(&expected_path),
            "an empty code_locations vec must not suppress the resolver fallback; \
             expected the brief to mention {expected_path}, got:\n{}",
            row.brief_md
        );
    }

    #[test]
    fn mapped_code_identity_keeps_its_structured_occurrence_target_and_producer_rule() {
        let db = temp_db();
        let project_id = db
            .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
            .expect("upsert");
        db.execute(move |conn| {
            conn.execute(
                "INSERT INTO work_items (
                     project_id, env_url, source, signal_id, check_id, category,
                     severity, title, description, first_seen_at, last_seen_at,
                     relative_path, line, producer_check_id
                 ) VALUES (
                     ?1, 'https://example.com', 'code_scan',
                     'code_scan:hsts_missing:src/http.ts:12', 'security.hsts',
                     'security', 'high', 'Missing HSTS', 'Missing HSTS',
                     1000, 1000, 'src/http.ts', 12, 'hsts_missing'
                 )",
                [project_id],
            )
            .map_err(|error| error.to_string())
        })
        .expect("dispatch insert")
        .expect("insert mapped Code work item");

        let mut args = base_args(project_id);
        args.check_id = "security.hsts".to_string();
        args.code_locations = Some(vec![BriefLocation {
            label: "src/http.ts:12".to_string(),
            path: "src/http.ts".to_string(),
            line: Some(12),
            reason: "Code Scan occurrence".to_string(),
            start_line: None,
            end_line: None,
            excerpt: None,
        }]);

        let dto = create_fix_attempt_inner(&db, args, 2_000).expect("create mapped attempt");
        let row = db
            .get_fix_attempt(dto.id)
            .expect("get")
            .expect("row exists");
        assert_eq!(row.check_id, "security.hsts");
        assert_eq!(row.producer_rule.as_deref(), Some("hsts_missing"));
        assert_eq!(row.target_kind, "occurrence");
        assert_eq!(row.target_relative_path.as_deref(), Some("src/http.ts"));
        assert_eq!(row.target_line, Some(12));
    }

    #[test]
    fn suppressed_code_occurrence_cannot_create_a_fix_attempt() {
        let db = temp_db();
        let project = tempfile::tempdir().expect("project");
        let sitecmd_dir = project.path().join(".sitecmd");
        std::fs::create_dir_all(&sitecmd_dir).expect("sitecmd directory");
        std::fs::write(
            sitecmd_dir.join("config.json"),
            r#"{
  "version": 1,
  "url": "https://example.com",
  "name": "Suppressed project",
  "code_scan": {
    "suppressions": [{
      "match": {
        "rule": "code_scan.cors-origin-reflection",
        "path": "content/security.ts"
      },
      "reason": "This file contains inert security guidance."
    }]
  }
}"#,
        )
        .expect("suppression config");
        let project_path = project.path().to_str().expect("utf8 path").to_string();
        let project_id = db
            .upsert_project("Suppressed project", &project_path, Some("typescript"))
            .expect("upsert");
        let issue = crate::core::code_scan::CodeIssue {
            id: "cors-origin-reflection:content/security.ts:371".to_string(),
            check_id: "code_scan.cors-origin-reflection".to_string(),
            category: "security".to_string(),
            severity: crate::checks::Severity::High,
            title: "CORS reflects the request origin while allowing credentials".to_string(),
            description: "The source appears to reflect credentialed origins.".to_string(),
            relative_path: "content/security.ts".to_string(),
            absolute_path: project
                .path()
                .join("content/security.ts")
                .to_string_lossy()
                .to_string(),
            line: Some(371),
            source_excerpt: Some("replace origin: true with an exact allowlist".to_string()),
            evidence: None,
            why_now: None,
            likely_fix: Some("Use an exact allowlist.".to_string()),
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            verify_hint: None,
        };
        let detail_json = serde_json::to_string(&issue).expect("issue json");
        db.execute(move |conn| {
            conn.execute(
                "INSERT INTO work_items (
                     project_id, env_url, source, signal_id, check_id, category,
                     severity, title, description, detail_json, first_seen_at,
                     last_seen_at, relative_path, line, producer_check_id
                 ) VALUES (
                     ?1, 'https://example.com', 'code_scan',
                     'code_scan:cors-origin-reflection:content/security.ts:371',
                     'code_scan.cors-origin-reflection', 'security', 'high',
                     'CORS reflects the request origin while allowing credentials',
                     'The source appears to reflect credentialed origins.', ?2,
                     1000, 1000, 'content/security.ts', 371,
                     'cors-origin-reflection'
                 )",
                rusqlite::params![project_id, detail_json],
            )
            .map_err(|error| error.to_string())
        })
        .expect("dispatch insert")
        .expect("insert code work item");

        let mut args = base_args(project_id);
        args.check_id = "code_scan.cors-origin-reflection".to_string();
        args.title = issue.title;
        args.description = issue.description;
        args.evidence = Some(serde_json::json!({ "excerpt": issue.source_excerpt }));
        args.manual_fix = issue.likely_fix;
        args.code_locations = Some(vec![BriefLocation {
            label: "content/security.ts:371".to_string(),
            path: "content/security.ts".to_string(),
            line: Some(371),
            reason: "Code Scan occurrence".to_string(),
            start_line: None,
            end_line: None,
            excerpt: None,
        }]);

        let error = create_fix_attempt_inner(&db, args, 2_000)
            .expect_err("a source-controlled suppression must block the attempt");
        assert!(error.contains("suppressed"), "{error}");
        assert!(error.contains("inert security guidance"), "{error}");
        assert!(db
            .get_latest_fix_attempt(
                project_id,
                "https://example.com",
                "code_scan.cors-origin-reflection"
            )
            .expect("query attempts")
            .is_none());
    }

    #[test]
    fn creation_never_consults_an_allowance() {
        // Local fix attempts are not metered.
        let db = temp_db();
        let project_id = db
            .upsert_project("Fix Loop", "/tmp/fix-loop", Some("astro"))
            .expect("upsert");
        let now = now_ms();
        for check_id in [
            "security.csp",
            "security.hsts",
            "seo.title",
            "seo.meta-description",
        ] {
            let mut args = base_args(project_id);
            args.check_id = check_id.to_string();
            create_fix_attempt_inner(&db, args, now)
                .expect("every dispatch creates; nothing meters local work");
        }
    }

    #[test]
    fn dto_serializes_camel_case() {
        let dto = FixAttemptDto {
            id: 7,
            status: "briefed".to_string(),
            agent_tool: "claude-code".to_string(),
            agent_summary: None,
            failure_detail: Some("header still missing".to_string()),
            kickoff_prompt: "prompt".to_string(),
            brief_fetched_at: Some(3),
            created_at: 1,
            updated_at: 2,
        };
        let json = serde_json::to_value(&dto).expect("serialize dto");
        let object = json.as_object().expect("dto serializes to an object");
        assert!(object.contains_key("agentTool"));
        assert!(object.contains_key("kickoffPrompt"));
        assert!(object.contains_key("failureDetail"));
        assert!(object.contains_key("briefFetchedAt"));
        assert!(!object.contains_key("agent_tool"));
    }
}
