//! Fulfils MCP agent requests with the desktop's own fix-attempt and scan
//! paths, and publishes the heartbeat the MCP server reads for liveness.

use std::sync::Arc;

use tauri::AppHandle;

use crate::commands::scan::execution::{run_scan_execution_internal, RunScanExecutionRequest};
use crate::commands::{create_fix_attempt_inner, emit_event, sanitize_error, CreateFixAttemptArgs};
use crate::constants::{AGENT_REQUEST_EXPIRY_MS, AGENT_REQUEST_POLL_INTERVAL};
use crate::core::agent_tools::AgentTool;
use crate::core::fix_brief::BriefLocation;
use crate::core::scan_control::ScanControlState;
use crate::core::scan_execution::{ScanExecutionMode, ScanTrigger};
use crate::core::scanner::ScanType;
use crate::db::{normalize_env_url, AgentRequestRow, Database, FixAttemptTarget};

/// Failure detail for a row whose claim did not survive the process restart.
pub(crate) const ORPHANED_REQUEST_DETAIL: &str = "app_restarted";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub async fn run(db: Arc<Database>, app: AppHandle, scan_control: ScanControlState) {
    reconcile_orphaned_requests(&db);
    loop {
        tick(&db, &app, &scan_control).await;
        tokio::time::sleep(AGENT_REQUEST_POLL_INTERVAL).await;
    }
}

/// No claim outlives the process that made it, so a `running` row found at
/// startup is abandoned work. Failing it here is what lets a later tick trust
/// `running` as the in-flight scan gate.
pub(crate) fn reconcile_orphaned_requests(db: &Database) {
    match db.fail_running_agent_requests(ORPHANED_REQUEST_DETAIL, now_ms()) {
        Ok(0) => {}
        Ok(abandoned) => {
            tracing::info!("agent request watcher: failed {abandoned} abandoned requests")
        }
        Err(error) => tracing::warn!("agent request watcher: reconcile: {error}"),
    }
}

async fn tick(db: &Arc<Database>, app: &AppHandle, scan_control: &ScanControlState) {
    let now = now_ms();
    if let Err(error) = crate::core::desktop_heartbeat::write_heartbeat(now) {
        tracing::warn!("agent request watcher: heartbeat: {error}");
    }
    if let Err(error) = db.expire_stale_agent_requests(now - AGENT_REQUEST_EXPIRY_MS, now) {
        tracing::warn!("agent request watcher: expire: {error}");
    }
    let requests = db
        .list_agent_requests_in_status("requested")
        .unwrap_or_else(|error| {
            tracing::warn!("agent request watcher: list: {error}");
            Vec::new()
        });
    for request in claim_due_requests(db, requests, now_ms()) {
        match request.kind.as_str() {
            "start_fix" => {
                let outcome = fulfil_start_fix(db, &request, now_ms());
                let created = outcome.is_ok();
                settle(db, request.id, outcome);
                if created {
                    emit_event(app, "fix-attempt-updated", ());
                }
            }
            "run_scan" => {
                // Scans take minutes; run on its own task so the heartbeat keeps beating.
                let db = db.clone();
                let app = app.clone();
                let scan_control = scan_control.clone();
                tauri::async_runtime::spawn(async move {
                    // run_scan_execution_internal emits scan-execution-completed
                    // itself, so settling needs no second event.
                    let outcome = fulfil_run_scan(&db, &app, &scan_control, &request).await;
                    settle(&db, request.id, outcome);
                });
            }
            other => settle(
                db,
                request.id,
                Err(format!("unknown agent request kind {other}")),
            ),
        }
    }
}

/// Claim the rows this tick will fulfil. Scans are serialized on the queue
/// itself: a scan claimed on an earlier tick is still `running`, so the table
/// bounds concurrency over time and the per-tick cap is the second guard.
pub(crate) fn claim_due_requests(
    db: &Database,
    requests: Vec<AgentRequestRow>,
    now: i64,
) -> Vec<AgentRequestRow> {
    let mut claimed = Vec::new();
    // Fail closed: never start a scan while the in-flight probe is unreadable.
    let mut scan_running = db.has_running_scan().unwrap_or_else(|error| {
        tracing::warn!("agent request watcher: running scan probe: {error}");
        true
    });
    for request in requests {
        if scan_running && request.kind == "run_scan" {
            continue;
        }
        match db.claim_agent_request(request.id, now) {
            Ok(true) => {
                scan_running |= request.kind == "run_scan";
                claimed.push(request);
            }
            Ok(false) => {}
            Err(error) => tracing::warn!("agent request watcher: claim {}: {error}", request.id),
        }
    }
    claimed
}

/// Write the terminal row. A settled request is never rewritten because both
/// statements are guarded on the requested/running statuses.
pub(crate) fn settle(db: &Database, request_id: i64, outcome: Result<String, String>) {
    let written = match outcome {
        Ok(result_json) => db.fulfil_agent_request(request_id, &result_json, now_ms()),
        Err(detail) => db.fail_agent_request(request_id, &sanitize_error(detail), now_ms()),
    };
    if let Err(error) = written {
        tracing::warn!("agent request watcher: settle {request_id}: {error}");
    }
}

/// A token outside the supported set is a caller error, not a reason to brief
/// a different agent than the one that asked.
fn agent_tool_from_token(token: &str) -> Result<AgentTool, String> {
    serde_json::from_value(serde_json::Value::String(token.to_string()))
        .map_err(|_| "unknown_agent_tool".to_string())
}

/// Create the attempt exactly as the desktop button does, from the stored issue.
pub(crate) fn fulfil_start_fix(
    db: &Database,
    request: &AgentRequestRow,
    now: i64,
) -> Result<String, String> {
    let env_url = normalize_env_url(Some(&request.env_url));
    let check_id = request
        .check_id
        .clone()
        .ok_or_else(|| "start_fix needs a check_id".to_string())?;
    let agent_tool = agent_tool_from_token(&request.agent_tool)?;
    if let Some((status, snooze_until, _, _)) = db
        .get_issue_state(request.project_id, Some(&env_url), &check_id)
        .map_err(|error| error.to_string())?
    {
        if status
            .effective(snooze_until, now)
            .is_inactive_for_scoring()
        {
            return Err(
                "This issue is no longer open; call get_issues for the current list.".into(),
            );
        }
    }
    let items = db
        .get_active_work_items(request.project_id, Some(&env_url))
        .map_err(|error| error.to_string())?;
    let matching = items.iter().filter(|item| item.check_id == check_id);
    let item = match request.target_relative_path.as_deref() {
        Some(path) => {
            let mut exact = matching.filter(|item| {
                item.source == "code_scan"
                    && item.metadata.relative_path.as_deref() == Some(path)
                    && item.metadata.line == request.target_line
            });
            let item = exact.next().ok_or_else(|| {
                "No open Code Scan occurrence at that location; call get_issue for current locations."
                    .to_string()
            })?;
            if exact.next().is_some() {
                return Err(
                    "More than one open occurrence matches; refresh Code Scan and call get_issue."
                        .into(),
                );
            }
            item
        }
        None => {
            if request.target_line.is_some() {
                return Err("line requires relative_path from get_issue.".into());
            }
            matching
                .min_by_key(|item| item.severity.sort_rank())
                .ok_or_else(|| format!("no open issue {check_id} for {env_url}"))?
        }
    };
    let code_locations = item.metadata.relative_path.as_ref().map(|path| {
        vec![BriefLocation {
            label: match item.metadata.line {
                Some(line) => format!("{path}:{line}"),
                None => path.clone(),
            },
            path: path.clone(),
            line: item.metadata.line,
            reason: "Code Scan occurrence".to_string(),
        }]
    });
    let attempt_target = match code_locations.as_deref() {
        Some([location]) => FixAttemptTarget::occurrence(location.path.clone(), location.line),
        _ => FixAttemptTarget::group(),
    };
    let previous_failure = db
        .get_latest_fix_attempt_for_target(request.project_id, &env_url, &check_id, attempt_target)
        .map_err(|error| error.to_string())?
        .filter(|attempt| attempt.status == "verify_failed")
        .and_then(|attempt| attempt.failure_detail);
    let args = CreateFixAttemptArgs {
        project_id: request.project_id,
        env_url: Some(env_url.clone()),
        check_id,
        agent_tool,
        title: item.title.clone(),
        severity: item.severity,
        description: item.description.clone(),
        why_it_matters: item.why_it_matters.clone(),
        evidence: None,
        manual_fix: item.manual_fix.clone(),
        url: env_url,
        detected_stack: None,
        code_locations,
        previous_failure,
    };
    let dto = create_fix_attempt_inner(db, args, now)?;
    Ok(serde_json::json!({ "attempt_id": dto.id, "status": dto.status }).to_string())
}

pub(crate) fn scan_plan_for_scope(
    scope: &str,
) -> Result<(ScanExecutionMode, Option<ScanType>), String> {
    match scope {
        "web" => Ok((ScanExecutionMode::Web, Some(ScanType::Health))),
        "code" => Ok((ScanExecutionMode::Code, None)),
        "full" => Ok((ScanExecutionMode::Full, Some(ScanType::Health))),
        other => Err(format!(
            "unknown scan scope {other}; use web, code, or full"
        )),
    }
}

async fn fulfil_run_scan(
    db: &Arc<Database>,
    app: &AppHandle,
    scan_control: &ScanControlState,
    request: &AgentRequestRow,
) -> Result<String, String> {
    let env_url = normalize_env_url(Some(&request.env_url));
    let (requested_mode, web_focus) =
        scan_plan_for_scope(request.scope.as_deref().unwrap_or("web"))?;
    let environment_id = db
        .get_projects()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|project| project.id == request.project_id)
        .and_then(|project| {
            project
                .environments
                .into_iter()
                .find(|environment| normalize_env_url(Some(&environment.url)) == env_url)
        })
        .map(|environment| environment.id);
    let execution_request = RunScanExecutionRequest {
        project_id: Some(request.project_id),
        environment_id,
        environment_url: Some(env_url.clone()),
        requested_mode,
        web_focus,
        urls: web_focus
            .map(|_| crate::db::scan_scope_urls_for_project(db, request.project_id, &env_url))
            .unwrap_or_default(),
        enabled_categories: None,
        timeout_secs: None,
        axe_enabled: Some(false),
        inspect_local_databases: false,
        project_path: db.get_project_path(request.project_id),
        scan_request_id: None,
        retention: Some(crate::commands::scan::configured_scan_retention(app)),
        trigger: ScanTrigger::Manual,
        idempotency_key: format!("agent_request:{}", request.id),
    };
    let result =
        run_scan_execution_internal(app.clone(), db.clone(), scan_control, execution_request)
            .await
            .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "execution_id": result.execution.id,
        "reused": result.reused,
        "status": result.execution.status,
    })
    .to_string())
}

#[cfg(test)]
#[path = "agent_request_watcher_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "agent_request_target_tests.rs"]
mod target_tests;
