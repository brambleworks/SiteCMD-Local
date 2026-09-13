//! Queue rows the MCP server inserts and the desktop watcher fulfils.

use rusqlite::{params, Row};

use super::helpers::normalize_env_url;
use super::{Database, DbError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentRequestRow {
    pub id: i64,
    pub kind: String,
    pub project_id: i64,
    pub env_url: String,
    pub check_id: Option<String>,
    pub scope: Option<String>,
    pub agent_tool: String,
    pub status: String,
    pub result_json: Option<String>,
    pub failure_detail: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub target_relative_path: Option<String>,
    pub target_line: Option<u32>,
}

const COLUMNS: &str = "id, kind, project_id, env_url, check_id, scope, agent_tool, status,
     result_json, failure_detail, created_at, updated_at, target_relative_path, target_line";

fn row_to_request(row: &Row) -> rusqlite::Result<AgentRequestRow> {
    Ok(AgentRequestRow {
        id: row.get(0)?,
        kind: row.get(1)?,
        project_id: row.get(2)?,
        env_url: row.get(3)?,
        check_id: row.get(4)?,
        scope: row.get(5)?,
        agent_tool: row.get(6)?,
        status: row.get(7)?,
        result_json: row.get(8)?,
        failure_detail: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        target_relative_path: row.get(12)?,
        target_line: row.get(13)?,
    })
}

impl Database {
    /// Test and CLI seam; production inserts come from the MCP server.
    pub fn insert_agent_request(
        &self,
        kind: &str,
        project_id: i64,
        env_url: &str,
        check_id: Option<&str>,
        scope: Option<&str>,
        agent_tool: &str,
        now_ms: i64,
    ) -> Result<i64, DbError> {
        let kind = kind.to_string();
        let env_key = normalize_env_url(Some(env_url));
        let check_id = check_id.map(str::to_string);
        let scope = scope.map(str::to_string);
        let agent_tool = agent_tool.to_string();
        self.execute(move |conn| {
            conn.execute(
                "INSERT INTO agent_requests (kind, project_id, env_url, check_id, scope, agent_tool,
                    status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?7)",
                params![kind, project_id, env_key, check_id, scope, agent_tool, now_ms],
            )?;
            Ok(conn.last_insert_rowid())
        })?
    }

    pub fn list_agent_requests_in_status(
        &self,
        status: &str,
    ) -> Result<Vec<AgentRequestRow>, DbError> {
        let status = status.to_string();
        self.execute(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {COLUMNS} FROM agent_requests WHERE status = ?1 ORDER BY id"
            ))?;
            let rows = stmt.query_map(params![status], row_to_request)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })?
    }

    /// Whether a claimed scan is still in flight. Scans are serialized on this,
    /// not on one pass of the queue, because a claim outlives the tick that won it.
    pub fn has_running_scan(&self) -> Result<bool, DbError> {
        self.execute(|conn| {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM agent_requests
                     WHERE kind = 'run_scan' AND status = 'running')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|found| found == 1)
            .map_err(DbError::from)
        })?
    }

    /// Fail every claimed row through the normal failure path. A claim cannot
    /// outlive the process that made it, so the watcher clears these at startup
    /// and `running` afterwards means running in this process.
    pub fn fail_running_agent_requests(&self, detail: &str, now_ms: i64) -> Result<usize, DbError> {
        let running = self.list_agent_requests_in_status("running")?;
        for request in &running {
            self.fail_agent_request(request.id, detail, now_ms)?;
        }
        Ok(running.len())
    }

    /// Move one requested row to running; false when another tick or an expiry won.
    pub fn claim_agent_request(&self, id: i64, now_ms: i64) -> Result<bool, DbError> {
        self.execute(move |conn| {
            conn.execute(
                "UPDATE agent_requests SET status = 'running', updated_at = ?2
                 WHERE id = ?1 AND status = 'requested'",
                params![id, now_ms],
            )
            .map(|changed| changed > 0)
            .map_err(DbError::from)
        })?
    }

    pub fn fulfil_agent_request(
        &self,
        id: i64,
        result_json: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        let result_json = result_json.to_string();
        self.execute(move |conn| {
            conn.execute(
                "UPDATE agent_requests SET status = 'fulfilled', result_json = ?2, updated_at = ?3
                 WHERE id = ?1 AND status IN ('requested', 'running')",
                params![id, result_json, now_ms],
            )
            .map(|_| ())
            .map_err(DbError::from)
        })?
    }

    pub fn fail_agent_request(&self, id: i64, detail: &str, now_ms: i64) -> Result<(), DbError> {
        let detail = detail.to_string();
        self.execute(move |conn| {
            conn.execute(
                "UPDATE agent_requests SET status = 'failed', failure_detail = ?2, updated_at = ?3
                 WHERE id = ?1 AND status IN ('requested', 'running')",
                params![id, detail, now_ms],
            )
            .map(|_| ())
            .map_err(DbError::from)
        })?
    }

    pub fn expire_stale_agent_requests(
        &self,
        cutoff_ms: i64,
        now_ms: i64,
    ) -> Result<usize, DbError> {
        self.execute(move |conn| {
            conn.execute(
                "UPDATE agent_requests SET status = 'expired', updated_at = ?2
                 WHERE updated_at < ?1 AND status IN ('requested', 'running')",
                params![cutoff_ms, now_ms],
            )
            .map_err(DbError::from)
        })?
    }
}
