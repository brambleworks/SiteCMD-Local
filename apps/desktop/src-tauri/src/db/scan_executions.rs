//! Durable top-level scan intent, idempotent admission, and canonical child runs.

use rusqlite::{named_params, OptionalExtension, Row};

use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionError, ScanAdmissionOutcome, ScanComponentStatus,
    ScanExecutionRecord, ScanExecutionStatus,
};

// Imported from `helpers` directly, like every other db module.
use super::helpers::{parse_optional_enum_required, parse_required_enum};
use super::{Database, DbError};

const EXECUTION_COLUMNS: &str = "
    id,
    project_id,
    environment_id,
    environment_url,
    environment_scope_key,
    requested_mode,
    web_focus,
    trigger,
    admission_class,
    status,
    idempotency_key,
    request_fingerprint,
    started_at,
    completed_at,
    score_snapshot_id,
    failure_summary,
    web_status,
    web_detail,
    code_status,
    code_detail";

fn execution_from_row(row: &Row<'_>) -> rusqlite::Result<ScanExecutionRecord> {
    Ok(ScanExecutionRecord {
        id: row.get("id")?,
        project_id: row.get("project_id")?,
        environment_id: row.get("environment_id")?,
        environment_url: row.get("environment_url")?,
        environment_scope_key: row.get("environment_scope_key")?,
        requested_mode: parse_required_enum(
            5,
            "scan_executions.requested_mode",
            &row.get::<_, String>("requested_mode")?,
        )?,
        web_focus: parse_optional_enum_required(
            6,
            "scan_executions.web_focus",
            row.get::<_, Option<String>>("web_focus")?,
        )?,
        trigger: parse_required_enum(
            7,
            "scan_executions.trigger",
            &row.get::<_, String>("trigger")?,
        )?,
        admission_class: parse_required_enum(
            8,
            "scan_executions.admission_class",
            &row.get::<_, String>("admission_class")?,
        )?,
        status: parse_required_enum(
            9,
            "scan_executions.status",
            &row.get::<_, String>("status")?,
        )?,
        idempotency_key: row.get("idempotency_key")?,
        request_fingerprint: row.get("request_fingerprint")?,
        started_at: row.get("started_at")?,
        completed_at: row.get("completed_at")?,
        score_snapshot_id: row.get("score_snapshot_id")?,
        failure_summary: row.get("failure_summary")?,
        web_status: parse_optional_enum_required(
            19,
            "scan_executions.web_status",
            row.get::<_, Option<String>>("web_status")?,
        )?,
        web_detail: row.get("web_detail")?,
        code_status: parse_optional_enum_required(
            21,
            "scan_executions.code_status",
            row.get::<_, Option<String>>("code_status")?,
        )?,
        code_detail: row.get("code_detail")?,
    })
}

fn validate_new_execution(request: &NewScanExecution) -> Result<(), ScanAdmissionError> {
    let key = request.idempotency_key.trim();
    if key.is_empty() || key.len() > 256 {
        return Err(ScanAdmissionError::InvalidRequest(
            "idempotency_key must contain 1 to 256 characters".into(),
        ));
    }
    if !request.request_fingerprint.starts_with("v1:") {
        return Err(ScanAdmissionError::InvalidRequest(
            "request_fingerprint must use the v1 digest format".into(),
        ));
    }
    if request.environment_scope_key.trim().is_empty() {
        return Err(ScanAdmissionError::InvalidRequest(
            "environment_scope_key is required".into(),
        ));
    }
    let has_planned_child = [request.web_status, request.code_status]
        .into_iter()
        .flatten()
        .any(|status| status == ScanComponentStatus::Planned);
    if !has_planned_child {
        return Err(ScanAdmissionError::InvalidRequest(
            "at least one collector must be planned".into(),
        ));
    }
    Ok(())
}

fn load_execution_by_key(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
) -> Result<Option<ScanExecutionRecord>, ScanAdmissionError> {
    tx.query_row(
        &format!(
            "SELECT {EXECUTION_COLUMNS}
             FROM scan_executions
             WHERE idempotency_key = :idempotency_key"
        ),
        named_params! { ":idempotency_key": key },
        execution_from_row,
    )
    .optional()
    .map_err(|error| ScanAdmissionError::Storage(error.to_string()))
}

impl Database {
    /// Atomically reuse or create an execution keyed by its idempotency key.
    #[tracing::instrument(skip(self, request), fields(mode = %request.requested_mode, trigger = request.trigger.as_str()))]
    pub fn admit_scan_execution(
        &self,
        request: NewScanExecution,
        terminal_retry_window_secs: i64,
    ) -> Result<ScanAdmissionOutcome, ScanAdmissionError> {
        validate_new_execution(&request)?;

        self.execute_mut(
            move |conn| -> Result<ScanAdmissionOutcome, ScanAdmissionError> {
                let tx = conn
                    .transaction()
                    .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;

                if let Some(existing) = load_execution_by_key(&tx, &request.idempotency_key)? {
                    if existing.request_fingerprint != request.request_fingerprint {
                        return Err(ScanAdmissionError::IdempotencyConflict);
                    }
                    let reusable = match existing.status {
                        ScanExecutionStatus::Planned | ScanExecutionStatus::Running => true,
                        terminal if terminal.is_terminal() => {
                            existing.completed_at.is_some_and(|completed_at| {
                                let age_ms = request.now_ms.saturating_sub(completed_at);
                                age_ms <= terminal_retry_window_secs.saturating_mul(1_000)
                            })
                        }
                        _ => false,
                    };
                    if !reusable {
                        return Err(ScanAdmissionError::IdempotencyStale);
                    }
                    tx.commit()
                        .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;
                    return Ok(ScanAdmissionOutcome {
                        execution: existing,
                    });
                }

                // Capture the event watermark at admission so updates arriving
                // mid-scan cannot raise the declared evidence basis.
                let based_on_event_sequence = super::connected_producer::site_event_watermark(
                    &tx,
                    request.project_id,
                    &request.environment_scope_key,
                )
                .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;

                tx.execute(
                    "INSERT INTO scan_executions (
                    project_id, environment_id, environment_url, environment_scope_key,
                    requested_mode, web_focus, trigger, admission_class, status,
                    idempotency_key, request_fingerprint, started_at, web_status,
                    web_detail, code_status, code_detail, based_on_event_sequence
                 ) VALUES (
                    :project_id, :environment_id, :environment_url, :environment_scope_key,
                    :requested_mode, :web_focus, :trigger, :admission_class, 'planned',
                    :idempotency_key, :request_fingerprint, :started_at, :web_status,
                    :web_detail, :code_status, :code_detail, :based_on_event_sequence
                 )",
                    named_params! {
                        ":project_id": request.project_id,
                        ":environment_id": request.environment_id,
                        ":environment_url": request.environment_url,
                        ":environment_scope_key": request.environment_scope_key,
                        ":requested_mode": request.requested_mode.as_str(),
                        ":web_focus": request.web_focus.map(|focus| focus.as_str()),
                        ":trigger": request.trigger.as_str(),
                        ":admission_class": request.admission_class.as_str(),
                        ":idempotency_key": request.idempotency_key,
                        ":request_fingerprint": request.request_fingerprint,
                        ":started_at": request.now_ms,
                        ":web_status": request.web_status.map(ScanComponentStatus::as_str),
                        ":web_detail": request.web_detail,
                        ":code_status": request.code_status.map(ScanComponentStatus::as_str),
                        ":code_detail": request.code_detail,
                        ":based_on_event_sequence": based_on_event_sequence,
                    },
                )
                .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;
                let execution_id = tx.last_insert_rowid();
                let execution = tx
                    .query_row(
                        &format!(
                            "SELECT {EXECUTION_COLUMNS}
                         FROM scan_executions
                         WHERE id = :execution_id"
                        ),
                        named_params! { ":execution_id": execution_id },
                        execution_from_row,
                    )
                    .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;
                tx.commit()
                    .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;
                Ok(ScanAdmissionOutcome { execution })
            },
        )
        .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?
    }

    #[tracing::instrument(skip(self), fields(execution_id))]
    pub fn start_scan_execution_component(&self, execution_id: i64) -> Result<(), DbError> {
        self.execute(move |conn| {
            let changed = conn.execute(
                "UPDATE scan_executions
                     SET status = 'running',
                         code_status = 'running'
                     WHERE id = :execution_id
                       AND code_status = 'planned'
                       AND status IN ('planned', 'running')",
                named_params! { ":execution_id": execution_id },
            )?;
            if changed == 0 {
                return Err(DbError::Other(format!(
                    "execution {execution_id} component Code is not planned"
                )));
            }
            Ok(())
        })?
    }

    #[tracing::instrument(skip(self, detail), fields(execution_id, component_status = ?component_status))]
    pub fn finish_scan_execution_component(
        &self,
        execution_id: i64,
        component_status: ScanComponentStatus,
        detail: Option<String>,
        completed_at: i64,
    ) -> Result<ScanExecutionRecord, DbError> {
        if component_status.is_unsettled() {
            return Err(DbError::Other(
                "finish_scan_execution_component requires a settled status".into(),
            ));
        }
        self.execute_mut(move |conn| {
            let tx = conn.transaction()?;
            let changed = tx.execute(
                "UPDATE scan_executions
                     SET code_status = :component_status,
                         code_detail = :detail
                     WHERE id = :execution_id
                       AND status IN ('planned', 'running')",
                named_params! {
                    ":component_status": component_status.as_str(),
                    ":detail": detail,
                    ":execution_id": execution_id,
                },
            )?;
            if changed == 0 {
                return Err(DbError::Other(format!(
                    "execution {execution_id} is missing or already settled"
                )));
            }

            let (web_status, web_detail, code_status, code_detail): (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ) = tx.query_row(
                "SELECT web_status, web_detail, code_status, code_detail
                 FROM scan_executions
                 WHERE id = :execution_id",
                named_params! { ":execution_id": execution_id },
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            let components = [
                (web_status.as_deref(), web_detail.as_deref()),
                (code_status.as_deref(), code_detail.as_deref()),
            ];
            let statuses = components
                .into_iter()
                .filter_map(|(status, _)| status)
                .collect::<Vec<_>>();
            let unsettled = statuses
                .iter()
                .any(|status| matches!(*status, "planned" | "running"));
            if !unsettled {
                let completed = statuses
                    .iter()
                    .filter(|status| **status == "complete")
                    .count();
                let failed = statuses
                    .iter()
                    .filter(|status| **status == "failed")
                    .count();
                let cancelled = statuses
                    .iter()
                    .filter(|status| **status == "cancelled")
                    .count();
                let incomplete_coverage = components
                    .iter()
                    .any(|(status, detail)| *status == Some("complete") && detail.is_some());
                let status = if completed > 0 && failed + cancelled == 0 {
                    if incomplete_coverage {
                        ScanExecutionStatus::Partial
                    } else {
                        ScanExecutionStatus::Complete
                    }
                } else if completed > 0 {
                    ScanExecutionStatus::Partial
                } else if cancelled > 0 && failed == 0 {
                    ScanExecutionStatus::Cancelled
                } else {
                    ScanExecutionStatus::Failed
                };
                tx.execute(
                    "UPDATE scan_executions
                     SET status = :status, completed_at = :completed_at
                     WHERE id = :execution_id",
                    named_params! {
                        ":status": status.as_str(),
                        ":completed_at": completed_at,
                        ":execution_id": execution_id,
                    },
                )?;
            }

            let execution = tx.query_row(
                &format!(
                    "SELECT {EXECUTION_COLUMNS}
                     FROM scan_executions
                     WHERE id = :execution_id"
                ),
                named_params! { ":execution_id": execution_id },
                execution_from_row,
            )?;
            tx.commit()?;
            Ok(execution)
        })?
    }
}

#[cfg(test)]
#[path = "scan_executions_tests.rs"]
mod tests;
