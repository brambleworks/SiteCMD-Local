use crate::time::now_utc;

use super::DbError;

use crate::core::audit::CodeScanReport;
use crate::core::code_provenance::CodeCheckoutProvenance;
use crate::core::normalized_scan::normalize_code_scan_with_provenance;
use crate::core::scan_execution::{
    NewScanExecution, ScanAdmissionClass, ScanComponentStatus, ScanExecutionMode, ScanTrigger,
};

use super::Database;

fn validate_code_scan_report_counts(report: &CodeScanReport) -> Result<(), DbError> {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    for issue in &report.issues {
        match issue.severity {
            crate::core::scan_types::Severity::Critical => critical += 1,
            crate::core::scan_types::Severity::High => high += 1,
            crate::core::scan_types::Severity::Medium => medium += 1,
            crate::core::scan_types::Severity::Low => low += 1,
        }
    }
    let expected = (report.issues.len(), critical, high, medium, low);
    let declared = (
        report.issue_count,
        report.critical_count,
        report.high_count,
        report.medium_count,
        report.low_count,
    );
    if declared != expected {
        return Err(DbError::Other(format!(
            "Code Scan report count mismatch: declared total/critical/high/medium/low {declared:?}, actual {expected:?}"
        )));
    }
    Ok(())
}

fn canonical_import_action_key() -> Result<String, DbError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| DbError::Other(format!("could not create import action key: {error}")))?;
    Ok(format!("migration:code:{}", hex::encode(random)))
}

impl Database {
    /// Persist a report with checkout facts captured before the source walk.
    pub fn save_code_scan_with_provenance(
        &self,
        project_id: i64,
        environment_url: Option<String>,
        project_path: String,
        report: &CodeScanReport,
        duration_ms: u64,
        provenance: CodeCheckoutProvenance,
    ) -> Result<i64, DbError> {
        self.save_code_scan_from_source(
            project_id,
            environment_url,
            project_path,
            report,
            duration_ms,
            Some(provenance),
        )
    }

    fn save_code_scan_from_source(
        &self,
        project_id: i64,
        environment_url: Option<String>,
        project_path: String,
        report: &CodeScanReport,
        duration_ms: u64,
        provenance: Option<CodeCheckoutProvenance>,
    ) -> Result<i64, DbError> {
        validate_code_scan_report_counts(report)?;
        let started_at = super::timestamp_text_to_ms(&report.checked_at)
            .unwrap_or_else(|| now_utc().timestamp_millis());
        let environment_scope_key = environment_url
            .as_deref()
            .map(|url| super::helpers::normalize_url(url).0)
            .unwrap_or_else(|| format!("project:{project_id}"));
        let action_key = canonical_import_action_key()?;
        let execution = self
            .admit_scan_execution(
                NewScanExecution {
                    project_id: Some(project_id),
                    environment_id: None,
                    environment_url: environment_url.clone(),
                    environment_scope_key: environment_scope_key.clone(),
                    requested_mode: ScanExecutionMode::Code,
                    web_focus: None,
                    trigger: ScanTrigger::Migration,
                    admission_class: ScanAdmissionClass::SystemExempt,
                    idempotency_key: action_key.clone(),
                    request_fingerprint: format!("v1:{action_key}"),
                    now_ms: started_at,
                    web_status: None,
                    web_detail: None,
                    code_status: Some(ScanComponentStatus::Planned),
                    code_detail: None,
                },
                crate::constants::SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS,
            )
            .map_err(|error| DbError::Other(error.to_string()))?
            .execution;
        self.start_scan_execution_component(execution.id)?;
        let batch = normalize_code_scan_with_provenance(
            report,
            execution.id,
            project_id,
            environment_url,
            environment_scope_key,
            project_path,
            duration_ms,
            started_at,
            provenance,
        );
        let run_id = match batch
            .map_err(DbError::from)
            .and_then(|batch| self.persist_normalized_scan_run(batch))
        {
            Ok(run_id) => run_id,
            Err(error) => {
                let _ = self.finish_scan_execution_component(
                    execution.id,
                    ScanComponentStatus::Failed,
                    Some(error.to_string()),
                    now_utc().timestamp_millis(),
                );
                return Err(error);
            }
        };
        self.finish_scan_execution_component(
            execution.id,
            ScanComponentStatus::Complete,
            None,
            started_at.saturating_add(duration_ms as i64),
        )?;
        Ok(run_id)
    }
}

#[cfg(test)]
#[path = "code_scans_tests.rs"]
mod tests;
