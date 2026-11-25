//! Drive the engine module with bounded host facts and reads.

use super::session_host::{answer_observed_batch, read_budget, SessionReport};
#[cfg(feature = "test-support")]
use super::CodeScanOptions;
use super::{CodeScanAuditProgress, CodeScanError};
#[cfg(feature = "test-support")]
use crate::core::engine_facts::session_request;
use crate::core::engine_facts::SessionInputs;
use crate::core::engine_io::ProjectIo;
use crate::core::project_listing::ProjectListing;
use sitecmd_engine_host::{EngineError, Interrupt};
use sitecmd_protocol::engine_abi::{AuditFailure, Done, Step, Want, WantAnswer};

#[cfg(feature = "test-support")]
pub(in crate::core) fn drive_module_for_test(
    listing: &ProjectListing,
    options: CodeScanOptions,
    now_ms: i64,
    progress: &dyn Fn(CodeScanAuditProgress),
    cancelled: impl Fn() -> bool + Send + 'static,
    max_text_bytes: u64,
    observe: impl FnMut(&[Want]),
) -> Result<SessionReport, CodeScanError> {
    let inputs = session_request(
        listing,
        options.inspect_local_databases,
        now_ms,
        &cancelled,
        listing.root(),
        max_text_bytes,
    )
    .map_err(scan_error)?;
    drive_session(
        listing,
        inputs,
        &Interrupt::new(),
        progress,
        cancelled,
        observe,
        &mut |_| {},
    )
}

pub(in crate::core) fn scan_error(error: AuditFailure) -> CodeScanError {
    match error {
        AuditFailure::Cancelled => CodeScanError::Cancelled,
        AuditFailure::NoProject => CodeScanError::Failed(
            "Code Scan could not find app source files, schema files, or project config in the linked project folder. Choose the project root that contains your project manifest (package.json, composer.json, Cargo.toml, go.mod, pyproject.toml) or source directories like src, app, pages, or api.".into(),
        ),
        AuditFailure::AnalysisFailed(message) => CodeScanError::Failed(message),
        AuditFailure::TextBudget(bytes) => CodeScanError::Failed(format!(
            "Code Scan stopped after reaching the {bytes} byte source and configuration text budget. The audit is incomplete and no report was produced. Choose a smaller project root or exclude generated folders."
        )),
        AuditFailure::InvalidInput => CodeScanError::Failed("Code Scan received invalid project data.".into()),
    }
}

pub(super) fn drive_session(
    listing: &ProjectListing,
    inputs: SessionInputs<'_>,
    interrupt: &Interrupt,
    progress: &dyn Fn(CodeScanAuditProgress),
    cancelled: impl Fn() -> bool + Send + 'static,
    mut observe: impl FnMut(&[Want]),
    handed_file: &mut dyn FnMut(&[u8]),
) -> Result<SessionReport, CodeScanError> {
    log::debug!("Loading the Code Scan engine module");
    let engine = sitecmd_engine_host::load().map_err(engine_error)?;
    let SessionInputs {
        request,
        files,
        databases,
    } = inputs;
    let io = ProjectIo::with_offers(listing, &files, &databases);
    let mut budget = read_budget();
    budget.retain_analysis_reads();
    let mut session = engine
        .session_with_cancellation(interrupt, cancelled)
        .map_err(engine_error)?;
    log::debug!("Running Code Scan in the engine module");
    super::emit_progress(progress, "code-scan.analyze-source", "running", 48, 0);
    let mut step = session.begin(&request).map_err(engine_error)?;
    loop {
        if session.is_interrupted() {
            return Err(CodeScanError::Cancelled);
        }
        match step {
            Step::Wants { wants } => {
                observe(&wants);
                let (answers, region) = match wants.as_slice() {
                    [Want::AnalyzeFiles { files, context }] => {
                        let mut snapshots = budget.take_analysis_reads();
                        let files = session
                            .analyze_files(files, context, |location| snapshots.remove(location))
                            .map_err(engine_error)?;
                        (vec![WantAnswer::AnalyzeFiles { files }], Vec::new())
                    }
                    _ => answer_observed_batch(
                        &request,
                        &mut budget,
                        &io,
                        wants,
                        &|| session.is_interrupted(),
                        handed_file,
                    )
                    .map_err(scan_error)?,
                };
                step = session.resume(answers, &region).map_err(engine_error)?;
            }
            Step::Done {
                done: Done::Audit(report),
            } => {
                super::emit_progress(
                    progress,
                    "code-scan.analyze-source",
                    "complete",
                    80,
                    report.issues.len(),
                );
                if session.is_interrupted() {
                    return Err(CodeScanError::Cancelled);
                }
                super::emit_progress(
                    progress,
                    "code-scan.finalize",
                    "complete",
                    86,
                    report.issues.len(),
                );
                return Ok(SessionReport {
                    report,
                    files: request.host.files,
                });
            }
            Step::Done {
                done: Done::AuditFailed(error),
            } => return Err(scan_error(error)),
            Step::Done { .. } => return Err(scan_error(AuditFailure::InvalidInput)),
        }
    }
}

pub(super) fn engine_error(error: EngineError) -> CodeScanError {
    match error {
        EngineError::Interrupted => CodeScanError::Cancelled,
        error => CodeScanError::Failed(error.to_string()),
    }
}
