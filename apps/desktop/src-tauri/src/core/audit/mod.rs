use super::project_listing::{list_project, ProjectListing};
use crate::time::now_millis;
pub(crate) use session_host::report::{
    resolved_issue_id, INCONSISTENT_CODE_RULE, UNKNOWN_CODE_RULE,
};
use sitecmd_engine_host::Interrupt;
use sitecmd_protocol::engine_abi::{AuditReport, CodeRuleInfo, EngineInfo};
use sitecmd_protocol::vocab::Category;

use std::path::Path;

pub(crate) mod fingerprints;
mod publication;
mod report_format;
mod report_views;

pub(crate) use publication::{published_issue, published_report};
pub(crate) use report_format::escape_terminal_text;
pub use report_format::format_report;
pub use report_views::CodeScanReportFormat;
pub(crate) use report_views::{CodeIssueView, CodeScanReportView};
pub use sitecmd_protocol::code_domain::CodeScanDomain;
pub use sitecmd_protocol::code_scan::{
    CodeIssue, CodeScanAuditProgress, CodeScanError, CodeScanReport,
};
pub use sitecmd_protocol::identity::{code_producer_rule_id, validate_canonical_check_id};

fn rule_for_issue<'a>(
    issue: &CodeIssue,
    rules: &'a EngineInfo,
) -> Result<&'a CodeRuleInfo, &'static str> {
    rules
        .code_rule(code_producer_rule_id(&issue.id))
        .ok_or(UNKNOWN_CODE_RULE)
}

/// The domain of the issue's rule in the module.
pub fn code_issue_domain(
    issue: &CodeIssue,
    rules: &EngineInfo,
) -> Result<CodeScanDomain, &'static str> {
    Ok(rule_for_issue(issue, rules)?.domain)
}

/// The product category of the issue's rule in the module.
pub fn code_issue_category(
    issue: &CodeIssue,
    rules: &EngineInfo,
) -> Result<Category, &'static str> {
    Ok(rule_for_issue(issue, rules)?.category)
}

pub(super) mod audit_session;
pub(super) mod session_host;

/// Explicitly authorized Code Scan behaviors that go beyond static file
/// analysis. The default remains entirely filesystem-local and never opens a
/// project database connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeScanOptions {
    pub inspect_local_databases: bool,
}

#[tracing::instrument(skip(root))]
pub fn audit_project(root: &Path) -> Result<CodeScanReport, String> {
    audit_project_with_options(root, CodeScanOptions::default())
}

#[tracing::instrument(skip(root))]
pub fn audit_project_with_options(
    root: &Path,
    options: CodeScanOptions,
) -> Result<CodeScanReport, String> {
    audit_project_with_options_and_progress(root, options, |_| {})
}

pub fn audit_project_with_options_and_progress<F>(
    root: &Path,
    options: CodeScanOptions,
    progress: F,
) -> Result<CodeScanReport, String>
where
    F: Fn(CodeScanAuditProgress),
{
    audit_project_with_control(root, options, progress, || false).map_err(|error| error.to_string())
}

/// Audit a project with cancellation polled by both the host and the module's epoch callback.
#[tracing::instrument(skip(root, progress, cancelled))]
pub fn audit_project_with_control<F, C>(
    root: &Path,
    options: CodeScanOptions,
    progress: F,
    cancelled: C,
) -> Result<CodeScanReport, CodeScanError>
where
    F: Fn(CodeScanAuditProgress),
    C: Fn() -> bool + Send + 'static,
{
    audit_project_with_control_at(root, options, now_millis(), progress, cancelled)
}

/// Audit using the UTC milliseconds sampled by the caller.
pub fn audit_project_with_control_at<F, C>(
    root: &Path,
    options: CodeScanOptions,
    now_ms: i64,
    progress: F,
    cancelled: C,
) -> Result<CodeScanReport, CodeScanError>
where
    F: Fn(CodeScanAuditProgress),
    C: Fn() -> bool + Send + 'static,
{
    let interrupt = Interrupt::new();
    let (result, listing) = run_module_audit(
        root,
        options,
        now_ms,
        &interrupt,
        &progress,
        cancelled,
        &mut |_| {},
    )?;
    native_module_report(result, &listing, now_ms)
}

#[cfg(feature = "test-support")]
pub(super) fn audit_project_with_text_budget<F, C>(
    root: &Path,
    options: CodeScanOptions,
    now_ms: i64,
    progress: F,
    cancelled: C,
    max_text_bytes: u64,
) -> Result<CodeScanReport, CodeScanError>
where
    F: Fn(CodeScanAuditProgress),
    C: Fn() -> bool + Send + 'static,
{
    if !root.is_dir() {
        return Err(CodeScanError::Failed(
            "Project path is not a valid directory".into(),
        ));
    }
    if cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    progress(CodeScanAuditProgress {
        check_id: "code-scan.collect-files",
        status: "running",
        results_count: 0,
        checks_done: 5,
        checks_total: 100,
    });
    let listing =
        crate::core::project_listing::list_project(root).map_err(|error| error.to_string())?;
    let mut rounds = 0;
    let report = audit_session::drive_module_for_test(
        &listing,
        options,
        now_ms,
        &progress,
        cancelled,
        max_text_bytes,
        |_| rounds += 1,
    )?;
    log::debug!("Code Scan completed in {rounds} rounds");
    native_module_report(report, &listing, now_ms)
}

pub(crate) fn audit_observing_files(
    root: &Path,
    mut handed_file: impl FnMut(&[u8]),
) -> Result<CodeScanReport, String> {
    let now_ms = now_millis();
    let (result, listing) = run_module_audit(
        root,
        CodeScanOptions::default(),
        now_ms,
        &Interrupt::new(),
        &|_| {},
        || false,
        &mut handed_file,
    )
    .map_err(|error| error.to_string())?;
    native_module_report(result, &listing, now_ms).map_err(|error| error.to_string())
}

fn native_module_report(
    result: session_host::SessionReport,
    listing: &ProjectListing,
    now_ms: i64,
) -> Result<CodeScanReport, CodeScanError> {
    let engine = sitecmd_engine_host::load().map_err(audit_session::engine_error)?;
    session_host::report::native_report(result, listing, now_ms, engine.info())
        .map_err(audit_session::scan_error)
}

fn run_module_audit(
    root: &Path,
    options: CodeScanOptions,
    now_ms: i64,
    interrupt: &Interrupt,
    progress: &dyn Fn(CodeScanAuditProgress),
    cancelled: impl Fn() -> bool + Send + 'static,
    handed_file: &mut dyn FnMut(&[u8]),
) -> Result<(session_host::SessionReport, ProjectListing), CodeScanError> {
    if !root.is_dir() {
        return Err(CodeScanError::Failed(
            "Project path is not a valid directory".into(),
        ));
    }
    if interrupt.is_triggered() || cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    emit_progress(progress, "code-scan.collect-files", "running", 5, 0);
    let listing = list_project(root).map_err(|error| error.to_string())?;
    if interrupt.is_triggered() || cancelled() {
        return Err(CodeScanError::Cancelled);
    }
    emit_progress(progress, "code-scan.collect-files", "complete", 48, 0);
    let inputs = super::engine_facts::session_request(
        &listing,
        options.inspect_local_databases,
        now_ms,
        &|| interrupt.is_triggered() || cancelled(),
        root,
        crate::constants::CODE_SCAN_MAX_TEXT_BYTES,
    )
    .map_err(audit_session::scan_error)?;
    let result = audit_session::drive_session(
        &listing,
        inputs,
        interrupt,
        progress,
        cancelled,
        |_| {},
        handed_file,
    )?;
    Ok((result, listing))
}

fn emit_progress(
    progress: &dyn Fn(CodeScanAuditProgress),
    check_id: &'static str,
    status: &'static str,
    checks_done: usize,
    results_count: usize,
) {
    progress(CodeScanAuditProgress {
        check_id,
        status,
        results_count,
        checks_done,
        checks_total: 100,
    });
}

pub(crate) fn audit_with_interrupt_at(
    root: &Path,
    options: CodeScanOptions,
    now_ms: i64,
    interrupt: &Interrupt,
) -> Result<CodeScanReport, CodeScanError> {
    let (result, listing) = run_module_audit(
        root,
        options,
        now_ms,
        interrupt,
        &|_| {},
        || false,
        &mut |_| {},
    )?;
    native_module_report(result, &listing, now_ms)
}

pub(crate) fn connected_audit_at(
    root: &Path,
    now_ms: i64,
) -> Result<(AuditReport, CodeScanReport), CodeScanError> {
    let (result, listing) = run_module_audit(
        root,
        CodeScanOptions::default(),
        now_ms,
        &Interrupt::new(),
        &|_| {},
        || false,
        &mut |_| {},
    )?;
    let wire = result.report.clone();
    let native = native_module_report(result, &listing, now_ms)?;
    Ok((wire, native))
}

#[cfg(all(test, unix))]
mod metadata_offer_tests;
#[cfg(test)]
mod report_tests;
