//! Native host access for integration tests.

use super::audit::{self, audit_session, session_host, CodeScanOptions};
use super::engine_facts::{self, OfferedFile, SessionInputs};
use super::engine_io::ProjectIo;
use super::project_listing::ProjectListing;
use crate::constants::CODE_SCAN_MAX_TEXT_BYTES;
use sitecmd_engine_host::wants::ReadBudget;
use sitecmd_protocol::code_scan::{CodeScanAuditProgress, CodeScanError, CodeScanReport};
use sitecmd_protocol::engine_abi::{
    AuditFailure, AuditPathKind, FileLocation, SessionBegin, Want, WantAnswer,
};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

pub use super::postgres_test_support::with_live_postgres_test_db;
pub use crate::cli::audit::run_audit_with_output;
pub use crate::cli::autofix::test_support::*;
pub use crate::cli::connected::audit_checkout_snapshot;
pub use crate::cli::fix::FixScanHarness;
pub use crate::cli::lane::{check_local_fetch_deadline, check_signed_out_local_scan};
pub use crate::connected_service::autofix_jobs::Committer;
pub use crate::core::normalized_scan::normalize_code_scan_with_inventory_for_test;
pub use crate::test_home::tempdir_in_worktree;
pub use session_host::SessionReport;

pub fn issue_fingerprint(issue: &sitecmd_protocol::code_scan::CodeIssue) -> String {
    crate::cli::audit_suppressions::issue_fingerprint(issue)
}

pub fn one_fix_text(target: sitecmd_protocol::engine_abi::FixTextTarget) -> Result<String, String> {
    super::fixes::one_fix_text(target)
}

pub const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn audit_with_text_budget(
    root: &Path,
    options: CodeScanOptions,
    now_ms: i64,
    max_text_bytes: u64,
) -> Result<CodeScanReport, CodeScanError> {
    audit_project_with_text_budget(root, options, now_ms, |_| {}, || false, max_text_bytes)
}

pub fn audit_project_with_text_budget(
    root: &Path,
    options: CodeScanOptions,
    now_ms: i64,
    progress: impl Fn(CodeScanAuditProgress),
    cancelled: impl Fn() -> bool + Send + 'static,
    max_text_bytes: u64,
) -> Result<CodeScanReport, CodeScanError> {
    audit::audit_project_with_text_budget(
        root,
        options,
        now_ms,
        progress,
        cancelled,
        max_text_bytes,
    )
}

pub fn session_request(
    listing: &ProjectListing,
    options: CodeScanOptions,
    now_ms: i64,
) -> Result<SessionBegin, CodeScanError> {
    engine_facts::session_request(
        listing,
        options.inspect_local_databases,
        now_ms,
        &|| false,
        listing.root(),
        CODE_SCAN_MAX_TEXT_BYTES,
    )
    .map(|inputs| inputs.request)
    .map_err(scan_error)
}

pub fn drive_module_for_test(
    listing: &ProjectListing,
    options: CodeScanOptions,
    now_ms: i64,
    progress: &dyn Fn(CodeScanAuditProgress),
    cancelled: impl Fn() -> bool + Send + 'static,
    max_text_bytes: u64,
    observe: impl FnMut(&[Want]),
) -> Result<SessionReport, CodeScanError> {
    audit_session::drive_module_for_test(
        listing,
        options,
        now_ms,
        progress,
        cancelled,
        max_text_bytes,
        observe,
    )
}

pub fn native_report(
    report: SessionReport,
    listing: &ProjectListing,
    now_ms: i64,
) -> Result<CodeScanReport, AuditFailure> {
    let engine = sitecmd_engine_host::load()
        .map_err(|error| AuditFailure::AnalysisFailed(error.to_string()))?;
    session_host::report::native_report(report, listing, now_ms, engine.info())
}

pub fn scan_error(error: AuditFailure) -> CodeScanError {
    audit_session::scan_error(error)
}

pub fn read_bounded_file(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    super::safe_fs::read_bounded_file(path, max_bytes)
}

pub fn tracked_files(root: &Path, paths: &[&str]) -> HashSet<String> {
    super::git::tracked_files(root, paths)
}

pub trait ProjectListingExt {
    fn root(&self) -> &Path;
    fn observed_kind(&self, path: &Path) -> Option<AuditPathKind>;
    fn observed_safe_directory(&self, path: &Path) -> bool;
    fn observed_children(&self, path: &Path) -> Vec<PathBuf>;
    fn read_relative_file(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>>;
    fn has_file(&self, path: &Path) -> bool;
    fn relative_files(&self) -> impl Iterator<Item = &Path>;
}

impl ProjectListingExt for ProjectListing {
    fn root(&self) -> &Path {
        self.root()
    }

    fn observed_kind(&self, path: &Path) -> Option<AuditPathKind> {
        self.observed_kind(path)
    }

    fn observed_safe_directory(&self, path: &Path) -> bool {
        self.observed_safe_directory(path)
    }

    fn observed_children(&self, path: &Path) -> Vec<PathBuf> {
        self.observed_children(path)
    }

    fn read_relative_file(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        self.read_relative_file(path, limit)
    }

    fn has_file(&self, path: &Path) -> bool {
        self.has_file(path)
    }

    fn relative_files(&self) -> impl Iterator<Item = &Path> {
        self.files().iter().map(|file| file.relative.as_path())
    }
}

#[cfg(unix)]
pub struct MetadataOffer(PathBuf);

#[cfg(unix)]
impl MetadataOffer {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn read(&self, listing: &ProjectListing, limit: u64) -> io::Result<Vec<u8>> {
        OfferedFile::Metadata(self.0.clone()).read(listing, limit)
    }
}

pub struct ScopeIo<'a> {
    listing: &'a ProjectListing,
    inputs: SessionInputs<'a>,
    budget: ReadBudget,
}

pub const MAX_PROJECT_DEPTH: usize = super::project_listing::MAX_PROJECT_DEPTH;
pub const MAX_PROJECT_FILES: usize = super::project_listing::MAX_PROJECT_FILES;

pub fn list_project_with_limits(
    root: &Path,
    max_files: usize,
    max_depth: usize,
) -> Result<ProjectListing, super::project_listing::ListingError> {
    super::project_listing::list_project_with_limits(root, max_files, max_depth)
}

impl<'a> ScopeIo<'a> {
    pub fn new(listing: &'a ProjectListing) -> Result<Self, CodeScanError> {
        Self::with_text_budget(listing, CODE_SCAN_MAX_TEXT_BYTES)
    }

    pub fn with_text_budget(
        listing: &'a ProjectListing,
        max_text_bytes: u64,
    ) -> Result<Self, CodeScanError> {
        Ok(Self {
            listing,
            inputs: engine_facts::session_request(
                listing,
                false,
                0,
                &|| false,
                listing.root(),
                max_text_bytes,
            )
            .map_err(scan_error)?,
            budget: session_host::read_budget(),
        })
    }

    pub fn skipped_scopes(&self) -> &sitecmd_protocol::engine_abi::SkippedScopes {
        &self.inputs.request.host.skipped_scopes
    }

    pub fn request(&self) -> &SessionBegin {
        &self.inputs.request
    }

    pub fn answer(&mut self, wants: Vec<Want>) -> Result<(Vec<WantAnswer>, Vec<u8>), AuditFailure> {
        let io = ProjectIo::with_offers(self.listing, &self.inputs.files, &self.inputs.databases);
        session_host::answer_observed_batch(
            &self.inputs.request,
            &mut self.budget,
            &io,
            wants,
            &|| false,
            &mut |_| {},
        )
    }

    pub fn source_path(&self, location: &FileLocation) -> Option<PathBuf> {
        let relative = match location {
            FileLocation::Listed(path) => self.listing.native_relative(path)?,
            FileLocation::Offer { id } => match self.inputs.files.get(*id as usize)? {
                OfferedFile::Inventory(file) => file.relative.as_path(),
                _ => return None,
            },
        };
        Some(self.listing.root().join(relative))
    }
}

pub fn git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    super::git::run_git_command(root, args, crate::constants::AUTOFIX_GIT_TIMEOUT, None)
        .map(|run| run.stdout)
}

pub fn request_fix(
    task: sitecmd_protocol::engine_abi::Task,
) -> Result<sitecmd_protocol::engine_abi::Done, String> {
    super::fixes::request(task, None)
}

pub use crate::cli::connected_submit::submission_observations_for_test;
pub use crate::db::connected_payload::ConnectedCodeBasis;

pub fn checkout_code_occurrence(
    observation: &crate::db::ObservedOccurrence,
    key: &sitecmd_protocol::sync::ProjectFingerprintKey,
    basis: &ConnectedCodeBasis,
) -> Option<sitecmd_protocol::sync::CodeOccurrence> {
    crate::db::connected_payload::code_occurrence(observation, key, basis)
}
