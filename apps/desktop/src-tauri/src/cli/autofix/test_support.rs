//! Access to template and publication boundaries for integration tests.

use super::{apply, artifact::Manifest, exit_check, publish_job, template_plan};
use crate::connected_service::ClaimedJob;
use crate::core::project_listing::ProjectListing;
use sitecmd_protocol::engine_abi::{Brief, FixerInfo, Listing, Patch, RelPath};
use std::path::Path;

pub fn template_catalog() -> Result<Vec<FixerInfo>, String> {
    template_plan::catalog()
}

pub fn regenerate_template(
    project: &ProjectListing,
    claimed: &ClaimedJob,
    manifest: &Manifest,
    catalog: &[FixerInfo],
    handed: &mut exit_check::HandedLines,
) -> Result<Vec<Patch>, String> {
    template_plan::regenerate(project, claimed, manifest, catalog, handed)
}

pub fn template_write_patches(
    listing: &Listing,
    root: &Path,
    patches: Vec<Patch>,
    allowed: impl Fn(&RelPath) -> bool,
) -> Result<Vec<Patch>, String> {
    apply::write_patches(listing, root, patches, allowed)
}

pub fn autofix_branch_name(claimed: &ClaimedJob, catalog: &[FixerInfo]) -> String {
    publish_job::branch_name(claimed, catalog)
}

pub fn checked_publish_brief(
    listing: &Listing,
    brief: Brief,
    handed: &exit_check::HandedLines,
    patches: &[Patch],
) -> Result<Brief, exit_check::ExitRefusal> {
    exit_check::check_publish_brief(listing, brief, handed, patches)
        .map(|checked| checked.as_brief().clone())
}

pub fn checked_hosted_brief(
    brief: Brief,
    handed: &exit_check::HandedLines,
    target: &sitecmd_protocol::engine_abi::BriefTarget,
) -> Result<Brief, exit_check::ExitRefusal> {
    exit_check::check_hosted_brief(brief, handed, target)
}

pub fn record_handed_lines(handed: &mut exit_check::HandedLines, bytes: &[u8]) {
    handed.record_lines(bytes);
}
