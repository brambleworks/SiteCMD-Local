//! Native project facts offered to the Code Scan session.

mod database;
mod hooks;
mod inventory;
mod npm;
mod presence;

use crate::core::database_targets::Target;
use crate::core::engine_facts::database::Databases;
use crate::core::engine_facts::hooks::inspect_hook_install;
use crate::core::engine_facts::inventory::{FileOffers, NativeOffer};
use crate::core::engine_facts::npm::npm_facts;
use crate::core::project_listing::ProjectListing;
use sitecmd_protocol::engine_abi::{
    AuditFailure, AuditHostFacts, AuditOptions, SessionBegin, Task,
};

pub(super) use crate::core::engine_facts::inventory::NativeOffer as OfferedFile;
pub(super) use crate::core::engine_facts::presence::path_presence;

use std::collections::HashMap;
use std::path::Path;

pub(super) struct SessionInputs<'a> {
    pub(super) request: SessionBegin,
    pub(super) files: Vec<NativeOffer<'a>>,
    pub(super) databases: HashMap<String, Target>,
}

pub(super) fn session_request<'a>(
    listing: &'a ProjectListing,
    inspect_local_databases: bool,
    now_ms: i64,
    cancelled: &dyn Fn() -> bool,
    audit_root: &Path,
    text_budget: u64,
) -> Result<SessionInputs<'a>, AuditFailure> {
    let databases = Databases::collect(listing, audit_root, inspect_local_databases, cancelled)?;
    let root = listing.root();
    let mut files = FileOffers::default();
    files.inventory(listing, cancelled)?;
    databases.offer_locations(listing, &mut files);
    let npm_ancestors = npm_facts(listing, &mut files, cancelled)?;
    files.metadata(listing, cancelled)?;
    let hooks = inspect_hook_install(listing);
    let request = SessionBegin {
        task: Task::Audit {},
        options: AuditOptions {
            inspect_local_databases,
            databases: databases.offers,
        },
        listing: listing.wire().clone(),
        now_ms,
        text_budget,
        host: AuditHostFacts {
            root: root.to_string_lossy().into_owned(),
            file_order: listing.file_order(),
            skipped_scopes: listing.audit_skipped_scopes(),
            files: files.wire,
            paths: files.paths,
            probe_order: files.probe_order,
            npm_ancestors,
            has_git_entry: listing.has_git_entry(),
            hooks,
            local_env: databases.env,
            remote_database: databases.remote,
        },
    };
    Ok(SessionInputs {
        request,
        files: files.native,
        databases: databases.targets,
    })
}
