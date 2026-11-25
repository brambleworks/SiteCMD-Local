use crate::core::project_listing::ProjectListing;
use sitecmd_engine_host::wants::PathPresence;
use sitecmd_protocol::engine_abi::{AuditPathKind, RelPath};

pub(in crate::core) fn path_presence(listing: &ProjectListing, path: &RelPath) -> PathPresence {
    match listing.probe_path(path) {
        Some(AuditPathKind::Symlink) => PathPresence::Symlink,
        Some(AuditPathKind::Unknown) | None => PathPresence::Absent,
        Some(_) => PathPresence::Present,
    }
}
