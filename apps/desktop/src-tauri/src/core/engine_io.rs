//! Project-scoped I/O for audit wants.

use crate::core::database_snapshot::{inspect_local_postgres_database, inspect_local_sqlite_file};
use crate::core::database_targets::Target;
use crate::core::engine_facts::{path_presence, OfferedFile};
use crate::core::git::{tracked_files, tracked_native_files};
use crate::core::project_listing::ProjectListing;
use sitecmd_engine_host::wants::{HostIo, PathPresence};
use sitecmd_protocol::engine_abi::{DatabaseTargetOffer, FileOfferId, RelPath, SchemaSnapshot};
use std::collections::HashMap;
use std::io;

pub struct ProjectIo<'a> {
    project: &'a ProjectListing,
    offers: &'a [OfferedFile<'a>],
    databases: Option<&'a HashMap<String, Target>>,
}

impl<'a> ProjectIo<'a> {
    /// Create an adapter for the opened project and its listed paths.
    pub(super) fn new(project: &'a ProjectListing) -> Self {
        Self {
            project,
            offers: &[],
            databases: None,
        }
    }

    pub(super) fn with_offers(
        project: &'a ProjectListing,
        offers: &'a [OfferedFile<'a>],
        databases: &'a HashMap<String, Target>,
    ) -> Self {
        Self {
            project,
            offers,
            databases: Some(databases),
        }
    }
}

impl HostIo for ProjectIo<'_> {
    fn read(&self, path: &RelPath, limit: u64) -> io::Result<Vec<u8>> {
        self.project
            .read_file(path, limit)
            .map_err(|error| io::Error::from(error.kind()))
    }

    fn git_tracked(&self, paths: &[RelPath]) -> io::Result<Vec<RelPath>> {
        let names: Vec<_> = paths.iter().map(RelPath::as_str).collect();
        let tracked = tracked_files(self.project.root(), &names);
        Ok(paths
            .iter()
            .filter(|path| tracked.contains(path.as_str()))
            .cloned()
            .collect())
    }

    fn read_offer(&self, id: FileOfferId, limit: u64) -> io::Result<Vec<u8>> {
        self.offers
            .get(id as usize)
            .ok_or(io::ErrorKind::NotFound)?
            .read(self.project, limit)
    }

    fn git_tracked_offers(&self, ids: &[FileOfferId]) -> io::Result<Vec<FileOfferId>> {
        let files: Vec<_> = ids
            .iter()
            .filter_map(|id| {
                let path = self.offers.get(*id as usize)?.tracking_path()?;
                Some((*id, path.as_os_str()))
            })
            .collect();
        let names: Vec<_> = files.iter().map(|(_, name)| *name).collect();
        let tracked = tracked_native_files(self.project.root(), &names);
        Ok(files
            .into_iter()
            .filter_map(|(id, name)| {
                #[cfg(windows)]
                let name_bytes = name.to_string_lossy().replace('\\', "/").into_bytes();
                #[cfg(not(windows))]
                let name_bytes = name.as_encoded_bytes();
                tracked.contains::<[u8]>(name_bytes.as_ref()).then_some(id)
            })
            .collect())
    }

    fn path_presence(&self, path: &RelPath) -> PathPresence {
        path_presence(self.project, path)
    }

    fn database_schema(&self, offer: &DatabaseTargetOffer) -> Option<SchemaSnapshot> {
        let target = self.databases?.get(&offer.id)?;
        if target.engine() != offer.engine {
            return None;
        }
        match target {
            Target::Sqlite(path) => inspect_local_sqlite_file(self.project.root(), path),
            Target::Postgres(target) => inspect_local_postgres_database(target),
        }
    }
}

#[cfg(test)]
pub(super) fn test_session(
    project: &ProjectListing,
    databases: Vec<DatabaseTargetOffer>,
) -> sitecmd_protocol::engine_abi::SessionBegin {
    use sitecmd_protocol::engine_abi::{AuditOptions, SessionBegin, Task};
    SessionBegin {
        task: Task::Audit {},
        listing: project.wire().clone(),
        options: AuditOptions {
            inspect_local_databases: !databases.is_empty(),
            databases,
        },
        now_ms: 0,
        text_budget: 100,
        host: Default::default(),
    }
}

#[cfg(test)]
#[path = "engine_io_tests.rs"]
mod tests;
