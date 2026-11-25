use crate::core::database_snapshot::relative_database_path;
use crate::core::database_targets::{
    collect_local_targets, summarize_remote_local_dev_database_targets, Target,
};
use crate::core::engine_facts::inventory::{FileOffers, NativeOffer};
use crate::core::project_listing::ProjectListing;
use sitecmd_protocol::database_env::{is_example_env_file, parse_env_file, EnvFileSnapshot};
use sitecmd_protocol::engine_abi::{
    AuditEnvFile, AuditFailure, AuditFileKind, AuditRemoteDatabase, DatabaseTargetOffer, RelPath,
};
use std::collections::HashMap;
use std::path::Path;

#[derive(Default)]
pub(super) struct Databases {
    pub(super) targets: HashMap<String, Target>,
    pub(super) offers: Vec<DatabaseTargetOffer>,
    pub(super) env: Vec<AuditEnvFile>,
    pub(super) remote: Option<AuditRemoteDatabase>,
}

impl Databases {
    pub(super) fn collect(
        listing: &ProjectListing,
        audit_root: &Path,
        enabled: bool,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, AuditFailure> {
        let mut databases = Self::default();
        if !enabled {
            return Ok(databases);
        }
        let root = listing.root();
        let mut env = Vec::new();
        for key in listing.file_order() {
            if cancelled() {
                return Err(AuditFailure::Cancelled);
            }
            let relative = Path::new(key.as_str());
            if !relative
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".env"))
            {
                continue;
            }
            let path = root.join(relative);
            let Some(bytes) = listing
                .read_listed_bytes(&path, 64_000)
                .filter(|bytes| !bytes.contains(&0))
            else {
                continue;
            };
            let Ok(content) = String::from_utf8(bytes) else {
                continue;
            };
            let retained_bytes = content.capacity() as u64;
            let snapshot = parse_env_file(path, key.as_str().into(), content);
            if !is_example_env_file(key.as_str()) {
                databases
                    .env
                    .push(env_fact(key, retained_bytes, snapshot.as_ref()));
            }
            env.extend(snapshot);
        }
        databases.remote =
            summarize_remote_local_dev_database_targets(&env).and_then(|(file, summary)| {
                Some(AuditRemoteDatabase {
                    path: RelPath::parse(&file.relative_path).ok()?,
                    summary,
                })
            });

        let targets = collect_local_targets(audit_root, &env, listing)
            .map_err(AuditFailure::AnalysisFailed)?;
        for (index, target) in targets.into_iter().enumerate() {
            let id = format!("db-{}", index + 1);
            databases.offers.push(DatabaseTargetOffer {
                id: id.clone(),
                engine: target.engine(),
            });
            databases.targets.insert(id, target);
        }
        Ok(databases)
    }

    pub(super) fn offer_locations(&self, listing: &ProjectListing, files: &mut FileOffers<'_>) {
        for database in &self.offers {
            let Some(Target::Sqlite(path)) = self.targets.get(&database.id) else {
                continue;
            };
            let display = relative_database_path(listing.root(), path);
            if RelPath::parse(&display).is_ok_and(|path| listing.wire().is_file(&path)) {
                continue;
            }
            if let Ok(metadata) = path.metadata() {
                files.add(
                    &display,
                    AuditFileKind::DatabaseLocation {},
                    metadata.len(),
                    NativeOffer::DatabaseLocation(path.clone()),
                );
            }
        }
    }
}

fn env_fact(path: RelPath, retained_bytes: u64, file: Option<&EnvFileSnapshot>) -> AuditEnvFile {
    let mut keys: Vec<_> = file
        .into_iter()
        .flat_map(|file| file.keys.iter().cloned())
        .collect();
    keys.sort_unstable();
    let app_debug = file
        .and_then(|file| file.entries.get("APP_DEBUG"))
        .is_some_and(|value| {
            value
                .trim_matches(['"', '\''])
                .trim()
                .eq_ignore_ascii_case("true")
        });
    let app_debug_line = file.and_then(|file| {
        file.content
            .lines()
            .position(|line| line.trim_start().starts_with("APP_DEBUG"))
            .map(|index| index as u32 + 1)
    });
    AuditEnvFile {
        path,
        retained_bytes,
        keys,
        app_debug,
        app_debug_line,
    }
}
