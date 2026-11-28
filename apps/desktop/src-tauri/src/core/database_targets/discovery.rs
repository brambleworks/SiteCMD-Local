use crate::core::database_targets::{
    is_mysql_database_target, resolve_local_sqlite_path, validate_local_database_target,
    LocalDatabaseKind,
};
use crate::core::project_listing::ProjectListing;
use sitecmd_engine_host::wants::is_portable_path;
use sitecmd_protocol::database_env::{
    is_local_dev_env_file, looks_like_database_url_key, looks_like_literal_database_url,
    EnvFileSnapshot,
};
use sitecmd_protocol::engine_abi::{DatabaseEngine, RelPath};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(in crate::core) enum Target {
    Sqlite(PathBuf),
    Postgres(Box<PostgresTarget>),
}

impl Target {
    pub(in crate::core) fn engine(&self) -> DatabaseEngine {
        match self {
            Self::Sqlite(_) => DatabaseEngine::Sqlite,
            Self::Postgres(_) => DatabaseEngine::Postgres,
        }
    }
}

pub(in crate::core) struct PostgresTarget {
    pub(in crate::core) absolute_path: PathBuf,
    pub(in crate::core) relative_path: String,
    pub(in crate::core) connection_url: String,
    pub(in crate::core) database_name: Option<String>,
    pub(in crate::core) host: Option<String>,
}

pub(in crate::core) fn collect_local_targets(
    audit_root: &Path,
    env_files: &[EnvFileSnapshot],
    listing: &ProjectListing,
) -> Result<Vec<Target>, String> {
    let mut targets = Vec::new();
    let mut seen_sqlite = HashSet::new();
    let mut seen_postgres = HashSet::new();

    for file in env_files
        .iter()
        .filter(|file| is_local_dev_env_file(&file.relative_path))
    {
        let Ok(source) = RelPath::parse(&file.relative_path) else {
            continue;
        };
        if !listing.wire().is_file(&source) || (cfg!(windows) && !is_portable_path(&source)) {
            continue;
        }
        for (key, value) in file.entries_in_order() {
            if !looks_like_database_url_key(key) || !looks_like_literal_database_url(value) {
                continue;
            }

            if is_mysql_database_target(value) {
                return Err(format!(
                    "Cannot inspect {} from {}: MySQL and MariaDB inspection is not supported. SiteCMD currently inspects only local SQLite and PostgreSQL targets.",
                    key, file.relative_path
                ));
            }

            let Ok(target) = validate_local_database_target(value) else {
                continue;
            };
            match target.kind {
                LocalDatabaseKind::Sqlite => {
                    if let Some(path) = sqlite_path(audit_root, &file.absolute_path, value)
                        .filter(|path| seen_sqlite.insert(path.clone()))
                    {
                        targets.push(Target::Sqlite(path));
                    }
                }
                LocalDatabaseKind::Postgres => {
                    let connection_url = value.trim().trim_matches('"').trim_matches('\'');
                    if seen_postgres.insert(connection_url) {
                        targets.push(Target::Postgres(Box::new(PostgresTarget {
                            absolute_path: file.absolute_path.clone(),
                            relative_path: file.relative_path.clone(),
                            connection_url: connection_url.to_owned(),
                            database_name: target.database,
                            host: target.host,
                        })));
                    }
                }
            }
        }
    }

    Ok(targets)
}

fn sqlite_path(root: &Path, env_file: &Path, value: &str) -> Option<PathBuf> {
    let path = resolve_local_sqlite_path(value, root, Some(env_file))?;
    let metadata = fs::symlink_metadata(&path).ok()?;
    (metadata.is_file() && metadata.len() <= 50_000_000).then_some(path)
}
