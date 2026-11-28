use postgres::config::Host as PostgresHost;
use postgres::Config as PostgresConfig;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

mod discovery;
mod env;
pub(super) use crate::core::database_targets::discovery::{
    collect_local_targets, PostgresTarget, Target,
};
pub(super) use crate::core::database_targets::env::summarize_remote_local_dev_database_targets;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDatabaseKind {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDatabaseTarget {
    pub kind: LocalDatabaseKind,
    pub host: Option<String>,
    pub database: Option<String>,
}

#[tracing::instrument(skip(raw))]
pub fn validate_local_database_target(raw: &str) -> Result<LocalDatabaseTarget, String> {
    let normalized = strip_wrapping_quotes(raw.trim());
    if normalized.is_empty() {
        return Err("Database target is empty.".into());
    }

    if looks_like_sqlite_target(normalized) {
        return Ok(LocalDatabaseTarget {
            kind: LocalDatabaseKind::Sqlite,
            host: None,
            database: sqlite_database_name(normalized),
        });
    }

    let scheme = normalized
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_default();

    if is_mysql_database_target(normalized) {
        return Err(
            "MySQL and MariaDB inspection is not supported. SiteCMD currently inspects only local SQLite and PostgreSQL targets."
                .into(),
        );
    }

    if matches!(scheme.as_str(), "postgres" | "postgresql") {
        let config = validated_local_postgres_config(normalized)?;
        let host = config.get_hosts().first().map(postgres_host_display);
        return Ok(LocalDatabaseTarget {
            kind: LocalDatabaseKind::Postgres,
            host,
            database: config.get_dbname().map(str::to_string),
        });
    }

    let parsed = Url::parse(normalized).map_err(|_| {
        "Only explicit local SQLite or PostgreSQL database URLs are allowed for DB deep scans."
            .to_string()
    })?;

    let kind = match parsed.scheme() {
        "sqlite" | "file" => LocalDatabaseKind::Sqlite,
        _ => {
            return Err(format!(
                "Unsupported database scheme '{}'. Only local SQLite or PostgreSQL targets are allowed.",
                parsed.scheme()
            ))
        }
    };

    Ok(LocalDatabaseTarget {
        kind,
        host: None,
        database: sqlite_database_name(normalized),
    })
}

pub fn is_mysql_database_target(raw: &str) -> bool {
    let normalized = strip_wrapping_quotes(raw.trim());
    normalized.split_once(':').is_some_and(|(scheme, _)| {
        matches!(
            scheme.to_ascii_lowercase().as_str(),
            "mysql" | "mysql2" | "mariadb"
        )
    })
}

/// Reject non-local driver targets, including libpq `hostaddr` and multi-host
/// fallbacks, before opening a socket.
pub fn validated_local_postgres_config(raw: &str) -> Result<PostgresConfig, String> {
    let normalized = strip_wrapping_quotes(raw.trim());
    if !normalized
        .split_once(':')
        .is_some_and(|(scheme, _)| matches!(scheme, "postgres" | "postgresql"))
    {
        return Err("Only PostgreSQL URLs can be inspected as PostgreSQL targets.".to_string());
    }

    let config = PostgresConfig::from_str(normalized)
        .map_err(|error| format!("Invalid local PostgreSQL URL: {error}"))?;
    if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
        return Err(
            "DB deep scans require an explicit local loopback host or Unix socket. Remote or ambiguous database targets are not allowed."
                .to_string(),
        );
    }

    for host in config.get_hosts() {
        match host {
            PostgresHost::Tcp(host) if !is_local_db_host(host) => {
                return Err(format!(
                    "Remote database host '{}' is not allowed for DB deep scans. Use SQLite, localhost, 127.0.0.1, ::1, or a local Unix socket instead.",
                    host
                ));
            }
            PostgresHost::Tcp(_) => {}
            #[cfg(unix)]
            PostgresHost::Unix(path) if !path.is_absolute() => {
                return Err(
                    "PostgreSQL Unix socket targets must use an absolute local path.".to_string(),
                );
            }
            #[cfg(unix)]
            PostgresHost::Unix(_) => {}
        }
    }
    for address in config.get_hostaddrs() {
        if !address.is_loopback() {
            return Err(format!(
                "Remote PostgreSQL hostaddr '{}' is not allowed for DB deep scans.",
                address
            ));
        }
    }

    Ok(config)
}

fn postgres_host_display(host: &PostgresHost) -> String {
    match host {
        PostgresHost::Tcp(host) => host.clone(),
        #[cfg(unix)]
        PostgresHost::Unix(path) => path.to_string_lossy().into_owned(),
    }
}

#[tracing::instrument(skip(raw, project_root, env_file_path), fields(has_env_file = env_file_path.is_some()))]
pub fn resolve_local_sqlite_path(
    raw: &str,
    project_root: &Path,
    env_file_path: Option<&Path>,
) -> Option<PathBuf> {
    let target = validate_local_database_target(raw).ok()?;
    if target.kind != LocalDatabaseKind::Sqlite {
        return None;
    }

    let normalized = strip_wrapping_quotes(raw.trim());
    let lower = normalized.to_ascii_lowercase();
    if normalized == ":memory:" || lower == "sqlite::memory:" || lower == "file::memory:" {
        return None;
    }

    let mut path_value = if let Some(rest) = normalized.strip_prefix("sqlite:") {
        rest.to_string()
    } else if let Some(rest) = normalized.strip_prefix("file:") {
        rest.to_string()
    } else {
        normalized.to_string()
    };

    if let Some((before_query, _)) = path_value.split_once('?') {
        path_value = before_query.to_string();
    }

    if path_value.starts_with("//") && !path_value.starts_with("///") {
        path_value = path_value.trim_start_matches('/').to_string();
    } else if path_value.starts_with("///") {
        path_value = format!("/{}", path_value.trim_start_matches('/'));
    }

    let candidate = PathBuf::from(path_value);
    let candidate = if candidate.is_absolute() {
        candidate
    } else if let Some(env_path) = env_file_path.and_then(Path::parent) {
        env_path.join(candidate)
    } else {
        project_root.join(candidate)
    };

    bound_local_sqlite_path(&candidate, project_root)
}

fn bound_local_sqlite_path(candidate: &Path, project_root: &Path) -> Option<PathBuf> {
    let root = project_root.canonicalize().ok()?;
    let candidate = candidate.canonicalize().ok()?;
    (candidate != root && candidate.starts_with(root)).then_some(candidate)
}

fn strip_wrapping_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn looks_like_sqlite_target(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower == ":memory:"
        || lower.starts_with("sqlite:")
        || lower.starts_with("file:")
        || lower.ends_with(".sqlite")
        || lower.ends_with(".sqlite3")
        || lower.ends_with(".db")
}

fn sqlite_database_name(value: &str) -> Option<String> {
    let stripped = strip_wrapping_quotes(value);
    if stripped == ":memory:" {
        return Some(":memory:".into());
    }

    if let Some(rest) = stripped.strip_prefix("sqlite:") {
        return Some(rest.trim_start_matches('/').to_string());
    }

    if let Some(rest) = stripped.strip_prefix("file:") {
        return Some(rest.to_string());
    }

    Some(stripped.to_string())
}

fn is_local_db_host(host: &str) -> bool {
    let normalized = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    normalized == "localhost"
        || normalized == "127.0.0.1"
        || normalized == "::1"
        || normalized.starts_with('/')
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::core::database_targets::{
        bound_local_sqlite_path, resolve_local_sqlite_path, validate_local_database_target,
        validated_local_postgres_config, LocalDatabaseKind,
    };
    use tempfile::tempdir;

    #[test]
    fn accepts_local_postgres_url() {
        let target =
            validate_local_database_target("postgresql://postgres:postgres@localhost:5432/sitecmd")
                .unwrap();
        assert_eq!(target.kind, LocalDatabaseKind::Postgres);
        assert_eq!(target.host.as_deref(), Some("localhost"));
        assert_eq!(target.database.as_deref(), Some("sitecmd"));
    }

    #[test]
    fn rejects_mysql_urls_as_unsupported_for_inspection() {
        for url in [
            "mysql://root:root@127.0.0.1:3306/sitecmd",
            "mysql2://root:root@localhost:3306/sitecmd",
            "mariadb://root:root@localhost:3306/sitecmd",
        ] {
            let error = validate_local_database_target(url)
                .expect_err("unsupported database engines must fail explicitly");
            assert!(
                error.contains("MySQL and MariaDB inspection is not supported"),
                "unexpected error for {url}: {error}"
            );
        }
    }

    #[test]
    fn accepts_sqlite_targets() {
        let file_target = validate_local_database_target("file:./dev.db").unwrap();
        assert_eq!(file_target.kind, LocalDatabaseKind::Sqlite);

        let memory_target = validate_local_database_target(":memory:").unwrap();
        assert_eq!(memory_target.kind, LocalDatabaseKind::Sqlite);
    }

    #[test]
    fn accepts_local_unix_socket_target() {
        let target =
            validate_local_database_target("postgresql:///sitecmd?host=/var/run/postgresql")
                .unwrap();
        assert_eq!(target.kind, LocalDatabaseKind::Postgres);
        assert_eq!(target.host.as_deref(), Some("/var/run/postgresql"));
    }

    #[test]
    fn rejects_remote_postgres_hosts() {
        let error =
            validate_local_database_target("postgresql://user:pass@db.supabase.co:5432/postgres")
                .unwrap_err();
        assert!(error.contains("Remote database host"));
    }

    #[test]
    fn rejects_non_loopback_container_hostnames() {
        let error = validate_local_database_target("postgres://postgres:postgres@db:5432/sitecmd")
            .unwrap_err();
        assert!(error.contains("Remote database host"));
    }

    #[test]
    fn rejects_remote_hostaddr_even_when_the_visible_host_is_localhost() {
        let error = validated_local_postgres_config(
            "postgresql://user@localhost/sitecmd?hostaddr=203.0.113.8",
        )
        .expect_err("remote hostaddr must not override localhost");
        assert!(error.contains("hostaddr"), "{error}");
    }

    #[test]
    fn rejects_additional_remote_query_hosts() {
        let error = validated_local_postgres_config(
            "postgresql:///sitecmd?host=localhost,db.example.com&load_balance_hosts=random",
        )
        .expect_err("every fallback host must be local");
        assert!(error.contains("db.example.com"), "{error}");
    }

    #[test]
    fn rejects_remote_comma_separated_url_hosts() {
        let error = validated_local_postgres_config(
            "postgresql://user@localhost:5432,192.0.2.4:5432/sitecmd",
        )
        .expect_err("every URL host must be local");
        assert!(error.contains("192.0.2.4"), "{error}");
    }

    #[test]
    fn accepts_multiple_loopback_candidates_even_with_random_load_balancing() {
        let config = validated_local_postgres_config(
            "postgresql://user@localhost:5432,127.0.0.1:5432/sitecmd?load_balance_hosts=random",
        )
        .expect("all resolved candidates are loopback");
        assert_eq!(config.get_hosts().len(), 2);
        assert!(config.get_hostaddrs().is_empty());
    }

    #[test]
    fn resolves_relative_sqlite_paths_against_env_file() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path().join("apps/web");
        std::fs::create_dir_all(env_dir.join("data")).unwrap();
        let db = env_dir.join("data/dev.db");
        std::fs::write(&db, "").unwrap();
        let path = resolve_local_sqlite_path(
            "file:./data/dev.db",
            dir.path(),
            Some(&env_dir.join(".env.local")),
        );
        assert_eq!(path, Some(db.canonicalize().unwrap()));
    }

    #[test]
    fn security_regression_rejects_absolute_sqlite_paths_outside_project() {
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let database = outside.path().join("other.db");
        std::fs::write(&database, "").unwrap();

        let path = resolve_local_sqlite_path(
            &format!("file:{}", database.display()),
            project.path(),
            Some(&project.path().join(".env.local")),
        );
        assert!(path.is_none());
    }

    #[test]
    fn security_regression_rejects_relative_sqlite_paths_that_escape_project() {
        let workspace = tempdir().unwrap();
        let project = workspace.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(workspace.path().join("other.db"), "").unwrap();

        let path = resolve_local_sqlite_path(
            "file:../other.db",
            &project,
            Some(&project.join(".env.local")),
        );
        assert!(path.is_none());
    }

    #[test]
    fn security_regression_rejects_sqlite_symlinks_that_escape_project() {
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_db = outside.path().join("outside.db");
        std::fs::write(&outside_db, "").unwrap();
        let linked_db = project.path().join("linked.db");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_db, &linked_db).expect("symlink db");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&outside_db, &linked_db).expect("symlink db");

        let path = bound_local_sqlite_path(&linked_db, project.path());

        assert!(path.is_none());
    }
    #[test]
    fn dot_root_rejects_unlisted_sqlite() {
        let outside = tempdir().unwrap();
        let database = outside.path().join("other.db");
        std::fs::write(&database, "").unwrap();
        let root = Path::new(".");
        assert!(!database
            .canonicalize()
            .unwrap()
            .starts_with(root.canonicalize().unwrap()));

        assert!(bound_local_sqlite_path(&database, root).is_none());
    }
}
