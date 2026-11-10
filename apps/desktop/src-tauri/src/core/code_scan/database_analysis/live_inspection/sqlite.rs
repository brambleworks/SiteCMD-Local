use super::*;

pub(in crate::core::code_scan) fn collect_local_sqlite_snapshots(
    root: &Path,
    env_files: &[EnvFileSnapshot],
) -> Vec<LocalSqliteSnapshot> {
    let mut snapshots = Vec::new();
    let mut seen_paths = HashSet::new();

    for env_file in env_files
        .iter()
        .filter(|file| is_local_dev_env_file(&file.relative_path))
    {
        for (key, value) in &env_file.entries {
            if !looks_like_database_url_key(key) || !looks_like_literal_database_url(value) {
                continue;
            }

            let Some(path) = resolve_local_sqlite_path(value, root, Some(&env_file.absolute_path))
            else {
                continue;
            };
            let Some(path) =
                canonicalize_local_sqlite_path(&path, root, Some(&env_file.absolute_path))
            else {
                continue;
            };
            if !seen_paths.insert(path.clone()) {
                continue;
            }
            if !path.is_file() {
                continue;
            }
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if metadata.len() > 50_000_000 {
                continue;
            }

            if let Some(snapshot) = inspect_local_sqlite_file(root, &path) {
                snapshots.push(snapshot);
            }
        }
    }

    snapshots
}

fn inspect_local_sqlite_file(root: &Path, path: &Path) -> Option<LocalSqliteSnapshot> {
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).ok()?;
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .ok()?;
    let table_names = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    let has_prisma_migrations_table = table_names
        .iter()
        .any(|table_name| table_name.eq_ignore_ascii_case("_prisma_migrations"));
    let applied_prisma_migrations = if has_prisma_migrations_table {
        let mut stmt = conn
            .prepare("SELECT migration_name FROM _prisma_migrations ORDER BY migration_name")
            .ok()?;
        let migrations = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .ok()?
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        migrations
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect()
    } else {
        HashSet::new()
    };
    let has_drizzle_migrations_table = table_names
        .iter()
        .any(|table_name| table_name.eq_ignore_ascii_case("__drizzle_migrations"));
    let applied_drizzle_migration_count = if has_drizzle_migrations_table {
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM __drizzle_migrations")
            .ok()?;
        stmt.query_row([], |row| row.get::<_, i64>(0)).ok()?.max(0) as usize
    } else {
        0
    };

    let mut tables = Vec::new();
    for table_name in table_names {
        if table_name.eq_ignore_ascii_case("_prisma_migrations")
            || table_name.eq_ignore_ascii_case("__drizzle_migrations")
        {
            continue;
        }

        let quoted_table = quote_sqlite_identifier(&table_name);
        let mut column_pragma = conn
            .prepare(&format!("PRAGMA table_info({})", quoted_table))
            .ok()?;
        let column_entries = column_pragma
            .query_map([], |row| {
                Ok::<_, rusqlite::Error>((
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(3)? != 0 || row.get::<_, i64>(5)? != 0,
                ))
            })
            .ok()?
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let columns = column_entries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let non_null_columns = column_entries
            .iter()
            .filter(|&(_name, non_null)| *non_null)
            .map(|(name, _non_null)| name.to_ascii_lowercase())
            .collect::<HashSet<_>>();

        let mut index_pragma = conn
            .prepare(&format!("PRAGMA index_list({})", quoted_table))
            .ok()?;
        let index_entries = index_pragma
            .query_map([], |row| {
                Ok::<_, rusqlite::Error>((row.get::<_, String>(1)?, row.get::<_, i64>(2)? != 0))
            })
            .ok()?
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

        let mut indexed_columns = HashSet::new();
        let mut unique_indexed_columns = HashSet::new();
        let mut unique_index_groups = Vec::new();
        for (index_name, is_unique) in index_entries {
            let quoted_index = quote_sqlite_identifier(&index_name);
            let mut pragma = conn
                .prepare(&format!("PRAGMA index_info({})", quoted_index))
                .ok()?;
            let rows = pragma
                .query_map([], |row| row.get::<_, String>(2))
                .ok()?
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            let mut group = HashSet::new();
            for column in rows {
                let normalized = column.to_ascii_lowercase();
                indexed_columns.insert(normalized.clone());
                if is_unique {
                    unique_indexed_columns.insert(normalized);
                    group.insert(column.to_ascii_lowercase());
                }
            }
            if is_unique && !group.is_empty() {
                unique_index_groups.push(group);
            }
        }

        let mut foreign_key_pragma = conn
            .prepare(&format!("PRAGMA foreign_key_list({})", quoted_table))
            .ok()?;
        let foreign_key_columns = foreign_key_pragma
            .query_map([], |row| row.get::<_, String>(3))
            .ok()?
            .collect::<Result<Vec<_>, _>>()
            .ok()?
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();

        tables.push(LocalDbTableSnapshot {
            name: table_name,
            columns,
            non_null_columns,
            indexed_columns,
            unique_indexed_columns,
            unique_index_groups,
            foreign_key_columns,
        });
    }

    Some(LocalSqliteSnapshot {
        absolute_path: path.to_path_buf(),
        relative_path: relative_database_path(root, path),
        tables,
        has_prisma_migrations_table,
        applied_prisma_migrations,
        has_drizzle_migrations_table,
        applied_drizzle_migration_count,
    })
}

fn relative_database_path(root: &Path, canonical_path: &Path) -> String {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let root = std::path::absolute(&root).unwrap_or(root);
    let mut root_components = root.components().peekable();
    let mut database_components = canonical_path.components().peekable();
    while root_components.peek().is_some() && root_components.peek() == database_components.peek() {
        root_components.next();
        database_components.next();
    }

    let mut relative = PathBuf::new();
    for component in root_components {
        if matches!(component, std::path::Component::Normal(_)) {
            relative.push("..");
        }
    }
    for component in database_components {
        if let std::path::Component::Normal(name) = component {
            relative.push(name);
        }
    }
    relative.to_string_lossy().replace('\\', "/")
}

fn quote_sqlite_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_audit_root_does_not_drop_the_database_snapshot() {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let path = temp.path().join("local.db");
        drop(Connection::open(&path).expect("fixture database"));
        let root = temp.path().join("unavailable");

        let snapshot = inspect_local_sqlite_file(&root, &path)
            .expect("root canonicalization failure must not drop database evidence");

        assert_eq!(snapshot.relative_path, "../local.db");
    }

    #[test]
    fn incomplete_migration_schema_drops_the_snapshot_instead_of_fabricating_empty_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("local.db");
        let conn = Connection::open(&path).expect("open fixture database");
        conn.execute("CREATE TABLE _prisma_migrations (wrong_column TEXT)", [])
            .expect("create malformed migration table");
        drop(conn);

        assert!(
            inspect_local_sqlite_file(temp.path(), &path).is_none(),
            "a partial snapshot would make missing-migration evidence inaccurate"
        );
    }
}
