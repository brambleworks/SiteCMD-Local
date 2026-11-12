//! Consistent standalone snapshots taken through the connection-owning worker.

use super::Database;

impl Database {
    /// Include committed WAL data without requiring other readers to release their snapshots.
    pub async fn backup_snapshot(&self) -> Result<tempfile::NamedTempFile, String> {
        self.run(move |conn| {
            let snapshot = tempfile::NamedTempFile::new()
                .map_err(|error| format!("Failed to prepare database snapshot: {error}"))?;
            conn.backup(
                rusqlite::MAIN_DB,
                snapshot.path(),
                None::<fn(rusqlite::backup::Progress)>,
            )
            .map_err(|error| format!("Failed to back up database: {error}"))?;
            Ok(snapshot)
        })
        .await?
    }
}
