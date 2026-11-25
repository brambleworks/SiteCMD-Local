//! Read immutable release stamps.

use rusqlite::{params, Connection, OptionalExtension};
use sitecmd_protocol::release::{ExecutionProfile, ReleaseStamp};

use super::DbError;

/// Read a run's release stamp without backfilling pre-stamp runs.
pub(super) fn read_stamp(conn: &Connection, run_id: i64) -> Result<Option<ReleaseStamp>, DbError> {
    let row = conn
        .query_row(
            "SELECT engine_release, manifest_digest, canonicalizer, crawl_profile,
                    execution_profile_json
             FROM scan_runs WHERE id = ?1",
            params![run_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((Some(engine_release), Some(manifest_digest), canonicalizer, crawl_profile, profile)) =
        row
    else {
        return Ok(None);
    };
    let execution: ExecutionProfile = profile
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    Ok(Some(ReleaseStamp {
        engine_release,
        manifest_digest,
        canonicalizer: canonicalizer.unwrap_or_default() as u16,
        crawl_profile: crawl_profile.unwrap_or_default() as u16,
        execution,
    }))
}

#[cfg(test)]
#[path = "engine_release_tests.rs"]
mod tests;
