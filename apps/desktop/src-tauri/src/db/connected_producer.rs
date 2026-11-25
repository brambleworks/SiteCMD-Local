//! Stored submission ordering and scan-start pull basis.

use rusqlite::{params, Connection, OptionalExtension};

use super::helpers::lifecycle_env_url;
use super::{Database, DbError};

/// Producer ordering state for display, including the last allocated sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerIdentity {
    pub last_submission_sequence: i64,
}

/// Last pulled event sequence for an environment, or protocol genesis `0`.
pub(super) fn site_event_watermark(
    conn: &Connection,
    project_id: Option<i64>,
    environment_scope_key: &str,
) -> Result<i64, DbError> {
    let Some(project_id) = project_id else {
        return Ok(0);
    };
    let env_url = lifecycle_env_url(environment_scope_key);
    Ok(conn
        .query_row(
            "SELECT event_sequence FROM connected_site_watermarks
             WHERE project_id = ?1 AND env_url = ?2",
            params![project_id, env_url],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0))
}

impl Database {
    /// The producer's ordering state, or `None` when this installation has
    /// never allocated a submission and therefore has no identity yet.
    #[tracing::instrument(skip(self))]
    pub fn get_producer_identity(&self) -> Result<Option<ProducerIdentity>, DbError> {
        self.execute(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT submission_sequence
                     FROM connected_producer WHERE id = 1",
                    [],
                    |row| {
                        Ok(ProducerIdentity {
                            last_submission_sequence: row.get(0)?,
                        })
                    },
                )
                .optional()?)
        })?
    }
}

#[cfg(test)]
#[path = "connected_producer_tests.rs"]
mod tests;
