//! Read persisted connected-site bindings.
//!
//! Bindings never store credentials; installation tokens remain in the OS keychain.

use rusqlite::{params, Connection, OptionalExtension};

use super::helpers::lifecycle_env_url;
use super::{Database, DbError};

/// A project environment's binding to a connected site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedSite {
    pub site_id: String,
    /// When the bootstrap submission committed, or `None` while it is still
    /// owed.
    pub bootstrapped_at: Option<i64>,
}

pub(super) fn connected_site(
    conn: &Connection,
    project_id: i64,
    env_url: &str,
) -> Result<Option<ConnectedSite>, DbError> {
    Ok(conn
        .query_row(
            "SELECT site_id, bootstrapped_at
               FROM connected_sites
              WHERE project_id = ?1 AND env_url = ?2",
            params![project_id, env_url],
            |row| {
                Ok(ConnectedSite {
                    site_id: row.get(0)?,
                    bootstrapped_at: row.get(1)?,
                })
            },
        )
        .optional()?)
}

impl Database {
    #[tracing::instrument(skip(self, environment_scope_key), fields(project_id))]
    pub fn get_connected_site(
        &self,
        project_id: i64,
        environment_scope_key: &str,
    ) -> Result<Option<ConnectedSite>, DbError> {
        let env_url = lifecycle_env_url(environment_scope_key);
        self.execute(move |conn| connected_site(conn, project_id, &env_url))?
    }
}
