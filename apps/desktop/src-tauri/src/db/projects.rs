//! Project registration and environment lookup.

use super::DbError;
use rusqlite::{named_params, params, OptionalExtension};

use super::helpers::{normalize_env_url, normalize_url};
use super::Database;

fn generate_secret_namespace() -> Result<String, DbError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| DbError::Other(format!("Failed to generate secret namespace: {}", e)))?;
    Ok(hex::encode(bytes))
}

impl Database {
    /// Add or update a project, returns project_id
    #[tracing::instrument(skip(self, path), fields(name = %name, has_project_path = !path.trim().is_empty(), framework = ?framework))]
    pub fn upsert_project(
        &self,
        name: &str,
        path: &str,
        framework: Option<&str>,
    ) -> Result<i64, DbError> {
        let name = name.to_string();
        let path = path.to_string();
        let framework = framework.map(|s| s.to_string());
        self.execute(move |conn| {
            let existing: Option<i64> = if !path.is_empty() {
                conn.query_row(
                    "SELECT id FROM projects WHERE path = :path",
                    named_params! { ":path": path },
                    |r| r.get(0),
                )
                .ok()
            } else {
                None
            };

            if let Some(id) = existing {
                let existing_namespace: Option<String> = conn
                    .query_row(
                        "SELECT secret_namespace FROM projects WHERE id = :id",
                        named_params! { ":id": id },
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .flatten();
                let secret_namespace = existing_namespace
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(generate_secret_namespace()?);
                conn.execute(
                    "UPDATE projects
                     SET name = :name,
                         framework = :framework,
                         secret_namespace = :secret_namespace
                     WHERE id = :id",
                    named_params! {
                        ":name": name,
                        ":framework": framework,
                        ":secret_namespace": secret_namespace,
                        ":id": id
                    },
                )?;
                return Ok(id);
            }

            let secret_namespace = generate_secret_namespace()?;
            conn.execute(
                "INSERT INTO projects (name, path, framework, secret_namespace)
                 VALUES (:name, :path, :framework, :secret_namespace)",
                named_params! {
                    ":name": name,
                    ":path": path,
                    ":framework": framework,
                    ":secret_namespace": secret_namespace
                },
            )?;
            Ok(conn.last_insert_rowid())
        })?
    }

    /// Strict project lookup for scan persistence and other accuracy-sensitive
    /// workflows. A genuinely unlinked URL is `Ok(None)`; storage failures stay
    /// errors so callers cannot skip canonical issue persistence.
    #[tracing::instrument(skip(self, url))]
    pub fn find_project_for_url_result(&self, url: &str) -> Result<Option<i64>, DbError> {
        let url = url.to_string();
        Ok(self.execute(move |conn| {
            let (normalized, url_slash) = normalize_url(&url);
            // ORDER BY id ASC keeps the pick deterministic when two projects
            // registered the same URL: the oldest environment row wins instead
            // of whichever row SQLite happens to visit first.
            conn.query_row(
                "SELECT project_id FROM environments WHERE url = ?1 OR url = ?2
                 ORDER BY id ASC LIMIT 1",
                params![normalized, url_slash],
                |row| row.get(0),
            )
            .optional()
        })??)
    }

    /// Add a normalized environment URL to a project.
    #[tracing::instrument(skip(self, url), fields(project_id, label = %label, environment = %environment, source = %source))]
    pub fn add_environment(
        &self,
        project_id: i64,
        url: &str,
        label: &str,
        environment: &str,
        source: &str,
    ) -> Result<i64, DbError> {
        let url = normalize_env_url(Some(url));
        let label = label.to_string();
        let environment = environment.to_string();
        let source = source.to_string();
        self.execute(move |conn| {
            let existing: Option<i64> = conn
                .query_row("SELECT id FROM environments WHERE project_id = :project_id AND url = :url",
                    named_params! { ":project_id": project_id, ":url": url }, |r| r.get(0))
                .optional()?;

            if let Some(id) = existing {
                conn.execute(
                    "UPDATE environments SET label = :label, environment = :environment, source = :source WHERE id = :id",
                    named_params! { ":label": label, ":environment": environment, ":source": source, ":id": id },
                )?;
                return Ok(id);
            }

            conn.execute(
                "INSERT INTO environments (project_id, url, label, environment, source) VALUES (:project_id, :url, :label, :environment, :source)",
                named_params! { ":project_id": project_id, ":url": url, ":label": label, ":environment": environment, ":source": source },
            )?;
            let environment_id = conn.last_insert_rowid();

            // Attach matching ad-hoc scan history without replacing an existing site.
            conn.execute(
                "UPDATE OR IGNORE sites SET project_id = :project_id
                 WHERE project_id IS NULL AND (url = :url OR url = :url || '/')",
                named_params! { ":project_id": project_id, ":url": url },
            )
            ?;

            Ok(environment_id)
        })?
    }
}
