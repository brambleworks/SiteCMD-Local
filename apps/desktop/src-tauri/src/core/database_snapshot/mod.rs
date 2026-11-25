//! Native access to authorized local database targets.

mod postgres;
mod schema;
mod sqlite;

pub(super) use crate::core::database_snapshot::postgres::inspect_local_postgres_database;
pub(super) use crate::core::database_snapshot::sqlite::{
    inspect_local_sqlite_file, relative_database_path,
};
