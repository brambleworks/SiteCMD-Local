use postgres::{Client as PostgresClient, NoTls};
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use url::Url;

static POSTGRES_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn postgres_test_db_name(label: &str) -> String {
    let suffix = POSTGRES_TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let sanitized = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("sitecmd_{}_{}", sanitized, suffix)
}

fn postgres_url_for_database(base_url: &Url, database_name: &str) -> String {
    let mut url = base_url.clone();
    url.set_path(&format!("/{}", database_name));
    url.to_string()
}

fn quote_test_db_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub fn with_live_postgres_test_db<F>(label: &str, test: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&TempDir, &str, &mut PostgresClient),
{
    with_test_database(label, |test_db_url| {
        let temp = TempDir::new()?;
        std::fs::write(
            temp.path().join(".env.local"),
            format!("DATABASE_URL={test_db_url}\n"),
        )?;

        let mut client = PostgresClient::connect(test_db_url, NoTls)?;
        client.simple_query("SET statement_timeout = '3000ms'")?;
        test(&temp, test_db_url, &mut client);
        Ok(())
    })
}

fn with_test_database<T>(
    label: &str,
    test: impl FnOnce(&str) -> Result<T, Box<dyn std::error::Error>>,
) -> Result<T, Box<dyn std::error::Error>> {
    let base_url = std::env::var("SITECMD_POSTGRES_TEST_URL").map_err(|_| {
        "Set SITECMD_POSTGRES_TEST_URL to a localhost Postgres maintenance database URL to run ignored Postgres integration tests."
    })?;
    let base_url = Url::parse(&base_url)?;
    let admin_connect_url = postgres_url_for_database(&base_url, "postgres");
    let db_name = postgres_test_db_name(label);
    let test_db_url = postgres_url_for_database(&base_url, &db_name);

    let mut admin = PostgresClient::connect(&admin_connect_url, NoTls)?;
    admin.batch_execute(&format!(
        "DROP DATABASE IF EXISTS {db};",
        db = quote_test_db_identifier(&db_name)
    ))?;
    admin.batch_execute(&format!(
        "CREATE DATABASE {db};",
        db = quote_test_db_identifier(&db_name)
    ))?;

    let result = test(&test_db_url);
    admin.batch_execute(&format!(
        "SELECT pg_terminate_backend(pid)
                 FROM pg_stat_activity
                 WHERE datname = '{db_name}'
                   AND pid <> pg_backend_pid();",
        db_name = db_name.replace('\'', "''"),
    ))?;
    admin.batch_execute(&format!(
        "DROP DATABASE IF EXISTS {db};",
        db = quote_test_db_identifier(&db_name)
    ))?;
    result
}
