use super::*;
use postgres::NoTls;
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use url::Url;

static POSTGRES_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn write_file(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn audit_project_with_local_databases(root: &Path) -> Result<CodeScanReport, String> {
    audit_project_with_options(
        root,
        CodeScanOptions {
            inspect_local_databases: true,
        },
    )
}

fn postgres_test_base_url() -> String {
    std::env::var("SITECMD_POSTGRES_TEST_URL").expect(
            "Set SITECMD_POSTGRES_TEST_URL to a localhost Postgres maintenance database URL to run ignored Postgres integration tests.",
        )
}

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

fn postgres_url_for_database(base_url: &str, database_name: &str) -> String {
    let mut url = Url::parse(base_url).expect("valid SITECMD_POSTGRES_TEST_URL");
    url.set_path(&format!("/{}", database_name));
    url.to_string()
}

fn quote_test_db_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn with_live_postgres_test_db<F>(label: &str, test: F)
where
    F: FnOnce(&TempDir, &str, &mut PostgresClient),
{
    let base_url = postgres_test_base_url();
    let admin_connect_url = postgres_url_for_database(&base_url, "postgres");
    let db_name = postgres_test_db_name(label);
    let test_db_url = postgres_url_for_database(&base_url, &db_name);

    let mut admin = PostgresClient::connect(&admin_connect_url, NoTls)
        .expect("connect to localhost Postgres maintenance database");
    admin
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS {db};",
            db = quote_test_db_identifier(&db_name)
        ))
        .expect("drop stale throwaway Postgres test database");
    admin
        .batch_execute(&format!(
            "CREATE DATABASE {db};",
            db = quote_test_db_identifier(&db_name)
        ))
        .expect("create throwaway Postgres test database");

    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        ".env.local",
        &format!("DATABASE_URL={}\n", test_db_url),
    );

    let mut client = PostgresClient::connect(&test_db_url, NoTls)
        .expect("connect to throwaway Postgres database");
    client
        .simple_query("SET statement_timeout = '3000ms'")
        .expect("set statement timeout");

    test(&temp, &test_db_url, &mut client);

    drop(client);
    admin
        .batch_execute(&format!(
            "SELECT pg_terminate_backend(pid)
                 FROM pg_stat_activity
                 WHERE datname = '{db_name}'
                   AND pid <> pg_backend_pid();",
            db_name = db_name.replace('\'', "''"),
        ))
        .expect("terminate throwaway Postgres test database connections");
    admin
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS {db};",
            db = quote_test_db_identifier(&db_name)
        ))
        .expect("drop throwaway Postgres test database");
}

mod ai_routes;
mod architecture_and_scoring;
mod audit_new_checks;
mod cancellation;
mod database_operations;
mod dependency_ranges;
mod laravel_routes;
mod postgres_live;
mod redirect_guards;
mod release_age_policy;
mod reporting;
mod route_detection;
mod router_coverage;
mod router_evidence;
mod router_guards;
mod runtime_eol_detection;
mod scan_precision;
mod scan_scope_rules;
mod scanner_signal_edges;
mod server_security;
mod supply_chain_app;
mod supply_chain_resolution;
mod typescript_config;
mod workflow_permissions;
mod workflow_pinning;
