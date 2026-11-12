use std::path::Path;
use std::process::Command;

#[test]
fn outside_database_is_inspected_and_reported_relative_to_the_audit_root() {
    let fixture = tempfile::tempdir().expect("temporary fixture");
    let project = fixture.path().join("app");
    let migrations = project.join("prisma/migrations/20260101000000_init");
    std::fs::create_dir_all(&migrations).expect("migration directory");
    std::fs::write(
        migrations.join("migration.sql"),
        "CREATE TABLE User (id TEXT PRIMARY KEY);\n",
    )
    .expect("migration fixture");
    std::fs::write(
        project.join(".env.local"),
        "DATABASE_URL=file:../shared.db\n",
    )
    .expect("dotenv fixture");
    let connection = sitecmd_runtime::db::Database::open(fixture.path().join("fixture.db"))
        .expect("fixture connection");
    let shared_path = fixture
        .path()
        .join("shared.db")
        .to_string_lossy()
        .into_owned();
    connection
        .execute_mut(move |connection| {
            connection
                .execute("ATTACH DATABASE ?1 AS fixture", [shared_path])
                .expect("attach fixture database");
            connection
                .execute("CREATE TABLE fixture.User (id TEXT PRIMARY KEY)", [])
                .expect("fixture table");
            connection
                .execute_batch("DETACH DATABASE fixture")
                .expect("detach fixture database");
        })
        .expect("create SQLite fixture");
    drop(connection);

    for format in ["json", "summary", "markdown", "review", "github", "sarif"] {
        let output = Command::new(env!("CARGO_BIN_EXE_sitecmd_cli"))
            .args([
                "audit",
                ".",
                "--inspect-local-databases",
                "--format",
                format,
            ])
            .current_dir(&project)
            .output()
            .expect("run CLI audit");
        assert!(output.status.success(), "audit failed for {format}");
        let rendered = String::from_utf8(output.stdout).expect("UTF-8 report");
        if format == "json" {
            assert!(
                rendered.contains("\"relativePath\": \"../shared.db\""),
                "discovered outside database was skipped"
            );
            assert!(rendered.contains("Local SQLite database is missing Prisma migration history"));
        }
        assert!(
            rendered.contains("../shared.db"),
            "missing location in {format}"
        );
        for root in [fixture.path(), project.as_path()] {
            let canonical = root.canonicalize().expect("canonical fixture root");
            for root in [root, canonical.as_path()] {
                assert_no_root(&rendered, root, format);
            }
        }
    }
}

fn assert_no_root(rendered: &str, root: &Path, format: &str) {
    let serialized = root.to_string_lossy().replace('\\', "\\\\");
    assert!(
        !rendered.contains(root.to_string_lossy().as_ref()) && !rendered.contains(&serialized),
        "absolute root in {format} report"
    );
}
