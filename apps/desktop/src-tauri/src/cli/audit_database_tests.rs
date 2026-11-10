use super::*;
use std::path::Path;
use tempfile::TempDir;

fn local_database_project() -> TempDir {
    let project = tempfile::tempdir_in(std::env::current_dir().expect("working directory"))
        .expect("temporary project");
    let prisma = project.path().join("prisma");
    let migrations = prisma.join("migrations/20260101000000_init");
    std::fs::create_dir_all(&migrations).expect("migration directory");
    std::fs::write(
        prisma.join("schema.prisma"),
        "datasource db {\n  provider = \"sqlite\"\n  url = env(\"DATABASE_URL\")\n}\n\nmodel User {\n  id String @id\n  email String @unique\n}\n",
    )
    .expect("Prisma schema");
    std::fs::write(
        migrations.join("migration.sql"),
        "CREATE TABLE User (id TEXT PRIMARY KEY, email TEXT NOT NULL);\n",
    )
    .expect("migration fixture");
    std::fs::write(
        project.path().join(".env.local"),
        "DATABASE_URL=file:./prisma/dev.db\n",
    )
    .expect("local database configuration");
    let connection = rusqlite::Connection::open(prisma.join("dev.db")).expect("fixture database");
    connection
        .execute("CREATE TABLE User (id TEXT PRIMARY KEY)", [])
        .expect("unmigrated schema");
    project
}

fn audit_roots(project: &TempDir) -> Vec<PathBuf> {
    let working_directory = std::env::current_dir().expect("working directory");
    vec![
        project
            .path()
            .strip_prefix(&working_directory)
            .expect("project inside working directory")
            .to_path_buf(),
        project.path().to_path_buf(),
        project.path().canonicalize().expect("canonical project"),
        project.path().join("prisma/.."),
    ]
}

#[test]
fn local_database_findings_are_relative_to_each_audit_root() {
    let project = local_database_project();
    for root in audit_roots(&project) {
        let report = audit_project_with_options(
            &root,
            CodeScanOptions {
                inspect_local_databases: true,
            },
        )
        .expect("local database analysis");
        let findings = report
            .issues
            .iter()
            .filter(|issue| issue.id.starts_with("local-"))
            .collect::<Vec<_>>();
        assert!(findings.len() >= 2, "migration and schema drift findings");
        for issue in findings {
            assert!(!Path::new(&issue.relative_path).is_absolute());
            assert_eq!(issue.relative_path, "prisma/dev.db");
            assert!(issue.line.is_none());
            assert!(issue.source_excerpt.is_none());
        }
    }
}

#[test]
fn local_database_reports_never_contain_the_absolute_audit_root() {
    let project = local_database_project();
    let canonical = project.path().canonicalize().expect("canonical project");
    let mut leaked_formats = Vec::new();
    for root in audit_roots(&project) {
        for format in [
            CodeScanReportFormat::Summary,
            CodeScanReportFormat::Json,
            CodeScanReportFormat::Markdown,
            CodeScanReportFormat::Review,
            CodeScanReportFormat::Github,
            CodeScanReportFormat::Sarif,
        ] {
            let outcome = run(&AuditArgs {
                project_path: root.clone(),
                format,
                fail_on: None,
                output: None,
                inspect_local_databases: true,
                baseline: None,
            })
            .expect("render local database audit");
            let serialized_root = serde_json::to_string(project.path()).expect("JSON root");
            let serialized_canonical = serde_json::to_string(&canonical).expect("JSON root");
            if [
                project.path().to_string_lossy().as_ref(),
                canonical.to_string_lossy().as_ref(),
                serialized_root.trim_matches('"'),
                serialized_canonical.trim_matches('"'),
            ]
            .iter()
            .any(|absolute_root| outcome.rendered.contains(absolute_root))
            {
                leaked_formats.push(format!("{format:?}"));
            }
        }
    }
    assert!(
        leaked_formats.is_empty(),
        "absolute roots in {leaked_formats:?}"
    );
}

#[test]
fn absolute_audit_targets_use_the_audit_root_in_report_titles() {
    let project = local_database_project();
    for format in [
        CodeScanReportFormat::Summary,
        CodeScanReportFormat::Markdown,
        CodeScanReportFormat::Review,
    ] {
        let outcome = run(&AuditArgs {
            project_path: project.path().to_path_buf(),
            format,
            fail_on: None,
            output: None,
            inspect_local_databases: true,
            baseline: None,
        })
        .expect("render absolute audit target");
        if format == CodeScanReportFormat::Summary {
            assert_eq!(
                outcome.rendered.lines().next(),
                Some("SiteCMD Code Scan - .")
            );
        } else {
            assert!(outcome.rendered.contains("- Project: `.`"));
        }
    }
}
