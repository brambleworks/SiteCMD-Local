use super::*;
use crate::core::code_scan::{
    analyze_ai_scaffolding, audit_project_with_text_budget, collect_ai_config_files,
    collect_database_artifacts, collect_deploy_config_files, collect_env_files,
    collect_package_manifests, CodeScanOptions,
};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use tempfile::tempdir;

fn project_file(root: &Path, relative_path: &str, content: &str) -> ProjectFile {
    let path = root.join(relative_path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    ProjectFile {
        absolute_path: path.canonicalize().unwrap(),
        relative_path: relative_path.to_string(),
        size: content.len() as u64,
    }
}

fn collect_fixture(
    kind: &str,
    files: &[ProjectFile],
    budget: &mut ScanTextBudget<'_>,
) -> Result<(), CodeScanError> {
    match kind {
        "database" => collect_database_artifacts(files, budget).map(|_| ()),
        "deploy" => collect_deploy_config_files(files, budget).map(|_| ()),
        "ai" => collect_ai_config_files(files, budget).map(|_| ()),
        "manifest" => collect_package_manifests(files, budget).map(|_| ()),
        "env" => collect_env_files(files, false, budget).map(|_| ()),
        _ => panic!("unknown fixture"),
    }
}

#[test]
fn retained_artifact_families_share_the_source_budget() {
    let temp = tempdir().unwrap();
    let fixtures = [
        ("manifest", "package.json", "{\"name\":\"p\"}"),
        ("database", "prisma/migrations/a.sql", "SELECT 1;"),
        ("deploy", "vercel.json", "{}"),
        ("ai", ".claude/settings.json", "{}"),
        ("env", ".env.example", "URL=local"),
    ];
    let source = SourceFile {
        absolute_path: temp.path().join("app.ts"),
        relative_path: "app.ts".into(),
        content: "export {};".into(),
        line_count: 1,
        inline_rust_tests: false,
    };
    let mut budget = ScanTextBudget::new(1024, &|| false);
    budget.account_sources(&[source]).unwrap();
    assert!(budget.retained_bytes > 0);

    for (kind, path, content) in fixtures {
        let file = project_file(temp.path(), path, content);
        let previous_bytes = budget.retained_bytes;
        collect_fixture(kind, std::slice::from_ref(&file), &mut budget).unwrap();
        assert!(
            budget.retained_bytes >= previous_bytes + content.len() as u64,
            "{kind}"
        );

        let original_max = budget.max_bytes;
        budget.max_bytes = budget.retained_bytes;
        let error = collect_fixture(kind, &[file], &mut budget).unwrap_err();
        assert!(matches!(error, CodeScanError::Failed(_)), "{kind}");
        assert!(error.to_string().contains("audit is incomplete"), "{kind}");
        budget.max_bytes = original_max;
    }
}

#[test]
fn database_collection_stops_at_the_cumulative_limit() {
    let temp = tempdir().unwrap();
    let files = (0..20)
        .map(|index| {
            project_file(
                temp.path(),
                &format!("prisma/migrations/{index}.sql"),
                "SELECT 1;",
            )
        })
        .collect::<Vec<_>>();
    let mut budget = ScanTextBudget::new(32, &|| false);

    let error = collect_database_artifacts(&files, &mut budget).unwrap_err();

    assert!(error
        .to_string()
        .contains("32 byte source and configuration text budget"));
    assert!(budget.retained_bytes <= 32);
    assert!(budget.retained_bytes < files.iter().map(|file| file.size).sum::<u64>());
}

#[test]
fn retained_capacity_and_current_file_bytes_cannot_bypass_the_budget() {
    let temp = tempdir().unwrap();
    let mut content = String::with_capacity(64);
    content.push('x');
    let source = SourceFile {
        absolute_path: temp.path().join("app.ts"),
        relative_path: "app.ts".into(),
        content,
        line_count: 1,
        inline_rust_tests: false,
    };
    let mut budget = ScanTextBudget::new(32, &|| false);
    assert!(budget.account_sources(&[source]).is_err());
    assert_eq!(budget.retained_bytes, 0);

    let file = project_file(temp.path(), "prisma/migrations/growing.sql", "x");
    fs::write(&file.absolute_path, "x".repeat(64)).unwrap();
    assert!(collect_database_artifacts(&[file], &mut budget).is_err());
    assert_eq!(budget.retained_bytes, 0);
}

#[test]
fn ai_instruction_and_root_mcp_config_reads_share_the_budget() {
    let temp = tempdir().unwrap();
    project_file(temp.path(), "AGENTS.md", "# Instructions\n");
    let mut budget = ScanTextBudget::new(1024, &|| false);
    analyze_ai_scaffolding(temp.path(), &mut budget).unwrap();
    assert!(budget.retained_bytes >= "# Instructions\n".len() as u64);

    project_file(temp.path(), ".mcp.json", "{}");
    budget.max_bytes = budget.retained_bytes * 2;
    let error = analyze_ai_scaffolding(temp.path(), &mut budget).unwrap_err();
    assert!(error.to_string().contains("no report was produced"));
    assert_eq!(budget.retained_bytes, budget.max_bytes);
}

#[test]
fn cancellation_stops_artifact_collection_before_all_files_are_retained() {
    let temp = tempdir().unwrap();
    let files = (0..20)
        .map(|index| {
            project_file(
                temp.path(),
                &format!("prisma/migrations/{index}.sql"),
                "SELECT 1;",
            )
        })
        .collect::<Vec<_>>();
    let polls = AtomicUsize::new(0);
    let cancelled = || polls.fetch_add(1, Ordering::SeqCst) >= 8;
    let mut budget = ScanTextBudget::new(1024, &cancelled);

    let result = collect_database_artifacts(&files, &mut budget);

    assert!(matches!(result, Err(CodeScanError::Cancelled)));
    assert!(budget.retained_bytes > 0);
    assert!(budget.retained_bytes < files.iter().map(|file| file.size).sum::<u64>());
}

#[test]
fn an_artifact_budget_failure_never_finalizes_an_audit() {
    let temp = tempdir().unwrap();
    project_file(temp.path(), "package.json", "{}");
    project_file(temp.path(), "prisma/migrations/a.sql", &"x".repeat(64));
    project_file(temp.path(), "prisma/migrations/b.sql", &"x".repeat(64));
    let stages = Mutex::new(Vec::new());

    let result = audit_project_with_text_budget(
        temp.path(),
        CodeScanOptions::default(),
        |progress| {
            stages
                .lock()
                .unwrap()
                .push((progress.check_id, progress.status))
        },
        || false,
        96,
    );

    let error = result.expect_err("an incomplete audit must return no report");
    assert!(error
        .to_string()
        .contains("source and configuration text budget"));
    let stages = stages.lock().unwrap();
    assert!(stages.contains(&("code-scan.operations", "running")));
    assert!(!stages.contains(&("code-scan.operations", "complete")));
    assert!(!stages
        .iter()
        .any(|(stage, _)| *stage == "code-scan.finalize"));
}

#[test]
fn cancellation_during_artifact_collection_never_finalizes_an_audit() {
    let temp = tempdir().unwrap();
    project_file(temp.path(), "package.json", "{}");
    project_file(temp.path(), "prisma/migrations/a.sql", "SELECT 1;");
    let collecting = AtomicBool::new(false);
    let stages = Mutex::new(Vec::new());

    let result = audit_project_with_text_budget(
        temp.path(),
        CodeScanOptions::default(),
        |progress| {
            if progress.check_id == "code-scan.operations" {
                collecting.store(true, Ordering::SeqCst);
            }
            stages
                .lock()
                .unwrap()
                .push((progress.check_id, progress.status));
        },
        || collecting.load(Ordering::SeqCst),
        1024,
    );

    assert!(matches!(result, Err(CodeScanError::Cancelled)));
    let stages = stages.lock().unwrap();
    assert!(!stages.contains(&("code-scan.operations", "complete")));
    assert!(!stages
        .iter()
        .any(|(stage, _)| *stage == "code-scan.finalize"));
}

#[test]
fn per_file_limits_still_skip_oversized_inputs_without_retaining_them() {
    let temp = tempdir().unwrap();
    let file = project_file(temp.path(), "config.json", "12345");
    let mut budget = ScanTextBudget::new(1024, &|| false);

    assert!(budget.read_project_file(&file, 4).unwrap().is_none());
    assert_eq!(budget.retained_bytes, 0);
}

#[cfg(unix)]
#[test]
fn a_file_replaced_by_a_symlink_is_not_read_or_retained() {
    let temp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let file = project_file(temp.path(), "config.json", "{}");
    let target = project_file(outside.path(), "outside.json", "outside");
    fs::remove_file(&file.absolute_path).unwrap();
    std::os::unix::fs::symlink(&target.absolute_path, &file.absolute_path).unwrap();
    let mut budget = ScanTextBudget::new(1024, &|| false);

    assert!(budget.read_project_file(&file, 1024).unwrap().is_none());
    assert_eq!(budget.retained_bytes, 0);
}
