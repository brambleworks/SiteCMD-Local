use super::super::scan_scope::GitignoreChain;
use super::{
    collect_project_inventory, collect_project_inventory_with_limits, collect_source_files,
    read_project_file, CollectionLimits, CollectionState, ProjectFile, SourceFile,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn rust_production_cargo_manifest_reads_share_text_budget() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        format!("[package]\nname = \"{}\"\n", "a".repeat(128)),
    )
    .unwrap();
    let limits = CollectionLimits {
        max_total_bytes: 64,
        ..super::DEFAULT_COLLECTION_LIMITS
    };
    let scope = GitignoreChain::for_root(project.path());
    let canonical_root = fs::canonicalize(project.path()).unwrap();
    let result = collect_project_inventory_with_limits(
        project.path(),
        &canonical_root,
        project.path(),
        &scope,
        &mut Vec::new(),
        &mut Vec::new(),
        limits,
        &mut CollectionState::default(),
        0,
    );
    assert!(
        result.is_err(),
        "Cargo manifest scope reads must respect the text budget"
    );
}

#[test]
fn rust_all_test_cfg_is_test_only() {
    for gate in [
        "all(test, unix)",
        "all(unix, test)",
        "all(unix, all(test, feature = \"a\"))",
    ] {
        let content = format!(
            "#[cfg({gate})]\nmod capacity {{ const FIXTURE: u8 = 1; }}\npub fn runtime() {{}}"
        );
        let stripped = super::sanitize_source_content(std::path::Path::new("lib.rs"), content);
        assert!(!stripped.contains("FIXTURE"), "{gate}: {stripped}");
    }
}

#[test]
fn rust_any_test_cfg_keeps_production_module() {
    let content = "#[cfg(any(test, fuzzing))]\npub(crate) mod tests { pub fn runtime() {} }";
    assert_eq!(
        super::sanitize_source_content(std::path::Path::new("lib.rs"), content.into()),
        content
    );
}

#[test]
fn rust_ungated_inline_tests_name_keeps_production_module() {
    let content = "pub mod tests { pub fn runtime() {} }";
    assert_eq!(
        super::sanitize_source_content(std::path::Path::new("lib.rs"), content.into()),
        content
    );
}

#[test]
fn rust_ungated_path_tests_name_keeps_production_file() {
    let project = tempdir().unwrap();
    fs::write(
        project.path().join("lib.rs"),
        "#[path = \"x.rs\"]\nmod tests;",
    )
    .unwrap();
    fs::write(
        project.path().join("x.rs"),
        "pub fn runtime() { let _ = std::env::var(\"UNGATED_TESTS_RUNTIME\"); }",
    )
    .unwrap();
    fs::write(project.path().join(".env.example"), "DOCUMENTED=\n").unwrap();
    let report = super::super::audit_project(project.path()).unwrap();
    assert!(report.issues.iter().any(|issue| {
        issue.id.starts_with("env-example-incomplete:")
            && issue
                .evidence
                .as_deref()
                .is_some_and(|evidence| evidence.contains("UNGATED_TESTS_RUNTIME"))
    }));
}

#[test]
fn rust_strip_quote_characters_preserves_runtime_and_removes_tests() {
    for literal in [r#"'"'"#, r#"'\"'"#, r#"b'"'"#] {
        let content = format!("fn quote() {{ let _ = {literal}; }}\n#[cfg(test)]\nmod checks {{ const TEST_ONLY: &str = \"secret\"; }}\npub fn runtime() {{}}\n");
        let stripped = super::sanitize_source_content(std::path::Path::new("src/lib.rs"), content);
        assert!(!stripped.contains("TEST_ONLY"), "{literal}: {stripped}");
        assert!(
            stripped.contains("pub fn runtime()"),
            "{literal}: {stripped}"
        );
    }
}

#[test]
fn vendored_library_files_are_inventoried_but_not_analysed_as_source() {
    let project = tempdir().expect("temp dir");
    let jquery = format!(
        "/*!\n * jQuery JavaScript Library v3.5.1\n */\n{}",
        "window.$ = function () { return null }\n".repeat(2000)
    );
    fs::write(project.path().join("jquery.js"), &jquery).expect("write vendored");
    fs::write(
        project.path().join("app.js"),
        "export function start() { return 1 }\n",
    )
    .expect("write first-party");

    let inventory = collect_project_inventory(project.path()).expect("inventory");
    assert!(
        inventory
            .source_files
            .iter()
            .any(|f| f.relative_path == "app.js"),
        "first-party source must be analysed"
    );
    assert!(
        inventory
            .source_files
            .iter()
            .all(|f| f.relative_path != "jquery.js"),
        "vendored library must be excluded from source analysis"
    );
    assert!(
        inventory
            .project_files
            .iter()
            .any(|f| f.relative_path == "jquery.js"),
        "vendored library must still appear in the file inventory"
    );
}

#[test]
fn gitignored_deployed_config_files_are_still_analysed_as_source() {
    let project = tempdir().expect("temp dir");
    fs::write(
        project.path().join(".gitignore"),
        "wp-config.php\nsettings.php\nsettings.py\nlegacy.php\n",
    )
    .expect("write gitignore");
    fs::write(
        project.path().join("wp-config.php"),
        "<?php\ndefine('WP_DEBUG', true);\n",
    )
    .expect("write wp-config");
    fs::write(
        project.path().join("settings.php"),
        "<?php\n$databases = [];\n",
    )
    .expect("write settings");
    fs::write(
        project.path().join("settings.py"),
        "DEBUG = True\nALLOWED_HOSTS = ['*']\n",
    )
    .expect("write django settings");
    fs::write(project.path().join("legacy.php"), "<?php\necho 'old';\n").expect("write legacy");

    let inventory = collect_project_inventory(project.path()).expect("inventory");
    let source_paths: Vec<&str> = inventory
        .source_files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect();
    assert!(
        source_paths.contains(&"wp-config.php"),
        "gitignored wp-config.php must stay in source analysis, got {source_paths:?}"
    );
    assert!(
        source_paths.contains(&"settings.php"),
        "gitignored settings.php must stay in source analysis, got {source_paths:?}"
    );
    assert!(
        source_paths.contains(&"settings.py"),
        "gitignored Django settings.py must stay in source analysis, got {source_paths:?}"
    );
    // Negative control: ordinary gitignored source is still excluded.
    assert!(
        !source_paths.contains(&"legacy.php"),
        "non-config gitignored source must stay out of analysis, got {source_paths:?}"
    );
}

// Symlinks cannot expose files outside the project root.
#[cfg(unix)]
#[test]
fn security_regression_source_walk_does_not_follow_symlinks_out_of_project() {
    use std::os::unix::fs::symlink;

    let project = tempdir().expect("temp dir");
    let outside = tempdir().expect("temp dir");
    let secret = outside.path().join("id_rsa");
    fs::write(
        &secret,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nUNIQUE_SECRET_MARKER\n",
    )
    .expect("write secret");

    // A source-looking symlink pointing at a file outside the project, and
    // a directory symlink escaping the root.
    symlink(&secret, project.path().join("config.ts")).expect("file symlink");
    symlink(outside.path(), project.path().join("vendored")).expect("dir symlink");
    // A genuine in-project file so the walk still returns real results.
    fs::write(project.path().join("real.ts"), "export const real = 1;\n").expect("write real");

    let mut files: Vec<SourceFile> = Vec::new();
    collect_source_files(project.path(), project.path(), &mut files).expect("walk");

    assert!(
        files.iter().any(|file| file.relative_path == "real.ts"),
        "the real in-project file should still be scanned"
    );
    assert!(
        files
            .iter()
            .all(|file| !file.content.contains("UNIQUE_SECRET_MARKER")),
        "a symlink target outside the project must never be read into scan data"
    );
    assert!(
        files.iter().all(|file| file.relative_path != "config.ts"),
        "the symlinked entry itself must be skipped"
    );
}

#[test]
fn security_regression_source_file_collection_enforces_file_count_budget() {
    let temp = tempdir().expect("temp dir");
    fs::write(temp.path().join("one.ts"), "export const one = 1;\n").expect("write file");
    fs::write(temp.path().join("package.json"), "{}\n").expect("write file");
    let limits = CollectionLimits {
        max_files: 1,
        max_total_files: 1,
        max_total_bytes: 1_000,
        max_depth: 8,
    };
    let mut files: Vec<SourceFile> = Vec::new();
    let mut project_files: Vec<ProjectFile> = Vec::new();
    let mut state = CollectionState::default();
    let canonical_root = fs::canonicalize(temp.path()).expect("canonical root");
    let scope = GitignoreChain::for_root(temp.path());

    let error = collect_project_inventory_with_limits(
        temp.path(),
        &canonical_root,
        temp.path(),
        &scope,
        &mut files,
        &mut project_files,
        limits,
        &mut state,
        0,
    )
    .expect_err("file budget should stop collection");

    assert!(error.contains("project-file budget"));
}

#[test]
fn source_collection_truncates_at_source_budget_without_aborting_on_total_files() {
    let temp = tempdir().expect("temp dir");
    for index in 0..5 {
        fs::write(
            temp.path().join(format!("src{index}.ts")),
            "export const x = 1;\n",
        )
        .expect("write source");
    }
    for index in 0..6 {
        fs::write(temp.path().join(format!("asset{index}.bin")), "binary\n").expect("write asset");
    }
    let limits = CollectionLimits {
        max_files: 2,
        max_total_files: 100,
        max_total_bytes: 64_000_000,
        max_depth: 8,
    };
    let mut files: Vec<SourceFile> = Vec::new();
    let mut project_files: Vec<ProjectFile> = Vec::new();
    let mut state = CollectionState::default();
    let canonical_root = fs::canonicalize(temp.path()).expect("canonical root");
    let scope = GitignoreChain::for_root(temp.path());

    collect_project_inventory_with_limits(
        temp.path(),
        &canonical_root,
        temp.path(),
        &scope,
        &mut files,
        &mut project_files,
        limits,
        &mut state,
        0,
    )
    .expect("11 total files under the total budget must not abort the scan");

    assert_eq!(files.len(), 2, "source files truncate at the source budget");
    assert_eq!(
        project_files.len(),
        11,
        "every file is still inventoried up to the total-file budget"
    );
}

#[test]
fn project_inventory_records_non_source_files_during_the_bounded_source_walk() {
    let temp = tempdir().expect("temp dir");
    fs::write(temp.path().join("app.ts"), "export const app = 1;\n").expect("write source");
    fs::write(temp.path().join("package.json"), "{\"name\":\"demo\"}\n").expect("write manifest");
    fs::write(
        temp.path().join(".env.example"),
        "API_URL=http://localhost\n",
    )
    .expect("write env");

    let inventory = collect_project_inventory(temp.path()).expect("collect inventory");

    assert_eq!(inventory.source_files.len(), 1);
    assert_eq!(inventory.project_files.len(), 3);
    assert!(inventory
        .project_files
        .iter()
        .any(|file| file.relative_path == "package.json"));
    assert!(inventory
        .project_files
        .iter()
        .any(|file| file.relative_path == ".env.example"));
}

#[cfg(unix)]
#[test]
fn security_regression_inventory_read_rejects_file_replaced_by_symlink() {
    use std::os::unix::fs::symlink;

    let project = tempdir().expect("temp dir");
    let outside = tempdir().expect("temp dir");
    let manifest = project.path().join("package.json");
    let secret = outside.path().join("secret.json");
    fs::write(&manifest, "{\"name\":\"safe\"}\n").expect("write manifest");
    fs::write(&secret, "{\"token\":\"outside-secret\"}\n").expect("write secret");

    let inventory = collect_project_inventory(project.path()).expect("collect inventory");
    let recorded = inventory
        .project_files
        .iter()
        .find(|file| file.relative_path == "package.json")
        .expect("recorded manifest");

    fs::remove_file(&manifest).expect("remove original manifest");
    symlink(&secret, &manifest).expect("replace manifest with symlink");

    assert!(
        read_project_file(recorded, 250_000).is_none(),
        "inventory-backed reads must reject files replaced by symlinks"
    );
}

// Guards fixed-path reads against symlink escape and unbounded files.
#[cfg(unix)]
#[test]
fn security_regression_read_text_under_root_rejects_symlink_escape() {
    use super::{read_text_under_root, read_under_root, MAX_FILE_BYTES};
    use std::os::unix::fs::symlink;

    let project = tempdir().expect("temp dir");
    let outside = tempdir().expect("temp dir");
    let secret = outside.path().join("id_rsa");
    fs::write(&secret, "SECRET_MARKER\n").expect("write secret");

    // A real instruction file under the root reads normally.
    let real = project.path().join("AGENTS.md");
    fs::write(&real, "# Agents\nreal guidance\n").expect("write real");
    assert_eq!(
        read_text_under_root(project.path(), &real).as_deref(),
        Some("# Agents\nreal guidance\n"),
    );

    // A symlinked instruction file pointing outside the root is refused.
    let linked = project.path().join("CLAUDE.md");
    symlink(&secret, &linked).expect("symlink");
    assert!(
        read_text_under_root(project.path(), &linked).is_none(),
        "fixed-path reads must not follow a symlink out of the project"
    );

    // An oversized file is refused (a link to /dev/zero would otherwise OOM).
    let big = project.path().join("BIG.md");
    fs::write(&big, vec![b'a'; (MAX_FILE_BYTES + 1) as usize]).expect("write big");
    assert!(
        read_under_root(project.path(), &big, MAX_FILE_BYTES).is_none(),
        "fixed-path reads must enforce the size budget"
    );
}

#[test]
fn source_budget_counts_retained_rust_content_after_removing_tests() {
    let project = tempdir().unwrap();
    let retained = "pub fn start() {}\n";
    let source = format!(
        "{retained}#[cfg(test)]\nmod tests {{\n{}\n}}\n",
        "// test fixture\n".repeat(100)
    );
    fs::write(project.path().join("app.rs"), &source).unwrap();
    let limits = CollectionLimits {
        max_total_bytes: 32,
        ..super::DEFAULT_COLLECTION_LIMITS
    };
    assert!(source.len() as u64 > limits.max_total_bytes);
    let mut files = Vec::new();
    let mut project_files = Vec::new();
    let mut state = CollectionState::default();
    let canonical_root = fs::canonicalize(project.path()).unwrap();
    let scope = GitignoreChain::for_root(project.path());

    collect_project_inventory_with_limits(
        project.path(),
        &canonical_root,
        project.path(),
        &scope,
        &mut files,
        &mut project_files,
        limits,
        &mut state,
        0,
    )
    .expect("sanitized source fits the retained-text budget");

    assert_eq!(project_files.len(), 1);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].content, retained);
    assert_eq!(state.total_bytes, files[0].content.capacity() as u64);
    assert!(state.total_bytes <= limits.max_total_bytes);
}

#[test]
fn security_regression_source_file_collection_enforces_total_byte_budget() {
    let temp = tempdir().expect("temp dir");
    fs::write(
        temp.path().join("one.ts"),
        "export const one = 'too much';\n",
    )
    .expect("write file");
    let limits = CollectionLimits {
        max_files: 10,
        max_total_files: 1_000,
        max_total_bytes: 8,
        max_depth: 8,
    };
    let mut files: Vec<SourceFile> = Vec::new();
    let mut project_files: Vec<ProjectFile> = Vec::new();
    let mut state = CollectionState::default();
    let canonical_root = fs::canonicalize(temp.path()).expect("canonical root");
    let scope = GitignoreChain::for_root(temp.path());

    let error = collect_project_inventory_with_limits(
        temp.path(),
        &canonical_root,
        temp.path(),
        &scope,
        &mut files,
        &mut project_files,
        limits,
        &mut state,
        0,
    )
    .expect_err("byte budget should stop collection");

    assert!(error.contains("8 byte source and configuration text budget"));
}

#[test]
fn skipped_scope_counter_tallies_nested_repos_and_gitignored_trees() {
    let project = tempdir().expect("temp dir");
    fs::write(
        project.path().join("app.js"),
        "export function start() { return 1 }\n",
    )
    .expect("write first-party source");
    // A gitignored tree whose directory name is NOT one of the hardcoded
    // IGNORED_DIRS (so it exercises the `.gitignore` prune, not the static list).
    fs::write(project.path().join(".gitignore"), "generated/\n").expect("write gitignore");

    // Nested repository: a child directory carrying its own `.git` entry.
    let clone_dir = project.path().join("vendor-clone");
    fs::create_dir_all(clone_dir.join(".git")).expect("nested .git");
    fs::write(
        clone_dir.join("index.js"),
        "module.exports = function () { return 2 }\n",
    )
    .expect("write nested source");

    // Gitignored tree: codegen output the project itself declares non-source.
    let generated_dir = project.path().join("generated");
    fs::create_dir_all(&generated_dir).expect("generated dir");
    fs::write(
        generated_dir.join("bundle.js"),
        "console.log('generated')\n",
    )
    .expect("write generated file");

    let inventory = collect_project_inventory(project.path()).expect("inventory");

    assert_eq!(
        inventory.skipped_scopes.nested_repositories, 1,
        "the nested .git clone must count as one skipped repository"
    );
    assert_eq!(
        inventory.skipped_scopes.gitignored_directories, 1,
        "the gitignored build/ tree must count as one skipped gitignored directory"
    );
    assert_eq!(inventory.skipped_scopes.total(), 2);
    assert!(
        inventory
            .skipped_scopes
            .sample_names
            .contains(&"vendor-clone".to_string()),
        "sample names must name the nested repo, got {:?}",
        inventory.skipped_scopes.sample_names
    );
    assert!(
        inventory
            .skipped_scopes
            .sample_names
            .contains(&"generated".to_string()),
        "sample names must name the gitignored tree, got {:?}",
        inventory.skipped_scopes.sample_names
    );

    // Neither skipped tree's source leaks into analysis (they were pruned).
    assert!(
        inventory
            .source_files
            .iter()
            .all(|f| !f.relative_path.starts_with("vendor-clone/")
                && !f.relative_path.starts_with("generated/")),
        "pruned trees must not appear in analysed source"
    );
    assert!(
        inventory
            .source_files
            .iter()
            .any(|f| f.relative_path == "app.js"),
        "first-party source is still analysed"
    );
}

#[test]
fn skipped_scope_counter_is_empty_for_a_clean_single_repo() {
    // Negative control: an ordinary project with no nested repos or gitignored
    // trees records nothing, so the UI shows no skipped-scope note.
    let project = tempdir().expect("temp dir");
    fs::write(
        project.path().join("app.js"),
        "export function start() { return 1 }\n",
    )
    .expect("write source");

    let inventory = collect_project_inventory(project.path()).expect("inventory");
    assert_eq!(inventory.skipped_scopes.total(), 0);
    assert!(inventory.skipped_scopes.sample_names.is_empty());
}
