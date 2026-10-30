use super::*;

pub(super) fn probe(name: &str) -> TempDir {
    let project = TempDir::new().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/code_scan")
        .join(name);
    fn copy(source: &Path, target: &Path) {
        std::fs::create_dir_all(target).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &target.join(entry.file_name()));
            } else {
                std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
            }
        }
    }
    copy(&source, project.path());
    write_file(project.path(), ".env.example", "DOCUMENTED=\n");
    project
}

pub(super) fn missing_env(project: &Path) -> String {
    audit_project(project)
        .unwrap()
        .issues
        .into_iter()
        .filter(|issue| issue.id.starts_with("env-example-incomplete:"))
        .filter_map(|issue| issue.evidence)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn rust_production_main_root_keeps_runtime_env() {
    let project = probe("main-root");
    let missing = missing_env(project.path());
    assert!(missing.contains("MAIN_RUNTIME"), "{missing}");
}

#[test]
fn rust_production_bin_root_keeps_runtime_env() {
    let project = probe("bin-root");
    let missing = missing_env(project.path());
    assert!(missing.contains("TOOL_RUNTIME"), "{missing}");
}

#[test]
fn rust_production_cfgattr_path_keeps_runtime_env() {
    let project = probe("cfgattr-path");
    let missing = missing_env(project.path());
    assert!(missing.contains("UNIX_RUNTIME"), "{missing}");
}

#[test]
fn rust_production_cfgattr_any_path_keeps_runtime_env() {
    let project = probe("cfgattr-path");
    let path = project.path().join("src/lib.rs");
    let content = std::fs::read_to_string(&path)
        .unwrap()
        .replace("cfg_attr(unix,", "cfg_attr(any(test, unix),");
    std::fs::write(path, content).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("UNIX_RUNTIME"), "{missing}");
}

#[test]
fn rust_production_cargo_roots_survive_test_aliases() {
    for (target, build, runtime) in [
        ("src/lib.rs", "", true),
        ("crates/app/src/main.rs", "", true),
        ("src/bin/worker/main.rs", "", true),
        ("build.rs", "", true),
        (
            "config/generate.rs",
            "build = \"config/generate.rs\"\n",
            true,
        ),
        ("build.rs", "build = false\n", false),
    ] {
        let project = TempDir::new().unwrap();
        write_file(project.path(), ".env.example", "DOCUMENTED=\n");
        write_file(
            project.path(),
            "Cargo.toml",
            &format!("[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{build}"),
        );
        write_file(
            project.path(),
            target,
            "fn main() { let _ = std::env::var(\"TARGET_RUNTIME\"); }",
        );
        if target.starts_with("crates/app/") {
            write_file(project.path(), "Cargo.toml", "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n[workspace]\nmembers = [\"crates/app\"]\n");
            write_file(
                project.path(),
                "crates/app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            );
        }
        let (alias, target_path) = if target == "src/lib.rs" {
            ("src/main.rs", "lib.rs".to_string())
        } else if let Some(path) = target.strip_prefix("src/") {
            ("src/lib.rs", path.to_string())
        } else {
            ("src/lib.rs", format!("../{target}"))
        };
        write_file(
            project.path(),
            alias,
            &format!("#[cfg(test)]\n#[path = \"{target_path}\"]\nmod target;"),
        );
        let missing = missing_env(project.path());
        assert_eq!(
            missing.contains("TARGET_RUNTIME"),
            runtime,
            "{target}, {build}: {missing}"
        );
    }
}

#[test]
fn rust_production_cfgattr_test_paths_stay_test_only() {
    for predicate in [
        "test",
        "all(test, unix)",
        "all(unix, all(test, feature = \"a\"))",
    ] {
        let project = TempDir::new().unwrap();
        write_file(project.path(), ".env.example", "DOCUMENTED=\n");
        write_file(
            project.path(),
            "Cargo.toml",
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"",
        );
        write_file(
            project.path(),
            "src/lib.rs",
            &format!("#[cfg_attr({predicate}, path = \"capacity.rs\")]\nmod platform;"),
        );
        write_file(
            project.path(),
            "src/platform.rs",
            "pub fn run() { let _ = std::env::var(\"FALLBACK_RUNTIME\"); }",
        );
        write_file(
            project.path(),
            "src/capacity.rs",
            "pub fn run() { let _ = std::env::var(\"TEST_ONLY_INPUT\"); }",
        );
        let missing = missing_env(project.path());
        assert!(
            !missing.contains("TEST_ONLY_INPUT"),
            "{predicate}: {missing}"
        );
        assert!(
            missing.contains("FALLBACK_RUNTIME"),
            "{predicate}: {missing}"
        );
    }
}

#[test]
fn rust_production_build_root_keeps_compile_time_provenance() {
    let project = TempDir::new().unwrap();
    write_file(project.path(), ".env.example", "DOCUMENTED=\n");
    write_file(
        project.path(),
        "Cargo.toml",
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"",
    );
    write_file(project.path(), "src/lib.rs", "#[cfg(test)]\n#[path = \"../build.rs\"]\nmod build_alias;\nconst ROOT: &str = env!(\"SOURCE_ROOT\");");
    write_file(
        project.path(),
        "build.rs",
        "mod values;\nfn main() { values::configure(); }",
    );
    write_file(
        project.path(),
        "values.rs",
        "pub fn configure() { println!(\"cargo:rustc-env=SOURCE_ROOT=root\"); }",
    );
    let missing = missing_env(project.path());
    assert!(!missing.contains("SOURCE_ROOT"), "{missing}");
}

#[test]
fn rust_timeout_quote_keeps_timeout_finding() {
    let project = probe("timeout-quote");
    let report = audit_project(project.path()).unwrap();
    assert!(
        report.issues.iter().any(|issue| {
            issue.id.starts_with("external-call-timeout:") && issue.severity == Severity::Medium
        }),
        "{:?}",
        report.issues
    );
}

#[test]
fn rust_char_quote_excludes_test_secret_and_env() {
    let project = probe("char-quote");
    let report = audit_project(project.path()).unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("hardcoded-secret:")),
        "{:?}",
        report.issues
    );
    let env = report
        .issues
        .iter()
        .find(|issue| issue.id.starts_with("env-example-incomplete:"))
        .unwrap();
    let missing = env.evidence.as_deref().unwrap();
    assert!(missing.contains("RUNTIME_URL"), "{missing}");
    assert!(!missing.contains("TEST_ONLY_FIXTURE"), "{missing}");
}

#[test]
fn rust_path_child_is_resolved_beside_path_loaded_file() {
    let project = probe("path-child");
    let report = audit_project(project.path()).unwrap();
    let missing = report
        .issues
        .iter()
        .find(|issue| issue.id.starts_with("env-example-incomplete:"))
        .unwrap()
        .evidence
        .as_deref()
        .unwrap();
    assert!(missing.contains("RUNTIME_URL"), "{missing}");
    assert!(!missing.contains("CAP_SHAPE"), "{missing}");
    assert!(!missing.contains("CAP_CONTROLLED"), "{missing}");
}

#[test]
fn rust_inline_tests_stacked_exempts_critical_path() {
    let project = probe("inline-tests-stacked");
    let report = audit_project(project.path()).unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("critical-path-no-test:")),
        "{:?}",
        report.issues
    );
}

#[test]
fn rust_disabled_build_script_does_not_exempt_compile_time_env() {
    let project = TempDir::new().unwrap();
    write_file(project.path(), ".env.example", "DOCUMENTED=\n");
    write_file(
        project.path(),
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nbuild = false\n",
    );
    write_file(
        project.path(),
        "build.rs",
        "fn main() { println!(\"cargo:rustc-env=SOURCE_ROOT=root\"); }",
    );
    write_file(
        project.path(),
        "src/lib.rs",
        "const ROOT: &str = env!(\"SOURCE_ROOT\");",
    );
    let report = audit_project(project.path()).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("env-example-incomplete:")
                && issue.evidence.as_deref().unwrap().contains("SOURCE_ROOT")),
        "{:?}",
        report.issues
    );
}

#[test]
fn rust_custom_build_script_exempts_its_compile_time_env() {
    let project = TempDir::new().unwrap();
    write_file(project.path(), ".env.example", "DOCUMENTED=\n");
    write_file(
        project.path(),
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nbuild = \"config/generate.rs\"\n",
    );
    write_file(
        project.path(),
        "config/generate.rs",
        "mod values;\nfn main() { values::configure(); }",
    );
    write_file(
        project.path(),
        "config/values.rs",
        "pub fn configure() { println!(\"cargo:rustc-env=SOURCE_ROOT=root\"); }",
    );
    write_file(
        project.path(),
        "src/lib.rs",
        "const ROOT: &str = env!(\"SOURCE_ROOT\");",
    );
    let report = audit_project(project.path()).unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("env-example-incomplete:")),
        "{:?}",
        report.issues
    );
}

fn assert_production_probe(name: &str, key: &str) {
    let project = probe(name);
    let path = project.path().join("src/lib.rs");
    let mut content = std::fs::read_to_string(&path).unwrap();
    content.push_str("\n#[cfg(test)]\n#[path = \"private.rs\"]\nmod private;\n");
    std::fs::write(path, content).unwrap();
    write_file(
        project.path(),
        "src/private.rs",
        "fn run() { let _ = std::env::var(\"ROUND3_TEST_ONLY\"); }",
    );
    let missing = missing_env(project.path());
    assert!(missing.contains(key), "{name}: {missing}");
    assert!(!missing.contains("ROUND3_TEST_ONLY"), "{name}: {missing}");
}

#[test]
fn rust_production_build_child_keeps_runtime_env() {
    assert_production_probe("build-child", "BUILD_HELPER_RUNTIME");
}

#[test]
fn rust_production_bin_file_child_keeps_runtime_env() {
    assert_production_probe("bin-file-child", "HELPER_RUNTIME");
}

#[test]
fn rust_production_cfgattr_multi_keeps_runtime_env() {
    assert_production_probe("cfgattr-multi", "MULTI_RUNTIME");
}

#[test]
fn rust_production_custom_bin_path_keeps_runtime_env() {
    assert_production_probe("custom-bin-path", "CUSTOM_BIN_RUNTIME");
}

#[test]
fn rust_production_custom_lib_path_keeps_runtime_env() {
    let project = probe("custom-bin-path");
    write_file(
        project.path(),
        "Cargo.toml",
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n[lib]\npath = \"tools/tool.rs\"\n",
    );
    let missing = missing_env(project.path());
    assert!(missing.contains("CUSTOM_BIN_RUNTIME"), "{missing}");
}

pub(super) fn assert_uncertain_project_keeps_files(declaration: &str) {
    let project = TempDir::new().unwrap();
    write_file(project.path(), ".env.example", "DOCUMENTED=\n");
    write_file(
        project.path(),
        "Cargo.toml",
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n",
    );
    write_file(
        project.path(),
        "src/lib.rs",
        &format!("{declaration}\n#[cfg(test)]\n#[path = \"private.rs\"]\nmod private_alias;"),
    );
    write_file(
        project.path(),
        "src/private.rs",
        "fn run() { let _ = std::env::var(\"FALLBACK_RUNTIME\"); }",
    );
    write_file(
        project.path(),
        "crates/known/Cargo.toml",
        "[package]\nname = \"known\"\nversion = \"0.1.0\"\n",
    );
    write_file(
        project.path(),
        "crates/known/src/lib.rs",
        "#[cfg(test)]\n#[path = \"private.rs\"]\nmod private_alias;",
    );
    write_file(
        project.path(),
        "crates/known/src/private.rs",
        "fn run() { let _ = std::env::var(\"KNOWN_TEST_ONLY\"); }",
    );
    write_file(project.path(), "src/alternate.rs", "pub fn run() {}");
    let missing = missing_env(project.path());
    assert!(
        missing.contains("FALLBACK_RUNTIME"),
        "{declaration}: {missing}"
    );
    assert!(
        missing.contains("KNOWN_TEST_ONLY"),
        "{declaration}: {missing}"
    );
}

#[test]
fn rust_uncertain_missing_module_keeps_project_files() {
    assert_uncertain_project_keeps_files("mod missing;");
}

#[test]
fn rust_uncertain_unread_path_keeps_project_files() {
    assert_uncertain_project_keeps_files(r#"#[path = r"private.rs"] mod alternate;"#);
}

#[test]
fn rust_uncertain_unread_cfgattr_path_keeps_project_files() {
    assert_uncertain_project_keeps_files(
        r#"#[cfg_attr(unix, path = r"private.rs")] mod alternate;"#,
    );
}

#[test]
fn rust_cfgattr_path_after_other_attributes_uses_only_predicate() {
    let project = probe("cfgattr-path");
    write_file(
        project.path(),
        "src/lib.rs",
        "#[cfg_attr(test, allow(dead_code), path = \"unix.rs\")]\nmod platform;",
    );
    write_file(
        project.path(),
        "src/platform.rs",
        "pub fn run() { let _ = std::env::var(\"FALLBACK_RUNTIME\"); }",
    );
    let missing = missing_env(project.path());
    assert!(missing.contains("FALLBACK_RUNTIME"), "{missing}");
    assert!(!missing.contains("UNIX_RUNTIME"), "{missing}");
}

#[test]
fn rust_cfgattr_quoted_feature_does_not_require_test() {
    let project = probe("cfgattr-path");
    let path = project.path().join("src/lib.rs");
    let content = std::fs::read_to_string(&path).unwrap().replace(
        "cfg_attr(unix,",
        r#"cfg_attr(all(unix, feature = ",test,"),"#,
    );
    std::fs::write(path, content).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("UNIX_RUNTIME"), "{missing}");
}

#[test]
fn rust_uncertain_macro_module_keeps_project_files() {
    assert_uncertain_project_keeps_files(
        "macro_rules! declare { ($name:ident) => { mod $name; } } declare!(private);",
    );
}
