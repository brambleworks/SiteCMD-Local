use super::*;

fn source(path: &str, content: &str) -> SourceFile {
    SourceFile {
        absolute_path: PathBuf::from(path),
        relative_path: path.into(),
        line_count: content.lines().count(),
        inline_rust_tests: false,
        content: content.into(),
    }
}

fn findings(files: &[SourceFile], with_example: bool) -> Vec<CodeIssue> {
    let project = tempfile::tempdir().unwrap();
    for file in files {
        let path = project.path().join(&file.relative_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &file.content).unwrap();
    }
    if with_example {
        std::fs::write(project.path().join(".env.example"), "DOCUMENTED=\n").unwrap();
    }
    audit_project(project.path())
        .unwrap()
        .issues
        .into_iter()
        .filter(|issue| issue.id.starts_with("env-example-"))
        .collect()
}

fn missing_keys(files: &[SourceFile]) -> String {
    findings(files, true)
        .into_iter()
        .filter(|issue| issue.id.starts_with("env-example-incomplete:"))
        .filter_map(|issue| issue.evidence)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn cfg_test_module_reads_do_not_require_example_entries() {
    let file = source(
        "src/lib.rs",
        r#"
#[cfg(test)]
mod capacity {
    fn measure() { let _ = std::env::var("CAPACITY_SHAPE"); }
}
pub fn start() { let _ = std::env::var("RUNTIME_URL"); }
"#,
    );
    let missing = missing_keys(&[file]);
    assert!(!missing.contains("CAPACITY_SHAPE"), "{missing}");
    assert!(missing.contains("RUNTIME_URL"), "{missing}");
}

#[test]
fn cfg_test_sibling_modules_and_their_children_are_test_only() {
    let files = [
        source(
            "src/lib.rs",
            "#[cfg(test)]\n#[path = \"capacity.rs\"]\nmod measurements;\n",
        ),
        source(
            "src/capacity.rs",
            "mod support;\nfn measure() { let _ = std::env::var(\"CAPACITY_SHAPE\"); }",
        ),
        source(
            "src/support.rs",
            "fn wait() { let _ = std::env::var(\"CAPACITY_CONTROLLED\"); }",
        ),
    ];
    assert!(missing_keys(&files).is_empty());
    assert!(findings(&files, false).is_empty());
}

#[test]
fn build_script_injected_compile_time_reads_do_not_require_example_entries() {
    let files = [
        source("Cargo.toml", "[package]\nname = \"fixture\""),
        source(
            "build.rs",
            "mod build_config;\nfn main() { build_config::configure(); }",
        ),
        source(
            "build_config.rs",
            r#"pub fn configure() {
    println!("cargo:rustc-env=SOURCE_ROOT={}", "root");
    println!("cargo::rustc-env=BUILD_REVISION=local");
}"#,
        ),
        source(
            "src/lib.rs",
            r#"const ROOT: &str = env!("SOURCE_ROOT");
const REV: Option<&str> = option_env!("BUILD_REVISION");"#,
        ),
    ];
    assert!(missing_keys(&files).is_empty());
    assert!(findings(&files, false).is_empty());
}

#[test]
fn runtime_and_unprovided_compile_time_reads_still_require_example_entries() {
    let files = [
        source("Cargo.toml", "[package]\nname = \"fixture\""),
        source(
            "build.rs",
            r#"fn main() { println!("cargo:rustc-env=SOURCE_ROOT=root"); }"#,
        ),
        source(
            "src/lib.rs",
            r#"fn start() { let _ = std::env::var("SOURCE_ROOT"); }
const TOKEN: Option<&str> = option_env!("DEPLOY_TOKEN");"#,
        ),
        source("tools/check.mjs", "const binary = process.env.TOOL_BINARY;"),
    ];
    let missing = missing_keys(&files);
    for name in ["SOURCE_ROOT", "DEPLOY_TOKEN", "TOOL_BINARY"] {
        assert!(missing.contains(name), "{name}: {missing}");
    }
    assert!(findings(&files, false)
        .iter()
        .any(|issue| issue.id.starts_with("env-example-missing:")));
}

#[test]
fn build_injection_does_not_cover_another_cargo_package() {
    let files = [
        source("Cargo.toml", "[package]\nname = \"fixture\""),
        source(
            "build.rs",
            r#"fn main() { println!("cargo:rustc-env=SOURCE_ROOT=root"); }"#,
        ),
        source("crates/other/Cargo.toml", "[package]\nname = \"other\""),
        source(
            "crates/other/src/lib.rs",
            r#"const ROOT: &str = env!("SOURCE_ROOT");"#,
        ),
    ];
    assert!(missing_keys(&files).contains("SOURCE_ROOT"));
}

#[test]
fn unlinked_or_commented_build_emissions_do_not_hide_configuration() {
    let files = [
        source("Cargo.toml", "[package]\nname = \"fixture\""),
        source(
            "build.rs",
            r#"fn main() {}
// println!("cargo:rustc-env=COMMENTED_ROOT=root");"#,
        ),
        source(
            "unlinked.rs",
            r#"fn example() { println!("cargo:rustc-env=UNLINKED_ROOT=root"); }"#,
        ),
        source(
            "src/lib.rs",
            r#"const A: &str = env!("COMMENTED_ROOT");
const B: &str = env!("UNLINKED_ROOT");"#,
        ),
    ];
    let missing = missing_keys(&files);
    assert!(missing.contains("COMMENTED_ROOT"), "{missing}");
    assert!(missing.contains("UNLINKED_ROOT"), "{missing}");
}

#[test]
fn test_module_paths_outside_project_do_not_hide_scanned_runtime_reads() {
    let files = [
        source(
            "src/lib.rs",
            "#[cfg(test)]\n#[path = \"../../outside.rs\"]\nmod fixture;",
        ),
        source(
            "outside.rs",
            "pub fn start() { let _ = std::env::var(\"RUNTIME_URL\"); }",
        ),
    ];
    assert!(missing_keys(&files).contains("RUNTIME_URL"));
}

#[test]
fn audit_keeps_runtime_reads_after_inline_tests_and_skips_test_siblings() {
    let project = tempfile::tempdir().unwrap();
    let fixtures = [
        source(".env.example", "DOCUMENTED_OPTION=\n"),
        source("Cargo.toml", "[package]\nname = \"fixture\"\nversion = \"0.1.0\""),
        source("build.rs", r#"fn main() { println!("cargo:rustc-env=SOURCE_ROOT=root"); }"#),
        source("src/lib.rs", r#"#[cfg(test)]
mod tests { fn check() { let _ = std::env::var("INLINE_TEST_INPUT"); } }
#[cfg(test)]
#[path = "capacity.rs"]
mod measurements;
const ROOT: &str = env!("SOURCE_ROOT");
pub fn start() { let _ = std::env::var("RUNTIME_URL"); }
"#),
        source("src/capacity.rs", "#[path = \"support.rs\"]\nmod support;\nfn measure() { let _ = std::env::var(\"CAPACITY_SHAPE\"); }"),
        source("src/support.rs", "fn wait() { let _ = std::env::var(\"CAPACITY_CONTROLLED\"); }"),
        source("client.test.ts", "const fixture = process.env.TEST_FIXTURE;"),
    ];
    for file in fixtures {
        let path = project.path().join(file.relative_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.content).unwrap();
    }
    let report = audit_project(project.path()).unwrap();
    let missing = report
        .issues
        .iter()
        .find(|issue| issue.id.starts_with("env-example-incomplete:"))
        .and_then(|issue| issue.evidence.as_deref())
        .expect("runtime configuration remains reported");
    assert!(missing.contains("RUNTIME_URL"), "{missing}");
    for name in [
        "SOURCE_ROOT",
        "INLINE_TEST_INPUT",
        "CAPACITY_SHAPE",
        "CAPACITY_CONTROLLED",
        "TEST_FIXTURE",
    ] {
        assert!(!missing.contains(name), "{name}: {missing}");
    }
}
