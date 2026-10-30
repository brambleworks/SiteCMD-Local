use super::rust_scope::{missing_env, probe};
use super::*;

#[test]
fn rust_graph_build_include_keeps_runtime_env() {
    let project = probe("build-include");
    let missing = missing_env(project.path());
    assert!(missing.contains("VENDOR_DIR_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_include_alias_keeps_runtime_env() {
    let project = probe("include-alias");
    let missing = missing_env(project.path());
    assert!(missing.contains("INCLUDE_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_cross_package_raw_path_keeps_runtime_env() {
    let project = probe("cross-package-raw-path");
    let missing = missing_env(project.path());
    assert!(missing.contains("CROSS_PACKAGE_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_cross_package_abs_path_keeps_runtime_env() {
    let project = probe("cross-package-abs-path");
    let shared = project.path().join("q/src/shared.rs");
    let content = format!(
        "#[path = {:?}]\nmod shared;\n\npub fn entry() {{\n    shared::run();\n}}\n",
        shared.to_str().unwrap()
    );
    std::fs::create_dir_all(project.path().join("p/src")).unwrap();
    std::fs::write(project.path().join("p/src/lib.rs"), content).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("CROSS_PACKAGE_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unparsed_large_parent_keeps_runtime_env() {
    let project = probe("large-parent");
    let path = project.path().join("src/lib.rs");
    let mut content = std::fs::read_to_string(&path).unwrap();
    content.push_str(&format!("// {}", "x".repeat(1_000_000)));
    std::fs::write(path, content).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("LARGE_PARENT_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unparsed_ignored_parent_keeps_runtime_env() {
    let project = probe("large-parent");
    write_file(project.path(), ".gitignore", "src/lib.rs\n");
    let missing = missing_env(project.path());
    assert!(missing.contains("LARGE_PARENT_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unparsed_non_utf8_parent_keeps_runtime_env() {
    let project = probe("large-parent");
    std::fs::write(project.path().join("src/lib.rs"), [0xff]).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("LARGE_PARENT_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unparsed_source_budget_keeps_runtime_env() {
    let project = probe("source-budget");
    for dir in ["alpha", "beta", "gamma"] {
        std::fs::create_dir(project.path().join(dir)).unwrap();
    }
    let directories = std::fs::read_dir(project.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    let first = directories[0].file_name().unwrap().to_str().unwrap();
    let last = directories[2].file_name().unwrap().to_str().unwrap();
    write_file(
        project.path(),
        "Cargo.toml",
        &format!(
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n[lib]\npath = \"{last}/parent.rs\"\n"),
    );
    std::fs::write(
        directories[0].join("alias.rs"),
        "#[cfg(test)] #[path = \"shared.rs\"] mod shared;",
    )
    .unwrap();
    std::fs::write(
        directories[0].join("shared.rs"),
        "fn run() { let _ = std::env::var(\"BUDGET_RUNTIME\"); }",
    )
    .unwrap();
    for index in 0..5_000 {
        std::fs::write(
            directories[1].join(format!("filler{index}.js")),
            "export {};",
        )
        .unwrap();
    }
    std::fs::write(
        directories[2].join("parent.rs"),
        format!("#[path = \"../{first}/shared.rs\"] mod shared;"),
    )
    .unwrap();
    let inventory = collect_project_inventory(project.path()).unwrap();
    assert!(inventory
        .source_files
        .iter()
        .any(|file| file.relative_path == format!("{first}/shared.rs")));
    assert!(!inventory
        .source_files
        .iter()
        .any(|file| file.relative_path == format!("{last}/parent.rs")));
    let missing = missing_env(project.path());
    assert!(missing.contains("BUDGET_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_bin_inline_array_keeps_runtime_env() {
    let project = probe("bin-inline-array");
    let missing = missing_env(project.path());
    assert!(missing.contains("INLINE_BIN_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_twin_macro_mod_keeps_runtime_env() {
    let project = probe("macro-mod-twin");
    let missing = missing_env(project.path());
    assert!(missing.contains("MACRO_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_twin_main_stem_nonroot_keeps_runtime_env() {
    let project = probe("main-stem-nonroot");
    let missing = missing_env(project.path());
    assert!(missing.contains("MAIN_STEM_RUNTIME"), "{missing}");
}

fn include_control(argument: &str) -> TempDir {
    let project = probe("include-alias");
    write_file(
        project.path(),
        "src/lib.rs",
        &format!("include!({argument});\n#[cfg(test)] #[path = \"private.rs\"] mod private;"),
    );
    write_file(
        project.path(),
        "src/private.rs",
        "fn run() { let _ = std::env::var(\"INCLUDE_TEST_ONLY\"); }",
    );
    project
}

#[test]
fn rust_graph_generated_include_keeps_project_env() {
    let project = include_control(r#"concat!(env!("OUT_DIR"), "/generated.rs")"#);
    let missing = missing_env(project.path());
    assert!(missing.contains("INCLUDE_TEST_ONLY"), "{missing}");
    assert!(missing.contains("INCLUDE_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unknown_include_keeps_project_env() {
    for argument in ["file_path!()", r#"concat!(env!("OTHER_DIR"), "/file.rs")"#] {
        let project = include_control(argument);
        let missing = missing_env(project.path());
        assert!(
            missing.contains("INCLUDE_TEST_ONLY"),
            "{argument}: {missing}"
        );
    }
}

#[test]
fn rust_graph_literal_include_forms_keep_runtime_edges() {
    for invocation in [
        r##"include!(r#"shared.rs"#);"##,
        r#"include! { "shared.rs" }"#,
        r#"include!["shared.rs"];"#,
    ] {
        let project = include_control(r#""shared.rs""#);
        let path = project.path().join("src/lib.rs");
        let content = std::fs::read_to_string(&path)
            .unwrap()
            .replace(r#"include!("shared.rs");"#, invocation);
        std::fs::write(path, content).unwrap();
        write_file(
            project.path(),
            "src/alias.rs",
            "#[cfg(test)] #[path = \"shared.rs\"] mod shared;",
        );
        let missing = missing_env(project.path());
        assert!(
            missing.contains("INCLUDE_RUNTIME"),
            "{invocation}: {missing}"
        );
        assert!(
            !missing.contains("INCLUDE_TEST_ONLY"),
            "{invocation}: {missing}"
        );
    }
}

#[test]
fn rust_graph_test_gated_includes_skip_only_env_names() {
    for code in [
        r#"#[cfg(test)] include!("shared.rs");"#,
        r#"#[cfg(test)] mod capacity { include!("shared.rs"); }"#,
    ] {
        let project = probe("include-alias");
        write_file(project.path(), "src/lib.rs", code);
        let missing = missing_env(project.path());
        assert!(!missing.contains("INCLUDE_RUNTIME"), "{code}: {missing}");
    }
}

#[test]
fn graph_test_siblings_still_emit_secret_findings() {
    let project = TempDir::new().unwrap();
    write_file(
        project.path(),
        "lib.rs",
        "#[cfg(test)]\n#[path = \"capacity.rs\"]\nmod capacity;",
    );
    let secret = format!(
        "const KEY: &str = \"-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\";",
        "MIIA".repeat(128)
    );
    write_file(project.path(), "capacity.rs", &secret);
    let inventory = collect_project_inventory(project.path()).unwrap();
    assert!(inventory
        .rust_modules
        .test_only_paths()
        .contains(Path::new("capacity.rs")));
    let report = audit_project(project.path()).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("hardcoded-secret:")),
        "{:?}",
        report.issues
    );
}

#[test]
fn rust_graph_unread_attribute_outside_group_keeps_project_env() {
    super::rust_scope::assert_uncertain_project_keeps_files(
        r#"#[path = "private.rs"] #[my_attr([1])] mod alternate;"#,
    );
}

#[test]
fn rust_graph_unparsed_include_target_keeps_runtime_env() {
    let project = probe("rs-in-include");
    let missing = missing_env(project.path());
    assert!(missing.contains("RS_IN_INCLUDE_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unparsed_module_target_keeps_runtime_env() {
    let project = probe("rs-in-module");
    let missing = missing_env(project.path());
    assert!(missing.contains("RS_IN_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_unparsed_testlike_parent_keeps_runtime_env() {
    let project = probe("testlike-parent");
    let missing = missing_env(project.path());
    assert!(missing.contains("TESTLIKE_PARENT_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_manifest_over_read_cap_keeps_runtime_env() {
    let project = probe("oversized-manifest");
    let path = project.path().join("Cargo.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(path, format!("{content}{}", "# padding\n".repeat(26_000))).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("OVERSIZED_MANIFEST_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_manifest_invalid_keeps_runtime_env() {
    let project = probe("oversized-manifest");
    let path = project.path().join("Cargo.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(path, format!("{content}\n[broken\n")).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("OVERSIZED_MANIFEST_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_manifest_non_utf8_keeps_runtime_env() {
    let project = probe("oversized-manifest");
    std::fs::write(project.path().join("Cargo.toml"), [0xff]).unwrap();
    let missing = missing_env(project.path());
    assert!(missing.contains("OVERSIZED_MANIFEST_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_generated_include_modules_keep_runtime_env() {
    let project = probe("out-dir-modules");
    let missing = missing_env(project.path());
    assert!(missing.contains("OUT_DIR_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_nested_comment_include_keeps_runtime_env() {
    let project = probe("nested-comment-include");
    let missing = missing_env(project.path());
    assert!(missing.contains("NESTED_INCLUDE_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_uninventoried_target_root_keeps_runtime_env() {
    let project = probe("build-dir-script");
    write_file(
        project.path(),
        "build/main.rs",
        r#"#[path = "../src/build_support.rs"]
mod build_support;

fn main() {
    if let Some(dir) = build_support::lib_dir() {
        println!("cargo:rustc-link-search=native={dir}");
    }
    println!("cargo:rerun-if-env-changed=BUILD_DIR_RUNTIME");
}
"#,
    );
    let missing = missing_env(project.path());
    assert!(missing.contains("BUILD_DIR_RUNTIME"), "{missing}");
}

#[test]
fn rust_graph_raw_c_string_keeps_runtime_env() {
    let project = probe("raw-c-string");
    let missing = missing_env(project.path());
    assert!(missing.contains("RAW_C_STRING_RUNTIME"), "{missing}");
}
