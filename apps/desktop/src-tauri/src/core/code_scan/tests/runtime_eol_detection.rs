use super::*;

fn runtime_eol_issue<'a>(report: &'a CodeScanReport, path: &str) -> Option<&'a CodeIssue> {
    report
        .issues
        .iter()
        .find(|issue| issue.id == format!("runtime-version-eol:{}", path))
}

#[test]
fn runtime_eol_flags_engines_node_past_end_of_life() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "package.json",
        r#"
{
  "name": "demo-app",
  "engines": { "node": ">=18" }
}
"#,
    );

    let report = audit_project(temp.path()).unwrap();
    let issue = runtime_eol_issue(&report, "package.json").expect("Node 18 should flag");
    assert_eq!(issue.severity, Severity::Low);
    assert_eq!(issue.confidence, crate::checks::IssueConfidence::High);
    assert!(issue.title.contains("permits"));
    assert!(issue.description.contains("does not prove"));
    assert!(issue
        .description
        .contains("commercial or downstream support"));
    let evidence = issue.evidence.as_deref().unwrap_or_default();
    assert!(
        evidence.contains("2025-04-30"),
        "evidence should carry the vendored EOL date: {evidence}"
    );
    assert!(
        evidence.contains("nodejs.org"),
        "evidence should cite the vendored source: {evidence}"
    );
}

#[test]
fn runtime_eol_resolves_the_range_minimum_not_the_newest_branch() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "package.json",
        r#"
{
  "name": "demo-app",
  "engines": { "node": "16 || >=22" }
}
"#,
    );

    let report = audit_project(temp.path()).unwrap();
    let issue = runtime_eol_issue(&report, "package.json")
        .expect("the range still admits Node 16, which is past end of life");
    let evidence = issue.evidence.as_deref().unwrap_or_default();
    assert!(
        evidence.contains("Node.js 16 at minimum"),
        "evidence should name the resolved minimum: {evidence}"
    );
}

#[test]
fn runtime_eol_flags_nvmrc_when_no_engines_field_exists() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "demo-app" }"#);
    write_file(temp.path(), ".nvmrc", "v18.17.0\n");

    let report = audit_project(temp.path()).unwrap();
    assert!(
        runtime_eol_issue(&report, ".nvmrc").is_some(),
        ".nvmrc is the fallback Node declaration"
    );
}

#[test]
fn runtime_selector_takes_precedence_over_compatibility_range() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "package.json",
        r#"{ "name": "demo-app", "engines": { "node": ">=18" } }"#,
    );
    write_file(temp.path(), ".nvmrc", "24\n");

    let report = audit_project(temp.path()).unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("runtime-version-eol:")),
        "a supported version selector must take precedence over a broad compatibility range"
    );
}

#[test]
fn runtime_eol_flags_python_version_file() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "pyproject.toml",
        "[project]\nname = \"demo\"\n",
    );
    write_file(temp.path(), ".python-version", "3.9.18\n");
    write_file(temp.path(), "src/main.py", "print(\"hello\")\n");

    let report = audit_project(temp.path()).unwrap();
    let issue = runtime_eol_issue(&report, ".python-version").expect("Python 3.9 should flag");
    let evidence = issue.evidence.as_deref().unwrap_or_default();
    assert!(
        evidence.contains("2025-10-31"),
        "evidence should carry the Python 3.9 EOL date: {evidence}"
    );
}

#[test]
fn runtime_eol_flags_pyproject_requires_python_minimum() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "pyproject.toml",
        "[project]\nname = \"demo\"\nrequires-python = \">=3.8,<3.13\"\n",
    );
    write_file(temp.path(), "src/main.py", "print(\"hello\")\n");

    let report = audit_project(temp.path()).unwrap();
    let issue =
        runtime_eol_issue(&report, "pyproject.toml").expect("requires-python >=3.8 should flag");
    let evidence = issue.evidence.as_deref().unwrap_or_default();
    assert!(
        evidence.contains("Python 3.8 at minimum"),
        "evidence should resolve the range minimum: {evidence}"
    );
}

#[test]
fn runtime_eol_flags_composer_php_requirement() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "composer.json",
        r#"
{
  "name": "demo/app",
  "require": { "php": "^8.1" }
}
"#,
    );
    write_file(temp.path(), "src/index.php", "<?php echo 'hello';\n");

    let report = audit_project(temp.path()).unwrap();
    let issue = runtime_eol_issue(&report, "composer.json").expect("PHP 8.1 should flag");
    let evidence = issue.evidence.as_deref().unwrap_or_default();
    assert!(
        evidence.contains("2025-12-31"),
        "evidence should carry the PHP 8.1 EOL date: {evidence}"
    );
}

#[test]
fn runtime_eol_does_not_fire_without_a_runtime_declaration() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "package.json",
        r#"{ "name": "demo-app", "dependencies": { "react": "^19.0.0" } }"#,
    );
    write_file(temp.path(), "src/index.ts", "export const app = 1;\n");

    let report = audit_project(temp.path()).unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("runtime-version-eol:")),
        "absence of a declaration is out of scope for this rule"
    );
}

#[test]
fn runtime_eol_does_not_fire_for_undeterminable_specs() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "demo-app" }"#);
    write_file(temp.path(), ".nvmrc", "lts/hydrogen\n");

    let report = audit_project(temp.path()).unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with("runtime-version-eol:")),
        "an alias with no resolvable version must not guess"
    );
}
