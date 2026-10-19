use super::*;

const UNVALIDATED_ROUTE: &str = r#"
export async function POST(request: Request) {
  const body = await request.json();
  return Response.json({ ok: Boolean(body.email) });
}
"#;

fn assert_no_issue_under(report: &CodeScanReport, prefix: &str) {
    let contaminated: Vec<&str> = report
        .issues
        .iter()
        .filter(|issue| issue.relative_path.starts_with(prefix))
        .map(|issue| issue.id.as_str())
        .collect();
    assert!(
        contaminated.is_empty(),
        "expected no findings under {prefix}, got {contaminated:?}"
    );
}

fn assert_issue_fires(report: &CodeScanReport, id_prefix: &str) {
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.id.starts_with(id_prefix)),
        "negative control: {id_prefix} must still fire on real source"
    );
}

#[test]
fn nested_git_repo_is_not_scanned_but_the_scan_root_repo_is() {
    let temp = TempDir::new().unwrap();
    // The scan root being a git repo itself must NOT stop the walk.
    std::fs::create_dir_all(temp.path().join(".git")).unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "app" }"#);
    write_file(temp.path(), "app/api/contact/route.ts", UNVALIDATED_ROUTE);
    // A nested clone (someone else's project) marked by a `.git` directory.
    std::fs::create_dir_all(temp.path().join("tools/work/clone/.git")).unwrap();
    write_file(
        temp.path(),
        "tools/work/clone/app/api/contact/route.ts",
        UNVALIDATED_ROUTE,
    );

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "tools/work/clone/");
    // Negative control: the identical first-party route still yields findings.
    assert_issue_fires(&report, "request-validation:app/api/contact/route.ts");
}

#[test]
fn nested_git_worktree_file_also_stops_the_walk() {
    // Worktrees and submodules mark their root with a `.git` file, not a
    // directory; both mean "separate repository".
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "app" }"#);
    write_file(temp.path(), "app/api/contact/route.ts", UNVALIDATED_ROUTE);
    write_file(
        temp.path(),
        "third_party/lib/.git",
        "gitdir: ../../.git/worktrees/lib\n",
    );
    write_file(
        temp.path(),
        "third_party/lib/app/api/contact/route.ts",
        UNVALIDATED_ROUTE,
    );

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "third_party/lib/");
    assert_issue_fires(&report, "request-validation:app/api/contact/route.ts");
}

#[test]
fn gitignored_directory_is_excluded_from_analysis() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), ".gitignore", "generated/\n");
    write_file(temp.path(), "package.json", r#"{ "name": "app" }"#);
    write_file(temp.path(), "app/api/contact/route.ts", UNVALIDATED_ROUTE);
    write_file(
        temp.path(),
        "generated/app/api/contact/route.ts",
        UNVALIDATED_ROUTE,
    );

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "generated/");
    assert_issue_fires(&report, "request-validation:app/api/contact/route.ts");
}

#[test]
fn nested_gitignore_excludes_its_own_subtree() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "app" }"#);
    write_file(temp.path(), "app/api/contact/route.ts", UNVALIDATED_ROUTE);
    write_file(temp.path(), "tools/benchmark/.gitignore", ".work/\n");
    write_file(
        temp.path(),
        "tools/benchmark/.work/repos/demo/app/api/contact/route.ts",
        UNVALIDATED_ROUTE,
    );

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "tools/benchmark/.work/");
    assert_issue_fires(&report, "request-validation:app/api/contact/route.ts");
}

#[test]
fn gitignored_file_stays_in_inventory_but_out_of_source_analysis() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), ".gitignore", "legacy.ts\n");
    write_file(temp.path(), "app.ts", "export const app = 1;\n");
    write_file(temp.path(), "legacy.ts", "export const legacy = 1;\n");

    let inventory = collect_project_inventory(temp.path()).unwrap();
    assert!(
        inventory
            .source_files
            .iter()
            .all(|file| file.relative_path != "legacy.ts"),
        "a gitignored file must not be analysed as source"
    );
    assert!(
        inventory
            .source_files
            .iter()
            .any(|file| file.relative_path == "app.ts"),
        "tracked source is still analysed"
    );
    assert!(
        inventory
            .project_files
            .iter()
            .any(|file| file.relative_path == "legacy.ts"),
        "the gitignored file must remain in the project inventory"
    );
}

#[test]
fn opted_in_gitignored_env_file_feeds_env_hygiene_checks() {
    let temp = TempDir::new().unwrap();
    std::fs::create_dir_all(temp.path().join(".git")).unwrap();
    write_file(temp.path(), ".gitignore", ".env*\n");
    write_file(temp.path(), "package.json", r#"{ "name": "app" }"#);
    write_file(temp.path(), "app/api/contact/route.ts", UNVALIDATED_ROUTE);
    write_file(
        temp.path(),
        ".env.production",
        "APP_DEBUG=true\nAPP_KEY=base64:abcdefghijklmnop\n",
    );

    let report = audit_project_with_local_databases(temp.path()).unwrap();
    assert_issue_fires(&report, "framework-debug-enabled:.env.production");
}

#[test]
fn rust_test_files_are_not_analysed_as_source() {
    let credentialed = "pub fn connect() { let password = \"changeme\"; }\n";
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "Cargo.toml", "[package]\nname = \"app\"\n");
    // Sibling test-file conventions.
    write_file(temp.path(), "src/commands/desktop_tests.rs", credentialed);
    write_file(temp.path(), "src/config_test.rs", credentialed);
    // Bench tree.
    write_file(temp.path(), "benches/setup.rs", credentialed);
    // Content-based: a file that is entirely #![cfg(test)] under any name.
    write_file(
        temp.path(),
        "src/support.rs",
        &format!("// shared helpers\n#![cfg(test)]\n{credentialed}"),
    );
    // Negative control: identical production source keeps the finding.
    write_file(temp.path(), "src/config.rs", credentialed);

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "src/commands/desktop_tests.rs");
    assert_no_issue_under(&report, "src/config_test.rs");
    assert_no_issue_under(&report, "benches/");
    assert_no_issue_under(&report, "src/support.rs");
    assert_issue_fires(&report, "weak-default-credential:src/config.rs");
}

#[test]
fn route_rule_definition_source_is_not_flagged_as_a_route() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "linter" }"#);
    write_file(
        temp.path(),
        "src/scanner/route_rules.ts",
        r#"
export function isRouteLike(lower: string): boolean {
  return (
    lower.includes("export async function post(") ||
    lower.includes("app.post(") ||
    lower.includes("router.post(")
  );
}
export function isSensitivePath(path: string): boolean {
  return path.includes("admin") || path.includes("billing");
}
"#,
    );
    // Negative control: a real sensitive route without an auth gate is
    // still reported.
    write_file(temp.path(), "app/api/admin/route.ts", UNVALIDATED_ROUTE);

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "src/scanner/route_rules.ts");
    assert_issue_fires(&report, "sensitive-auth:app/api/admin/route.ts");
}

#[test]
fn quoted_sink_samples_in_rule_sources_are_not_live_sinks() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "linter" }"#);
    write_file(
        temp.path(),
        "src/scanner/php_rules.js",
        "// A prose mention (`echo \"please include $_GET[x]\"`) never matches.\nexport const RULES = [];\n",
    );
    write_file(
        temp.path(),
        "public/page.php",
        "<?php echo $_GET['name']; ?>\n",
    );

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "src/scanner/php_rules.js");
    assert_issue_fires(&report, "unsafe-html:public/page.php");
}

#[test]
fn php_attribute_context_sinks_survive_quote_suppression() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "app" }"#);
    write_file(
        temp.path(),
        "public/search.php",
        "<form><input name=\"q\" value=\"<?= $_GET['q'] ?>\"></form>\n",
    );
    write_file(
        temp.path(),
        "views/profile.blade.php",
        "<img alt=\"{!! $_GET['bio'] !!}\">\n",
    );

    let report = audit_project(temp.path()).unwrap();
    assert_issue_fires(&report, "unsafe-html:public/search.php");
    assert_issue_fires(&report, "unsafe-html:views/profile.blade.php");
}

#[test]
fn gitignored_wp_config_keeps_its_framework_debug_finding() {
    let temp = TempDir::new().unwrap();
    std::fs::create_dir_all(temp.path().join(".git")).unwrap();
    write_file(temp.path(), ".gitignore", "wp-config.php\nlegacy.php\n");
    write_file(
        temp.path(),
        "wp-config.php",
        "<?php\ndefine('WP_DEBUG', true);\n",
    );
    // Negative control: ordinary gitignored source stays out of analysis.
    write_file(
        temp.path(),
        "legacy.php",
        "<?php echo '<h1>' . $_GET['q'] . '</h1>';\n",
    );

    let report = audit_project(temp.path()).unwrap();
    assert_issue_fires(&report, "framework-debug-enabled:wp-config.php");
    assert_no_issue_under(&report, "legacy.php");
}

#[test]
fn placeholder_marker_vocabulary_is_rule_definition_not_a_weak_credential() {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), "package.json", r#"{ "name": "linter" }"#);
    write_file(
        temp.path(),
        "src/validator.ts",
        r#"
const PLACEHOLDERS = [
  "changeme",
  "change-me",
  "replace_me",
  "your_value_here",
  "not-set",
];
export const isPlaceholder = (v: string) => PLACEHOLDERS.includes(v);
"#,
    );
    // Negative control: a single weak fallback in app code still fires.
    write_file(
        temp.path(),
        "src/config.ts",
        "export const password = process.env.ADMIN_PASSWORD || \"changeme\";\n",
    );

    let report = audit_project(temp.path()).unwrap();
    assert_no_issue_under(&report, "src/validator.ts");
    assert_issue_fires(&report, "weak-default-credential:src/config.ts");
}

#[test]
fn runtime_pem_armor_is_not_a_hardcoded_secret() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "src/test-support/keys.ts",
        r#"
export async function testKeyPair() {
  const body = "generated";
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`; // gitleaks:allow
}
"#,
    );
    write_file(
        temp.path(),
        "src/key.ts",
        &format!(
            "export const pem = `-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----`;",
            "A".repeat(64)
        ),
    ); // gitleaks:allow
    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id == "hardcoded-secret:src/key.ts"));
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.id == "hardcoded-secret:src/test-support/keys.ts"));
}

#[test]
fn regex_literal_sink_names_in_rule_tables_are_not_live_sinks() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "tools/rules.mjs",
        r#"
export const RULES = [
  [/dangerouslySetInnerHTML/, isScript, "render as text"],
  [/\binnerHTML\s*=/, isScript, "render as text"],
];
"#,
    );
    write_file(
        temp.path(),
        "src/bio.tsx",
        "export const Bio = ({ user }) => <div dangerouslySetInnerHTML={{ __html: user.bio }} />;",
    );
    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("unsafe-html:src/bio.tsx:")));
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("unsafe-html:tools/rules.mjs:")));
}
