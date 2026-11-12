use sitecmd_runtime::checks::Severity;
use sitecmd_runtime::core::code_scan::registry::CODE_CHECKS;
use sitecmd_runtime::core::code_scan::{canonical_code_check_id, registry::RuleClass};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sitecmd_cli"))
        .args(args)
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap()
}

fn rules_json() -> Output {
    let output = cli(&["rules", "--format", "json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "rules command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

// Node is a repository prerequisite; use its JSON parser without adding a crate.
fn assert_json(output: &Output, assertions: &str, expected: &str) {
    let script = format!(
        "const assert = require('node:assert/strict');
         const data = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
         const expected = process.argv[1];
         function validateSeverity(rule) {{
           assert(['fixed', 'per_finding'].includes(rule.severitySource));
           if (rule.severitySource === 'fixed')
             assert(['critical', 'high', 'medium', 'low'].includes(rule.defaultSeverity));
           else assert.equal(rule.defaultSeverity, null);
         }}
         {assertions}"
    );
    let mut child = Command::new("node")
        .args(["-e", &script, expected])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&output.stdout)
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "JSON contract failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn fixtures() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/code_scan");
    let mut paths: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "existing audit fixtures disappeared");
    paths
}

fn audit_fixture(fixture: &Path) -> Output {
    fn copy(source: &Path, target: &Path) {
        std::fs::create_dir_all(target).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &destination);
            } else {
                std::fs::copy(entry.path(), destination).unwrap();
            }
        }
    }
    // The audit excludes fixture paths, so mirror the existing Rust fixture harness.
    let project = tempfile::tempdir().unwrap();
    copy(fixture, project.path());
    std::fs::write(project.path().join(".env.example"), "DOCUMENTED=\n").unwrap();
    let output = cli(&[
        "audit",
        project.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}: {}",
        fixture.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn rules_inventory_does_not_drift_from_registry_or_real_fixture_audits() {
    let output = rules_json();
    let mut slugs: Vec<_> = CODE_CHECKS.iter().map(|rule| rule.slug).collect();
    slugs.sort_unstable();
    assert_json(
        &output,
        "assert.deepEqual(data.rules.map(rule => rule.producerRuleId), expected.split('\\n'));",
        &slugs.join("\n"),
    );
    let mut findings = 0;
    for fixture in fixtures() {
        let audit = audit_fixture(&fixture);
        assert_json(
            &audit,
            "const rules = new Set(expected.split('\\n'));
             for (const finding of data.issues) assert(rules.has(finding.producerRuleId), finding.id);",
            &slugs.join("\n"),
        );
        findings += String::from_utf8(audit.stdout)
            .unwrap()
            .matches("\"producerRuleId\"")
            .count();
    }
    assert!(
        findings > 0,
        "fixtures must actually exercise audit emitters"
    );
}

#[test]
fn rules_json_is_one_document_and_exits_zero_without_stdout_noise() {
    let output = Command::new(env!("CARGO_BIN_EXE_sitecmd_cli"))
        .args(["rules", "--format", "json"])
        .env("RUST_LOG", "debug")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_json(
        &output,
        "assert.equal(typeof data, 'object');
         assert(!Array.isArray(data));
         assert.equal(data.version, expected);
         assert(Array.isArray(data.rules));
         assert(data.rules.length > 0);",
        env!("CARGO_PKG_VERSION"),
    );
}

#[test]
fn rules_metadata_does_not_disagree_with_registry_policy_or_fixture_findings() {
    let output = rules_json();
    let expected: Vec<_> = CODE_CHECKS
        .iter()
        .map(|rule| {
            let severity = rule.policy_severity.map(|severity| {
                if rule.class == RuleClass::Advisory
                    && matches!(severity, Severity::Critical | Severity::High)
                {
                    Severity::Medium
                } else if severity == Severity::Critical && !rule.allows_critical {
                    Severity::High
                } else {
                    severity
                }
            });
            format!(
                "{}\t{}\t{}\t{}",
                rule.slug,
                canonical_code_check_id(rule.slug),
                rule.domain,
                severity.map(|value| value.as_str()).unwrap_or("null")
            )
        })
        .collect();
    assert_json(
        &output,
        "const rules = new Map(data.rules.map(rule => [rule.producerRuleId, rule]));
         for (const line of expected.split('\\n')) {
           const [producerRuleId, checkId, domain, severity] = line.split('\\t');
           assert.deepEqual(rules.get(producerRuleId), {producerRuleId, checkId, domain,
             defaultSeverity: severity === 'null' ? null : severity,
             severitySource: severity === 'null' ? 'per_finding' : 'fixed'});
         }",
        &expected.join("\n"),
    );
    let mut findings = 0;
    for fixture in fixtures() {
        let audit = audit_fixture(&fixture);
        let audit = String::from_utf8(audit.stdout).unwrap();
        findings += audit.matches("\"producerRuleId\"").count();
        assert_json(
            &output,
            "const rules = new Map(data.rules.map(rule => [rule.producerRuleId, rule]));
             for (const finding of JSON.parse(expected).issues) {
               const rule = rules.get(finding.producerRuleId);
               assert(rule, finding.id);
               assert.equal(rule.checkId, finding.checkId, finding.id);
               assert.equal(rule.domain, finding.domain, finding.id);
               if (rule.severitySource === 'fixed')
                 assert.equal(rule.defaultSeverity, finding.severity, finding.id);
             }",
            &audit,
        );
    }
    assert!(findings > 0, "metadata parity must exercise audit findings");
}

#[test]
fn rules_order_is_sorted_and_stable_across_two_runs() {
    let first = rules_json();
    let second = rules_json();
    assert_eq!(first.stdout, second.stdout);
    assert_json(
        &first,
        "const ids = data.rules.map(rule => rule.producerRuleId);
         assert.deepEqual(ids, [...ids].sort());
         assert.equal(new Set(ids).size, ids.length);",
        "",
    );
}

#[test]
fn rules_text_defaults_and_explicit_text_show_the_json_fields() {
    let default = cli(&["rules"]);
    let explicit = cli(&["rules", "--format", "text"]);
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(explicit.status.code(), Some(0));
    assert_eq!(default.stdout, explicit.stdout);
    let text = String::from_utf8(default.stdout).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), CODE_CHECKS.len() + 1);
    assert_eq!(
        lines[0].split_whitespace().collect::<Vec<_>>(),
        [
            "producerRuleId",
            "checkId",
            "domain",
            "defaultSeverity",
            "severitySource"
        ]
    );
    assert_json(
        &rules_json(),
        "const rows = expected.split('\\n').slice(1).map(line => line.trim().split(/\\s+/));
         assert.deepEqual(rows, data.rules.map(rule => [rule.producerRuleId, rule.checkId,
           rule.domain, String(rule.defaultSeverity), rule.severitySource]));",
        text.trim_end(),
    );
}

#[test]
fn rules_help_is_discoverable_and_invalid_arguments_exit_two() {
    let help = cli(&["--help"]);
    assert!(String::from_utf8_lossy(&help.stderr).contains("rules"));
    let help = cli(&["rules", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stderr).contains("--format"));
    for args in [
        vec!["rules", "--format"],
        vec!["rules", "--format", "yaml"],
        vec!["rules", "unexpected"],
        vec!["rules", "--unknown"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn severity_sources_partition_the_registry_without_inventing_grades() {
    let fixed = CODE_CHECKS
        .iter()
        .filter(|rule| rule.policy_severity.is_some())
        .count();
    assert_json(
        &rules_json(),
        "data.rules.forEach(validateSeverity);
         const fixed = data.rules.filter(rule => rule.severitySource === 'fixed');
         const perFinding = data.rules.filter(rule => rule.severitySource === 'per_finding');
         const [expectedFixed, total] = expected.split('\\t').map(Number);
         assert.equal(fixed.length, expectedFixed);
         assert.equal(perFinding.length, total - expectedFixed);
         assert.equal(fixed.length + perFinding.length, total);",
        &format!("{fixed}\t{}", CODE_CHECKS.len()),
    );
}

#[test]
fn pinned_grade_fixture_with_stale_per_finding_source_is_rejected() {
    assert_json(
        &rules_json(),
        "data.rules.forEach(validateSeverity);
         const fixture = JSON.parse(expected);
         const actual = data.rules.find(rule => rule.producerRuleId === fixture.producerRuleId);
         assert.equal(actual.severitySource, 'fixed');
         assert.equal(actual.defaultSeverity, fixture.defaultSeverity);
         assert.throws(() => validateSeverity(fixture));",
        include_str!("fixtures/pinned-grade-stale-source.json"),
    );
}
