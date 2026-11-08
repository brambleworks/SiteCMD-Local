// A code-scan credential format is added without a decision for served pages, so hosted scans miss a format the CLI finds.

use super::{CODE_ONLY_SECRET_RULES, HARDCODED_SECRET_PATTERNS, WEAK_DEFAULT_CREDENTIAL_PATTERNS};
use crate::core::code_scan::patterns::{MCP_SECRET_NAME_VALUE_PATTERN, MCP_SECRET_VALUE_PATTERNS};
use sitecmd_engine::checks::security::key_pattern_services;

#[path = "../../../../../crates/engine/tests/support/bundle_corpus.rs"]
mod bundle_corpus;

fn corpus() -> Vec<(String, String)> {
    bundle_corpus::read(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine"))
}

fn code_only(rule: &regex::Regex) -> bool {
    CODE_ONLY_SECRET_RULES
        .iter()
        .any(|(pattern, _)| *pattern == rule.as_str())
}

#[test]
fn every_code_scan_value_rule_has_a_served_format_or_a_code_only_decision() {
    let samples: Vec<String> = [
        ("sk_live_", "aB3".repeat(8)),
        ("sk_test_", "aB3".repeat(8)),
        ("AKIA", "A1B2".repeat(4)),
        ("sk-", "aB3".repeat(8)),
        ("ghp_", "aB3".repeat(12)),
        ("gho_", "aB3".repeat(12)),
        ("glpat-", "aB3_".repeat(5)),
        ("xoxb-", "aB3".repeat(8)),
        (
            "SG.",
            format!("{}.{}", "aB3_".repeat(5) + "aB", "aB3_".repeat(10) + "aB3"),
        ),
        ("AIza", "aB3_".repeat(8) + "aB3"),
        ("npm_", "aB3".repeat(12)),
        ("rk_live_", "aB3".repeat(8)),
        ("sk-proj-", "aB3_".repeat(6)),
        ("github_pat_", "aB3_".repeat(20) + "Z9"),
        ("sk-ant-", "aB3".repeat(8)),
    ]
    .into_iter()
    .map(|(prefix, body)| format!("\"{prefix}{body}\""))
    .chain(std::iter::once(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        "aB3+".repeat(32)
    )))
    .collect();
    let mut missing = Vec::new();
    for rule in HARDCODED_SECRET_PATTERNS
        .iter()
        .chain(MCP_SECRET_VALUE_PATTERNS.iter())
    {
        let sample = samples
            .iter()
            .find(|sample| rule.is_match(sample))
            .unwrap_or_else(|| panic!("missing witness for code-scan rule {}", rule.as_str()));
        if !code_only(rule) && key_pattern_services(sample).is_empty() {
            missing.push(rule.as_str());
        }
    }
    assert!(
        missing.is_empty(),
        "no served format or code-only decision: {missing:?}"
    );
}

#[test]
fn generic_rules_run_on_the_corpus_and_keep_explicit_code_only_reasons() {
    let corpus = corpus();
    let rules = [
        ("unbounded sk- value", &MCP_SECRET_VALUE_PATTERNS[0], true),
        (
            "MCP name-value heuristic",
            &*MCP_SECRET_NAME_VALUE_PATTERN,
            true,
        ),
    ]
    .into_iter()
    .chain(
        WEAK_DEFAULT_CREDENTIAL_PATTERNS
            .iter()
            .map(|rule| ("weak default literal", rule, false)),
    );
    let mut missing = Vec::new();
    for (name, rule, duplicate) in rules {
        let hits: Vec<_> = corpus
            .iter()
            .filter_map(|(path, text)| rule.is_match(text).then_some(path))
            .collect();
        println!(
            "{name} {}: {} {hits:?}",
            rule.as_str(),
            if hits.is_empty() { "silent" } else { "matched" }
        );
        if (duplicate || !hits.is_empty()) && !code_only(rule) {
            missing.push(rule.as_str());
        }
    }
    assert!(
        missing.is_empty(),
        "generic rules need code-only reasons: {missing:?}"
    );
}

#[test]
fn sendgrid_code_scan_finds_full_keys_and_ignores_single_segment_fragments() {
    let temp = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(temp.path().join("src")).unwrap();
    let segment = "aB3_".repeat(5) + "aB";
    let full = format!("SG.{segment}.{}", "cD4_".repeat(10) + "cD4");
    let fragment = format!("SG.{segment}");
    for (token, expected) in [(full, true), (fragment, false)] {
        std::fs::write(
            temp.path().join("src/keys.ts"),
            format!("const key = '{token}';"),
        )
        .unwrap();
        let report = crate::core::code_scan::audit_project(temp.path()).unwrap();
        assert_eq!(
            report
                .issues
                .iter()
                .any(|issue| issue.id == "hardcoded-secret:src/keys.ts"),
            expected,
            "two-segment={expected}"
        );
    }
}

#[test]
fn code_only_decisions_name_existing_rules_and_nonempty_reasons() {
    let existing: Vec<_> = HARDCODED_SECRET_PATTERNS
        .iter()
        .chain(MCP_SECRET_VALUE_PATTERNS.iter())
        .chain(std::iter::once(&*MCP_SECRET_NAME_VALUE_PATTERN))
        .chain(WEAK_DEFAULT_CREDENTIAL_PATTERNS.iter())
        .map(|rule| rule.as_str())
        .collect();
    for (index, (rule, reason)) in CODE_ONLY_SECRET_RULES.iter().enumerate() {
        assert!(existing.contains(rule), "unknown code-only rule: {rule}");
        assert!(!reason.trim().is_empty(), "missing reason for {rule}");
        assert!(!CODE_ONLY_SECRET_RULES[..index]
            .iter()
            .any(|(other, _)| rule == other));
    }
}
