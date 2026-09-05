//! Registry compatibility tests.

use super::{descriptor_for_issue_id, CodeScanPhase, RuleClass, CODE_CHECKS};
use crate::checks::{IssueConfidence, Severity};
use crate::core::code_scan::{
    canonical_code_check_id, code_issue_domain, code_rule_id, CodeIssue, CodeScanDomain,
};
use crate::core::severity_policy::{normalized_code_issue_severity, policy_clamped_code_severity};
use std::collections::HashSet;

// Reference implementations used for parity checks.

fn code_id_matches(issue_id: &str, slug: &str) -> bool {
    issue_id == slug
        || issue_id
            .strip_prefix(slug)
            .is_some_and(|rest| rest.starts_with(':'))
}

fn code_id_matches_any(issue_id: &str, slugs: &[&str]) -> bool {
    slugs.iter().any(|slug| code_id_matches(issue_id, slug))
}

const CRITICAL_CODE_SLUGS: &[&str] = &[
    "client-ai-sdk",
    "client-db-access",
    "client-env-secret",
    "cors-credentials-wildcard",
    "eval-exec-injection",
    "hardcoded-secret",
    "js-command-injection",
    "php-code-execution",
    "php-dynamic-command",
    "php-file-inclusion",
    "php-object-injection",
    "plaintext-password",
    "python-code-execution",
    "python-command-injection",
    "python-sql-injection",
    "python-template-injection",
    "python-unsafe-deserialization",
    "shell-injection",
    "supabase-service-role-client",
    "webhook-signature",
];

const HIGH_CODE_SLUGS: &[&str] = &[
    "ai-concurrency",
    "ai-loop-risk",
    "ai-output-cap",
    "ai-rate-limit",
    "ai-spend-guardrails",
    "ai-timeout",
    "ai-user-controlled-model",
    "ai-user-controlled-settings",
    "client-auth-without-server-enforcement",
    "csrf-missing",
    "external-call-timeout",
    "hardcoded-localhost-url",
    "jwt-decode-without-verify",
    "localstorage-auth-token",
    "multi-write-no-transaction",
    "no-pagination",
    "oauth-callback-pkce",
    "oauth-callback-state",
    "one-time-token-no-expiry",
    "one-time-token-no-single-use",
    "one-time-token-raw-lookup",
    "open-redirect",
    "php-path-traversal",
    "python-open-redirect",
    "python-path-traversal",
    "raw-sql-unsafe",
    "sensitive-auth",
    "sensitive-authz",
    "session-cookie-flags",
    "stripe-user-controlled-price",
    "stripe-user-controlled-redirect",
    "tenant-scope-missing",
    "upload-key-scope",
    "upload-validation",
    "user-controlled-fetch",
    "unsafe-html",
    "webhook-idempotency",
];

const MEDIUM_CODE_SLUGS: &[&str] = &[
    "ai-cache-dedupe",
    "ai-observability",
    "ai-retry-bounds",
    "console-log-error-handling",
    "critical-path-no-test",
    "db-in-route",
    "external-call-retry",
    "jsx-inline-style-density",
    "n-plus-one-query",
    "public-endpoint-rate-limit",
    "stripe-checkout-idempotency",
    "typescript-any-abuse",
    "weak-default-credential",
];

const LOW_CODE_SLUGS: &[&str] = &["ai-conversation-artifacts"];

fn legacy_code_policy_severity(issue: &CodeIssue) -> Option<Severity> {
    let id = issue.id.as_str();
    Some(match id {
        id if code_id_matches_any(id, CRITICAL_CODE_SLUGS) => Severity::Critical,
        id if code_id_matches_any(id, HIGH_CODE_SLUGS) => Severity::High,
        id if code_id_matches_any(id, MEDIUM_CODE_SLUGS) => Severity::Medium,
        id if code_id_matches_any(id, LOW_CODE_SLUGS) => Severity::Low,
        id if code_id_matches(id, "ai-kill-switch-missing") => Severity::High,
        id if code_id_matches(id, "build-script-missing") => Severity::High,
        id if code_id_matches(id, "ci-quality-gate-missing") => Severity::High,
        id if code_id_matches(id, "ci-workflow-missing") => Severity::High,
        id if code_id_matches(id, "env-example-incomplete") => issue.severity,
        id if code_id_matches(id, "env-drift") => issue.severity,
        id if code_id_matches(id, "gitignore-missing") => Severity::High,
        id if code_id_matches(id, "gitignore-missing-env") => Severity::High,
        id if code_id_matches(id, "local-db-target-remote") => Severity::High,
        id if code_id_matches(id, "lockfile-mismatch") => Severity::High,
        id if code_id_matches(id, "registry-host-mismatch") => issue.severity,
        id if code_id_matches(id, "supabase-policy-operation-missing") => issue.severity,
        id if code_id_matches(id, "supabase-rls-missing") => Severity::High,
        id if code_id_matches(id, "undeclared-package") => Severity::High,

        id if code_id_matches(id, "ai-observability-integration-missing") => Severity::Medium,
        id if code_id_matches(id, "backup-restore-plan-missing") => Severity::Medium,
        id if code_id_matches(id, "ci-only-builds") => Severity::Medium,
        id if code_id_matches(id, "db-scattered-across-routes") => issue.severity,
        id if code_id_matches(id, "db-index-hints-missing") => Severity::Medium,
        id if code_id_matches(id, "deploy-rollback-plan-missing") => Severity::Medium,
        id if code_id_matches(id, "direct-url-dependency") => Severity::Medium,
        id if code_id_matches(id, "empty-catch-blocks") => Severity::Medium,
        id if code_id_matches(id, "env-example-missing") => Severity::Medium,
        id if code_id_matches(id, "error-boundary-missing") => Severity::Medium,
        id if code_id_matches(id, "error-reporting-missing") => Severity::Medium,
        id if code_id_matches(id, "god-module") => issue.severity,
        id if code_id_matches(id, "god-route") => issue.severity,
        id if code_id_matches(id, "healthcheck-missing") => Severity::Medium,
        id if code_id_matches(id, "job-visibility-missing") => Severity::Medium,
        id if code_id_matches(id, "linter-missing") => Severity::Medium,
        id if code_id_matches(id, "lockfile-missing") => Severity::Medium,
        id if code_id_matches(id, "migration-workflow-missing") => Severity::Medium,
        id if code_id_matches(id, "no-automated-tests") => Severity::Medium,
        id if code_id_matches(id, "oversized-module") => issue.severity,
        id if code_id_matches(id, "placeholder-density") => issue.severity,
        id if code_id_matches(id, "pre-commit-hooks-missing") => Severity::Medium,
        id if code_id_matches(id, "pre-commit-hooks-weak") => Severity::Medium,
        id if code_id_matches(id, "recovery-runbook-missing") => Severity::Medium,
        id if code_id_matches(id, "schema-join-nullable-relations") => Severity::Medium,
        id if code_id_matches(id, "structured-logging-missing") => Severity::Medium,

        id if code_id_matches(id, "duplicate-utility-deps") => Severity::Low,
        id if code_id_matches(id, "unused-dependency") => Severity::Low,

        id if id.starts_with("config-secret:") => Severity::Critical,
        id if id.starts_with("suspicious-manifest-package:") => Severity::Critical,
        id if id.starts_with("suspicious-package:") => Severity::Critical,
        id if id.starts_with("local-drizzle-")
            || id.starts_with("local-postgres-")
            || id.starts_with("local-prisma-")
            || id.starts_with("local-sqlite-") =>
        {
            issue.severity
        }

        _ => return None,
    })
}

fn legacy_code_issue_allows_critical(issue_id: &str) -> bool {
    code_id_matches_any(issue_id, CRITICAL_CODE_SLUGS)
        || code_id_matches(issue_id, "config-secret")
        || code_id_matches(issue_id, "registry-host-mismatch")
        || code_id_matches(issue_id, "suspicious-manifest-package")
        || code_id_matches(issue_id, "suspicious-package")
}

// The normalized severity the pre-refactor policy would have produced.
fn legacy_normalized_severity(issue: &CodeIssue) -> Severity {
    let severity = legacy_code_policy_severity(issue).unwrap_or(issue.severity);
    if severity == Severity::Critical && !legacy_code_issue_allows_critical(&issue.id) {
        Severity::High
    } else {
        severity
    }
}

const DATABASE_ID_PREFIXES: &[&str] = &[
    "local-db-target-remote",
    "local-sqlite-",
    "local-postgres-",
    "local-prisma-",
    "local-drizzle-",
    "supabase-",
    "schema-join-",
    "schema-relation-",
    "db-index-hints-",
    "db-scattered-across-routes",
    "unsafe-raw-sql",
    "interpolated-sql",
    "formatted-sql",
];

fn legacy_code_issue_domain(issue: &CodeIssue) -> CodeScanDomain {
    if issue.category == "ai-scaffolding" {
        return CodeScanDomain::AiScaffolding;
    }
    if issue.category == "ai-safety" || issue.id.starts_with("ai-") {
        return CodeScanDomain::AiSafety;
    }
    if issue.category == "data"
        || DATABASE_ID_PREFIXES
            .iter()
            .any(|prefix| issue.id.starts_with(prefix))
    {
        return CodeScanDomain::Database;
    }
    if issue.category == "security" {
        return CodeScanDomain::Security;
    }
    if issue.category == "supply-chain" {
        return CodeScanDomain::SupplyChain;
    }
    if issue.category == "operations" {
        return CodeScanDomain::Operations;
    }
    CodeScanDomain::Architecture
}

const INTENTIONAL_DOMAIN_FIXES: &[&str] = &[
    // AiSafety -> Architecture: leftover AI conversation artifacts in code are a
    // code-hygiene smell, not an AI runtime risk; the "ai-" id-prefix over-captured.
    "ai-conversation-artifacts",
    "db-scattered-across-routes",
];

const INTENTIONAL_SEVERITY_PASSTHROUGH_FIXES: &[&str] = &[
    // Hygiene findings graduate on whether any other automated gate exists.
    "no-automated-tests",
    "pre-commit-hooks-missing",
    "pre-commit-hooks-weak",
    "public-endpoint-rate-limit",
    "upload-validation",
    "upload-key-scope",
    "session-cookie-flags",
    "oauth-callback-pkce",
    "one-time-token-no-single-use",
    "empty-catch-blocks",
    "ai-rate-limit",
    "ai-loop-risk",
    // Output-limit matches grade High; sampling-only controls grade Medium.
    "ai-user-controlled-settings",
    // Raw request input is Critical; shell-escaped/quoted input is a scoped
    // Medium argument-policy review.
    "php-dynamic-command",
    "python-command-injection",
];

// New Critical-capable checks that have no legacy policy entry.
const POST_AUDIT_CRITICAL_CHECKS: &[&str] = &[];

// Intentional `(slug, severity, allows_critical)` policy overrides.
const INTENTIONAL_PIN_CHANGES: &[(&str, Severity, bool)] = &[
    ("webhook-signature", Severity::High, false),
    ("localstorage-auth-token", Severity::Medium, false),
    ("weak-default-credential", Severity::High, false),
    ("ci-workflow-missing", Severity::Medium, false),
    ("ci-quality-gate-missing", Severity::Medium, false),
    ("build-script-missing", Severity::Medium, false),
    ("gitignore-missing", Severity::Medium, false),
    ("gitignore-missing-env", Severity::Medium, false),
    ("local-db-target-remote", Severity::Medium, false),
    ("tests-not-enforced", Severity::Medium, false),
    ("undeclared-package", Severity::Medium, false),
    ("lockfile-mismatch", Severity::Medium, false),
    ("cors-credentials-wildcard", Severity::Medium, false),
    ("client-ai-sdk", Severity::High, false),
    ("client-db-access", Severity::High, false),
    ("suspicious-package", Severity::Medium, false),
    ("suspicious-manifest-package", Severity::High, false),
    ("supabase-policy-set-empty", Severity::Medium, false),
    ("supabase-policy-operation-missing", Severity::Medium, false),
    ("supabase-rls-missing", Severity::Medium, false),
    ("shell-injection", Severity::High, false),
    ("client-env-secret", Severity::High, false),
    ("eval-exec-injection", Severity::High, false),
    ("plaintext-password", Severity::High, false),
    ("hardcoded-localhost-url", Severity::Medium, false),
    ("hardcoded-secret", Severity::High, false),
    ("config-secret", Severity::High, false),
    ("npmrc-committed-token", Severity::High, false),
    ("supabase-service-role-client", Severity::High, false),
    ("registry-host-mismatch", Severity::High, false),
    ("ai-kill-switch-missing", Severity::Medium, false),
    ("ai-output-cap", Severity::Medium, false),
    ("ai-cache-dedupe", Severity::Low, false),
    ("jsx-inline-style-density", Severity::Low, false),
    ("cors-origin-reflection", Severity::High, false),
    ("external-call-retry", Severity::Low, false),
    ("ai-retry-bounds", Severity::Low, false),
    ("no-pagination", Severity::Medium, false),
];

fn intentional_pin_change(slug: &str) -> Option<&'static (&'static str, Severity, bool)> {
    INTENTIONAL_PIN_CHANGES
        .iter()
        .find(|(changed, _, _)| *changed == slug)
}

fn representative_issue(slug: &str, category: &str, severity: Severity) -> CodeIssue {
    CodeIssue {
        id: format!("{slug}:app/x.ts"),
        check_id: String::new(),
        category: category.to_string(),
        severity,
        title: String::new(),
        description: String::new(),
        relative_path: "app/x.ts".to_string(),
        absolute_path: "/tmp/app/x.ts".to_string(),
        line: Some(1),
        source_excerpt: None,
        evidence: None,
        why_now: None,
        likely_fix: None,
        confidence: IssueConfidence::High,
        confidence_reason: None,
        verify_hint: None,
    }
}

#[test]
fn registry_severity_matches_legacy_policy_for_every_slug() {
    // Compare every registry descriptor against the legacy policy mapping.
    for check in CODE_CHECKS {
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            let issue = representative_issue(check.slug, check.category, severity);
            if POST_AUDIT_CRITICAL_CHECKS.contains(&check.slug) {
                assert!(
                    check.policy_severity.is_none(),
                    "{} is a post-audit check but pins a policy severity",
                    check.slug,
                );
                assert!(
                    check.allows_critical,
                    "{} is on POST_AUDIT_CRITICAL_CHECKS but does not allow Critical \
                     (a non-Critical new check needs no allowlisting at all)",
                    check.slug,
                );
                assert_eq!(
                    policy_clamped_code_severity(&issue),
                    severity,
                    "post-audit Critical-capable slug {} must keep its emitted severity",
                    check.slug,
                );
                continue;
            }
            if let Some((_, new_pin, allows_critical)) = intentional_pin_change(check.slug) {
                assert_eq!(
                    check.policy_severity,
                    Some(*new_pin),
                    "{} is on INTENTIONAL_PIN_CHANGES but the registry pin disagrees",
                    check.slug,
                );
                assert_eq!(
                    check.allows_critical, *allows_critical,
                    "{} allows_critical disagrees with INTENTIONAL_PIN_CHANGES",
                    check.slug,
                );
                assert_eq!(
                    policy_clamped_code_severity(&issue),
                    *new_pin,
                    "pin-changed slug {} must normalize to its new pin",
                    check.slug,
                );
                continue;
            }
            if INTENTIONAL_SEVERITY_PASSTHROUGH_FIXES.contains(&check.slug) {
                assert!(
                    check.policy_severity.is_none(),
                    "{} is on the passthrough allowlist but still pins a policy severity",
                    check.slug,
                );
                let expected = if severity == Severity::Critical && !check.allows_critical {
                    Severity::High
                } else {
                    severity
                };
                assert_eq!(
                    policy_clamped_code_severity(&issue),
                    expected,
                    "passthrough slug {} must keep its emitted severity",
                    check.slug,
                );
            } else {
                assert_eq!(
                    policy_clamped_code_severity(&issue),
                    legacy_normalized_severity(&issue),
                    "normalized severity diverged for {} at emitted {:?} (add to \
                     INTENTIONAL_SEVERITY_PASSTHROUGH_FIXES if deliberate)",
                    check.slug,
                    severity,
                );
            }
        }
        if !POST_AUDIT_CRITICAL_CHECKS.contains(&check.slug)
            && intentional_pin_change(check.slug).is_none()
        {
            assert_eq!(
                check.allows_critical,
                legacy_code_issue_allows_critical(&format!("{}:app/x.ts", check.slug)),
                "allows_critical diverged for {}",
                check.slug,
            );
        }
    }
}

#[test]
fn every_rule_is_classified_risk_or_advisory() {
    let mut advisory = 0usize;
    let mut risk = 0usize;
    for check in CODE_CHECKS {
        match check.class {
            RuleClass::Advisory => advisory += 1,
            RuleClass::Risk => risk += 1,
        }
    }
    assert_eq!(advisory + risk, CODE_CHECKS.len());
    assert_eq!(CODE_CHECKS.len(), 170);
    assert_eq!((advisory, risk), (109, 61), "advisory/risk split drifted");
}

#[test]
fn advisory_rules_never_normalize_above_medium() {
    for check in CODE_CHECKS {
        if check.class != RuleClass::Advisory {
            continue;
        }
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            let issue = representative_issue(check.slug, check.category, severity);
            let normalized = normalized_code_issue_severity(&issue);
            assert!(
                normalized.sort_rank() >= Severity::Medium.sort_rank(),
                "advisory rule {} emitted {:?} normalized to {:?}, above Medium",
                check.slug,
                severity,
                normalized,
            );
        }
    }
}

#[test]
fn risk_rules_keep_their_policy_severity_uncapped() {
    for check in CODE_CHECKS {
        if check.class != RuleClass::Risk {
            continue;
        }
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            let issue = representative_issue(check.slug, check.category, severity);
            assert_eq!(
                normalized_code_issue_severity(&issue),
                policy_clamped_code_severity(&issue),
                "risk rule {} must not be capped (emitted {:?})",
                check.slug,
                severity,
            );
        }
    }
}

#[test]
fn exploitable_cap_candidates_are_registered_and_critical_capable() {
    for slug in crate::core::code_scan::SCORE_CAP_CANDIDATE_CODE_RULES {
        let descriptor = super::descriptor(slug)
            .unwrap_or_else(|| panic!("exploitable rule {slug} is not a registered check"));
        assert!(
            descriptor.allows_critical,
            "{slug} is cap-listed but its Critical would be clamped to High"
        );
        assert!(
            matches!(descriptor.policy_severity, None | Some(Severity::Critical)),
            "{slug} is cap-listed but the policy pins it below Critical"
        );
    }
}

#[test]
fn registry_domain_matches_legacy_except_intentional_fixes() {
    for check in CODE_CHECKS {
        let issue = representative_issue(check.slug, check.category, Severity::High);
        let registry_domain = code_issue_domain(&issue);
        let legacy_domain = legacy_code_issue_domain(&issue);
        if INTENTIONAL_DOMAIN_FIXES.contains(&check.slug) {
            assert_ne!(
                registry_domain, legacy_domain,
                "{} is on the intentional-fix allowlist but its domain did not change",
                check.slug,
            );
        } else {
            assert_eq!(
                registry_domain, legacy_domain,
                "unexpected domain change for {} (add to INTENTIONAL_DOMAIN_FIXES if deliberate)",
                check.slug,
            );
        }
    }
}

#[test]
fn registry_check_ids_round_trip_and_have_no_boundary_collisions() {
    for check in CODE_CHECKS {
        let check_id = canonical_code_check_id(&format!("{}:some/path.ts", check.slug));
        assert!(!check_id.contains(':'), "canonical id retained a location");
        assert_eq!(
            code_rule_id(&check_id),
            Some(check.slug),
            "check_id did not round-trip to slug for {}",
            check.slug,
        );
    }

    for a in CODE_CHECKS {
        for b in CODE_CHECKS {
            if a.slug == b.slug {
                continue;
            }
            let b_id = format!("{}:app/x.ts", b.slug);
            assert!(
                !code_id_matches(&b_id, a.slug),
                "slug `{}` collides with `{}` under `:`-boundary matching",
                a.slug,
                b.slug,
            );
        }
    }
}

#[test]
fn registry_slugs_are_unique() {
    let mut seen = HashSet::new();
    for check in CODE_CHECKS {
        assert!(
            seen.insert(check.slug),
            "duplicate descriptor slug: {}",
            check.slug,
        );
    }
    assert_eq!(seen.len(), super::code_check_count());
}

#[test]
fn descriptor_lookup_resolves_slug_from_full_id() {
    let descriptor =
        descriptor_for_issue_id("local-postgres-prisma-migration-drift:.env.local").unwrap();
    assert_eq!(descriptor.slug, "local-postgres-prisma-migration-drift");
    assert_eq!(descriptor.domain, CodeScanDomain::Database);
    assert!(descriptor_for_issue_id("not-a-real-slug:x").is_none());
}

#[test]
fn honest_check_count_totals_by_domain() {
    use super::code_check_count_for_domain;
    // The honest per-domain breakdown; the sum is the total check count.
    let per_domain = [
        (CodeScanDomain::Security, 47),
        (CodeScanDomain::Database, 40),
        (CodeScanDomain::Operations, 28),
        (CodeScanDomain::Architecture, 16),
        (CodeScanDomain::AiSafety, 15),
        (CodeScanDomain::SupplyChain, 20),
        (CodeScanDomain::AiScaffolding, 4),
    ];
    let mut total = 0;
    for (domain, expected) in per_domain {
        assert_eq!(
            code_check_count_for_domain(domain),
            expected,
            "unexpected check count for {domain:?}",
        );
        total += expected;
    }
    assert_eq!(total, super::code_check_count());
    assert_eq!(super::code_check_count(), 170);
}

// Every `.rs` file under `core/code_scan` except test code.
fn production_source_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read code_scan source dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if path.is_dir() {
            if name == "tests" {
                continue;
            }
            production_source_files(&path, out);
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

// Return check slugs emitted through supported production ID constructors.
fn emitted_slugs_in(content: &str) -> Vec<String> {
    let build_issue = regex::Regex::new(r#"build_issue\(\s*"([a-z][a-z0-9-]*)""#).unwrap();
    // One emit site picks its slug conditionally:
    // `build_issue(if uses_llm { "a" } else { "b" },...)`.
    let conditional_build_issue = regex::Regex::new(
        r#"build_issue\(\s*if\s[^,]*?\{\s*"([a-z][a-z0-9-]*)"\s*\}\s*else\s*\{\s*"([a-z][a-z0-9-]*)"\s*\}"#,
    )
    .unwrap();
    // Inline ids appear as struct fields (`id: format!("slug:...`) and as
    // locals (`let id = format!("slug:...`).
    let inline_id =
        regex::Regex::new(r#"\bid(?::|\s*=)\s*format!\(\s*"([a-z][a-z0-9-]*):"#).unwrap();
    let templated_id =
        regex::Regex::new(r#"\bid(?::|\s*=)\s*format!\(\s*"local-\{\}(-?[a-z][a-z0-9-]*):"#)
            .unwrap();

    let mut slugs = Vec::new();
    for cap in build_issue.captures_iter(content) {
        slugs.push(cap[1].to_string());
    }
    for cap in conditional_build_issue.captures_iter(content) {
        slugs.push(cap[1].to_string());
        slugs.push(cap[2].to_string());
    }
    for cap in inline_id.captures_iter(content) {
        slugs.push(cap[1].to_string());
    }
    for cap in templated_id.captures_iter(content) {
        let suffix = &cap[1];
        if let Some(stripped) = suffix.strip_prefix('-') {
            // `local-{}-x` fills in `EngineText::slug` ("sqlite" / "postgres").
            slugs.push(format!("local-sqlite-{stripped}"));
            slugs.push(format!("local-postgres-{stripped}"));
        } else {
            // `local-{}x` fills in `migration_slug` ("" / "postgres-").
            slugs.push(format!("local-{suffix}"));
            slugs.push(format!("local-postgres-{suffix}"));
        }
    }
    slugs
}

fn phase_for_source_path(relative: &str) -> CodeScanPhase {
    if relative.starts_with("file_analysis") {
        CodeScanPhase::AnalyzeFile
    } else if relative.starts_with("supply_chain") {
        CodeScanPhase::SupplyChain
    } else if relative.starts_with("operations") || relative.starts_with("database_analysis") {
        CodeScanPhase::Operations
    } else if relative.starts_with("ai_scaffolding") {
        CodeScanPhase::AiScaffolding
    } else {
        panic!(
            "emit site in unmapped module {relative}: add it to phase_for_source_path \
             and register its checks under the right phase"
        );
    }
}

// slug -> every code_scan-relative source path that emits it.
fn emitted_slug_map() -> std::collections::HashMap<String, Vec<String>> {
    let root = std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("src/core/code_scan");
    let mut files = Vec::new();
    production_source_files(&root, &mut files);
    let mut emitted: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for path in files {
        let content = std::fs::read_to_string(&path).expect("read production source");
        let relative = path
            .strip_prefix(&root)
            .expect("source under code_scan root")
            .to_string_lossy()
            .to_string();
        for slug in emitted_slugs_in(&content) {
            emitted.entry(slug).or_default().push(relative.clone());
        }
    }
    emitted
}

#[test]
fn every_emitted_slug_is_registered_and_every_registered_slug_is_emitted() {
    let emitted = emitted_slug_map();
    assert!(
        emitted.len() > 100,
        "emit-site extraction collapsed ({} slugs found) - the id shapes in \
         the production tree changed; update emitted_slugs_in",
        emitted.len()
    );

    for (slug, files) in &emitted {
        assert!(
            super::descriptor(slug).is_some(),
            "emit site(s) {files:?} use unregistered slug {slug:?}: register it in \
             registry.rs or fix the typo (unknown slugs clamp Critical to High and \
             misclassify domain)"
        );
    }

    let emitted_names: HashSet<&str> = emitted.keys().map(String::as_str).collect();
    for check in CODE_CHECKS {
        assert!(
            emitted_names.contains(check.slug),
            "registered check {:?} has no emit site: dead registry entry or a \
             renamed emit slug",
            check.slug
        );
    }
}

#[test]
fn registry_phase_matches_emitting_module_for_every_slug() {
    let emitted = emitted_slug_map();
    for check in CODE_CHECKS {
        let files = emitted
            .get(check.slug)
            .unwrap_or_else(|| panic!("no emit site for {}", check.slug));
        for file in files {
            assert_eq!(
                phase_for_source_path(file),
                check.phase,
                "{} is registered under {:?} but emitted from {file}",
                check.slug,
                check.phase
            );
        }
    }
}

#[test]
fn confidence_policy_arms_reference_registered_slugs() {
    let content = std::fs::read_to_string(
        std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("src/core/confidence_policy.rs"),
    )
    .expect("read confidence_policy.rs");
    let start = content
        .find("fn code_issue_confidence")
        .expect("code_issue_confidence exists");
    let end = content[start..]
        .find("\npub fn ")
        .map(|offset| start + offset)
        .unwrap_or(content.len());
    let slug_literal = regex::Regex::new(r#""([a-z][a-z0-9-]*)""#).unwrap();
    let mut checked = 0;
    for cap in slug_literal.captures_iter(&content[start..end]) {
        let slug = &cap[1];
        assert!(
            super::descriptor(slug).is_some(),
            "confidence_policy::code_issue_confidence grades unknown slug {slug:?}: \
             fix the arm or register the check"
        );
        checked += 1;
    }
    assert!(
        checked >= 15,
        "confidence-policy slug extraction collapsed ({checked} literals found); \
         update the extraction in this test"
    );
}

#[test]
fn inline_code_issue_evidence_is_none_or_redacted() {
    let root = std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("src/core/code_scan");
    let mut files = Vec::new();
    production_source_files(&root, &mut files);

    let mut checked = 0usize;
    let mut violations = Vec::new();
    for path in &files {
        let content = std::fs::read_to_string(path).expect("read production source");
        let relative = path
            .strip_prefix(&root)
            .expect("source under code_scan root")
            .to_string_lossy()
            .to_string();
        // Inline `#[cfg(test)]` modules build fixture issues by hand; only
        // the production half of the file is subject to the invariant.
        let production_half = content
            .find("#[cfg(test)]")
            .map(|cut| &content[..cut])
            .unwrap_or(&content);
        let lines: Vec<&str> = production_half.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index].trim_start();
            let is_literal_open = line.contains("CodeIssue {")
                && !line.contains("struct CodeIssue")
                && !line.starts_with("//");
            if !is_literal_open {
                index += 1;
                continue;
            }
            let mut cursor = index;
            loop {
                cursor += 1;
                assert!(
                    cursor < lines.len(),
                    "{relative}:{}: CodeIssue literal with no evidence field; \
                     update the extraction in this test",
                    index + 1
                );
                let field = lines[cursor].trim_start();
                if !field.starts_with("evidence:") {
                    continue;
                }
                checked += 1;
                let allowed = field.starts_with("evidence: None")
                    || field.starts_with("evidence: Some(redact_evidence(")
                    // build_issue itself is the other chokepoint.
                    || field.contains("redact_sensitive_excerpt_line");
                if !allowed {
                    violations.push(format!("{relative}:{}: {field}", cursor + 1));
                }
                break;
            }
            index = cursor + 1;
        }
    }

    assert!(
        checked >= 50,
        "CodeIssue literal extraction collapsed: only {checked} evidence fields found; \
         update the extraction in this test"
    );
    assert!(
        violations.is_empty(),
        "inline CodeIssue evidence must be `None` or `Some(redact_evidence(..))` \
         so secret-like values never reach scan reports unmasked:\n{}",
        violations.join("\n")
    );
}

// Collect behavioral test sources while excluding this file's severity tables.
fn test_source_corpus() -> String {
    fn walk(dir: &std::path::Path, in_tests: bool, out: &mut String) {
        for entry in std::fs::read_dir(dir).expect("read code_scan source dir") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if path.is_dir() {
                walk(&path, in_tests || name == "tests", out);
                continue;
            }
            if !name.ends_with(".rs") || name == "registry_tests.rs" {
                continue;
            }
            let content = std::fs::read_to_string(&path).expect("read source file");
            let is_test_file = in_tests || name == "tests.rs" || name.ends_with("_tests.rs");
            if is_test_file {
                out.push_str(&content);
            } else if let Some(cut) = content.find("#[cfg(test)]") {
                out.push_str(&content[cut..]);
            }
        }
    }
    let root = std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("src/core/code_scan");
    let mut corpus = String::new();
    walk(&root, false, &mut corpus);
    corpus
}

#[test]
fn every_registered_slug_is_referenced_by_a_test() {
    let corpus = test_source_corpus();
    let mut untested = Vec::new();
    for descriptor in CODE_CHECKS {
        let slug = descriptor.slug;
        let referenced =
            corpus.contains(&format!("\"{slug}:")) || corpus.contains(&format!("\"{slug}\""));
        if !referenced {
            untested.push(slug);
        }
    }
    assert!(
        untested.is_empty(),
        "registered checks with no test reference (write a fixture test that \
         asserts the slug fires, or a drafting-layer test for live-DB checks): {untested:?}"
    );
}
