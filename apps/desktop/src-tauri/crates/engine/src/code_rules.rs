//! Code-scan rules and the policy each carries.
//!
//! The runtime's code scan emits these rules. The table lives in the engine
//! because the severity policy reads it, and the policy runs wherever the
//! engine does: the CLI, the hosted runner's artifact and Connect.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::vocab::Severity;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export_to = "ipc-bindings.ts"))]
#[serde(rename_all = "kebab-case")]
pub enum CodeScanDomain {
    Database,
    AiSafety,
    Security,
    Architecture,
    Operations,
    SupplyChain,
    AiScaffolding,
}

impl CodeScanDomain {
    /// Stable wire and display value. Must remain log-free because `Display`
    /// can run while the logger holds a non-reentrant writer lock.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::AiSafety => "ai-safety",
            Self::Security => "security",
            Self::Architecture => "architecture",
            Self::Operations => "operations",
            Self::SupplyChain => "supply-chain",
            Self::AiScaffolding => "ai-scaffolding",
        }
    }
}

impl std::fmt::Display for CodeScanDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CodeScanDomain {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "database" => Ok(Self::Database),
            "ai-safety" => Ok(Self::AiSafety),
            "security" => Ok(Self::Security),
            "architecture" => Ok(Self::Architecture),
            "operations" => Ok(Self::Operations),
            "supply-chain" => Ok(Self::SupplyChain),
            "ai-scaffolding" => Ok(Self::AiScaffolding),
            _ => Err(format!("Unknown code scan domain: {}", value)),
        }
    }
}

/// The four analyze passes in `src/core/code_scan/mod.rs` (1:1 with the `analyze_*` calls). Each
/// descriptor records the pass that emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeScanPhase {
    /// `file_analysis::analyze_file` (php/python sinks, route + service
    /// security, architecture, AI checks).
    AnalyzeFile,
    /// `supply_chain::analyze_supply_chain` (dependencies, lockfiles,
    /// registries, workflow pinning, release age).
    SupplyChain,
    /// `operations::analyze_operations` (env, readiness, hygiene, runtime EOL,
    /// Supabase policies, schema integrity, local databases).
    Operations,
    /// `ai_scaffolding::analyze_ai_scaffolding` (agent instruction files).
    AiScaffolding,
}

/// Distinguishes exposure risks from recommendations capped at Medium severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleClass {
    Risk,
    Advisory,
}

/// Code-scan registry entry. `domain` is authoritative, `policy_severity`
/// optionally overrides emitted severity, and advisory classes cap at Medium.
#[derive(Debug)]
pub struct CodeCheckDescriptor {
    pub slug: &'static str,
    /// The `category` field the emit site stamps on the `CodeIssue`. Retained so
    /// the domain differential test can reconstruct the legacy heuristic verdict.
    pub category: &'static str,
    pub domain: CodeScanDomain,
    pub phase: CodeScanPhase,
    /// `Some(sev)` = severity policy forces this severity; `None` = pass the
    /// emitted severity through unchanged.
    pub policy_severity: Option<Severity>,
    /// Whether an emitted `Critical` survives normalization (otherwise it is
    /// clamped to `High`).
    pub allows_critical: bool,
    /// Risk vs advisory. Advisory rules are capped at Medium centrally.
    pub class: RuleClass,
}

const fn d(
    slug: &'static str,
    category: &'static str,
    domain: CodeScanDomain,
    phase: CodeScanPhase,
    policy_severity: Option<Severity>,
    allows_critical: bool,
    class: RuleClass,
) -> CodeCheckDescriptor {
    CodeCheckDescriptor {
        slug,
        category,
        domain,
        phase,
        policy_severity,
        allows_critical,
        class,
    }
}

use CodeScanDomain as Dom;
use CodeScanPhase as Ph;
use RuleClass as Cls;
use Severity as Sev;

// `d(slug, category, domain, phase, policy_severity, allows_critical, class)`.
// rustfmt::skip keeps one descriptor per line; widths intentionally exceed 100.
#[rustfmt::skip]
pub const CODE_CHECKS: &[CodeCheckDescriptor] = &[
    d("ai-timeout", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("client-ai-sdk", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("jsx-inline-style-density", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Low), false, Cls::Advisory),
    d("ai-rate-limit", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("ai-concurrency", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("ai-spend-guardrails", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("ai-observability", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("ai-user-controlled-model", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("ai-output-cap", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("ai-user-controlled-settings", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("ai-cache-dedupe", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::Low), false, Cls::Advisory),
    d("ai-loop-risk", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("god-route", "architecture", Dom::Architecture, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("god-module", "architecture", Dom::Architecture, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("oversized-module", "architecture", Dom::Architecture, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("hardcoded-secret", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    // A shipped default or weak credential is an exposure, not a style finding.
    d("weak-default-credential", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("empty-catch-blocks", "architecture", Dom::Architecture, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("console-log-error-handling", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    // ai-conversation-artifacts: code-hygiene (leftover AI chat artifacts), NOT AI runtime -> Architecture.
    d("ai-conversation-artifacts", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Low), false, Cls::Advisory),
    // A loopback literal is factual, but whether it is a deployment mistake
    // depends on topology (same-container sidecars and local-only paths exist).
    d("hardcoded-localhost-url", "operations", Dom::Operations, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("client-env-secret", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("typescript-any-abuse", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("eval-exec-injection", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    // File-level request parsing plus process execution is a useful
    // signal, but unlike js-command-injection it does not prove a data flow.
    d("shell-injection", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    // Tokens in localStorage are the standard SPA pattern; grades with the
    // cookie-flag advisories, not the exposure tier.
    d("localstorage-auth-token", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("no-pagination", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("plaintext-password", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("n-plus-one-query", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    // Graduated: High when TypeScript build errors are
    // ignored, Medium when only ESLint is skipped.
    d("nextconfig-errors-ignored", "operations", Dom::Operations, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("js-command-injection", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("php-file-inclusion", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("php-object-injection", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("php-dynamic-command", "security", Dom::Security, Ph::AnalyzeFile, None, true, Cls::Risk),
    d("php-code-execution", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("php-path-traversal", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("python-command-injection", "security", Dom::Security, Ph::AnalyzeFile, None, true, Cls::Risk),
    d("python-unsafe-deserialization", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("python-code-execution", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    // python-sql-injection is emitted with category "data"; SQL findings live in the Database domain.
    d("python-sql-injection", "data", Dom::Database, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("python-template-injection", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Critical), true, Cls::Risk),
    d("python-open-redirect", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("python-path-traversal", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    // One emit site: request-validation vs ai-request-validation, gated on uses_llm.
    d("ai-request-validation", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("request-validation", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Advisory),
    // Passthrough: these collectors grade severity per finding (public-risk
    // escalation, missing-guard count, missing-flag mix), so the emitted
    // severity is authoritative. Pinning them here silently reverted the
    // escalation/downgrade branches.
    d("public-endpoint-rate-limit", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("upload-validation", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Risk),
    d("upload-key-scope", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Risk),
    d("jwt-decode-without-verify", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("oauth-callback-state", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("oauth-callback-pkce", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Risk),
    d("one-time-token-raw-lookup", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("one-time-token-no-expiry", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("one-time-token-no-single-use", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Risk),
    // Passthrough: the collector downgrades to Medium when only sameSite is
    // missing (httpOnly + secure present); see src/core/code_scan/file_analysis/route_security.rs.
    d("session-cookie-flags", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Advisory),
    d("tenant-scope-missing", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("open-redirect", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("cors-credentials-wildcard", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Risk),
    d("cors-origin-reflection", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("tls-verification-disabled", "security", Dom::Security, Ph::AnalyzeFile, None, false, Cls::Risk),
    // Unverified webhooks grade as unauthenticated state changes.
    d("webhook-signature", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("webhook-idempotency", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("stripe-user-controlled-price", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("stripe-user-controlled-redirect", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("stripe-checkout-idempotency", "operations", Dom::Operations, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("sensitive-auth", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("sensitive-authz", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("csrf-missing", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    // client-db-access / multi-write-no-transaction / raw-sql-unsafe: category "data" -> Database domain.
    d("client-db-access", "data", Dom::Database, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("db-in-route", "architecture", Dom::Architecture, Ph::AnalyzeFile, Some(Sev::Medium), false, Cls::Advisory),
    d("multi-write-no-transaction", "data", Dom::Database, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("raw-sql-unsafe", "data", Dom::Database, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("user-controlled-fetch", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("unsafe-html", "security", Dom::Security, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Risk),
    d("external-call-timeout", "operations", Dom::Operations, Ph::AnalyzeFile, Some(Sev::High), false, Cls::Advisory),
    d("external-call-retry", "operations", Dom::Operations, Ph::AnalyzeFile, Some(Sev::Low), false, Cls::Advisory),
    d("ai-retry-bounds", "ai-safety", Dom::AiSafety, Ph::AnalyzeFile, Some(Sev::Low), false, Cls::Advisory),

    d("undeclared-package", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Medium), false, Cls::Advisory),
    d("suspicious-package", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Medium), false, Cls::Risk),
    d("direct-url-dependency", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Medium), false, Cls::Risk),
    d("lockfile-missing", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Medium), false, Cls::Advisory),
    d("suspicious-manifest-package", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::High), false, Cls::Risk),
    d("lockfile-mismatch", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Medium), false, Cls::Advisory),
    d("registry-host-mismatch", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::High), false, Cls::Risk),
    d("unused-dependency", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Low), false, Cls::Advisory),
    d("config-secret", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::High), false, Cls::Risk),
    d("duplicate-utility-deps", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::Low), false, Cls::Advisory),
    d("unpinned-github-action", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Risk),
    d("workflow-write-all-permissions", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Risk),
    d("workflow-script-injection", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Risk),
    d("workflow-pr-target-checkout", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Risk),
    d("npmrc-committed-token", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, Some(Sev::High), false, Cls::Risk),
    d("dockerfile-unpinned-base", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Advisory),
    d("remote-pipe-to-shell", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Risk),
    d("unbounded-dependency-range", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Advisory),
    d("lockfile-integrity-weak", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Advisory),
    d("release-age-policy-missing", "supply-chain", Dom::SupplyChain, Ph::SupplyChain, None, false, Cls::Advisory),

    d("env-example-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("env-example-incomplete", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    d("env-drift", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    // Database-targeting configuration remains in the Database domain.
    d("local-db-target-remote", "operations", Dom::Database, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("healthcheck-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("error-reporting-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("deploy-rollback-plan-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("structured-logging-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("ai-observability-integration-missing", "ai-safety", Dom::AiSafety, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("client-auth-without-server-enforcement", "security", Dom::Security, Ph::Operations, Some(Sev::High), false, Cls::Risk),
    d("error-boundary-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    // AI runtime controls remain in the AiSafety domain.
    d("ai-kill-switch-missing", "operations", Dom::AiSafety, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("job-visibility-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    // db-scattered-across-routes: a code-layering smell (no data layer), twin of db-in-route -> Architecture.
    d("db-scattered-across-routes", "architecture", Dom::Architecture, Ph::Operations, None, false, Cls::Advisory),
    d("migration-workflow-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("recovery-runbook-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("backup-restore-plan-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    // Graduated: Django DEBUG=True / WP_DEBUG / APP_DEBUG=true are High;
    // an ALLOWED_HOSTS wildcard alone is Medium.
    d("framework-debug-enabled", "security", Dom::Security, Ph::Operations, None, false, Cls::Risk),
    // Graduated: Medium when the project has routes or data access, Low for a
    // static site that can ship on build and lint gates alone.
    d("no-automated-tests", "architecture", Dom::Architecture, Ph::Operations, None, false, Cls::Advisory),
    // Process-hygiene gaps grade Medium alongside no-automated-tests. A missing
    // env ignore rule only reduces accidental staging; a separate detector
    // owns actual credential material.
    d("gitignore-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("gitignore-missing-env", "security", Dom::Security, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("linter-missing", "architecture", Dom::Architecture, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("ci-workflow-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("ci-quality-gate-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("build-script-missing", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("ci-only-builds", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("tests-not-enforced", "operations", Dom::Operations, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    // Hook findings graduate: Low when a CI quality gate is the enforcement
    // point, Medium when the hook would be the only automated gate.
    d("pre-commit-hooks-missing", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    d("pre-commit-hooks-weak", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    d("pre-commit-hooks-not-installed", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    d("placeholder-density", "architecture", Dom::Architecture, Ph::Operations, None, false, Cls::Advisory),
    d("critical-path-no-test", "architecture", Dom::Architecture, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("runtime-version-eol", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    d("tsconfig-strict-off", "operations", Dom::Operations, Ph::Operations, None, false, Cls::Advisory),
    d("supabase-rls-missing", "security", Dom::Database, Ph::Operations, Some(Sev::Medium), false, Cls::Risk),
    d("supabase-policy-set-empty", "data", Dom::Database, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("supabase-policy-operation-missing", "data", Dom::Database, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("supabase-open-policy", "security", Dom::Database, Ph::Operations, None, false, Cls::Risk),
    d("supabase-policy-not-auth-scoped", "security", Dom::Database, Ph::Operations, None, false, Cls::Risk),
    d("supabase-service-role-client", "security", Dom::Database, Ph::Operations, Some(Sev::High), false, Cls::Risk),
    d("db-index-hints-missing", "architecture", Dom::Database, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("schema-relation-missing-index", "data", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("schema-join-missing-composite-unique", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("schema-join-nullable-relations", "architecture", Dom::Database, Ph::Operations, Some(Sev::Medium), false, Cls::Advisory),
    d("schema-join-missing-delete-intent", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-prisma-migration-history-missing", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-prisma-migration-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-drizzle-migration-history-missing", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-drizzle-migration-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-unmigrated", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-schema-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-column-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-unindexed-lookups", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-missing-foreign-keys", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-missing-unique-constraints", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-missing-composite-unique", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-sqlite-nullable-relations", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-prisma-migration-history-missing", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-prisma-migration-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-drizzle-migration-history-missing", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-drizzle-migration-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-unmigrated", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-schema-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-column-drift", "operations", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-unindexed-lookups", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-missing-foreign-keys", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-missing-unique-constraints", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-missing-composite-unique", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),
    d("local-postgres-nullable-relations", "architecture", Dom::Database, Ph::Operations, None, false, Cls::Advisory),

    d("agent-instructions-stub", "ai-scaffolding", Dom::AiScaffolding, Ph::AiScaffolding, None, false, Cls::Advisory),
    d("agent-instructions-fragmented", "ai-scaffolding", Dom::AiScaffolding, Ph::AiScaffolding, None, false, Cls::Advisory),
    d("agent-instructions-secret", "ai-scaffolding", Dom::AiScaffolding, Ph::AiScaffolding, None, false, Cls::Risk),
    d("agent-instructions-legacy-format", "ai-scaffolding", Dom::AiScaffolding, Ph::AiScaffolding, None, false, Cls::Advisory),
];

static DESCRIPTOR_BY_SLUG: LazyLock<HashMap<&'static str, &'static CodeCheckDescriptor>> =
    LazyLock::new(|| {
        CODE_CHECKS
            .iter()
            .map(|check| (check.slug, check))
            .collect()
    });

/// The descriptor for an exact check slug, which precedes the first `:` in a
/// `CodeIssue.id`, if it is a known code-scan check.
pub fn descriptor(slug: &str) -> Option<&'static CodeCheckDescriptor> {
    DESCRIPTOR_BY_SLUG.get(slug).copied()
}

/// The descriptor for a full `CodeIssue.id` (`<slug>:<path...>`). The slug is
/// everything before the first `:`; slugs never contain a `:`, so this is exact.
pub fn descriptor_for_issue_id(issue_id: &str) -> Option<&'static CodeCheckDescriptor> {
    descriptor(issue_id.split(':').next().unwrap_or(issue_id))
}

#[cfg(test)]
#[path = "code_rules_tests.rs"]
mod tests;
