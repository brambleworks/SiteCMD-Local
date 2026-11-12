//! Confidence policy for code-scan findings.
//!
//! Unmapped heuristics default to `NeedsReview`; stronger levels require an
//! explicit policy entry.

use crate::checks::IssueConfidence;

/// Assign explicit confidence to known Code Scan rules.
/// Unmapped rules default to `NeedsReview`.
pub fn code_issue_confidence(slug: &str) -> (IssueConfidence, Option<&'static str>) {
    use IssueConfidence::{Confirmed, High, NeedsReview};
    match slug {
        "empty-catch-blocks" => (
            Confirmed,
            Some("The empty catch blocks and their count are directly observed in the scanned file; whether each ignored failure is intentional still depends on its fallback behavior."),
        ),
        "env-example-missing" | "env-example-incomplete" => (
            Confirmed,
            Some("The example-file absence or source-to-template key mismatch is directly observed in the scanned project; individual variables may still be optional or documented elsewhere."),
        ),
        "jsx-inline-style-density" => (
            Confirmed,
            Some("The repeated JSX style props are directly counted in the scanned file; whether they should remain dynamic or become a shared visual pattern is a design decision."),
        ),
        "placeholder-density" => (
            Confirmed,
            Some("The placeholder-style tokens and their density are directly counted in the scanned source; each marker still needs context to determine whether it represents unfinished work."),
        ),
        "god-route" | "god-module" | "oversized-module" => (
            High,
            Some("File size and multiple responsibility markers provide strong structural evidence, although generated regions, cohesion, and framework conventions can still make the current boundary reasonable."),
        ),
        "undeclared-package" => (
            NeedsReview,
            Some("An external-looking import remained unmatched after manifest, workspace, alias, type-package, and local-module filtering, but the scan resolves imports statically and cannot follow generated modules, custom resolvers, or a parent workspace above the scan root."),
        ),
        "unused-dependency" => (
            NeedsReview,
            Some("No import, package script, quoted configuration value, or lockfile peer requirement matched the dependency in the files the usage search read, which is a bounded sample of source, component, stylesheet, and tool-configuration files; packages loaded by name at runtime or by external tooling leave no static trace at all."),
        ),
        // Same-call request-accessor/sink matches are strong review leads, but
        // the regex scan cannot resolve validation wrappers, aliases, control
        // flow, runtime reachability, or deployed configuration.
        "php-file-inclusion"
        | "php-object-injection"
        | "php-dynamic-command"
        | "php-code-execution"
        | "php-path-traversal"
        | "python-command-injection"
        | "python-unsafe-deserialization"
        | "python-code-execution"
        | "python-sql-injection"
        | "python-template-injection"
        | "python-open-redirect"
        | "python-path-traversal"
        | "js-command-injection"
        => (
            NeedsReview,
            Some("A request accessor and dangerous sink occur in the same call window, but static matching does not prove unsanitized runtime flow or exploitability."),
        ),
        // Explicit-looking configuration patterns still require effective
        // config, framework version, environment, and comment/string review.
        "tls-verification-disabled"
        | "nextconfig-errors-ignored"
        | "cors-origin-reflection"
        => (
            NeedsReview,
            Some("An explicit-looking configuration pattern was found, but static source does not establish the effective deployed behavior or affected data path."),
        ),
        // Absence and local-response heuristics cannot see provider defaults,
        // wrappers, inherited instrumentation, or runtime transports.
        "ai-output-cap" | "console-log-error-handling" => (
            NeedsReview,
            Some("The scanned file lacks a recognized local control, but an imported wrapper, provider default, or runtime integration may supply equivalent behavior."),
        ),
        "ai-timeout"
        | "ai-rate-limit"
        | "ai-concurrency"
        | "ai-spend-guardrails"
        | "ai-observability"
        | "ai-cache-dedupe" => (
            NeedsReview,
            Some("The scanned file lacks a recognized local control, but middleware, wrappers, gateways, provider settings, or deployment infrastructure may supply equivalent behavior."),
        ),
        "ai-user-controlled-model" | "ai-user-controlled-settings" => (
            NeedsReview,
            Some("A request-derived expression and provider setting were matched locally, but imported validation, normalization, and the effective provider request were not resolved."),
        ),
        "ai-loop-risk" => (
            NeedsReview,
            Some("AI usage and an unbounded loop primitive occur in the same file, but static matching does not prove the provider call executes inside the loop or lacks an external stop."),
        ),
        "request-validation"
        | "ai-request-validation"
        | "public-endpoint-rate-limit"
        | "upload-validation"
        | "oauth-callback-state"
        | "oauth-callback-pkce"
        | "one-time-token-no-expiry"
        | "one-time-token-no-single-use"
        | "session-cookie-flags"
        | "tenant-scope-missing" => (
            NeedsReview,
            Some("The scanned file lacks a recognized local control, but middleware, imported services, framework defaults, database policy, or deployment infrastructure may enforce it elsewhere."),
        ),
        "upload-key-scope" | "jwt-decode-without-verify" | "one-time-token-raw-lookup" => (
            NeedsReview,
            Some("The local source pattern is a meaningful boundary signal, but imported validation, ownership policy, cryptographic processing, and effective runtime use were not resolved."),
        ),
        "open-redirect" => (
            NeedsReview,
            Some("A request-derived redirect-style value and redirect sink co-occur locally, but full value flow, normalization, and imported allowlist behavior were not resolved."),
        ),
        "cors-credentials-wildcard" => (
            NeedsReview,
            Some("Wildcard-origin and credentialed-CORS settings co-occur locally, but middleware transformation, route scope, and effective response headers were not resolved."),
        ),
        "webhook-signature" | "webhook-idempotency" => (
            NeedsReview,
            Some("The scanned webhook handler lacks a recognized local control, but imported verification, called-service deduplication, database constraints, or gateway policy may enforce it elsewhere."),
        ),
        "stripe-user-controlled-price" | "stripe-user-controlled-redirect" => (
            NeedsReview,
            Some("Request-derived data and a Stripe checkout field were matched locally, but full value flow, imported validation, effective session data, and fulfillment behavior were not resolved."),
        ),
        "stripe-checkout-idempotency" => (
            NeedsReview,
            Some("The scanned route lacks a recognized local checkout idempotency boundary, but an imported service, order store, or Stripe wrapper may own stable operation keys and session reuse."),
        ),
        "sensitive-auth" | "sensitive-authz" => (
            NeedsReview,
            Some("Sensitive-route indicators and locally visible access checks were classified heuristically; framework middleware, proxies, called services, and database policy may enforce access elsewhere."),
        ),
        "csrf-missing" => (
            NeedsReview,
            Some("A cookie-backed write lacks a recognized local anti-forgery check, but middleware, framework protection, effective cookie attributes, and client requirements were not resolved."),
        ),
        "client-db-access" => (
            NeedsReview,
            Some("A client-component directive and server-database marker co-occur, but import reachability, type-only use, framework enforcement, and emitted browser bundles were not analyzed."),
        ),
        "db-in-route" => (
            NeedsReview,
            Some("Direct database access in a route is factual, but whether extraction improves cohesion and policy consistency depends on handler size, reuse, framework conventions, and transaction ownership."),
        ),
        "multi-write-no-transaction" => (
            NeedsReview,
            Some("Multiple write-like matches lack a recognized local transaction, but handler boundaries, shared invariants, called services, stored procedures, and database-managed atomicity were not resolved."),
        ),
        "raw-sql-unsafe" => (
            NeedsReview,
            Some("A raw or string-built query pattern was matched, but request-to-query value flow, runtime reachability, bound parameters, and upstream identifier allowlisting were not resolved."),
        ),
        "user-controlled-fetch" => (
            NeedsReview,
            Some("A request accessor was matched at a server-side fetch boundary, but full value flow, imported URL policy, DNS behavior, redirects, proxies, and egress controls were not resolved."),
        ),
        "unsafe-html" => (
            NeedsReview,
            Some("A raw-HTML sink lacks a recognized local sanitizer, but source trust, imported sanitization, runtime reachability, and the effective rendering boundary were not resolved."),
        ),
        "external-call-timeout" | "external-call-retry" | "ai-retry-bounds" => (
            NeedsReview,
            Some("The scanned file lacks a recognized local resilience policy, but client/SDK defaults, wrappers, queues, gateways, platform deadlines, and an intentional fail-fast policy may define the effective behavior."),
        ),
        "no-pagination" => (
            NeedsReview,
            Some("A collection query lacks a recognized local bound, but query wrappers, database views, framework defaults, and inherently bounded datasets were not resolved."),
        ),
        "n-plus-one-query" => (
            NeedsReview,
            Some("A single-record lookup appears inside a loop-like construct, but runtime iteration bounds, request-scoped caching/batching, control flow, and actual query counts were not measured."),
        ),
        _ => (
            NeedsReview,
            Some("Pattern-based heuristic; verify the evidence before acting."),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_code_observations_are_confirmed() {
        for slug in [
            "empty-catch-blocks",
            "env-example-missing",
            "env-example-incomplete",
            "jsx-inline-style-density",
            "placeholder-density",
        ] {
            assert_eq!(
                code_issue_confidence(slug).0,
                IssueConfidence::Confirmed,
                "{slug}"
            );
        }
    }

    #[test]
    fn bounded_code_inferences_are_high_confidence() {
        for slug in ["god-route", "god-module", "oversized-module"] {
            assert_eq!(
                code_issue_confidence(slug).0,
                IssueConfidence::High,
                "{slug}"
            );
        }
    }

    /// Dependency resolution reaches a verdict the scan cannot fully
    /// establish: an import may resolve through machinery the static walk
    /// does not model, and a package may be loaded by name at runtime.
    #[test]
    fn dependency_resolution_verdicts_need_review() {
        for slug in ["undeclared-package", "unused-dependency"] {
            let (confidence, reason) = code_issue_confidence(slug);
            assert_eq!(confidence, IssueConfidence::NeedsReview, "{slug}");
            assert!(reason.is_some(), "{slug} should explain the caveat");
        }
    }

    #[test]
    fn runtime_and_unknown_signals_still_need_review() {
        for slug in [
            "external-call-timeout",
            "n-plus-one-query",
            "public-endpoint-rate-limit",
            "brand-new-unmapped-rule",
        ] {
            assert_eq!(
                code_issue_confidence(slug).0,
                IssueConfidence::NeedsReview,
                "{slug}"
            );
        }
    }
}
