use super::*;

#[path = "dynamic_eval.rs"]
mod dynamic_eval;
use dynamic_eval::request_derived_dynamic_eval_line;
#[cfg(test)]
use dynamic_eval::{request_var_matchers, REQUEST_VAR_MATCHER_CHUNK};

fn is_eslint_configuration(path: &str) -> bool {
    matches!(
        path.rsplit('/').next().unwrap_or(path),
        "eslint.config.js"
            | "eslint.config.mjs"
            | "eslint.config.cjs"
            | "eslint.config.ts"
            | "eslint.config.mts"
            | "eslint.config.cts"
            | ".eslintrc.js"
            | ".eslintrc.cjs"
    )
}

pub(super) fn collect_architecture_issues(
    issues: &mut Vec<CodeIssue>,
    ctx: &FileAnalysisContext<'_>,
) {
    let file = ctx.file;
    let content = ctx.content;
    // `content` is the executable view with comments blanked. A few checks
    // here are about the comments themselves - assistant narration, a
    // credential literal left behind in commented-out code, and whether a
    // catch body says anything at all - so they read the file as written.
    // Byte offsets match, so line numbers agree either way.
    let source_text = ctx.file.content.as_str();
    let lower = ctx.signals.lower.as_str();
    let pattern_registry = ctx.signals.pattern_registry;
    let scanner_rule_impl = ctx.signals.scanner_rule_impl;
    let route_like = ctx.signals.route_like;
    let uses_outbound_http = ctx.signals.uses_outbound_http;
    let uses_llm = ctx.signals.uses_llm;
    let parses_body = ctx.signals.parses_body;
    let touches_db = ctx.signals.touches_db;
    let responsibility_labels = &ctx.responsibility_labels;

    if is_next_config_file(&file.relative_path) {
        // `content` already has comments blanked, so a commented-out override
        // cannot satisfy either pattern.
        let ignores_build_errors = NEXTCONFIG_IGNORE_BUILD_ERRORS_PATTERN.is_match(content);
        let ignores_lint = NEXTCONFIG_IGNORE_LINT_PATTERN.is_match(content);
        if ignores_build_errors || ignores_lint {
            let flags = match (ignores_build_errors, ignores_lint) {
                (true, true) => {
                    "`typescript.ignoreBuildErrors: true` and `eslint.ignoreDuringBuilds: true` are"
                }
                (true, false) => "`typescript.ignoreBuildErrors: true` is",
                _ => "`eslint.ignoreDuringBuilds: true` is",
            };
            issues.push(build_issue(
                "nextconfig-errors-ignored",
                "operations",
                if ignores_build_errors { Severity::Medium } else { Severity::Low },
                if ignores_build_errors {
                    "Next.js type-error build gate is configured to be skipped"
                } else {
                    "Legacy Next.js config requests skipping build-time lint"
                },
                if ignores_build_errors {
                    "This Next.js config contains `typescript.ignoreBuildErrors: true`, which allows `next build` to complete when TypeScript errors exist. The setting does not prove the project currently has type errors, that a separate required type-check is absent, or that dynamic configuration leaves the value enabled in the deployed build."
                } else {
                    "This Next.js config contains `eslint.ignoreDuringBuilds: true`. In Next.js versions through 15, that skips the integrated build lint step; Next.js 16 removed the `eslint` next.config option and `next lint`, so the setting may now be legacy no-op configuration. Its presence does not prove the project lacks a separate required ESLint command."
                },
                file,
                first_match_line_single(content, &NEXTCONFIG_IGNORE_BUILD_ERRORS_PATTERN)
                    .or_else(|| first_match_line_single(content, &NEXTCONFIG_IGNORE_LINT_PATTERN)),
                Some(format!("{} set in {}.", flags, file.relative_path)),
                Some(if ignores_build_errors {
                    "Confirm the resolved Next config and CI gates. Prefer removing `ignoreBuildErrors`; if a separate required `tsc --noEmit` gate deliberately owns type checking, document and test that ordering. Fix real errors or use a narrow, explained `@ts-expect-error` instead of a project-wide bypass."
                } else {
                    "Check the installed Next.js version and existing CI. On Next.js 16+, remove the obsolete config and run ESLint through the supported CLI. On older versions, remove the bypass or retain it only when a required external lint gate runs before deployment."
                }.into()),
                Some(if ignores_build_errors {
                    "Introduce a safe temporary type error on a branch and confirm the required pre-deploy type-check fails, then remove it and verify `next build` plus the type-check pass with the intended resolved config."
                } else {
                    "Introduce a safe temporary lint violation on a branch and confirm the required ESLint command fails in CI, then remove it and verify the production workflow passes on the installed Next.js version."
                }.into()),
            ));
        }
    }

    let reports_god_route =
        route_like && file.line_count >= 250 && responsibility_labels.len() >= 4;
    if reports_god_route {
        issues.push(build_issue(
            "god-route",
            "architecture",
            if responsibility_labels.len() >= 6 || file.line_count >= 500 {
                Severity::High
            } else {
                Severity::Medium
            },
            "Large route has multiple detected responsibilities",
            "The scanned route is large and contains markers from several responsibility groups such as authentication, validation, persistence, outbound calls, uploads, billing, or AI. This structural heuristic does not establish poor design: generated code, framework conventions, or a cohesive orchestration function can legitimately match. Review whether policy and failure handling remain understandable and testable.",
            file,
            Some(1),
            Some(format!(
                "Detected responsibility groups [{}] across {} lines. The scan did not assess control flow, generated regions, cohesion, or called-module boundaries.",
                responsibility_labels.join(", "),
                file.line_count
            )),
            Some("Review the route by business invariant and failure boundary. If responsibilities are genuinely entangled, extract the smallest cohesive validation, authorization, transaction, or external-service operations while retaining clear orchestration; do not split solely to reduce line count.".into()),
            Some("Before and after any refactor, run route-level tests for authorization, validation, success, timeout, rollback/idempotency, and external failure paths. Confirm behavior, transaction scope, and observability remain equivalent and that the resulting boundaries are easier to review.".into()),
        ));
    }

    let reports_god_module = !route_like
        && !is_eslint_configuration(&file.relative_path)
        && !pattern_registry
        && !scanner_rule_impl
        && file.line_count >= 450
        && responsibility_labels.len() >= 4
        && (touches_db || uses_llm || uses_outbound_http);
    if reports_god_module {
        issues.push(build_issue(
            "god-module",
            "architecture",
            if responsibility_labels.len() >= 6 || file.line_count >= 700 {
                Severity::High
            } else {
                Severity::Medium
            },
            "Large module has multiple detected responsibilities",
            "The scanned non-route module is large and contains markers from several responsibility groups, including at least one database, AI, or outbound-service concern. This heuristic does not establish poor design: a cohesive adapter, generated module, or deliberate orchestration boundary can legitimately match. Review whether policy, dependencies, and failure behavior remain clear and testable.",
            file,
            Some(1),
            Some(format!(
                "Detected responsibility groups [{}] across {} lines. The scan did not assess generated regions, cohesion, public API size, or delegation into called modules.",
                responsibility_labels.join(", "),
                file.line_count
            )),
            Some("Review the module's responsibilities, invariants, and dependency directions. If unrelated policy is coupled, extract cohesive domain, persistence, or provider adapters behind narrow typed interfaces; keep coordinated work together when splitting would obscure the transaction or failure model.".into()),
            Some("Characterize the module's public behavior and important failure paths before refactoring. Afterward, run consumer and contract tests and confirm dependency direction, transaction ownership, retries, and telemetry did not change unintentionally.".into()),
        ));
    }

    // Prefer the specific multi-responsibility issue over a duplicate size issue.
    if !reports_god_route
        && !is_eslint_configuration(&file.relative_path)
        && !reports_god_module
        && !pattern_registry
        && file.line_count >= 900
        && (touches_db || route_like || uses_llm)
    {
        issues.push(build_issue(
            "oversized-module",
            "architecture",
            if file.line_count >= 1400 { Severity::High } else { Severity::Medium },
            "Very large module contains high-risk application concerns",
            "The scanned file exceeds the size threshold and contains route, database, or AI markers. Size alone does not establish a defect, and generated code or a cohesive implementation may be legitimate. The review is whether security boundaries, ownership, tests, and failure behavior remain discoverable and maintainable at this scale.",
            file,
            Some(1),
            Some(format!("This file has {} lines and contains a recognized route, database, or AI marker. Generated regions, cohesion, and test coverage were not assessed.", file.line_count)),
            Some("First exclude generated/vendor content and map the file's public API, invariants, and failure boundaries. If unrelated concerns are coupled, extract cohesive modules behind narrow typed interfaces; do not split a cohesive implementation merely to satisfy a line threshold.".into()),
            Some("Use characterization and consumer tests before and after any refactor. Confirm authorization, transaction scope, external-call policy, error handling, and observable behavior remain equivalent, then review whether ownership and change boundaries actually improved.".into()),
        ));
    }

    if !pattern_registry && !scanner_rule_impl {
        if let Some(mat) = HARDCODED_SECRET_PATTERNS
            .iter()
            .find_map(|pat| pat.find(source_text))
        {
            let line = line_number(source_text, mat.start());
            let matched = mat.as_str();
            // Persist only a short prefix and mask; never expose a secret suffix.
            let redacted = format!("{}***", matched.chars().take(4).collect::<String>());
            issues.push(build_issue(
                "hardcoded-secret",
                "security",
                Severity::High,
                "Source file contains a credential-shaped literal",
                "This file contains a literal matching a known API-key, token, or private-key format. That is a high-risk secret-management pattern, but this static match does not verify that the value is genuine, live, privileged, tracked by version control, shared, or deployed; provider-like fixtures and revoked values can match too.",
                file,
                Some(line),
                Some(format!("Detected a literal matching a known credential format: {}. The value was not tested or looked up at its provider.", redacted)),
                Some("Classify the value without copying it into logs or tickets. If it is a real credential, revoke or rotate it first when it may have been tracked, shared, logged, packaged, or deployed; then remove the literal and load the replacement from an appropriate server-side secret store or injected environment. If it is a fake fixture or public identifier, make that unmistakable or use a provider-documented non-secret test value.".into()),
                Some("For a real credential, confirm the old credential fails and the least-privilege replacement works only in the intended environment. Search tracked history, build artifacts, logs, packages, and deployment output for the old value according to the incident policy; for a fixture, verify it cannot authenticate and document the test boundary.".into()),
            ));
        } else if let Some(mat) = WEAK_DEFAULT_CREDENTIAL_PATTERNS
            .iter()
            .flat_map(|pat| pat.find_iter(content))
            .find(|mat| !is_hash_call_argument(content, mat.start()))
        {
            let line = line_number(content, mat.start());
            issues.push(build_issue(
                "weak-default-credential",
                "security",
                // High: a shipped default credential is a real exposure, not a
                // style nit (matches the registry pin).
                Severity::High,
                "Weak placeholder or default credential in source",
                "This file uses a weak placeholder credential (like \"changeme\" or \"password123\"), often as an environment-variable fallback. It is not a leaked production key, but if the real value is ever missing the app silently runs on a guessable default.",
                file,
                Some(line),
                Some("Detected a known weak placeholder credential value.".into()),
                Some("Remove the default and fail fast when the variable is missing - throw if the env value is unset instead of falling back to a constant.".into()),
                Some("Confirm the app refuses to start (or clearly errors) when the credential env variable is unset, rather than running on the placeholder.".into()),
            ));
        }
    }

    if !pattern_registry && is_js_or_ts_file(&file.relative_path) {
        // Both catch-block checks read the file as written: a catch body whose
        // only content is a comment explaining the ignored failure is
        // documented, not silent, and the rule says so in its own description.
        let empty_catches = EMPTY_CATCH_PATTERN.find_iter(source_text).count();
        if empty_catches >= 2 {
            let first_match = EMPTY_CATCH_PATTERN.find(source_text);
            let line = first_match
                .map(|m| line_number(source_text, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "empty-catch-blocks",
                "architecture",
                // Emit the effective Medium severity applied by policy.
                Severity::Medium,
                "Multiple empty catch blocks silently swallow errors",
                "This file has several catch blocks that discard errors completely. That can hide failed work and remove diagnostic context, although an empty catch can be intentional when the ignored failure is narrow, documented, and covered by a fallback.",
                file,
                Some(line),
                Some(format!("Found {} empty catch blocks that discard errors without logging, reporting, or rethrowing.", empty_catches)),
                Some("Add meaningful error handling to each catch block: log the error with context, report it to your error tracker, rethrow it, or return a user-safe error response.".into()),
                Some("Trigger an error condition that would be caught by one of these blocks and confirm it now surfaces visibly in logs or error reporting.".into()),
            ));
        }

        let console_catches = CONSOLE_LOG_CATCH_PATTERN.find_iter(source_text).count();
        if console_catches >= 3 {
            let first_match = CONSOLE_LOG_CATCH_PATTERN.find(source_text);
            let line = first_match
                .map(|m| line_number(source_text, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "console-log-error-handling",
                "architecture",
                Severity::Medium,
                "Catch blocks use console.log as their only local response",
                "This file has several catch blocks whose bodies only call console.log. Depending on the runtime and log collection, those messages may be transient, unstructured, or detached from request and deployment context; the scanner cannot see a global console transport or an intentional best-effort fallback.",
                file,
                Some(line),
                Some(format!("Found {} catch blocks where console.log is the only error handling.", console_catches)),
                Some("Review each catch by failure semantics. Rethrow or return a safe error when the operation must fail; otherwise send a sanitized error plus stable operation/request context to the project's production logging or monitoring path. Keep console logging only when the runtime deliberately captures it and the fallback is documented.".into()),
                Some("Trigger representative failures in a production-like environment and confirm required failures propagate correctly, intentional fallbacks still work, and approved telemetry receives enough non-sensitive context to diagnose the event.".into()),
            ));
        }
    }

    if !pattern_registry && !scanner_rule_impl {
        let ai_comment_count: usize = AI_COMMENT_PATTERNS
            .iter()
            .map(|pat| pat.find_iter(source_text).count())
            .sum();
        if ai_comment_count >= 2 {
            let first_match = AI_COMMENT_PATTERNS
                .iter()
                .find_map(|pat| pat.find(source_text));
            let line = first_match
                .map(|m| line_number(source_text, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "ai-conversation-artifacts",
                "architecture",
                Severity::Low,
                "Comments match conversational assistant phrases",
                "This file has multiple comments that resemble conversational assistant text. The pattern does not establish who wrote the code, whether it was reviewed, or whether the surrounding implementation is incorrect; documentation and examples can match legitimately.",
                file,
                Some(line),
                Some(format!("Found {} comments with AI conversation patterns like 'As an AI', 'Here's how', 'I'll help you', etc.", ai_comment_count)),
                Some("Read each matched comment in context. Keep useful project documentation, and rewrite or remove only chat-like narration that is inaccurate, redundant, or inappropriate for maintainers. Review the nearby behavior on its own merits rather than treating phrasing as proof of a defect.".into()),
                Some("Confirm retained comments describe the current behavior and constraints, then run the tests and review checks that cover the surrounding code. Clearing the phrase matches alone is not evidence that the implementation is correct.".into()),
            ));
        }
    }

    if !pattern_registry
        && is_js_or_ts_file(&file.relative_path)
        && !is_config_file(&file.relative_path)
    {
        let localhost_count: usize = LOCALHOST_URL_PATTERNS
            .iter()
            .map(|pat| pat.find_iter(content).count())
            .sum();
        if localhost_count >= 1 && route_like {
            let first_match = LOCALHOST_URL_PATTERNS
                .iter()
                .find_map(|pat| pat.find(content));
            let line = first_match
                .map(|m| line_number(content, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "hardcoded-localhost-url",
                "operations",
                Severity::Medium,
                "Server code contains a fixed loopback URL",
                "This route or server file contains a fixed localhost or loopback URL. It may be an accidental development assumption, but an intentional loopback sidecar, same-container service, emulator, or local-only execution path can be valid. Static source cannot determine the deployed network topology or whether this path runs there.",
                file,
                Some(line),
                Some(format!(
                    "Found {} fixed localhost {} in route-like or server code; deployment configuration and reachability were not inspected.",
                    localhost_count,
                    if localhost_count == 1 { "URL" } else { "URLs" }
                )),
                Some("Confirm the intended deployment topology first. If the destination varies by environment, move it to validated server-only configuration, provide a development default only in an explicitly detected development mode, and fail startup in deployed modes when the value is missing. If loopback is intentional, document the co-located dependency and keep the finding as reviewed.".into()),
                Some("Exercise the feature in a representative staging or packaged deployment and confirm the configured destination matches that deployment topology. Also test missing/invalid deployed configuration and, for an intentional loopback dependency, verify its health and startup ordering.".into()),
            ));
        }
    }

    if !pattern_registry && !scanner_rule_impl && has_any(content, &CLIENT_ENV_SECRET_PATTERNS) {
        // Match actual env access and exclude known-public key conventions so
        // explanatory strings do not become secret-exposure findings.
        let real_secret_matches = client_env_secret_references(content);
        if let Some(first_match) = real_secret_matches.first() {
            let line = line_number(content, first_match.start);
            issues.push(build_issue(
                "client-env-secret",
                "security",
                Severity::High,
                "Possible sensitive credential uses a client-public environment name",
                "This source reads a client-prefixed environment variable whose name suggests a secret, private key, password, or privileged token. Frameworks make these namespaces eligible for substitution into client bundles when the module reaches a client build. This source reference does not prove that a live value is configured or present in the deployed bundle.",
                file,
                Some(line),
                Some(format!(
                    "Matched client-prefixed env var reference: {}. No environment value or deployed bundle content was inspected. Known-public naming conventions are excluded from this heuristic.",
                    first_match.name,
                )),
                Some("First confirm whether the variable is populated and whether this module reaches a client bundle. If the value is public by design, document that scope and mark the finding not applicable. If it is privileged, revoke and rotate any value confirmed exposed, move it to a server-only environment name, and put the privileged operation behind an authenticated and authorized server boundary.".into()),
                Some("Build the production client in a controlled environment and inspect emitted JavaScript plus browser network behavior for the configured value. Confirm privileged credentials are absent from client assets and that the replacement server endpoint enforces authentication, authorization, and input validation.".into()),
            ));
        }
    }

    if is_typescript_file(&file.relative_path) && !pattern_registry {
        let any_count = TYPESCRIPT_ANY_PATTERN.find_iter(content).count();
        let threshold = if file.line_count >= 200 { 10 } else { 6 };
        if any_count >= threshold {
            let first_match = TYPESCRIPT_ANY_PATTERN.find(content);
            let line = first_match
                .map(|m| line_number(content, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "typescript-any-abuse",
                "architecture",
                Severity::Medium,
                "Heavy use of TypeScript 'any' bypasses local type checks",
                "This file uses the 'any' type extensively. Each use allows operations to pass without normal static checking, but generated bindings, migration boundaries, tests, and deliberately untyped third-party data can make some occurrences reasonable.",
                file,
                Some(line),
                Some(format!("Found {} uses of ': any' in a {} line file.", any_count, file.line_count)),
                Some("Replace 'any' with specific types, 'unknown' (for values that need runtime checking), or generic type parameters. Start with the most-used 'any' values and work outward.".into()),
                Some("Run tsc --noEmit with strict mode and confirm the file compiles without falling back to 'any' for the types you replaced.".into()),
            ));
        }
    }

    if !pattern_registry && !scanner_rule_impl && route_like {
        // Require both child_process use and a shell call.
        let has_child_process = content.contains("child_process");
        let has_shell_exec = has_child_process && has_any(content, &SHELL_COMMAND_PATTERNS);
        let has_safe_exec = has_any(content, &EXEC_SAFE_PATTERNS);

        // Python and PHP use their dedicated taint checks.
        let is_py = file.relative_path.to_ascii_lowercase().ends_with(".py");
        let is_php = file.relative_path.to_ascii_lowercase().ends_with(".php");
        if !is_py && !is_php {
            if let Some(line) = request_derived_dynamic_eval_line(content) {
                issues.push(build_issue(
                "eval-exec-injection",
                "security",
                Severity::High,
                "Possible request-controlled dynamic evaluation",
                "SiteCMD found an eval or Function-constructor argument that references a request accessor or a local variable assigned from request parsing in the same file. That is a strong injection review signal, but this shallow static match does not prove runtime reachability, the full value flow, or whether a restrictive parser runs before evaluation.",
                file,
                Some(line),
                Some("A dynamic-evaluation call and a request-derived expression were matched in the same file; exploitable runtime flow is not proven.".into()),
                Some("Trace the value into the evaluation call and remove dynamic language evaluation from request-controlled paths. Parse data with JSON or a typed schema, dispatch through a server-owned lookup table, or use a purpose-built expression language with an explicit operation allowlist and resource limits. Do not treat a restricted globals object as a general JavaScript sandbox.".into()),
                Some("Add a focused unit test around the parser or dispatcher using valid expressions plus property-access, constructor, import, loop, and resource-exhaustion payloads. Confirm only the documented grammar is accepted and no JavaScript evaluator is reached.".into()),
            ));
            }
        }

        // Precise language-specific command-injection checks take precedence over
        // this broader shell-exec and body-parse co-occurrence heuristic.
        let js_command_injection_fired = issues
            .iter()
            .any(|issue| issue.id.starts_with("js-command-injection:"));
        if has_shell_exec
            && parses_body
            && !has_safe_exec
            && !is_php
            && !is_py
            && !js_command_injection_fired
        {
            let first_match = SHELL_COMMAND_PATTERNS
                .iter()
                .find_map(|pat| pat.find(content));
            let line = first_match
                .map(|m| line_number(content, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "shell-injection",
                "security",
                Severity::High,
                "Possible request-to-shell data flow needs review",
                "This file both parses request input and invokes a child process through a command-string-capable API. That co-occurrence is a meaningful review signal, but this check does not prove that request data reaches the command or that the call enables a shell. Trace the actual value flow and process options before treating it as exploitable command injection.",
                file,
                Some(line),
                Some("Request-body parsing and a child_process command invocation were detected in the same file; a request-to-command data flow is not proven.".into()),
                Some("Trace every value passed to the process call. Where request-derived data can reach it, select a fixed executable and pass validated values in an argument array with the shell disabled. Validate command-specific allowlists and reject leading options where the target program could interpret them; do not concatenate untrusted data into shell source.".into()),
                Some("Add a focused test that exercises valid input plus leading-option and shell-metacharacter payloads. Confirm the fixed executable and argument boundaries do not change, no shell is enabled, invalid values are rejected, and no unintended process or option is invoked.".into()),
            ));
        }
    }

    // localStorage auth token detection
    if !pattern_registry
        && is_frontend_surface(file)
        && has_any(content, &LOCALSTORAGE_AUTH_PATTERNS)
    {
        let first_match = LOCALSTORAGE_AUTH_PATTERNS
            .iter()
            .find_map(|pat| pat.find(content));
        let line = first_match
            .map(|m| line_number(content, m.start()))
            .unwrap_or(1);
        issues.push(build_issue(
                "localstorage-auth-token",
                "security",
                // Medium: tokens in localStorage are the standard SPA pattern;
                // grades with the cookie-flag advisories, not the exposure
                // tier (matches the registry pin).
                Severity::Medium,
                "Browser storage uses an authentication-like key",
                "This frontend code reads or writes localStorage/sessionStorage under a key commonly used for a JWT, access token, refresh token, session, or API key. If the value is a reusable bearer credential, JavaScript executing in the same origin can read and exfiltrate it. The key name alone does not prove what the value contains, how long it lives, or whether another control binds it to the client.",
                file,
                Some(line),
                Some("localStorage or sessionStorage is read or written with an authentication-like key name. Runtime values, token lifetime, and server validation were not inspected.".into()),
                Some("Choose the authentication architecture before changing storage. For a same-site web app, prefer a server-managed opaque session in a Secure, HttpOnly, narrowly scoped cookie when compatible, with server-side authorization, rotation/revocation, bounded lifetime, and CSRF protection for cookie-authenticated mutations. If a browser bearer token is required, minimize lifetime and persistence, keep it in memory where practical, and design refresh/reuse controls for the threat model.".into()),
                Some("Inspect runtime storage and network behavior with a test account, then test XSS assumptions, direct API authorization, CSRF, logout/revocation, refresh reuse, expiration, OAuth redirects, multiple tabs, and the production proxy's cookie attributes. Confirm no long-lived reusable bearer credential remains in browser storage unless the reviewed architecture explicitly accepts that risk.".into()),
            ));
    }

    // Unbounded list query detection
    if !pattern_registry && !scanner_rule_impl && route_like {
        let has_list_query = has_any(content, &LIST_QUERY_PATTERNS);
        let has_pagination = has_any(content, &PAGINATION_GUARD_PATTERNS);

        if has_list_query && !has_pagination {
            let first_match = LIST_QUERY_PATTERNS.iter().find_map(|pat| pat.find(content));
            let line = first_match
                .map(|m| line_number(content, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "no-pagination",
                "architecture",
                Severity::Medium,
                "No recognized local bound on a list-query route",
                "The scanned route contains a collection-query pattern and SiteCMD did not recognize a local limit, cursor, page size, offset, or pagination helper. This does not establish an unbounded response: a wrapper, database view, framework default, or inherently bounded dataset may constrain it. If no effective bound exists, query work, memory, serialization, and response size can grow with the collection.",
                file,
                Some(line),
                Some("A recognized list-style database query appears in a route file with no recognized local `take`, `limit`, page-size, cursor, offset, or pagination-helper pattern. Called-query wrappers and effective database bounds were not resolved.".into()),
                Some("Confirm the endpoint's collection cardinality and any existing wrapper/default. Where a bound is needed, enforce a server-side maximum, deterministic ordering, and a cursor or offset contract appropriate to the dataset; validate caller page parameters and avoid returning sensitive pagination metadata unnecessarily.".into()),
                Some("Against a disposable dataset larger than the maximum page, test missing, zero, negative, excessive, malformed, first, middle, and final page inputs plus concurrent inserts where relevant. Confirm every response stays bounded, ordering is deterministic, and query latency/plan remains acceptable.".into()),
            ));
        }
    }

    // Plaintext password storage detection
    if !pattern_registry && !scanner_rule_impl {
        let has_password_store = has_any(content, &PASSWORD_STORE_PATTERNS);
        let has_password_hash = has_any(content, &PASSWORD_HASH_PATTERNS);

        // Prisma password relation writes target a separate hashed-password
        // table and are not plaintext scalar storage.
        let writes_password_as_relation = lower
            .split("password:")
            .skip(1)
            .any(|segment| segment.trim_start().starts_with('{'));
        if has_password_store
            && !has_password_hash
            && !writes_password_as_relation
            && (route_like
                || lower.contains("signup")
                || lower.contains("register")
                || lower.contains("create_user")
                || lower.contains("createuser"))
        {
            let first_match = PASSWORD_STORE_PATTERNS
                .iter()
                .find_map(|pat| pat.find(content));
            let line = first_match
                .map(|m| line_number(content, m.start()))
                .unwrap_or(1);
            issues.push(build_issue(
                "plaintext-password",
                "security",
                Severity::High,
                "Possible password write without visible hashing",
                "This file appears to pass a password value directly into a database create or insert operation, and no recognized password-hashing call is visible in the same file. If the stored value is plaintext, a database or backup disclosure exposes reusable credentials. This check does not inspect ORM middleware, database triggers, imported wrappers, or existing authentication hooks, so the storage path must be verified before treating plaintext storage as proven.",
                file,
                Some(line),
                Some("A password-named field is written by a create or insert pattern, while no recognized password-hashing call appears in this file; external hooks and storage transforms were not inspected.".into()),
                Some("Trace the complete signup and password-change path, including existing authentication hooks and ORM middleware. If plaintext reaches storage, hash it before persistence with a maintained slow password-hashing function such as Argon2id, scrypt, or bcrypt using parameters calibrated to the deployment, store only the encoded verifier, and plan a safe reset or migration for existing plaintext records.".into()),
                Some("Create a disposable test account, inspect the stored value through an authorized development path, and confirm it is a salted encoded verifier rather than the submitted password. Verify correct login succeeds, an incorrect password fails, password changes use the same path, and logs or events do not contain the plaintext.".into()),
            ));
        }
    }

    // N+1 query detection
    if !pattern_registry && !scanner_rule_impl {
        let nplus1_match = NPLUS1_ORM_IN_LOOP_PATTERNS
            .iter()
            .find_map(|pat| pat.find(content));
        if let Some(mat) = nplus1_match {
            let line = line_number(content, mat.start());
            issues.push(build_issue(
                "n-plus-one-query",
                "architecture",
                Severity::Medium,
                "Possible N+1 query pattern inside a loop",
                "Static analysis matched a single-record database lookup inside a loop-like construct. This does not establish N+1 runtime behavior: the loop may be tightly bounded, the call may hit a request-scoped loader/cache, or the client may batch operations. If each iteration performs a separate remote query, database round-trips grow with the item count and can increase latency and load.",
                file,
                Some(line),
                Some("A recognized ORM lookup such as `findUnique`, `findFirst`, `findOne`, `findById`, a receiver-qualified database query, or a Django model-manager lookup appears inside a loop pattern. Runtime iteration bounds, loader/cache behavior, and actual query counts were not measured.".into()),
                Some("Measure first. If query count grows with items, use an eager relation/include, a set-based `IN` query followed by an in-memory lookup map, or a request-scoped batching loader appropriate to the access pattern. Merely running the same queries concurrently reduces wall time but not database work.".into()),
                Some("Instrument query count and latency in a non-production request for 1, 10, and a representative maximum item count. Confirm the corrected path has a bounded query count, preserves missing/duplicate ordering semantics, respects database parameter limits, and does not broaden selected data.".into()),
            ));
        }
    }
}

/// Whether the credential literal at `start` is the value being hashed, as in
/// `bcrypt.hash("password123", 10)`. A weak literal that only ever reaches a
/// password hash is seed or fixture input, not a default the app would run on.
fn is_hash_call_argument(content: &str, start: usize) -> bool {
    let mut window_start = start.saturating_sub(HASH_CALL_LOOKBACK);
    while !content.is_char_boundary(window_start) {
        window_start += 1;
    }
    HASH_CALL_ARGUMENT_PREFIX_PATTERN.is_match(&content[window_start..start])
}

/// How far in front of a credential literal the hash-call check reads, in bytes.
const HASH_CALL_LOOKBACK: usize = 80;

struct ClientEnvSecretReference {
    start: usize,
    name: String,
}

fn client_env_secret_references(content: &str) -> Vec<ClientEnvSecretReference> {
    // Build the span map once and binary-search matches to avoid repeated
    // full-file walks.
    let mut spans: Option<Vec<(usize, usize)>> = None;
    let mut references = Vec::new();
    for pattern in CLIENT_ENV_SECRET_REFERENCE_PATTERNS.iter() {
        for captures in pattern.captures_iter(content) {
            let Some(full_match) = captures.get(0) else {
                continue;
            };
            let spans = spans.get_or_insert_with(|| js_string_comment_spans(content));
            if index_inside_spans(spans, full_match.start()) {
                continue;
            }
            let Some(name) = captures.get(1) else {
                continue;
            };
            let name = name.as_str();
            if CLIENT_ENV_PUBLIC_ALLOWLIST_PATTERNS
                .iter()
                .any(|allow| allow.is_match(name))
            {
                continue;
            }
            references.push(ClientEnvSecretReference {
                start: full_match.start(),
                name: name.to_string(),
            });
        }
    }
    references
}

/// Sorted, non-overlapping byte spans for JavaScript strings and comments.
fn js_string_comment_spans(content: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut chars = content.char_indices().peekable();

    while let Some((position, ch)) = chars.next() {
        let next_index = position + ch.len_utf8();

        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                if let Some(start) = current_start.take() {
                    spans.push((start, next_index));
                }
            }
            continue;
        }

        if in_block_comment {
            if ch == '*' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                chars.next();
                in_block_comment = false;
                if let Some(start) = current_start.take() {
                    spans.push((start, next_index));
                }
            }
            continue;
        }

        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
                if let Some(start) = current_start.take() {
                    spans.push((start, next_index));
                }
            }
            continue;
        }

        if ch == '/' {
            if chars.peek().is_some_and(|(_, next)| *next == '/') {
                chars.next();
                in_line_comment = true;
                current_start = Some(next_index);
            } else if chars.peek().is_some_and(|(_, next)| *next == '*') {
                chars.next();
                in_block_comment = true;
                current_start = Some(next_index);
            }
        } else if ch == '"' || ch == '\'' || ch == '`' {
            in_string = Some(ch);
            current_start = Some(next_index);
        }
    }

    // An unterminated string/comment runs to end of file.
    if let Some(start) = current_start {
        spans.push((start, content.len()));
    }
    spans
}

fn index_inside_spans(spans: &[(usize, usize)], index: usize) -> bool {
    let insert = spans.partition_point(|(start, _)| *start <= index);
    insert > 0 && spans[insert - 1].1 > index
}

#[cfg(test)]
#[path = "architecture_checks_tests.rs"]
mod tests;
