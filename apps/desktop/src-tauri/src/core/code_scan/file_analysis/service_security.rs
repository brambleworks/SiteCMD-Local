use super::*;

#[path = "outbound.rs"]
mod outbound;

pub(super) fn collect_service_security_issues(
    issues: &mut Vec<CodeIssue>,
    ctx: &FileAnalysisContext<'_>,
) {
    let file = ctx.file;
    let content = ctx.content;
    let pattern_registry = ctx.signals.pattern_registry;
    let scanner_rule_impl = ctx.signals.scanner_rule_impl;
    let route_like = ctx.signals.route_like;
    let wp_hook_handler = ctx.signals.wp_hook_handler;
    let middleware_auth_protected = ctx.signals.middleware_auth_protected;
    let has_identity_auth = ctx.signals.has_identity_auth;
    let has_authz = ctx.signals.has_authz;
    let has_auth = ctx.signals.has_auth;
    let has_cors_wildcard = ctx.signals.has_cors_wildcard;
    let has_cors_credentials = ctx.signals.has_cors_credentials;
    let has_runtime_cors_config = ctx.signals.has_runtime_cors_config;
    let has_cookie_session = ctx.signals.has_cookie_session;
    let has_csrf = ctx.signals.has_csrf;
    let parses_body = ctx.signals.parses_body;
    let is_webhook = ctx.signals.is_webhook;
    let has_webhook_verify = ctx.signals.has_webhook_verify;
    let has_idempotency_guard = ctx.signals.has_idempotency_guard;
    let touches_db = ctx.signals.touches_db;
    let db_write_count = ctx.signals.db_write_count;
    let has_transaction = ctx.signals.has_transaction;
    let has_unsafe_raw_sql = ctx.signals.has_unsafe_raw_sql;
    let dangerous_html = ctx.signals.dangerous_html;
    let write_handler = ctx.signals.write_handler;
    let sensitive_handler = ctx.signals.sensitive_handler;
    let uses_stripe_checkout = ctx.signals.uses_stripe_checkout;
    let has_user_controlled_stripe_price = ctx.signals.has_user_controlled_stripe_price;
    let has_redirect_allowlist = ctx.signals.has_redirect_allowlist;
    let has_user_controlled_stripe_redirect = ctx.signals.has_user_controlled_stripe_redirect;
    let has_stripe_price_allowlist = ctx.signals.has_stripe_price_allowlist;
    let user_controlled_fetch = ctx.signals.user_controlled_fetch;
    let likely_public_endpoint = ctx.signals.likely_public_endpoint;

    if has_cors_wildcard
        && has_cors_credentials
        && !pattern_registry
        && !scanner_rule_impl
        && (route_like || has_runtime_cors_config)
    {
        issues.push(build_issue(
            "cors-credentials-wildcard",
            "security",
            Severity::Medium,
            "Credentialed CORS uses an invalid wildcard origin",
            "This file combines credentialed cross-origin access with a wildcard origin. A standards-compliant browser blocks JavaScript from reading that credentialed response, so this is usually a broken CORS configuration rather than an authenticated-data exposure. Verify the actual response because some middleware may transform configuration values before sending headers.",
            file,
            first_match_line(content, &CORS_WILDCARD_PATTERNS)
                .or_else(|| first_match_line(content, &CORS_CREDENTIAL_PATTERNS)),
            Some("A wildcard origin and credentialed CORS setting were both detected in the same file.".into()),
            Some("If credentials are required, replace the wildcard with an explicit allowlist of trusted origins and emit `Vary: Origin`. If the API is intentionally public, keep the wildcard and disable credentials instead.".into()),
            Some("Inspect the response in a browser: trusted credentialed origins should receive their exact allowed origin, while untrusted origins should receive no CORS permission.".into()),
        ));
    }

    if has_cors_credentials
        && !pattern_registry
        && !scanner_rule_impl
        && (route_like || has_runtime_cors_config)
    {
        if let Some(line) = first_match_line(content, &CORS_ORIGIN_REFLECTION_PATTERNS) {
            issues.push(build_issue(
                "cors-origin-reflection",
                "security",
                Severity::High,
                "CORS reflects the request origin while allowing credentials",
                "This file appears to echo the caller's Origin header (or use the cors() middleware's `origin: true` shorthand) while allowing credentialed CORS. A browser can expose a response to that origin when it also attaches eligible ambient credentials, but this static pattern does not prove the route is private, the configuration is effective, or cookies are eligible for the cross-site request under SameSite and other browser rules. If those conditions hold, an untrusted site may read authenticated responses.",
                file,
                Some(line),
                Some("An Access-Control-Allow-Origin value taken directly from the request origin (or `origin: true`) was detected in the same file as a credentialed CORS setting; effective middleware scope, authentication, cookie attributes, and response sensitivity were not evaluated.".into()),
                Some("Validate the request origin against an explicit allowlist of trusted origins before echoing it, or list the trusted origins directly in the CORS configuration instead of reflecting whatever arrives.".into()),
                Some("Against a non-production deployment, test trusted and untrusted origins through the real proxy with the application's actual authentication and preflight behavior. Confirm an untrusted origin receives no matching Access-Control-Allow-Origin value and cannot read a sensitive response.".into()),
            ));
        }
    }

    if !pattern_registry && !scanner_rule_impl {
        if let Some(line) = first_match_line(content, &TLS_VERIFICATION_DISABLED_PATTERNS) {
            issues.push(build_issue(
                "tls-verification-disabled",
                "security",
                Severity::High,
                "Outbound TLS certificate verification is disabled",
                "This file contains a recognized setting that disables certificate verification for a matching outbound client or call. If that path executes, the affected connection can accept a certificate that is not trusted for the destination, so a network-path attacker could impersonate the endpoint and read or alter data sent through that connection. The scan does not establish whether the path runs, which environment selects it, or what data it carries.",
                file,
                Some(line),
                Some("A recognized TLS certificate-verification disable idiom was detected at the reported line; runtime reachability and environment selection were not evaluated.".into()),
                Some("Remove the disable override from production-capable paths. For a self-signed development or private-service certificate, trust the specific development CA or certificate through the client's supported trust configuration instead of disabling verification globally. Keep any test-only exception isolated and prove it cannot be selected in release configuration.".into()),
                Some("Run the affected client with the intended trust store: the valid destination should succeed, while an untrusted or wrong-host certificate must fail. Also verify the release configuration cannot select a verification-disabled branch.".into()),
            ));
        }
    }

    if route_like && is_webhook && !has_webhook_verify {
        issues.push(build_issue(
            "webhook-signature",
            "security",
            // High: a possibly-unverified webhook signature is the same
            // finding class as csrf-missing (unauthenticated state change),
            // not verified secret exposure (matches the
            // registry pin).
            Severity::High,
            "No recognized webhook signature verification in handler",
            "The scanned file looks like an inbound webhook handler, but SiteCMD did not find a recognized provider-SDK or cryptographic verification step. This file-local absence does not establish that the deployed endpoint is unverified: imported middleware, a gateway, or an unrecognized wrapper may authenticate it. If no equivalent control exists before side effects, a reachable caller may be able to submit forged provider events.",
            file,
            find_line(content, "webhook").or_else(|| find_line(content, "stripe")).or_else(|| find_line(content, "svix")),
            Some("A request-reading webhook handler was detected, but this file contains no recognized Stripe `constructEvent`, Svix verification, HMAC verification, or equivalent local pattern. Imported and infrastructure-level controls were not resolved.".into()),
            Some("If verification is not already enforced upstream, use the provider's maintained verification library against the exact raw request bytes before parsing or performing side effects. Validate the expected signing secret/key and any signed timestamp or replay window; support deliberate key rotation without accepting arbitrary keys.".into()),
            Some("With a non-production test fixture and mocked side effects, submit valid, missing, malformed, stale, wrong-key, and body-altered signatures. Confirm only the valid fixture reaches business logic and that failures return the provider-appropriate response without logging secrets or full sensitive payloads.".into()),
        ));
    }

    if route_like && is_webhook && write_handler && !has_idempotency_guard {
        issues.push(build_issue(
            "webhook-idempotency",
            "security",
            Severity::High,
            "No recognized webhook idempotency guard in handler",
            "The scanned file looks like a write-capable webhook handler, but SiteCMD did not find a recognized processed-event claim, unique constraint, upsert, or idempotency helper. This does not establish that duplicates are unhandled because a called service or database constraint may enforce the guarantee. If no such boundary exists, provider retries or concurrent duplicate deliveries can repeat side effects.",
            file,
            find_line(content, "webhook").or_else(|| find_line(content, "event")).or_else(|| first_match_line(content, &WEBHOOK_VERIFY_PATTERNS)),
            Some("A write-capable webhook handler was detected, but no recognized idempotency key, processed-event claim, upsert, unique constraint, or duplicate-event guard appears in this file. Called-service and database behavior were not resolved.".into()),
            Some("If the event is not already deduplicated downstream, atomically claim the provider's stable event identifier with a unique database constraint before applying local effects. Commit local state plus an outbox record together; give non-transactional external effects their own stable idempotency key and resumable state.".into()),
            Some("In an isolated environment with provider-authentic test fixtures and mocked external effects, deliver the same event sequentially and concurrently, then simulate a crash around each side effect. Verify one logical event produces one final effect and retries can safely resume.".into()),
        ));
    }

    if route_like
        && uses_stripe_checkout
        && has_user_controlled_stripe_price
        && !has_stripe_price_allowlist
    {
        issues.push(build_issue(
            "stripe-user-controlled-price",
            "security",
            Severity::High,
            "Possible client-controlled Stripe price selection",
            "Static analysis matched a request-derived price value near Stripe Checkout or Payment Link creation and found no recognized local server-owned catalog mapping. The match does not establish full value flow, effective validation, or fulfillment behavior. If the client can choose any accepted price identifier, it may select an unintended product, billing interval, currency, environment, or entitlement path.",
            file,
            first_match_line(content, &USER_CONTROLLED_STRIPE_PRICE_PATTERNS)
                .or_else(|| find_line(content, "checkout.sessions.create"))
                .or_else(|| find_line(content, "paymentLinks.create")),
            Some("A request-derived price expression and Stripe checkout-creation pattern were detected in the same route, but no recognized local `PRICE_MAP`, lookup-key policy, or allowlist was found. Imported validation and downstream fulfillment checks were not resolved.".into()),
            Some("Map a narrow client intent such as a product/plan key to a server-owned catalog entry. Validate the allowed product, currency, interval, environment, and current business state before creating the session; derive fulfillment entitlements from trusted server catalog data and verified webhook objects, not a client-supplied price or amount.".into()),
            Some("Using Stripe test mode and non-production catalog fixtures, submit every allowed plan plus unknown, cross-environment, inactive, wrong-currency, and unintended price identifiers. Confirm only server-mapped choices create sessions and fulfillment grants exactly the mapped entitlement.".into()),
        ));
    }

    if route_like
        && uses_stripe_checkout
        && has_user_controlled_stripe_redirect
        && !has_redirect_allowlist
    {
        issues.push(build_issue(
            "stripe-user-controlled-redirect",
            "security",
            Severity::High,
            "Possible client-controlled Stripe return URL",
            "Static analysis matched request-derived data near a Stripe `success_url` or `cancel_url` and found no recognized local redirect policy. The match does not establish full value flow, normalization, or imported validation. If an arbitrary external URL reaches the checkout session, the trusted payment flow can return a customer to an attacker-controlled destination.",
            file,
            first_match_line(content, &USER_CONTROLLED_STRIPE_REDIRECT_PATTERNS)
                .or_else(|| find_line(content, "success_url"))
                .or_else(|| find_line(content, "cancel_url")),
            Some("A request-derived expression and Stripe `success_url` or `cancel_url` assignment were detected in the same route, but no recognized same-origin or allowlist check appears locally. Imported helpers and effective URL parsing were not resolved.".into()),
            Some("Construct return URLs from a server-owned canonical origin and a small allowlisted route key or relative-path map. Parse and normalize any permitted input once; reject alternate schemes, credentials, protocol-relative forms, encoded parser-confusion cases, and non-allowlisted hosts.".into()),
            Some("In Stripe test mode, exercise allowed return routes plus external, protocol-relative, credential-bearing, encoded, and mixed-case inputs. Inspect the created test session and confirm every accepted URL resolves to the intended canonical origin.".into()),
        ));
    }

    if route_like && likely_public_endpoint && uses_stripe_checkout && !has_idempotency_guard {
        issues.push(build_issue(
            "stripe-checkout-idempotency",
            "operations",
            Severity::Medium,
            "No recognized idempotency policy for Stripe checkout creation",
            "The scanned public-looking route creates Stripe Checkout or Payment Link work, but SiteCMD did not find a recognized local idempotency key, operation claim, or pending-session reuse check. This does not establish that duplicate creation is possible because an imported service may provide the boundary. If it does not, concurrent submissions or a retry after an ambiguous network failure can create multiple sessions for one logical order.",
            file,
            find_line(content, "checkout.sessions.create")
                .or_else(|| find_line(content, "paymentLinks.create"))
                .or_else(|| find_line(content, "stripe")),
            Some("Stripe checkout creation was detected on a public-looking route, but no recognized local idempotency key, stable operation identifier, or existing-session guard was found. Called-service and order-store behavior were not resolved.".into()),
            Some("If the service layer does not already handle this, derive a stable server-side operation key from the authenticated customer and immutable order/version, persist the order state, and pass the key through Stripe's supported idempotency mechanism. Do not reuse one key after the logical request changes; keep fulfillment independently webhook-idempotent.".into()),
            Some("In Stripe test mode, send simultaneous identical requests and simulate a timeout after Stripe accepts a create call. Retry with the same operation key and verify one logical order maps to one session; verify a materially changed order receives a new key.".into()),
        ));
    }

    if route_like && sensitive_handler && !has_auth {
        issues.push(build_issue(
            "sensitive-auth",
            "security",
            Severity::High,
            "No recognized local auth gate for a sensitive-looking handler",
            "The scanned handler has admin, billing, account, or other sensitive-route indicators, but SiteCMD did not recognize an authentication or authorization gate in the file. This heuristic does not establish that the deployed route is public: framework middleware, a reverse proxy, or an imported wrapper may enforce access before the handler runs.",
            file,
            find_line(content, "POST").or_else(|| find_line(content, "admin")).or_else(|| find_line(content, "billing")),
            Some("Sensitive-route indicators were found, but no recognized session verification, credential validation, role/capability check, or resolved middleware protection was detected for this file. Unrecognized and infrastructure-level controls remain possible.".into()),
            Some("Trace the effective route from edge/proxy and framework middleware to the handler. If no prior control exists, require a verified server-side identity and then enforce the action's role, ownership, tenant, or capability policy before reading sensitive data or performing side effects.".into()),
            Some("Against a production-like non-production route, test unauthenticated, expired/revoked-session, wrong-tenant, low-privilege, and authorized identities. Confirm denials occur before sensitive reads or side effects and produce an auditable server-side decision.".into()),
        ));
    }

    // Laravel authorization often lives in route middleware, so do not infer its
    // absence from a protected controller. WordPress capability checks stay in-file.
    // A webhook authorizes the provider, not a user, and an ownership or tenant
    // predicate in the query is itself the authorization decision.
    if route_like
        && sensitive_handler
        && has_identity_auth
        && !has_authz
        && !middleware_auth_protected
        && !is_webhook
        && !ctx.signals.has_auth_owned_id_scope
        && !ctx.signals.has_tenant_scope_query
    {
        issues.push(build_issue(
            "sensitive-authz",
            "security",
            Severity::High,
            "No recognized local authorization decision for a sensitive handler",
            "The scanned handler contains an identity/authentication pattern and sensitive-route indicators, but SiteCMD did not recognize a role, ownership, tenant, capability, or policy decision in the file. This does not establish missing authorization because route middleware, a called service, or database policy may enforce it elsewhere.",
            file,
            find_line(content, "admin")
                .or_else(|| find_line(content, "billing"))
                .or_else(|| first_match_line(content, &AUTH_PATTERNS)),
            Some("Sensitive-route and identity-check patterns were found, but no recognized local role, ownership, tenant, capability, or policy check was detected. Imported services, framework callbacks, and database row policies were not resolved.".into()),
            Some("Trace the effective authorization boundary. If it is absent, make the action-specific policy explicit using trusted server-derived identity and resource ownership/tenant context; default to deny and enforce the same rule across alternate entry points and background paths.".into()),
            Some("Use production-like test identities to cover anonymous, ordinary, wrong-owner, wrong-tenant, suspended, privileged, and authorized cases. Confirm denied requests cannot observe or change the resource and that alternate endpoints enforce the same policy.".into()),
        ));
    }

    if route_like && write_handler && parses_body && has_cookie_session && !has_csrf {
        issues.push(build_issue(
            "csrf-missing",
            "security",
            Severity::High,
            "No recognized local CSRF defense for a cookie-backed write",
            "The scanned handler appears state-changing and cookie/session-authenticated, but SiteCMD did not recognize a CSRF token check or strict Origin/Referer policy in the file. This absence does not establish exposure because middleware or a framework may enforce anti-forgery checks. If no equivalent control exists and the browser can send the authentication cookie cross-site, another origin may be able to trigger the action.",
            file,
            first_match_line(content, &COOKIE_SESSION_PATTERNS)
                .or_else(|| first_match_line(content, &REQUEST_BODY_PATTERNS)),
            Some("Cookie/session patterns and a body-reading write handler were detected, but no recognized local anti-forgery token or strict origin-verification pattern was found. Middleware and effective cookie attributes were not resolved.".into()),
            Some("If middleware does not already protect the route, require a server-validated anti-forgery token or an exact allowlisted Origin check appropriate to the application's clients. Use Secure, HttpOnly, and an intentional SameSite cookie policy as defense in depth; SameSite alone is not a complete authorization or CSRF design.".into()),
            Some("In a controlled non-production setup, send authenticated state-changing requests from the canonical origin and a different origin, with missing, invalid, replayed, and valid anti-forgery signals. Confirm only policy-compliant requests reach side effects, including simple form content types where applicable.".into()),
        ));
    }

    if let Some(client_directive_line) = client_component_directive_line(content) {
        if has_any(content, &SERVER_DB_PATTERNS) {
            issues.push(build_issue(
                "client-db-access",
                "data",
                Severity::High,
                "Client component contains a server-database access marker",
                "The scanned file has a client-component directive and a recognized server database driver, SQL, or query-layer marker. This co-occurrence does not prove the database code reaches a browser bundle: the reference may be type-only, dead, or rejected by the framework build. If it is bundled or invoked client-side, server credentials or trusted query construction may cross into a browser-controlled boundary.",
                file,
                Some(client_directive_line),
                Some("A client-component directive and a recognized server database client or SQL-access pattern occur in the same file. Import reachability and bundle output were not analyzed; Supabase's browser-oriented Data API is audited separately and does not trigger this rule.".into()),
                Some("Keep server database drivers and credentials behind a server-only module, route, action, loader, or backend service. Expose a narrow authenticated and authorized operation to the client; add the framework's server-only boundary marker where supported.".into()),
                Some("Run a production build, inspect the emitted client dependency graph/source map with an appropriate bundle tool, and exercise the feature. Confirm no server driver, connection material, or server-only query code appears in client artifacts and that the server boundary enforces auth and validation.".into()),
            ));
        }
    }

    // Exempt WordPress hooks because direct $wpdb access is the framework's
    // plugin architecture and exposes no transaction API.
    if route_like && touches_db && write_handler && !wp_hook_handler {
        issues.push(build_issue(
            "db-in-route",
            "architecture",
            Severity::Medium,
            "Route handler contains direct database access",
            "The scanned write-capable route file contains a recognized database-access pattern. This is an architecture review signal, not a vulnerability by itself: small handlers can be clear and correct. As the workflow grows, mixing transport and persistence logic can make shared authorization, validation, transactions, and tests harder to apply consistently.",
            file,
            first_match_line(content, &DB_PATTERNS),
            Some("A write-capable route and a recognized database-access pattern were found in the same file. The scan did not assess handler size, cohesion, or whether a framework convention intentionally keeps the operation local.".into()),
            Some("Review the handler's cohesion. Keep a small, single-use transaction local if that is clearer; otherwise extract the business/persistence operation behind a typed service or repository boundary while leaving request parsing and response shaping in the route.".into()),
            Some("Whether retained or extracted, test authentication, authorization, validation, success, expected database failures, and transaction behavior through the public route. Confirm the refactor does not broaden the callable data operation.".into()),
        ));
    }

    // A repository module's writes belong to separate methods with separate
    // callers, so two of them are never one unatomic operation.
    if route_like
        && touches_db
        && db_write_count >= 2
        && !has_transaction
        && !wp_hook_handler
        && !is_repository_module(&file.relative_path)
    {
        issues.push(build_issue(
            "multi-write-no-transaction",
            "data",
            Severity::High,
            "Possible related database writes without a local transaction",
            "Static analysis counted multiple write-like database operations in a route file and found no recognized local transaction wrapper. It does not establish that the writes belong to one invariant or lack an atomic boundary: a called service, stored procedure, or database API may own the transaction. If the writes must succeed together and no such boundary exists, failure or concurrency can leave partial state.",
            file,
            first_match_line(content, &DB_WRITE_PATTERNS),
            Some(format!(
                "Detected {} {} with no recognized local transaction pattern. Called-service transaction behavior was not resolved.",
                db_write_count,
                if is_js_source_path(&file.relative_path) {
                    "awaited write-like database operations inside one handler body"
                } else {
                    "write-like database-operation matches in this route file"
                }
            )),
            Some("First confirm which writes share an atomic invariant. If they do, execute them through the database's supported transaction boundary at the service/repository layer. For unavoidable external effects, use persisted workflow/outbox state and idempotency rather than pretending a database transaction spans the network.".into()),
            Some("Against a disposable non-production database, inject a controlled failure before and after each related write and run two concurrent attempts. Verify database-only changes roll back together or the persisted workflow resumes safely without duplicate external effects.".into()),
        ));
    }

    // Python raw SQL is owned by the precise `python-sql-injection` check
    // (request taint reaching the query string directly), so `.py` files skip
    // this fuzzier "an f-string/concat SQL appears somewhere" heuristic to
    // avoid double-flagging the same call.
    let is_py = file.relative_path.to_ascii_lowercase().ends_with(".py");
    if route_like && has_unsafe_raw_sql && !is_py {
        issues.push(build_issue(
            "raw-sql-unsafe",
            "data",
            Severity::High,
            "Possible string-built raw SQL in a route handler",
            "Static analysis matched a raw-SQL helper or a query execution pattern near string interpolation, concatenation, or formatted SQL text. The match does not prove attacker-controlled data reaches SQL structure or that the query executes; wrappers and prior allowlisting were not resolved. If untrusted text can change SQL syntax, it may alter the query within the connected database role's privileges.",
            file,
            first_match_line(content, &RAW_SQL_UNSAFE_PATTERNS),
            Some("A recognized raw-SQL helper or string-built query-execution pattern was detected in the route file. Static analysis did not establish request-to-query value flow, runtime reachability, or upstream validation.".into()),
            Some("Use the database driver's bound-parameter API for values. SQL identifiers cannot usually be bound, so map any dynamic table, column, direction, or clause choice through a strict server-owned allowlist; run the application with the least-privileged database role.".into()),
            Some("With a disposable database or mocked query adapter, send inert metacharacter canaries through each relevant input and capture the prepared statement plus bound values. Confirm the SQL structure is invariant and the canary appears only as data; separately test each allowed identifier choice.".into()),
        ));
    }

    if user_controlled_fetch {
        issues.push(build_issue(
            "user-controlled-fetch",
            "security",
            Severity::High,
            "Request-derived URL reaches a server-side fetch pattern",
            "Static analysis matched a request accessor at a server-side HTTP-fetch boundary and found no recognized local destination policy. The match does not prove attacker control, reachability, or the absence of an imported/network-layer guard. If a caller can choose the effective destination, the server may be induced to reach internal services, cloud metadata, or trusted network locations unavailable to that caller.",
            file,
            first_match_line(content, &SSRF_PATTERNS),
            Some("A fetch destination bound to a request value was matched: either a direct request accessor at the call, or a local `url`/`requestUrl`/`targetUrl` bound to a request in this file - assigned from a request accessor, from a parsed body such as `req.json()`, `req.text()` or `req.formData()`, or destructured out of one. No recognized local allowlist or URL policy was found, and full value flow, DNS resolution, redirects, proxies, and egress controls were not evaluated.".into()),
            Some("Prefer a server-owned destination allowlist. Parse once with a standards-compliant URL library; allow only required schemes and ports; reject credentials and private, loopback, link-local, multicast, reserved, and otherwise disallowed resolved addresses for both IPv4 and IPv6. Disable redirects or reapply the complete policy, including DNS/IP checks, on every hop; bound time and response size.".into()),
            Some("In an isolated test network with instrumented mock destinations, exercise allowed hosts plus loopback, private/link-local IPv4 and IPv6, alternate numeric forms, credentials, DNS changes, and redirects to disallowed addresses. Confirm every hop is revalidated and no request reaches the blocked fixtures.".into()),
        ));
    }

    if dangerous_html {
        for offset in unsafe_html_sink_offsets(content) {
            let line = line_number(content, offset);
            let mut issue = build_issue(
                "unsafe-html",
                "security",
                Severity::High,
                "Raw HTML sink has no recognized local sanitization",
                "The reported raw-HTML rendering sink has no recognized local sanitizer. This does not establish XSS: the value may be trusted static content or sanitized by an imported boundary. If attacker-controlled HTML reaches this sink, active markup can execute or alter content in the application's origin unless an appropriate context-aware allowlist policy removes it.",
                file,
                Some(line),
                Some("This raw-HTML sink has no recognized DOMPurify, sanitize-html, escaping, or equivalent sanitization in its value expression. The source and trust level of the rendered value were not resolved.".into()),
                Some("Prefer structured rendering that treats content as text. If the feature intentionally accepts HTML, sanitize at the final rendering boundary with a maintained allowlist policy appropriate to the execution environment; constrain URLs and active elements, keep the sanitizer current, and consider Trusted Types/CSP as defense in depth.".into()),
                Some("In a browser test against non-production fixtures, render an inert corpus covering script tags, event attributes, dangerous URL schemes, SVG/MathML, malformed markup, and mutation cases. Confirm active behavior is removed while explicitly allowed formatting remains; do not use a live exploit payload against production data.".into()),
            );
            issue.id = format!("unsafe-html:{}:{}", file.relative_path, line);
            issues.push(issue);
        }
    }

    outbound::collect_outbound_issues(issues, ctx);
}
