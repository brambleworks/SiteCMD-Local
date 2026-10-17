use super::*;

pub(super) fn collect_route_security_issues(
    issues: &mut Vec<CodeIssue>,
    ctx: &FileAnalysisContext<'_>,
) {
    let file = ctx.file;
    let content = ctx.content;
    let route_like = ctx.signals.route_like;
    let has_auth = ctx.signals.has_auth;
    let has_validation = ctx.signals.has_validation;
    let has_rate_limit = ctx.signals.has_rate_limit;
    let has_cookie_http_only = ctx.signals.has_cookie_http_only;
    let has_cookie_secure = ctx.signals.has_cookie_secure;
    let has_cookie_same_site = ctx.signals.has_cookie_same_site;
    let has_request_token = ctx.signals.has_request_token;
    let has_jwt_decode = ctx.signals.has_jwt_decode;
    let has_jwt_verify = ctx.signals.has_jwt_verify;
    let has_oauth_state_guard = ctx.signals.has_oauth_state_guard;
    let has_oauth_pkce = ctx.signals.has_oauth_pkce;
    let has_oauth_client_secret = ctx.signals.has_oauth_client_secret;
    let has_one_time_token_hash = ctx.signals.has_one_time_token_hash;
    let has_one_time_token_expiry = ctx.signals.has_one_time_token_expiry;
    let has_one_time_token_single_use = ctx.signals.has_one_time_token_single_use;
    let has_one_time_token_raw_lookup = ctx.signals.has_one_time_token_raw_lookup;
    let uses_llm = ctx.signals.uses_llm;
    let parses_body = ctx.signals.parses_body;
    let has_multi_tenant_context = ctx.signals.has_multi_tenant_context;
    let has_tenant_scope_query = ctx.signals.has_tenant_scope_query;
    let has_auth_owned_id_scope = ctx.signals.has_auth_owned_id_scope;
    let write_handler = ctx.signals.write_handler;
    let sensitive_handler = ctx.signals.sensitive_handler;
    let public_risk_endpoint = ctx.signals.public_risk_endpoint;
    let has_upload_size_guard = ctx.signals.has_upload_size_guard;
    let has_upload_type_guard = ctx.signals.has_upload_type_guard;
    let has_storage_write = ctx.signals.has_storage_write;
    let has_user_controlled_storage_key = ctx.signals.has_user_controlled_storage_key;
    let has_scoped_storage_key = ctx.signals.has_scoped_storage_key;
    let likely_public_endpoint = ctx.signals.likely_public_endpoint;
    let oauth_callback_like = ctx.oauth_callback_like;
    let one_time_token_handler = ctx.one_time_token_handler;
    let session_cookie_handler = ctx.session_cookie_handler;
    let upload_handler = ctx.upload_handler;
    let multi_tenant_handler = ctx.multi_tenant_handler;

    if route_like && parses_body && !has_validation {
        issues.push(build_issue(
            if uses_llm { "ai-request-validation" } else { "request-validation" },
            if uses_llm { "ai-safety" } else { "security" },
            Severity::High,
            if uses_llm {
                "No recognized schema validation for parsed AI request"
            } else {
                "No recognized schema validation for parsed request body"
            },
            if uses_llm {
                "This route-like file parses request data and contains recognized AI provider usage, but SiteCMD found no local schema-validation pattern. Imported middleware, a wrapper, or a framework boundary may still validate it. If the effective path accepts malformed, oversized, or out-of-policy fields, invalid work can consume provider quota or reach tools and storage before rejection. Schema validation bounds shape and size; it does not by itself solve prompt injection."
            } else {
                "This route-like file parses request data, but SiteCMD found no local schema-validation pattern. Imported middleware, generated validators, a framework boundary, or downstream typed parsing may still enforce one. If the effective path accepts malformed, oversized, or out-of-range fields, invalid state or unnecessary work can reach persistence and external services."
            },
            file,
            first_match_line(content, &REQUEST_BODY_PATTERNS),
            Some(if uses_llm {
                "AI request parsing was detected, but no local Zod, Valibot, Pydantic, framework-validator, or schema-parse pattern was found; imported validation was not resolved."
                    .into()
            } else {
                "Request parsing was detected, but no local Zod, Valibot, Pydantic, framework-validator, or schema-parse pattern was found; imported validation was not resolved."
                    .into()
            }),
            Some(if uses_llm {
                "Trace the effective validation boundary. Enforce request byte/field limits before expensive parsing where possible, then validate prompt inputs, tool choices, model settings, and authorization-relevant identifiers against a server-owned schema before provider or tool work starts."
                    .into()
            } else {
                "Trace any inherited validator, then enforce request byte/field limits and a server-owned schema at the trusted boundary before database writes, external calls, or rendering. Keep authorization separate from shape validation."
                    .into()
            }),
            Some(if uses_llm {
                "Test valid, missing, wrong-type, out-of-range, unknown-field, and oversized inputs. Confirm invalid requests fail with the documented 4xx response before provider, tool, storage, or billing work starts."
                    .into()
            } else {
                "Test valid, missing, wrong-type, out-of-range, unknown-field, and oversized inputs. Confirm invalid requests fail with the documented 4xx response before persistence or external side effects.".into()
            }),
        ));
    }

    if likely_public_endpoint && !uses_llm && !has_rate_limit {
        let route_reason = ctx
            .signals
            .route_evidence
            .as_deref()
            .unwrap_or("a route handler");
        let risk_match = ctx.signals.public_risk_match.as_ref();
        let surface = match risk_match {
            Some(risk) => format!("matched the abuse-sensitive word {}", risk.describe()),
            None => "parses request input or writes without a recognized auth gate".to_string(),
        };
        // A word matched in the path names no line in the file, so point at the
        // handler the route was recognized by instead of an unrelated match.
        let anchor_line = if risk_match.is_some_and(|risk| risk.in_route_path()) {
            route_handler_marker_line(content)
                .or_else(|| first_match_line(content, &REQUEST_BODY_PATTERNS))
        } else {
            first_match_line(content, &PUBLIC_RISK_ENDPOINT_PATTERNS)
                .or_else(|| first_match_line(content, &REQUEST_BODY_PATTERNS))
        };
        issues.push(build_issue(
            "public-endpoint-rate-limit",
            "security",
            if public_risk_endpoint { Severity::High } else { Severity::Medium },
            "No recognized rate limit for public-looking route",
            "This file is route-like and shows an abuse-sensitive surface, but SiteCMD found no local limiter or inherited middleware signal. Static source does not establish actual internet exposure, edge policy, authentication, or gateway quotas. If the effective path is public and performs abuse-sensitive or expensive work without a caller-aware limit, automation and accidental loops can consume capacity or amplify brute-force attempts.",
            file,
            anchor_line.or_else(|| find_line(content, "export async function post(")),
            Some(format!(
                "Route-like by {route_reason}; the file {surface}. No recognized local rate-limit pattern was found; edge, gateway, and custom middleware controls were not resolved."
            )),
            Some("Trace every deployment entry point and inventory effective edge, gateway, account, user, tenant, and network controls. If a gap remains, enforce an atomic shared limit before expensive work, with separate policies for authenticated and pre-auth abuse and a documented fail-open or fail-closed choice.".into()),
            Some("Load-test bursts and sustained traffic across multiple identities, networks, and application instances. Confirm rejected requests start no protected work, allowed callers remain fair, and HTTP throttles return the intended 429 and Retry-After behavior.".into()),
        ));
    }

    if upload_handler && (!has_upload_size_guard || !has_upload_type_guard) {
        let mut missing_guards = Vec::new();
        if !has_upload_size_guard {
            missing_guards.push("file size");
        }
        if !has_upload_type_guard {
            missing_guards.push("file type");
        }

        let severity = if likely_public_endpoint || !has_auth || missing_guards.len() > 1 {
            Severity::High
        } else {
            Severity::Medium
        };

        issues.push(build_issue(
            "upload-validation",
            "security",
            severity,
            "Upload handler lacks recognized size or content-type guards",
            "This file matches an upload flow, but SiteCMD did not recognize one or more local size or type controls. A reverse proxy, signed-upload policy, object store, framework, or downstream processor may still enforce them. If the effective path accepts oversized or unexpected content, it can consume bandwidth, storage, memory, or parser resources and expose unsafe downstream behavior.",
            file,
            first_match_line(content, &UPLOAD_FILE_INPUT_PATTERNS)
                .or_else(|| first_match_line(content, &STORAGE_WRITE_PATTERNS))
                .or_else(|| first_match_line(content, &UPLOAD_PATTERNS)),
            Some(format!(
                "Upload flow detected, but no recognized local {} check was found; upstream and storage-policy controls were not resolved.",
                missing_guards.join(" or ")
            )),
            Some("Trace limits at the proxy, request parser, signed-upload policy, object store, and processor. Enforce a streaming byte ceiling at the earliest trusted boundary, allowlist the feature's expected formats using content inspection appropriate to the parser, generate server-owned object metadata, and quarantine content before risky transformation or public serving.".into()),
            Some("In an isolated upload environment, test just-below/above limits, truncated files, extension/MIME/content mismatches, polyglots, decompression or image-dimension expansion, and interrupted streams. Confirm rejection happens before unintended storage, processing, or public access.".into()),
        ));
    }

    if upload_handler
        && has_storage_write
        && has_user_controlled_storage_key
        && !has_scoped_storage_key
    {
        let severity = if has_auth || likely_public_endpoint || has_multi_tenant_context {
            Severity::High
        } else {
            Severity::Medium
        };

        issues.push(build_issue(
            "upload-key-scope",
            "security",
            severity,
            "Request-derived upload key lacks recognized ownership scope",
            "This file appears to use a raw filename or request-derived object key for a storage write, but SiteCMD found no recognized local owner, tenant, or workspace component. A server-generated opaque key, database ownership record, bucket policy, or wrapper may still isolate access. If the client can choose a shared key without authoritative ownership enforcement, uploads may collide with or overwrite another principal's object.",
            file,
            first_match_line(content, &USER_CONTROLLED_STORAGE_KEY_PATTERNS)
                .or_else(|| first_match_line(content, &STORAGE_WRITE_PATTERNS)),
            Some("A storage write and request-derived key or raw filename were detected, but no recognized local user, workspace, tenant, owner, or opaque-key generation pattern was found; database and bucket policy were not resolved.".into()),
            Some("Trace object-key construction and every read, overwrite, list, and delete policy. Generate an opaque key server-side, store authoritative owner/tenant metadata, and authorize each operation from verified server context. Preserve the original filename only as sanitized display metadata when needed.".into()),
            Some("Using two users or tenants, test the same filename and guessed or copied object keys across create, overwrite, read, list, and delete operations. Confirm object identity is collision-resistant and cross-owner operations are denied.".into()),
        ));
    }

    if route_like
        && has_jwt_decode
        && !has_jwt_verify
        && (has_request_token
            || sensitive_handler
            || file.relative_path.to_ascii_lowercase().contains("auth"))
    {
        issues.push(build_issue(
            "jwt-decode-without-verify",
            "security",
            Severity::High,
            "JWT decode found without recognized local verification",
            "This route-like file decodes JWT-shaped data, but SiteCMD found no recognized verifier in the scanned file. An imported authentication layer may verify it, or the decoded claims may be used only for non-security display. If unverified claims influence identity, tenant, role, or authorization, a caller can supply forged values because decoding alone does not authenticate a token.",
            file,
            first_match_line(content, &JWT_DECODE_PATTERNS)
                .or_else(|| first_match_line(content, &REQUEST_TOKEN_PATTERNS)),
            Some("A JWT decode-style pattern was detected without a recognized local jwt.verify, jwtVerify, getToken, or equivalent verifier; imported authentication and claim usage were not resolved.".into()),
            Some("Trace every decoded claim use. For security decisions, use the identity provider or framework's maintained server verifier and pin the expected issuer, audience, algorithms, key source, time claims, and token type; perform authorization separately after verification.".into()),
            Some("With test keys, exercise a valid token plus edited payload, wrong signature/key, disallowed algorithm, wrong issuer/audience/type, expired, not-yet-valid, and revoked cases. Confirm no unverified claim reaches identity or authorization decisions.".into()),
        ));
    }

    if oauth_callback_like && !has_oauth_state_guard {
        issues.push(build_issue(
            "oauth-callback-state",
            "security",
            Severity::High,
            "No recognized OAuth state binding in manual callback",
            "This file resembles a manual OAuth authorization-code callback, but SiteCMD found no local state read-and-compare pattern. A maintained OAuth library, upstream callback handler, or another protocol-specific browser binding may still supply it. If the callback is not bound to the browser session that initiated the flow, login or account-linking CSRF and response mixups may be possible.",
            file,
            first_match_line(content, &OAUTH_CODE_PATTERNS)
                .or_else(|| first_match_line(content, &OAUTH_TOKEN_EXCHANGE_PATTERNS)),
            Some("An authorization-code exchange pattern was detected without a recognized local state read-and-compare, initiating-session lookup, or library callback verifier; imported flow state was not resolved.".into()),
            Some("Trace the OAuth library and full authorization request. If no equivalent browser-flow binding exists, generate a high-entropy single-use state value, bind it to the initiating session and intended return context with a short expiry, and validate and consume it before token exchange. PKCE protects the code and is not a universal replacement for this browser binding.".into()),
            Some("In an isolated provider/test flow, exercise correct, missing, mismatched, expired, replayed, and cross-session state values. Confirm every invalid callback is rejected and consumes no code before the token exchange.".into()),
        ));
    }

    if oauth_callback_like && !has_oauth_client_secret && !has_oauth_pkce {
        issues.push(build_issue(
            "oauth-callback-pkce",
            "security",
            // Keep emitted severity aligned with the High policy override.
            Severity::High,
            "No recognized PKCE or client authentication in manual code exchange",
            "This file resembles a manual authorization-code exchange, but SiteCMD found no local PKCE code_verifier or client-secret pattern. A maintained library, private_key_jwt, mTLS, upstream broker, or other confidential-client authentication may still apply. If this is a public client without PKCE, an intercepted authorization code has no proof-of-possession binding to the initiating client.",
            file,
            first_match_line(content, &OAUTH_TOKEN_EXCHANGE_PATTERNS)
                .or_else(|| first_match_line(content, &OAUTH_CODE_PATTERNS)),
            Some("A manual authorization-code exchange was detected without a recognized local client secret or PKCE code_verifier; library-managed PKCE and other client-authentication methods were not resolved.".into()),
            Some("Confirm the provider, grant, and client type. Prefer a maintained OAuth client that generates a high-entropy verifier, sends an S256 code challenge, binds the verifier to the initiating session, and supplies it once at exchange. Configure the provider's required confidential-client authentication separately; a browser or native public client cannot keep a client secret.".into()),
            Some("In an isolated provider/test flow, verify the token endpoint accepts the correct verifier and rejects missing, mismatched, replayed, and cross-session verifiers. Also confirm the registered redirect URI and configured client-authentication method are enforced.".into()),
        ));
    }

    if one_time_token_handler && has_one_time_token_raw_lookup && !has_one_time_token_hash {
        issues.push(build_issue(
            "one-time-token-raw-lookup",
            "security",
            Severity::High,
            "Incoming one-time token appears in raw storage lookup",
            "This file resembles a reset, magic-link, verification, or invite flow and contains a storage lookup using an incoming token-shaped value. SiteCMD found no recognized local hashing step, but an imported helper or database expression may transform it. If the bearer token is stored in reusable raw form, a database or backup disclosure can reveal immediately usable links until they expire or are consumed.",
            file,
            first_match_line(content, &ONE_TIME_TOKEN_RAW_LOOKUP_PATTERNS)
                .or_else(|| first_match_line(content, &REQUEST_TOKEN_PATTERNS)),
            Some("A reset/invite-style handler appears to use an incoming token in a storage lookup, but no recognized local hash/HMAC step was found; imported and database transforms were not resolved.".into()),
            Some("Trace token generation, storage, and lookup. Generate a high-entropy random bearer token, send only the raw value to the user, and store a one-way digest or keyed digest appropriate to the token entropy and threat model. Query by that derived value, with expiry and atomic single-use enforcement kept separate.".into()),
            Some("In an authorized isolated environment, create a token and inspect the stored representation without printing the bearer value. Confirm the raw token is absent from storage/logs, the derived lookup succeeds once within expiry, and altered values fail.".into()),
        ));
    }

    if one_time_token_handler && !has_one_time_token_expiry {
        issues.push(build_issue(
            "one-time-token-no-expiry",
            "security",
            Severity::High,
            "No recognized expiry check in one-time-token handler",
            "This file resembles a one-time-token flow, but SiteCMD found no local expiration field or time comparison. An imported service, database predicate, or provider may still enforce expiry. If no effective check exists, a leaked reset, invite, verification, or magic-link token can remain usable beyond its intended lifetime.",
            file,
            first_match_line(content, &REQUEST_TOKEN_PATTERNS)
                .or_else(|| first_match_line(content, &ONE_TIME_TOKEN_FLOW_PATTERNS)),
            Some("A one-time-token handler was detected without a recognized local expiresAt, expiration, TTL, or time-predicate pattern; imported and database enforcement were not resolved.".into()),
            Some("Trace the effective lookup. Store an explicit expiry and require it in the same authoritative lookup or atomic claim used to consume the token, using a trusted server/database clock and a feature-specific lifetime. Reject expiry before account or session changes and clean up stale records separately.".into()),
            Some("With an injectable clock in an isolated test, check just-before, exact-boundary, and just-after expiry plus clock-skew policy. Confirm an expired token cannot change credentials, accept an invite, verify an account, or create a session.".into()),
        ));
    }

    if one_time_token_handler && write_handler && !has_one_time_token_single_use {
        issues.push(build_issue(
            "one-time-token-no-single-use",
            "security",
            // Keep emitted severity aligned with the High policy override.
            Severity::High,
            "No recognized atomic single-use transition for one-time token",
            "This file resembles a one-time-token flow that changes account state, but SiteCMD found no local deletion or consumed marker. An imported service or database procedure may still claim the token. If the token is not atomically claimed with expiry enforcement, sequential or concurrent replay can repeat the protected action.",
            file,
            first_match_line(content, &ONE_TIME_TOKEN_FLOW_PATTERNS)
                .or_else(|| first_match_line(content, &REQUEST_TOKEN_PATTERNS)),
            Some("A reset/invite-style write handler was detected, but no recognized local delete, usedAt, consumedAt, atomic claim, or equivalent invalidation pattern was found; imported data-layer behavior was not resolved.".into()),
            Some("Claim the unexpired token atomically with a conditional update/delete or transaction before or together with the protected state change, and make downstream work idempotent. A read followed by a later delete can race; define recovery so a failed protected action does not silently resurrect or double-consume the token.".into()),
            Some("Run sequential and truly concurrent redemption attempts against an isolated database. Confirm at most one claim and protected state transition succeeds, expired tokens fail, and retry behavior after a mid-transaction failure matches the documented policy.".into()),
        ));
    }

    if session_cookie_handler
        && (!has_cookie_http_only || !has_cookie_secure || !has_cookie_same_site)
    {
        let mut missing_flags = Vec::new();
        if !has_cookie_http_only {
            missing_flags.push("httpOnly");
        }
        if !has_cookie_secure {
            missing_flags.push("secure");
        }
        if !has_cookie_same_site {
            missing_flags.push("sameSite");
        }

        let severity = if !has_cookie_http_only || !has_cookie_secure {
            Severity::High
        } else {
            Severity::Medium
        };

        issues.push(build_issue(
            "session-cookie-flags",
            "security",
            severity,
            "Cookie write lacks recognized explicit session hardening flags",
            "This file appears to write a session- or auth-named cookie without one or more recognized local options. Framework defaults, environment branches, a proxy, or a centralized cookie helper may still set the effective attributes. If the emitted cookie lacks HttpOnly, Secure, or an intentional SameSite policy, exposure to script access, cleartext transport, or cross-site delivery can widen depending on the missing flag and authentication flow.",
            file,
            first_match_line(content, &COOKIE_WRITE_PATTERNS)
                .or_else(|| first_match_line(content, &SESSION_COOKIE_NAME_PATTERNS)),
            Some(format!(
                "This session-style cookie write does not show recognized local {} protection; effective response headers and framework defaults were not inspected.",
                missing_flags.join(", ")
            )),
            Some("Inspect the effective Set-Cookie header and authentication flow first. For bearer sessions, normally use HttpOnly and Secure on HTTPS, choose SameSite deliberately for same-site versus cross-site/OAuth needs, minimize Domain/Path and lifetime, and consider __Host- or __Secure- prefix contracts. Add CSRF protection when cookies authenticate state changes; SameSite is defense in depth, not universal authorization.".into()),
            Some("Through the real proxy in production-like HTTPS, inspect Set-Cookie and browser storage for login, refresh, OAuth return, logout, and expiry. Confirm the intended attributes, prefix contract, cross-site behavior, CSRF defense, rotation, and revocation without relying only on source options.".into()),
        ));
    }

    // A webhook has no signed-in principal to scope by: the provider signature
    // is the whole authorization story.
    if multi_tenant_handler
        && !ctx.signals.is_webhook
        && !has_tenant_scope_query
        && !has_auth_owned_id_scope
    {
        issues.push(build_issue(
            "tenant-scope-missing",
            "security",
            Severity::High,
            "No recognized tenant or owner scope in authenticated handler",
            "This file resembles an authenticated workspace, organization, team, tenant, or account handler and contains database activity, but SiteCMD found no local tenant or authenticated-owner predicate. An imported repository, database RLS policy, or authorization service may still enforce isolation. If the effective query trusts only a record id or request-supplied tenant, one authenticated principal may access another tenant's data.",
            file,
            first_match_line(content, &DB_QUERY_PATTERNS)
                .or_else(|| first_match_line(content, &DB_WRITE_PATTERNS))
                .or_else(|| first_match_line(content, &AUTH_PATTERNS)),
            Some("The handler looks multi-tenant and authenticated, but no recognized local orgId, workspaceId, tenantId, accountId, ownerId, authenticated-self predicate, or policy call was found; repository and RLS enforcement were not resolved.".into()),
            Some("Trace the effective query and policy boundary. Derive the active tenant and membership from a verified server session, not an untrusted request field, and scope every read, write, uniqueness check, cache/object key, job, search, and export or enforce an equivalent tested database policy. Keep privileged cross-tenant operations explicit and audited.".into()),
            Some("With two users in different tenants and an authorized admin case, test direct ids plus list, create, update, delete, search, export, cache, and background-job paths. Confirm cross-tenant access is denied unless the explicit privileged role permits it.".into()),
        ));
    }

    if let Some(line) = ctx.signals.open_redirect_line {
        issues.push(build_issue(
            "open-redirect",
            "security",
            Severity::High,
            "Possible request-derived redirect lacks recognized local allowlist",
            "This file contains both a request-derived redirect-style value and a redirect sink, but SiteCMD did not resolve full value flow or find a local same-origin/allowlist helper. Imported validation or a server-owned intermediate value may make the path safe. If an attacker-controlled absolute or scheme-relative target reaches the sink, a trusted application URL can redirect users to an attacker-chosen site.",
            file,
            Some(line),
            Some("A request-derived redirect-style field and redirect sink were detected in the same handler, but value flow was not proven and no recognized local safeRedirect, same-origin, or relative-path guard was found.".into()),
            Some("Trace the actual target into the sink. Prefer named routes or a server-owned map of return destinations. If URLs are required, parse and normalize with a maintained helper and allowlist exact origins or application paths after accounting for scheme-relative URLs, backslashes, encoding, user-info, and proxy origin handling.".into()),
            Some("In a route test, try approved paths plus absolute, scheme-relative, encoded, backslash, and user-info variants targeting example.invalid. Confirm only documented destinations survive the same normalization and proxy configuration used in production.".into()),
        ));
    }
}
