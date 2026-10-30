use super::*;

pub(super) struct FileAnalysisSignals {
    pub(super) lower: String,
    pub(super) pattern_registry: bool,
    pub(super) scanner_rule_impl: bool,
    pub(super) route_like: bool,
    /// Why the file is route-like, phrased for evidence text.
    pub(super) route_evidence: Option<String>,
    pub(super) wp_hook_handler: bool,
    pub(super) middleware_auth_protected: bool,
    pub(super) has_identity_auth: bool,
    pub(super) has_authz: bool,
    pub(super) has_auth: bool,
    pub(super) has_validation: bool,
    pub(super) has_rate_limit: bool,
    pub(super) has_cors_wildcard: bool,
    pub(super) has_cors_credentials: bool,
    pub(super) has_runtime_cors_config: bool,
    pub(super) has_cookie_session: bool,
    pub(super) has_cookie_write: bool,
    pub(super) has_session_cookie_name: bool,
    pub(super) has_cookie_http_only: bool,
    pub(super) has_cookie_secure: bool,
    pub(super) has_cookie_same_site: bool,
    pub(super) has_csrf: bool,
    pub(super) has_request_token: bool,
    pub(super) has_jwt_decode: bool,
    pub(super) has_jwt_verify: bool,
    pub(super) has_oauth_code: bool,
    pub(super) has_oauth_token_exchange: bool,
    pub(super) has_oauth_state_guard: bool,
    pub(super) has_oauth_pkce: bool,
    pub(super) has_oauth_client_secret: bool,
    pub(super) has_one_time_token_flow: bool,
    pub(super) has_one_time_token_hash: bool,
    pub(super) has_one_time_token_expiry: bool,
    pub(super) has_one_time_token_single_use: bool,
    pub(super) has_one_time_token_raw_lookup: bool,
    pub(super) has_timeout: bool,
    pub(super) has_retry_guard: bool,
    pub(super) has_concurrency_guard: bool,
    pub(super) uses_outbound_http: bool,
    pub(super) skips_internal_http: bool,
    pub(super) uses_llm: bool,
    pub(super) uses_ai_sdk: bool,
    pub(super) has_llm_spend_guard: bool,
    pub(super) has_llm_usage_logging: bool,
    pub(super) has_llm_observability: bool,
    pub(super) has_llm_output_cap: bool,
    pub(super) has_llm_cache_dedupe: bool,
    pub(super) has_user_controlled_llm_model: bool,
    pub(super) has_user_controlled_llm_settings: bool,
    pub(super) has_model_allowlist: bool,
    pub(super) has_numeric_bounds: bool,
    pub(super) has_loop_pattern: bool,
    pub(super) has_loop_guard: bool,
    pub(super) parses_body: bool,
    pub(super) is_webhook: bool,
    pub(super) has_webhook_verify: bool,
    pub(super) has_idempotency_guard: bool,
    pub(super) touches_db: bool,
    pub(super) has_db_query: bool,
    pub(super) has_multi_tenant_context: bool,
    pub(super) has_tenant_scope_query: bool,
    pub(super) has_auth_owned_id_scope: bool,
    pub(super) db_write_count: usize,
    pub(super) has_transaction: bool,
    pub(super) has_unsafe_raw_sql: bool,
    pub(super) dangerous_html: bool,
    pub(super) write_handler: bool,
    pub(super) sensitive_handler: bool,
    pub(super) public_risk_endpoint: bool,
    /// The abuse-sensitive word that made the route look public, and where it
    /// was found.
    pub(super) public_risk_match: Option<PublicRiskMatch>,
    pub(super) has_upload_flow: bool,
    pub(super) has_upload_input: bool,
    pub(super) has_upload_size_guard: bool,
    pub(super) has_upload_type_guard: bool,
    pub(super) has_storage_write: bool,
    pub(super) has_user_controlled_storage_key: bool,
    pub(super) has_scoped_storage_key: bool,
    pub(super) has_payment_flow: bool,
    pub(super) uses_stripe_checkout: bool,
    pub(super) has_user_controlled_stripe_price: bool,
    pub(super) open_redirect_line: Option<u32>,
    pub(super) has_redirect_allowlist: bool,
    pub(super) has_user_controlled_stripe_redirect: bool,
    pub(super) has_stripe_price_allowlist: bool,
    pub(super) has_email_flow: bool,
    pub(super) user_controlled_fetch: bool,
    pub(super) likely_public_endpoint: bool,
}

impl FileAnalysisSignals {
    /// Computes the per-file signals plus the small `FileSignalSummary` the
    /// serial operations phase consumes, so corpus-level booleans never
    /// require re-scanning file content after the parallel phase.
    pub(super) fn from_file(
        file: &SourceFile,
        laravel_protection: &LaravelRouteProtection,
    ) -> (Self, FileSignalSummary) {
        let content = &file.content;
        let lower = content.to_lowercase();
        let pattern_registry = looks_like_pattern_registry(content);
        let scanner_rule_impl =
            content.contains("impl Check for") && content.contains("CheckStatus::");
        let server_action_like = is_server_action_like(&lower);
        // Laravel route files supply controller reachability, auth, and throttle
        // evidence that controller files do not contain.
        let laravel_controller = laravel_protection.status_for(&file.relative_path);
        let middleware_auth_protected = laravel_controller
            .map(|status| status.auth_protected)
            .unwrap_or(false)
            || laravel_protection.routes_file_is_auth_protected(&file.relative_path);
        let middleware_throttled = laravel_controller
            .map(|status| status.throttled)
            .unwrap_or(false);
        let route_evidence_raw = route_like_evidence(file, &lower);
        let route_like_raw = route_evidence_raw.is_some();
        let route_like = !pattern_registry
            && (route_like_raw || server_action_like || laravel_controller.is_some());
        let route_evidence = route_evidence_raw
            .or_else(|| server_action_like.then(|| "a `use server` directive".to_string()))
            .or_else(|| {
                laravel_controller
                    .is_some()
                    .then(|| "a Laravel route manifest entry".to_string())
            })
            .filter(|_| route_like);
        let wp_hook_handler = has_wp_handler_registration(&lower);
        // Logged-in WordPress actions prove identity; REST permission callbacks
        // also count as authorization because their bodies may live elsewhere.
        let wp_rest_guarded = wp_rest_routes_all_have_permission_callbacks(&lower);
        let has_auth_pattern_evidence = has_any(content, &AUTH_PATTERNS);
        let has_identity_auth =
            has_auth_pattern_evidence || has_wp_logged_in_action(&lower) || wp_rest_guarded;
        let has_authz = has_any(content, &AUTHZ_PATTERNS) || wp_rest_guarded;
        let has_token_guard = has_inline_secret_guard(&lower);
        // Route middleware proves an access gate without creating in-file
        // identity evidence or an authorization follow-up.
        let has_auth = has_identity_auth || has_token_guard || middleware_auth_protected;
        let has_validation = has_any(content, &VALIDATION_PATTERNS);
        let has_rate_limit = has_rate_limit_evidence(content) || middleware_throttled;
        let has_cors_wildcard = has_any(content, &CORS_WILDCARD_PATTERNS);
        let has_cors_credentials = has_any(content, &CORS_CREDENTIAL_PATTERNS);
        let has_runtime_cors_config = has_any(content, &CORS_RUNTIME_PATTERNS);
        let has_cookie_session = has_any(content, &COOKIE_SESSION_PATTERNS);
        let has_cookie_write = has_any(content, &COOKIE_WRITE_PATTERNS);
        let has_session_cookie_name = has_any(content, &SESSION_COOKIE_NAME_PATTERNS);
        let has_cookie_http_only = has_any(content, &COOKIE_HTTP_ONLY_PATTERNS);
        let has_cookie_secure = has_any(content, &COOKIE_SECURE_PATTERNS);
        let has_cookie_same_site = has_any(content, &COOKIE_SAMESITE_PATTERNS);
        // Laravel manifests never show CSRF evidence in-file: VerifyCsrfToken
        // runs at the kernel middleware-group layer for web routes, and api
        // routes authenticate statelessly. Next.js Server Actions carry their
        // own anti-forgery boundary: the framework rejects an invocation whose
        // Origin does not match the Host before the action body runs.
        let has_csrf = has_any(content, &CSRF_PATTERNS)
            || laravel_protection.is_routes_manifest(&file.relative_path)
            || server_action_like;
        let has_request_token = has_any(content, &REQUEST_TOKEN_PATTERNS);
        let has_jwt_decode = has_any(content, &JWT_DECODE_PATTERNS);
        let has_jwt_verify = has_any(content, &JWT_VERIFY_PATTERNS);
        let has_oauth_code = has_any(content, &OAUTH_CODE_PATTERNS);
        let has_oauth_token_exchange = has_any(content, &OAUTH_TOKEN_EXCHANGE_PATTERNS);
        let has_oauth_state_guard = has_any(content, &OAUTH_STATE_GUARD_PATTERNS);
        let has_oauth_pkce = has_any(content, &OAUTH_PKCE_PATTERNS);
        let has_oauth_client_secret = has_any(content, &OAUTH_CLIENT_SECRET_PATTERNS);
        let has_one_time_token_flow = has_any(content, &ONE_TIME_TOKEN_FLOW_PATTERNS)
            || file.relative_path.to_ascii_lowercase().contains("invite")
            || file.relative_path.to_ascii_lowercase().contains("reset")
            || file.relative_path.to_ascii_lowercase().contains("magic");
        let has_one_time_token_hash = has_any(content, &ONE_TIME_TOKEN_HASH_PATTERNS);
        let has_one_time_token_expiry = has_any(content, &ONE_TIME_TOKEN_EXPIRY_PATTERNS);
        let has_one_time_token_single_use = has_any(content, &ONE_TIME_TOKEN_SINGLE_USE_PATTERNS);
        let has_one_time_token_raw_lookup = has_any(content, &ONE_TIME_TOKEN_RAW_LOOKUP_PATTERNS);
        let has_timeout = has_any(content, &TIMEOUT_PATTERNS);
        let has_retry_guard = has_any(content, &RETRY_PATTERNS);
        let has_concurrency_guard = has_any(content, &CONCURRENCY_PATTERNS);
        // Stripe signature checks, bundled-asset loads, Worker fetch handlers,
        // and assets bindings look outbound but stay local. Blanking these
        // shapes preserves offsets and leaves real remote calls detectable.
        let uses_outbound_http =
            !pattern_registry && has_any(&outbound_view(content), &OUTBOUND_HTTP_PATTERNS);
        let skips_internal_http = has_any(content, &OUTBOUND_HTTP_RETRY_SKIP_PATTERNS);
        let uses_llm = !pattern_registry && has_any(content, &LLM_PATTERNS);
        let uses_ai_sdk = !pattern_registry
            && (content.contains("streamText(")
                || content.contains("generateText(")
                || content.contains("generateObject(")
                || content.contains("streamObject(")
                || content.contains("@ai-sdk/")
                || content.contains("from \"ai\"")
                || content.contains("from 'ai'")
                || content.contains("require(\"ai\")")
                || content.contains("require('ai')"));
        let has_llm_spend_guard = has_any(content, &LLM_SPEND_GUARD_PATTERNS);
        let has_llm_usage_logging = has_any(content, &LLM_USAGE_LOGGING_PATTERNS);
        let has_llm_observability_context = has_any(content, &LLM_OBSERVABILITY_CONTEXT_PATTERNS);
        let has_llm_observability = has_llm_usage_logging && has_llm_observability_context;
        let has_llm_output_cap = has_any(content, &LLM_TOKEN_CAP_PATTERNS);
        let has_llm_cache_dedupe = has_any(content, &LLM_CACHE_DEDUPE_PATTERNS);
        let has_user_controlled_llm_model = has_any(content, &USER_CONTROLLED_LLM_MODEL_PATTERNS);
        let has_user_controlled_llm_settings =
            has_any(content, &USER_CONTROLLED_LLM_SETTING_PATTERNS);
        let has_model_allowlist = has_any(content, &MODEL_ALLOWLIST_PATTERNS);
        let has_numeric_bounds = has_any(content, &NUMERIC_BOUND_PATTERNS);
        let has_loop_pattern = has_any(content, &LOOP_PATTERNS);
        let has_loop_guard = has_any(content, &LOOP_GUARD_PATTERNS);
        // Presence checks do not carry PHP request values into sinks.
        let body_scan_content = PHP_PRESENCE_CHECK_PATTERN.replace_all(content, "");
        let parses_body = has_any(&body_scan_content, &REQUEST_BODY_PATTERNS)
            || (server_action_like && has_any(content, &SERVER_ACTION_INPUT_PATTERNS));
        // Require both a webhook path hint and inbound-request evidence so DTOs
        // and support files under `webhooks/` do not become handlers.
        let path_lower = file.relative_path.to_lowercase();
        let filename_hints_webhook =
            path_lower.contains("webhook") || path_lower.contains("/hooks/");
        let body_provider_signal = lower.contains("stripe-signature")
            // A bare `svix` also matches unrelated imports and class names.
            || lower.contains("svix-signature")
            || lower.contains("constructevent")
            || lower.contains("x-hub-signature")
            || lower.contains("x-github-signature")
            || lower.contains("x-line-signature")
            || lower.contains("x-slack-signature");
        // Webhook receivers may consume raw text or bytes instead of parsed
        // JSON, so both forms count as inbound payload handling.
        let reads_inbound_body = parses_body
            || lower.contains("request.text(")
            || lower.contains("req.text(")
            || lower.contains(".rawbody")
            || lower.contains("rawbody");
        let is_webhook =
            filename_hints_webhook && (body_provider_signal || (route_like && reads_inbound_body));
        // Providers that sign with a static shared secret are authenticated by
        // the same header-and-compare gate the token guard already recognizes.
        let has_webhook_verify =
            has_any(content, &WEBHOOK_VERIFY_PATTERNS) || (is_webhook && has_token_guard);
        let has_idempotency_guard = has_any(content, &IDEMPOTENCY_PATTERNS);
        let touches_db_raw = has_any(content, &DB_PATTERNS);
        let touches_db = !pattern_registry && touches_db_raw;
        let db_write_count = max_db_writes_per_handler(file, content);
        let has_db_query = has_any(content, &DB_QUERY_PATTERNS) || db_write_count > 0;
        let has_multi_tenant_context = has_any(content, &MULTI_TENANT_CONTEXT_PATTERNS);
        let has_tenant_scope_query = has_any(content, &TENANT_SCOPE_QUERY_PATTERNS);
        let has_auth_owned_id_scope =
            has_any(content, &AUTH_OWNED_ID_SCOPE_PATTERNS) || has_session_scoped_binding(content);
        let has_transaction = has_any(content, &TRANSACTION_PATTERNS);
        let has_unsafe_raw_sql = has_any(content, &RAW_SQL_UNSAFE_PATTERNS);
        // Ignore quoted sink definitions while preserving PHP markup sinks in
        // quoted HTML attributes; see `has_any_unquoted`.
        let dangerous_html = !pattern_registry
            && has_any_unquoted(content, &DANGEROUS_HTML_PATTERNS)
            && !is_json_ld_serialization_sink(content);
        let ssrf_like = has_any(content, &SSRF_PATTERNS);
        let has_ssrf_guard = has_any(content, &SSRF_GUARD_PATTERNS);
        let write_handler_raw = is_write_handler(&lower);
        let write_handler = write_handler_raw || server_action_like;
        // The lowercased content already covers every case of the original,
        // because each risk pattern is lowercase, so one lookup answers both
        // the predicate and the evidence wording.
        let public_risk_match = public_risk_match(file, &lower);
        let public_risk_endpoint = public_risk_match.is_some();
        let has_upload_input = has_any(content, &UPLOAD_FILE_INPUT_PATTERNS);
        let has_storage_write = has_any(content, &STORAGE_WRITE_PATTERNS);
        // `formData()`, `File`, and `Blob` appear in every form-post handler, so
        // an upload flow needs a named file input, a multipart body, or a
        // storage write alongside them.
        let has_upload_flow = has_any(content, &UPLOAD_PATTERNS)
            && (has_upload_input || has_storage_write || lower.contains("multipart"));
        let has_upload_size_guard = has_any(content, &UPLOAD_SIZE_GUARD_PATTERNS);
        let has_upload_type_guard = has_any(content, &UPLOAD_TYPE_GUARD_PATTERNS);
        let has_user_controlled_storage_key =
            has_any(content, &USER_CONTROLLED_STORAGE_KEY_PATTERNS);
        let has_scoped_storage_key = has_any(content, &SCOPED_STORAGE_KEY_PATTERNS);
        let has_payment_flow = has_any(content, &PAYMENT_PATTERNS);
        let uses_stripe_checkout = has_any(content, &STRIPE_CHECKOUT_PATTERNS);
        let has_user_controlled_stripe_price =
            has_any(content, &USER_CONTROLLED_STRIPE_PRICE_PATTERNS);
        let has_redirect_sink = has_any(content, &REDIRECT_SINK_PATTERNS);
        let has_user_controlled_redirect = has_any(content, &USER_CONTROLLED_REDIRECT_PATTERNS);
        let has_user_controlled_stripe_redirect =
            has_any(content, &USER_CONTROLLED_STRIPE_REDIRECT_PATTERNS);
        let js_source = is_js_source_path(&file.relative_path);
        // In JavaScript this guards only the Stripe return URL check; open
        // redirects are paired per handler below.
        let has_redirect_allowlist = if js_source {
            route_like
                && uses_stripe_checkout
                && has_user_controlled_stripe_redirect
                && super::redirect_guards::has_guarded_redirects(content, uses_stripe_checkout)
        } else {
            has_any(content, &REDIRECT_ALLOWLIST_PATTERNS)
        };
        // JavaScript pairs a request field with a redirect inside one route
        // handler; other languages keep the file-level pairing.
        let open_redirect_line =
            if !(route_like && has_redirect_sink && has_user_controlled_redirect) {
                None
            } else if js_source {
                super::redirect_guards::unguarded_request_redirect(content)
                    .map(|field| line_number(content, field))
            } else if has_redirect_allowlist {
                None
            } else {
                first_match_line(content, &USER_CONTROLLED_REDIRECT_PATTERNS)
                    .or_else(|| first_match_line(content, &REDIRECT_SINK_PATTERNS))
            };
        let has_stripe_price_allowlist = has_any(content, &STRIPE_PRICE_ALLOWLIST_PATTERNS);
        let has_email_flow = has_any(content, &EMAIL_PATTERNS);
        let user_controlled_fetch = route_like && ssrf_like && !has_ssrf_guard;
        // Framework-enforced WordPress and Laravel access gates make handlers
        // non-public even when their content contains risky terms.
        // A Server Action is a POST endpoint, but one that neither persists,
        // calls out, sends mail, stores files, nor reads request input has no
        // work to limit.
        let server_action_does_work = server_action_like
            && (touches_db_raw
                || db_write_count > 0
                || uses_outbound_http
                || has_email_flow
                || has_storage_write);
        // The same emptiness makes it a non-sensitive handler: cache
        // revalidation is the whole body, even though the action's path sits
        // under `settings/` or `admin/`.
        let sensitive_handler =
            is_sensitive_handler(file, &lower) && (!server_action_like || server_action_does_work);
        let likely_public_endpoint = route_like
            && !is_wp_gated_surface(&lower)
            && !middleware_auth_protected
            && (public_risk_endpoint
                || (!has_auth && (write_handler_raw || parses_body || server_action_does_work)));

        // Compute operation predicates during the shared lowercase pass; raw
        // pattern hits preserve the operations phase's established semantics.
        let rel_lower = file.relative_path.to_ascii_lowercase();
        let path_norm = rel_lower.replace('\\', "/");
        let frontend_surface = is_frontend_surface(file);
        let background_jobs = has_any(content, &BACKGROUND_JOB_PATTERNS);
        let summary = FileSignalSummary {
            pattern_registry,
            scanner_rule_impl,
            route_like: route_like_raw,
            server_action_like,
            uses_env: has_any(content, &ENV_USAGE_PATTERNS),
            uses_llm: has_any(content, &LLM_PATTERNS),
            touches_db: touches_db_raw,
            background_jobs,
            frontend_supabase: frontend_surface && lower.contains("supabase."),
            client_auth: frontend_surface && has_any(content, &AUTH_CLIENT_PATTERNS),
            healthcheck: rel_lower.contains("health")
                || rel_lower.contains("ready")
                || rel_lower.contains("status")
                || rel_lower.contains("ping")
                || lower.contains("/health"),
            error_reporting: lower.contains("sentry")
                || lower.contains("bugsnag")
                || lower.contains("rollbar")
                || lower.contains("honeybadger"),
            structured_logging: has_any(content, &STRUCTURED_LOGGING_PATTERNS),
            ai_observability: has_any(content, &AI_OBSERVABILITY_INTEGRATION_PATTERNS),
            feature_flags: has_any(content, &FEATURE_FLAG_PATTERNS),
            error_boundary: has_any(content, &ERROR_BOUNDARY_PATTERNS),
            job_visibility: has_any(content, &JOB_VISIBILITY_PATTERNS),
            job_marker_words: lower.contains("job_id")
                || lower.contains("queuename")
                || lower.contains("queue_name")
                || lower.contains("attempt"),
            auth_enforcement: has_auth_pattern_evidence || has_token_guard,
            ai_heavy_marker: background_jobs
                || lower.contains("streamtext(")
                || lower.contains("generatetext(")
                || lower.contains("generateobject(")
                || lower.contains("streamobject("),
            shared_data_layer: touches_db_raw
                && !route_like_raw
                && !path_norm.contains("/app/api/")
                && !path_norm.contains("/pages/api/")
                && [
                    "/lib/",
                    "/server/",
                    "/services/",
                    "/service/",
                    "/repositories/",
                    "/repository/",
                    "/models/",
                    "/data/",
                ]
                .iter()
                .any(|needle| path_norm.contains(needle)),
            sensitive_handler,
            write_handler: write_handler_raw,
            inline_rust_tests: file.inline_rust_tests,
        };

        let signals = Self {
            lower,
            pattern_registry,
            scanner_rule_impl,
            route_like,
            route_evidence,
            wp_hook_handler,
            middleware_auth_protected,
            has_identity_auth,
            has_authz,
            has_auth,
            has_validation,
            has_rate_limit,
            has_cors_wildcard,
            has_cors_credentials,
            has_runtime_cors_config,
            has_cookie_session,
            has_cookie_write,
            has_session_cookie_name,
            has_cookie_http_only,
            has_cookie_secure,
            has_cookie_same_site,
            has_csrf,
            has_request_token,
            has_jwt_decode,
            has_jwt_verify,
            has_oauth_code,
            has_oauth_token_exchange,
            has_oauth_state_guard,
            has_oauth_pkce,
            has_oauth_client_secret,
            has_one_time_token_flow,
            has_one_time_token_hash,
            has_one_time_token_expiry,
            has_one_time_token_single_use,
            has_one_time_token_raw_lookup,
            has_timeout,
            has_retry_guard,
            has_concurrency_guard,
            uses_outbound_http,
            skips_internal_http,
            uses_llm,
            uses_ai_sdk,
            has_llm_spend_guard,
            has_llm_usage_logging,
            has_llm_observability,
            has_llm_output_cap,
            has_llm_cache_dedupe,
            has_user_controlled_llm_model,
            has_user_controlled_llm_settings,
            has_model_allowlist,
            has_numeric_bounds,
            has_loop_pattern,
            has_loop_guard,
            parses_body,
            is_webhook,
            has_webhook_verify,
            has_idempotency_guard,
            touches_db,
            has_db_query,
            has_multi_tenant_context,
            has_tenant_scope_query,
            has_auth_owned_id_scope,
            db_write_count,
            has_transaction,
            has_unsafe_raw_sql,
            dangerous_html,
            write_handler,
            sensitive_handler,
            public_risk_endpoint,
            public_risk_match,
            has_upload_flow,
            has_upload_input,
            has_upload_size_guard,
            has_upload_type_guard,
            has_storage_write,
            has_user_controlled_storage_key,
            has_scoped_storage_key,
            has_payment_flow,
            uses_stripe_checkout,
            has_user_controlled_stripe_price,
            open_redirect_line,
            has_redirect_allowlist,
            has_user_controlled_stripe_redirect,
            has_stripe_price_allowlist,
            has_email_flow,
            user_controlled_fetch,
            likely_public_endpoint,
        };

        (signals, summary)
    }
}
