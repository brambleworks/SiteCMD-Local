use super::*;
mod ai_checks;
mod architecture_checks;
mod blanking;
mod handler_spans;
mod js_sinks;
mod php_sinks;
mod python_sinks;
mod redirect_guards;
mod route_security;
mod service_security;
mod signals;

use ai_checks::collect_ai_issues;
use architecture_checks::collect_architecture_issues;
pub(in crate::core::code_scan) use blanking::{blank_non_code_for_env, blank_python};
use js_sinks::collect_js_sink_issues;
use php_sinks::collect_php_sink_issues;
use python_sinks::collect_python_sink_issues;
use route_security::collect_route_security_issues;
use service_security::collect_service_security_issues;
use signals::FileAnalysisSignals;

pub(super) struct FileAnalysisContext<'a> {
    file: &'a SourceFile,
    content: &'a str,
    signals: FileAnalysisSignals,
    oauth_callback_like: bool,
    one_time_token_handler: bool,
    session_cookie_handler: bool,
    upload_handler: bool,
    multi_tenant_handler: bool,
    needs_outbound_guards: bool,
    responsibility_labels: Vec<&'static str>,
}

/// Per-file predicates collected during parallel analysis for the serial
/// operations phase. Raw pattern fields remain distinct from combined signals.
pub(super) struct FileSignalSummary {
    pub(super) pattern_registry: bool,
    pub(super) scanner_rule_impl: bool,
    pub(super) route_like: bool,
    pub(super) server_action_like: bool,
    pub(super) uses_env: bool,
    pub(super) uses_llm: bool,
    pub(super) touches_db: bool,
    pub(super) background_jobs: bool,
    pub(super) frontend_supabase: bool,
    pub(super) client_auth: bool,
    pub(super) healthcheck: bool,
    pub(super) error_reporting: bool,
    pub(super) structured_logging: bool,
    pub(super) ai_observability: bool,
    pub(super) feature_flags: bool,
    pub(super) error_boundary: bool,
    pub(super) job_visibility: bool,
    pub(super) job_marker_words: bool,
    pub(super) auth_enforcement: bool,
    pub(super) ai_heavy_marker: bool,
    pub(super) shared_data_layer: bool,
    pub(super) sensitive_handler: bool,
    pub(super) write_handler: bool,
    pub(super) inline_rust_tests: bool,
}

pub(super) fn analyze_file(
    file: &SourceFile,
    laravel_protection: &LaravelRouteProtection,
) -> (Vec<CodeIssue>, FileSignalSummary) {
    let mut issues = Vec::new();
    // Comments describe code, they are not code. Every signal reads the
    // executable view, so a commented-out query or a JSDoc mention of a sink
    // cannot produce a finding. Blanking preserves byte offsets and newlines,
    // so reported line numbers still point at the real source line, and
    // `ctx.file` stays the original so excerpts quote real source.
    let code_view = code_view_for_analysis(file);
    let analysis_file = code_view.as_ref().unwrap_or(file);
    let content = &analysis_file.content;
    let (mut signals, summary) = FileAnalysisSignals::from_file(analysis_file, laravel_protection);
    refine_sink_signals(&mut signals, content);
    let oauth_callback_like = signals.route_like
        && signals.has_oauth_code
        && signals.has_oauth_token_exchange
        && (file.relative_path.to_ascii_lowercase().contains("callback")
            || signals.lower.contains("oauth")
            || signals.lower.contains("openid"))
        && !is_oauth_authorization_server_file(file, content, signals.parses_body);
    let one_time_token_handler = signals.route_like
        && signals.has_request_token
        && signals.has_one_time_token_flow
        && (signals.touches_db || signals.sensitive_handler);
    let session_cookie_handler = signals.route_like
        && signals.has_cookie_write
        && (signals.has_session_cookie_name
            || signals.has_cookie_session
            || file.relative_path.to_ascii_lowercase().contains("auth")
            || file.relative_path.to_ascii_lowercase().contains("login")
            || file.relative_path.to_ascii_lowercase().contains("session"));
    let upload_handler = signals.route_like
        && signals.has_upload_flow
        && (signals.parses_body || signals.has_upload_input || signals.has_storage_write);
    let multi_tenant_handler = signals.route_like
        && signals.touches_db
        && signals.has_auth
        && signals.has_db_query
        && (signals.has_multi_tenant_context || is_multi_tenant_route_like(file));
    let needs_outbound_guards = signals.route_like
        && !signals.uses_llm
        && signals.uses_outbound_http
        && !signals.skips_internal_http;
    let path_lower = file.relative_path.to_ascii_lowercase();
    // Generic File and checkout tokens help route detection but are too weak
    // to assign architecture responsibility in non-route modules.
    let architecture_upload_flow = signals.has_upload_flow
        && (signals.route_like
            || signals.has_upload_input
            || signals.has_storage_write
            || path_lower.contains("upload"));
    let architecture_payment_flow = signals.has_payment_flow
        && (signals.route_like
            || signals.uses_stripe_checkout
            || path_lower.contains("billing")
            || path_lower.contains("payment")
            || path_lower.contains("subscription")
            || path_lower.contains("commerce")
            || signals.lower.contains("new stripe(")
            || signals.lower.contains("stripe."));
    let responsibility_labels = collect_code_responsibilities(ResponsibilitySignals {
        has_auth: signals.has_auth,
        has_authz: signals.has_authz,
        has_validation: signals.has_validation,
        touches_db: signals.touches_db,
        uses_llm: signals.uses_llm,
        uses_outbound_http: needs_outbound_guards,
        is_webhook: signals.is_webhook,
        has_upload_flow: architecture_upload_flow,
        has_payment_flow: architecture_payment_flow,
        has_email_flow: signals.has_email_flow,
        has_background_jobs: has_any(content, &BACKGROUND_JOB_PATTERNS),
        dangerous_html: signals.dangerous_html,
    });
    let ctx = FileAnalysisContext {
        file,
        content,
        signals,
        oauth_callback_like,
        one_time_token_handler,
        session_cookie_handler,
        upload_handler,
        multi_tenant_handler,
        needs_outbound_guards,
        responsibility_labels,
    };

    collect_ai_issues(&mut issues, &ctx);
    collect_route_security_issues(&mut issues, &ctx);
    collect_service_security_issues(&mut issues, &ctx);
    // Run precise sink analysis first so broader architecture heuristics can
    // avoid duplicate findings.
    collect_js_sink_issues(&mut issues, &ctx);
    collect_architecture_issues(&mut issues, &ctx);
    collect_php_sink_issues(&mut issues, &ctx);
    collect_python_sink_issues(&mut issues, &ctx);

    (issues, summary)
}

/// A same-length copy of `file` whose comments are blanked, for languages
/// where the signal patterns would otherwise read documentation as code.
///
/// Returns `None` when the file needs no rewrite, so the caller keeps
/// borrowing the original. String literals are left intact: quoted route
/// names, cookie names, CORS values, and `"use server"` directives are
/// evidence, and the patterns that must ignore quoted data already use
/// `has_any_unquoted`. PHP and Python sink checks build their own views.
fn code_view_for_analysis(file: &SourceFile) -> Option<SourceFile> {
    let path = file.relative_path.to_ascii_lowercase();
    let content = if path.ends_with(".py") {
        blank_python(&file.content, false)
    } else if is_js_or_ts_file(&file.relative_path) {
        js_sinks::blank_js(&file.content, false)
    } else {
        return None;
    };
    if content == file.content {
        return None;
    }
    Some(SourceFile {
        absolute_path: file.absolute_path.clone(),
        relative_path: file.relative_path.clone(),
        content,
        line_count: file.line_count,
    })
}

/// Withdraw whole-file sink signals that the sink site itself disproves.
///
/// `FileAnalysisSignals` grades a file by whether a pattern appears anywhere
/// in it. Two sinks need the value beside them before the finding is honest:
/// a raw-HTML sink handed a literal renders fixed text, and a fetch whose
/// argument is a bare `url` identifier is only request-derived when the file
/// binds that identifier to a request.
fn refine_sink_signals(signals: &mut FileAnalysisSignals, content: &str) {
    if signals.dangerous_html && all_raw_html_values_are_static(content) {
        signals.dangerous_html = false;
    }
    if signals.user_controlled_fetch && !ssrf_destination_is_request_derived(content) {
        signals.user_controlled_fetch = false;
    }
}

/// Whether every raw-HTML sink in the file assigns a literal value, and no
/// other raw-HTML sink shape (`v-html`, dynamic `innerHTML`, a PHP echo of a
/// superglobal) appears alongside it.
fn all_raw_html_values_are_static(content: &str) -> bool {
    if !content.contains(RAW_HTML_SINK_MARKER) {
        return false;
    }
    if has_any_unquoted(
        &content.replace(RAW_HTML_SINK_MARKER, ""),
        &DANGEROUS_HTML_PATTERNS,
    ) {
        return false;
    }
    content
        .match_indices(RAW_HTML_SINK_MARKER)
        .all(|(start, _)| {
            let mut end = (start + RAW_HTML_VALUE_WINDOW).min(content.len());
            while !content.is_char_boundary(end) {
                end += 1;
            }
            RAW_HTML_STATIC_VALUE_PATTERN.is_match(&content[start..end])
        })
}

/// React's raw-HTML prop, the only sink whose value the literal check reads.
const RAW_HTML_SINK_MARKER: &str = "dangerouslySetInnerHTML";

/// How far past a raw-HTML sink the literal-value check reads, in bytes.
const RAW_HTML_VALUE_WINDOW: usize = 200;

/// Whether the file's SSRF evidence names a request source.
///
/// A direct accessor argument (`fetch(req.query.url)`) proves it on its own.
/// When every match is the bare-identifier form, the file must also bind that
/// identifier to a request value; a URL built from a stored credential,
/// configuration, or a provider's own pagination link is not attacker-chosen.
fn ssrf_destination_is_request_derived(content: &str) -> bool {
    let only_bare_identifiers = SSRF_PATTERNS
        .iter()
        .flat_map(|pattern| pattern.find_iter(content))
        .all(|matched| {
            SSRF_BARE_IDENTIFIER_FETCH_PATTERNS
                .iter()
                .any(|bare| bare.is_match(matched.as_str()))
        });
    !only_bare_identifiers || has_any(content, &SSRF_REQUEST_SOURCE_ASSIGNMENT_PATTERNS)
}

/// Whether this file is the authorization server's own endpoint rather than a
/// client-side callback. It reads the client secret out of the request, or
/// lives in the OAuth client-registration tree, so there is no browser state
/// it could have stored and no code verifier of its own to send.
///
/// A secret read off an already-parsed `body`/`payload`/`dto` is only counted
/// when the file actually parses a request body, because those names are
/// equally natural for the OUTGOING token request a client builds. An OAuth
/// redirect callback reads query parameters, not a body.
fn is_oauth_authorization_server_file(file: &SourceFile, content: &str, parses_body: bool) -> bool {
    let path = file.relative_path.replace('\\', "/").to_ascii_lowercase();
    format!("/{path}").contains("/oauth-clients/")
        || has_any(content, &OAUTH_SERVER_REQUEST_SECRET_PATTERNS)
        || (parses_body && has_any(content, &OAUTH_SERVER_PARSED_BODY_SECRET_PATTERNS))
}

fn is_js_or_ts_file(path: &str) -> bool {
    is_js_source_path(path)
}

fn is_next_config_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    matches!(
        base,
        "next.config.js" | "next.config.mjs" | "next.config.cjs" | "next.config.ts"
    )
}

fn is_typescript_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".tsx")
}

fn is_jsx_or_tsx_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".tsx") || lower.ends_with(".jsx")
}

pub(super) fn is_config_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("config")
        || lower.contains(".env")
        || lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
}

fn looks_like_pattern_registry(content: &str) -> bool {
    if content.contains("LazyLock<Vec<regex::Regex>>")
        || content.matches("regex::Regex::new").count() >= 6
        // Scanner signal aggregators consume many pattern catalogs without
        // compiling the expressions themselves. Treating the marker names as
        // application behavior otherwise invents auth, billing, AI, and DB
        // responsibilities in the scanner implementation.
        || (content.matches("_PATTERNS").count() >= 12
            && content.matches("has_any(").count() >= 6)
    {
        return true;
    }

    // Several distinct placeholder literals identify a detection-rule registry,
    // not an application containing real secrets.
    const DETECTION_MARKERS: &[&str] = &[
        "changeme",
        "change-me",
        "placeholder",
        "redacted",
        "dummy",
        "supersecretkey",
        "password123",
        "your-api-key",
        "your_api_key",
        "your_value_here",
        "example-key",
        "fake-key",
        "test-secret",
        "replace_me",
        "replace-me",
        "not-set",
    ];
    let lower = content.to_ascii_lowercase();
    let distinct_markers = DETECTION_MARKERS
        .iter()
        .filter(|marker| lower.contains(*marker))
        .count();
    if distinct_markers >= 4 {
        return true;
    }

    // Several quoted route markers identify rule data rather than live routes.
    // Exclude markers that real PHP routinely quotes or interpolates.
    const QUOTED_ROUTE_MARKERS: &[&str] = &[
        "route::get(",
        "route::post(",
        "route::put(",
        "route::patch(",
        "route::delete(",
        "route::any(",
        "route::resource(",
        "router.post(",
        "router.put(",
        "router.patch(",
        "router.delete(",
        "app.post(",
        "app.put(",
        "app.patch(",
        "app.delete(",
        "export async function get(",
        "export async function post(",
        "register_rest_route(",
        "dangerouslysetinnerhtml",
    ];
    let quoted_route_markers = QUOTED_ROUTE_MARKERS
        .iter()
        .filter(|marker| has_delimiter_prefixed_occurrence(&lower, marker))
        .count();
    quoted_route_markers >= 4
}

/// Whether `marker` appears as quoted data rather than executable code.
///
/// Backslashes escape quote-leading markers but qualify bare PHP names, matching
/// `route_helpers::contains_unquoted`.
fn has_delimiter_prefixed_occurrence(lower: &str, marker: &str) -> bool {
    let escape_marks_data = marker.starts_with('"') || marker.starts_with('\'');
    let mut search = 0;
    while let Some(pos) = lower[search..].find(marker) {
        let at = search + pos;
        let preceding = lower[..at].chars().next_back();
        if matches!(preceding, Some('"' | '\'' | '`'))
            || (escape_marks_data && preceding == Some('\\'))
        {
            return true;
        }
        search = at + marker.len();
    }
    false
}

#[cfg(test)]
mod pattern_registry_tests {
    use super::looks_like_pattern_registry;

    #[test]
    fn recognizes_marker_definition_files() {
        let markers =
            r#"const PLACEHOLDER_MARKERS = ["changeme", "placeholder", "redacted", "dummy"];"#;
        assert!(looks_like_pattern_registry(markers));
        // A normal source file is not a pattern registry.
        assert!(!looks_like_pattern_registry(
            "export function add(a, b) { return a + b; }"
        ));
    }

    #[test]
    fn recognizes_quoted_route_marker_definitions() {
        // A scanner's route-helper source quotes many distinct declaration
        // markers; that shape must classify as rule-definition code.
        assert!(looks_like_pattern_registry(
            r#"const ROUTE_MARKERS = ["route::get(", "route::post(", "app.post(", "router.post(", "export async function post("];"#
        ));
        // Real declarations are code, not data: an actual Express app with
        // several live routes stays analysable.
        assert!(!looks_like_pattern_registry(
            "app.post('/a', a);\napp.put('/b', b);\napp.patch('/c', c);\napp.delete('/d', d);\nrouter.post('/e', e);\n"
        ));
    }

    #[test]
    fn recognizes_pattern_signal_aggregators() {
        let mut source = String::from("fn signals(content: &str) {\n");
        for index in 0..12 {
            source.push_str(&format!(
                "let signal_{index} = has_any(content, &RULE_{index}_PATTERNS);\n"
            ));
        }
        source.push('}');
        assert!(looks_like_pattern_registry(&source));

        assert!(!looks_like_pattern_registry(
            "let auth = has_any(content, &AUTH_PATTERNS);"
        ));
    }

    #[test]
    fn fqcn_laravel_routes_are_not_a_pattern_registry() {
        assert!(!looks_like_pattern_registry(
            "<?php\n\\Route::get('/a', A::class);\n\\Route::post('/b', B::class);\n\\Route::put('/c', C::class);\n\\Route::delete('/d', D::class);\n"
        ));
    }
}

#[cfg(test)]
mod blank_python_tests {
    use super::blank_python;

    #[test]
    fn preserves_fstrings_but_removes_comments_and_docstrings() {
        let src = "def f():\n    \"\"\"os.system(x) here\"\"\"\n    y = f\"{request.args['q']}\"  # note request.form\n";

        let scan = blank_python(src, false);
        // Byte offsets and newlines are preserved so line numbers stay correct.
        assert_eq!(scan.len(), src.len());
        assert_eq!(scan.matches('\n').count(), src.matches('\n').count());
        // Docstring body and the `#` comment are blanked in both views.
        assert!(
            !scan.contains("os.system"),
            "docstring not blanked: {scan:?}"
        );
        assert!(
            !scan.contains("request.form"),
            "comment not blanked: {scan:?}"
        );
        // The f-string argument survives the comment-only view so taint is seen.
        assert!(
            scan.contains("request.args['q']"),
            "f-string was wrongly blanked: {scan:?}"
        );

        // The structure view additionally blanks all string literals.
        let structure = blank_python(src, true);
        assert_eq!(structure.len(), src.len());
        assert!(!structure.contains("request.args['q']"));
    }
}

#[cfg(test)]
mod code_view_tests {
    use super::{
        all_raw_html_values_are_static, code_view_for_analysis, is_oauth_authorization_server_file,
        ssrf_destination_is_request_derived, SourceFile,
    };
    use std::path::PathBuf;

    fn source(relative_path: &str, content: &str) -> SourceFile {
        SourceFile {
            absolute_path: PathBuf::from("/tmp").join(relative_path),
            relative_path: relative_path.to_string(),
            content: content.to_string(),
            line_count: content.lines().count(),
        }
    }

    #[test]
    fn comments_are_blanked_while_offsets_and_strings_survive() {
        let file = source(
            "app/api/settings/route.ts",
            "export async function GET() {\n  // await prisma.account.findMany();\n  /* dangerouslySetInnerHTML */\n  return Response.json({ path: \"/api/settings\" });\n}\n",
        );
        let view = code_view_for_analysis(&file).expect("a commented JavaScript file gets a view");
        assert_eq!(view.content.len(), file.content.len());
        assert_eq!(
            view.content.lines().count(),
            file.content.lines().count(),
            "line numbers must survive blanking"
        );
        assert!(!view.content.contains("findMany"));
        assert!(!view.content.contains("dangerouslySetInnerHTML"));
        // String literals are evidence and stay readable.
        assert!(view.content.contains("\"/api/settings\""));
    }

    #[test]
    fn files_without_comments_and_other_languages_keep_their_own_content() {
        assert!(
            code_view_for_analysis(&source("src/plain.ts", "export const value = 1;\n")).is_none()
        );
        assert!(code_view_for_analysis(&source(
            "src/class-import.php",
            "<?php\n// $wpdb->get_results();\n"
        ))
        .is_none());
    }

    #[test]
    fn only_literal_raw_html_values_count_as_static() {
        assert!(all_raw_html_values_are_static(
            "<style dangerouslySetInnerHTML={{ __html: `* { animation: none }` }} />",
        ));
        assert!(!all_raw_html_values_are_static(
            "<div dangerouslySetInnerHTML={{ __html: user.bio }} />",
        ));
        // One dynamic sink beside a literal one keeps the whole file graded.
        assert!(!all_raw_html_values_are_static(
            "<style dangerouslySetInnerHTML={{ __html: `a{}` }} />\n<div dangerouslySetInnerHTML={{ __html: user.bio }} />",
        ));
        // A different raw-HTML sink shape is never excused by a literal one.
        assert!(!all_raw_html_values_are_static(
            "<style dangerouslySetInnerHTML={{ __html: `a{}` }} />\n<div v-html=\"post.body\" />",
        ));
    }

    #[test]
    fn a_bare_fetch_identifier_is_request_derived_only_with_a_binding() {
        assert!(!ssrf_destination_is_request_derived(
            "const url = `${credential.account.href}/projects.json`;\nawait fetch(url);",
        ));
        assert!(ssrf_destination_is_request_derived(
            "const url = req.body.url;\nawait fetch(url);",
        ));
        // A direct accessor argument proves it without any binding line.
        assert!(ssrf_destination_is_request_derived(
            "await fetch(req.query.target);",
        ));
    }

    #[test]
    fn the_authorization_server_side_of_oauth_is_recognised() {
        let server = source(
            "app/api/oauth/callback/route.ts",
            "const body = await request.json();\nconst tokens = await exchange(body.code, body.client_secret);",
        );
        assert!(is_oauth_authorization_server_file(
            &server,
            &server.content,
            true
        ));

        let direct = source(
            "app/api/oauth/token/route.ts",
            "const tokens = await exchange(req.body.code, req.body.client_secret);",
        );
        assert!(is_oauth_authorization_server_file(
            &direct,
            &direct.content,
            false
        ));

        let registration = source(
            "src/modules/oauth-clients/controllers/oauth-flow.controller.ts",
            "const tokens = await exchange(code);",
        );
        assert!(is_oauth_authorization_server_file(
            &registration,
            &registration.content,
            false
        ));

        let client = source(
            "app/api/oauth/callback/route.ts",
            "const tokens = await exchange({ code, client_secret: process.env.SECRET });",
        );
        assert!(!is_oauth_authorization_server_file(
            &client,
            &client.content,
            false
        ));

        // A client callback that builds its OUTGOING token request reads the
        // secret off a local payload. With no request body parsed, that is not
        // the authorization server.
        let outgoing = source(
            "app/api/oauth/callback/route.ts",
            "const payload = { code, client_secret: env.SECRET };\nlog(payload.client_secret);",
        );
        assert!(!is_oauth_authorization_server_file(
            &outgoing,
            &outgoing.content,
            false
        ));
    }
}
