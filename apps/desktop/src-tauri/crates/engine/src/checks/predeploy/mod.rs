//! Localhost-only checks for common pre-deployment mistakes.
//! The capability manifest marks these checks unsupported because hosted pages are never localhost.

use crate::checks::{Check, CheckResult, CheckStatus, PageContext, ScanCategory, Severity};
use regex::Regex;
use std::sync::LazyLock;

/// Detects hardcoded localhost/127.0.0.1 URLs in links, images, scripts, etc.
pub struct LocalhostRefsCheck;

static ABSOLUTE_URL_CANDIDATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:https?:)?//[^\s"'<>`)};]+"#).expect("static absolute URL regex")
});

static CSS_COMMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").expect("static CSS comment regex"));

fn is_loopback_or_unspecified_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
        }
        Some(url::Host::Ipv4(address)) => address.is_loopback() || address.is_unspecified(),
        Some(url::Host::Ipv6(address)) => address.is_loopback() || address.is_unspecified(),
        None => false,
    }
}

fn collect_loopback_url_candidates(text: &str, out: &mut Vec<String>) {
    for matched in ABSOLUTE_URL_CANDIDATE_RE.find_iter(text) {
        let candidate = matched
            .as_str()
            .trim_end_matches(['.', ',', ':', '!', '?', ']']);
        let parse_value = if candidate.starts_with("//") {
            format!("http:{candidate}")
        } else {
            candidate.to_string()
        };
        let Ok(parsed) = url::Url::parse(&parse_value) else {
            continue;
        };
        if is_loopback_or_unspecified_host(&parsed) {
            out.push(crate::log_sanitizer::evidence_safe_url_reference(candidate));
        }
    }
}

fn mask_javascript_comments(script: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        SingleQuote,
        DoubleQuote,
        Template,
        LineComment,
        BlockComment,
    }

    let bytes = script.as_bytes();
    let mut masked = bytes.to_vec();
    let mut state = State::Code;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Code => match (byte, next) {
                (b'/', Some(b'/')) => {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = State::LineComment;
                    index += 2;
                    continue;
                }
                (b'/', Some(b'*')) => {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = State::BlockComment;
                    index += 2;
                    continue;
                }
                (b'\'', _) => state = State::SingleQuote,
                (b'"', _) => state = State::DoubleQuote,
                (b'`', _) => state = State::Template,
                _ => {}
            },
            State::SingleQuote | State::DoubleQuote | State::Template => {
                let terminator = match state {
                    State::SingleQuote => b'\'',
                    State::DoubleQuote => b'"',
                    State::Template => b'`',
                    _ => unreachable!(),
                };
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == terminator {
                    state = State::Code;
                }
            }
            State::LineComment => {
                if matches!(byte, b'\n' | b'\r') {
                    state = State::Code;
                } else if byte.is_ascii() {
                    masked[index] = b' ';
                }
            }
            State::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = State::Code;
                    index += 2;
                    continue;
                }
                if byte.is_ascii() {
                    masked[index] = b' ';
                }
            }
        }
        index += 1;
    }
    String::from_utf8(masked).expect("masking ASCII preserves valid UTF-8")
}

fn collect_loopback_references(ctx: &PageContext) -> Vec<String> {
    let mut references = Vec::new();
    for tag in crate::checks::html_attrs::all_tag_slices(&ctx.body, ctx.body_lower()) {
        for attribute in [
            "href",
            "src",
            "srcset",
            "action",
            "formaction",
            "data",
            "poster",
            "style",
        ] {
            if let Some(value) = crate::checks::html_attrs::attr_value(tag, attribute) {
                let decoded = crate::checks::html_attrs::decode_url_character_references(&value);
                collect_loopback_url_candidates(&decoded, &mut references);
            }
        }
    }
    for (_, script) in
        crate::checks::html_attrs::raw_text_elements(&ctx.body, ctx.body_lower(), "script")
    {
        collect_loopback_url_candidates(&mask_javascript_comments(script), &mut references);
    }
    for style in
        crate::checks::html_attrs::raw_text_element_contents(&ctx.body, ctx.body_lower(), "style")
    {
        let without_comments = CSS_COMMENT_RE.replace_all(style, " ");
        collect_loopback_url_candidates(&without_comments, &mut references);
    }
    references.sort_unstable();
    references.dedup();
    references
}

impl Check for LocalhostRefsCheck {
    fn id(&self) -> &str {
        "config.localhost_refs"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if !ctx.is_localhost {
            return vec![];
        }

        let matches = collect_loopback_references(ctx);

        if matches.is_empty() {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "No hardcoded localhost URLs".into(),
                description: "No loopback or unspecified-host URL was found in recognized URL-bearing attributes, inline CSS, or non-comment inline-script text in the local preview's initial HTML. Runtime-created values and external assets were not inspected.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }]
        } else {
            let sample: Vec<&str> = matches.iter().take(5).map(|s| s.as_str()).collect();
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "Loopback URLs appear in local preview output".into(),
                description: format!(
                    "Found {} distinct URL reference{} to a localhost, loopback-IP, or unspecified-address target in recognized initial-HTML attributes, inline CSS, or non-comment inline-script text in the local preview. This does not establish a deployed defect: a production build may replace the value, or an intentional browser-to-local-service feature may require it. If the same browser-facing URL ships to ordinary remote users, it targets each user's device rather than your remote service.",
                    matches.len(),
                    if matches.len() != 1 { "s" } else { "" }
                ),
                status: CheckStatus::Warn,
                severity: Severity::Medium,
                fix_prompt: Some("Confirm whether the production artifact retains these loopback URLs; replace only unintended references with a relative URL or validated environment-specific server configuration.".into()),
                manual_fix: Some("Build the exact production artifact and inspect its rendered HTML, CSS, and client bundles. For unintended references, prefer same-origin relative URLs or a validated public configuration value. Keep intentional local-companion integrations explicit, user-consented, and restricted to the expected scheme, host, port, and protocol.".into()),
                raw_data: Some(serde_json::json!({ "distinct_url_count": matches.len(), "samples": sample, "initial_html_only": true })),
                confidence: crate::checks::IssueConfidence::NeedsReview,
                confidence_reason: Some("The reference is present in a local preview response, but production build substitution, deployment topology, and intentional local-companion behavior were not evaluated.".into()),
                why_it_matters: Some("An unintended loopback URL in a remote-user build targets the user's own device and can break links, assets, forms, or API calls; intentional localhost integrations require a different, explicit trust model.".into()),
            }]
        }
    }
}

/// Detects source map references that would expose original source code in production.
pub struct SourceMapsCheck;

static SOURCEMAP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)").unwrap()
});

fn is_map_reference(value: &str) -> bool {
    let decoded = crate::checks::html_attrs::decode_url_character_references(value);
    if let Ok(parsed) = url::Url::parse(decoded.trim()) {
        return parsed.path().to_ascii_lowercase().ends_with(".map");
    }
    decoded
        .split(['?', '#'])
        .next()
        .unwrap_or(&decoded)
        .trim()
        .to_ascii_lowercase()
        .ends_with(".map")
}

fn collect_source_map_references(ctx: &PageContext) -> Vec<String> {
    let mut references = Vec::new();
    for (opening, script) in
        crate::checks::html_attrs::raw_text_elements(&ctx.body, ctx.body_lower(), "script")
    {
        if !script_type_is_javascript(opening) {
            continue;
        }
        for capture in SOURCEMAP_PATTERN.captures_iter(script) {
            let value = capture[1].trim_end_matches([';', ',', ')']);
            references.push(format!(
                "sourceMappingURL={}",
                crate::log_sanitizer::evidence_safe_url_reference(value)
            ));
        }
    }

    for tag in crate::checks::html_attrs::all_tag_slices(&ctx.body, ctx.body_lower()) {
        let name = tag
            .trim_start_matches('<')
            .split(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '/' | '>')
            })
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let attribute = match name.as_str() {
            "script" => "src",
            "link" => "href",
            _ => continue,
        };
        let Some(value) = crate::checks::html_attrs::attr_value(tag, attribute) else {
            continue;
        };
        if is_map_reference(&value) {
            references.push(format!(
                "{name} {attribute}={}",
                crate::log_sanitizer::evidence_safe_url_reference(&value)
            ));
        }
    }

    references.sort_unstable();
    references.dedup();
    references
}

impl Check for SourceMapsCheck {
    fn id(&self) -> &str {
        "security.source_maps"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if !ctx.is_localhost {
            return vec![];
        }

        let references = collect_source_map_references(ctx);
        let total = references.len();

        if total == 0 {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "No source map references found".into(),
                description: "No sourceMappingURL comment or .map reference was found in the fetched local-preview HTML. This source check does not enumerate unreferenced files in the build or deployment.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }]
        } else {
            let samples: Vec<String> = references.into_iter().take(5).collect();
            vec![CheckResult {
                check_id: self.id().into(),
                // A sourceMappingURL comment alone does not prove the map is public.
                title: "Source map references in local preview output".into(),
                category: self.category(),
                description: format!(
                    "Found {} source map reference{} in the local preview output. Source maps are normal during development. This scan did not fetch the referenced files or inspect the production artifact, so it does not establish public exposure. If readable maps are deployed publicly, visitors can retrieve the original-source mapping and any source content embedded in it.",
                    total,
                    if total != 1 { "s" } else { "" }
                ),
                status: CheckStatus::Warn,
                severity: Severity::Low,
                fix_prompt: Some("Inspect the production artifact and deployment; keep public source maps only when their debugging value and source-disclosure tradeoff are deliberate.".into()),
                manual_fix: Some("Build and inspect the exact production artifact, then request each referenced map without exposing credentials. If public maps are not intended, disable their emission or exclude them and their references from deployment; if error reporting needs them, upload private maps to that service and restrict access. Do not treat map secrecy as a substitute for keeping credentials out of client code.".into()),
                raw_data: Some(serde_json::json!({ "count": total, "samples": samples })),
                confidence: crate::checks::IssueConfidence::NeedsReview,
                confidence_reason: Some("Only a reference in local preview output was seen; the map was not fetched and the production artifact/deployment was not inspected.".into()),
                why_it_matters: Some("Public source maps can disclose original source, paths, and comments and lower the effort needed to understand client code, although client-side security must never depend on source secrecy.".into()),
            }]
        }
    }
}

/// Detects debug mode indicators in rendered HTML (React DevTools, Vue devtools, debug banners, etc.)
pub struct DebugModeCheck;

/// A truthy debug assignment (debug: true / debug=true / debug = "on").
static DEBUG_TRUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bdebug["']?\s*[:=]\s*["']?(true|1|on)\b"#).unwrap());

static HTML_COMMENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").unwrap());
// Real error-dump signatures only; matched against the lowercased body.
static STACK_DUMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"traceback \(most recent call last\)|stack trace:|\n\s+at [\w$.<>\[\]/-]+ \([^)\n]*:\d+:\d+\)")
        .unwrap()
});

impl Check for DebugModeCheck {
    fn id(&self) -> &str {
        "config.debug_mode"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Security
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if !ctx.is_localhost {
            return vec![];
        }

        let body_lower = ctx.body_lower();
        let mut indicators: Vec<&str> = vec![];

        // Framework debug indicators
        if body_lower.contains("__react_devtools_global_hook__") {
            indicators.push("React DevTools hook");
        }
        if body_lower.contains("__vue_devtools_global_hook__") {
            indicators.push("Vue DevTools hook");
        }
        if body_lower.contains("data-reactroot") && body_lower.contains("data-reactid") {
            indicators.push("React debug attributes");
        }
        // ng-version= is NOT an indicator: production Angular emits it on
        // every build.

        // Common debug patterns. Only a truthy assignment counts -
        // "debug:" alone matched `{debug: false}`, the flag being
        // correctly off.
        if DEBUG_TRUE_RE.is_match(body_lower) {
            indicators.push("Debug flag in HTML");
        }
        // Require an actual error-dump signature, not the phrase "stack
        // trace" in marketing copy: Python's
        // traceback header, PHP/Java-style "Stack trace:" dumps, or JS/JVM
        // "at fn (file:line:col)" frame lines.
        let has_stack_dump = STACK_DUMP_RE.is_match(body_lower);
        if has_stack_dump {
            indicators.push("Error stack trace in output");
        }
        // The words must appear inside a comment - ANDing whole-body
        // "<!--" with whole-body "todo" flagged any commented page whose
        // visible copy mentions a to-do list.
        let has_debug_comment = HTML_COMMENT_RE.find_iter(body_lower).any(|m| {
            let comment = m.as_str();
            comment.contains("debug") || comment.contains("todo") || comment.contains("fixme")
        });
        if has_debug_comment {
            indicators.push("Debug/TODO HTML comments");
        }

        if indicators.is_empty() {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "No debug mode indicators".into(),
                description: "No debug mode flags or development tools detected in the HTML."
                    .into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }]
        } else {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "Debug-oriented markers in local preview output".into(),
                description: format!(
                    "Found debug-oriented markers in the local preview output: {}. These may be expected in development and do not establish that the production build exposes them. A rendered stack trace is direct local disclosure and deserves a production-path check; hooks, flags, and comments require context.",
                    indicators.join(", ")
                ),
                status: CheckStatus::Warn,
                severity: if has_stack_dump { Severity::Medium } else { Severity::Low },
                fix_prompt: Some("Inspect the exact production artifact and error path, then remove unintended debug output or stack disclosure from the release configuration.".into()),
                manual_fix: Some("Build and run the release configuration through the production proxy, trigger a controlled error, and inspect the response and client bundle. Keep public errors generic, send sanitized diagnostic context to approved server-side telemetry, and disable only debug hooks/flags that are not intentionally part of the product.".into()),
                raw_data: Some(serde_json::json!({ "indicators": indicators })),
                confidence: crate::checks::IssueConfidence::NeedsReview,
                confidence_reason: Some("The markers were observed in local preview HTML; production configuration, reachability, framework semantics, and whether the output is intentional were not evaluated.".into()),
                why_it_matters: Some("If equivalent stack traces or debug controls are reachable in production, they can disclose implementation context or change runtime behavior; development-only markers that are stripped from release output are expected.".into()),
            }]
        }
    }
}

/// Detects console.log/warn/error statements in inline scripts.
pub struct ConsoleLogCheck;

static CONSOLE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"console\.(log|warn|error|debug|info|trace|dir|table)\s*\(").unwrap()
});

fn script_type_is_javascript(opening_tag: &str) -> bool {
    let Some(value) = crate::checks::html_attrs::attr_value(opening_tag, "type") else {
        return true;
    };
    let value = value.trim().to_ascii_lowercase();
    value.is_empty()
        || value == "module"
        || value.ends_with("javascript")
        || value.ends_with("ecmascript")
        || matches!(value.as_str(), "text/jscript" | "text/livescript")
}

/// Mask JavaScript strings and comments while preserving byte offsets.
fn mask_javascript_non_code(script: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        SingleQuote,
        DoubleQuote,
        Template,
        LineComment,
        BlockComment,
    }

    let bytes = script.as_bytes();
    let mut masked = bytes.to_vec();
    let mut state = State::Code;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Code => match (byte, next) {
                (b'/', Some(b'/')) => {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = State::LineComment;
                    index += 2;
                    continue;
                }
                (b'/', Some(b'*')) => {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = State::BlockComment;
                    index += 2;
                    continue;
                }
                (b'\'', _) => state = State::SingleQuote,
                (b'"', _) => state = State::DoubleQuote,
                (b'`', _) => state = State::Template,
                _ => {
                    index += 1;
                    continue;
                }
            },
            State::LineComment => {
                if matches!(byte, b'\n' | b'\r') {
                    state = State::Code;
                    index += 1;
                    continue;
                }
            }
            State::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = State::Code;
                    index += 2;
                    continue;
                }
            }
            State::SingleQuote | State::DoubleQuote | State::Template => {
                let terminator = match state {
                    State::SingleQuote => b'\'',
                    State::DoubleQuote => b'"',
                    State::Template => b'`',
                    _ => unreachable!(),
                };
                if byte == b'\\' {
                    if byte.is_ascii() {
                        masked[index] = b' ';
                    }
                    if let Some(escaped) = masked.get_mut(index + 1) {
                        if bytes[index + 1].is_ascii() {
                            *escaped = b' ';
                        }
                    }
                    index += 2;
                    continue;
                }
                if byte == terminator {
                    state = State::Code;
                }
            }
        }
        if byte.is_ascii() {
            masked[index] = b' ';
        }
        index += 1;
    }

    String::from_utf8(masked).expect("masking ASCII preserves valid UTF-8")
}

impl Check for ConsoleLogCheck {
    fn id(&self) -> &str {
        "config.console_logs"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Polish
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if !ctx.is_localhost {
            return vec![];
        }

        let mut console_count = 0;
        let mut samples: Vec<String> = vec![];

        for (opening_tag, script_text) in
            crate::checks::html_attrs::raw_text_elements(&ctx.body, ctx.body_lower(), "script")
        {
            if !script_type_is_javascript(opening_tag) {
                continue;
            }
            let scannable = mask_javascript_non_code(script_text);
            for m in CONSOLE_PATTERN.find_iter(&scannable) {
                console_count += 1;
                if samples.len() < 5 {
                    // Get context from the original script using byte-identical
                    // offsets from the masked copy. Snap to char boundaries so
                    // multibyte text near the window cannot panic.
                    let start = crate::checks::floor_char_boundary(
                        script_text,
                        m.start().saturating_sub(20),
                    );
                    let end = crate::checks::floor_char_boundary(
                        script_text,
                        (m.end() + 30).min(script_text.len()),
                    );
                    let snippet = &script_text[start..end];
                    samples.push(crate::log_sanitizer::redact_issue_evidence(snippet.trim()));
                }
            }
        }

        if console_count == 0 {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "No console statements in inline scripts".into(),
                description: "No console.log/warn/error found in inline scripts.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }]
        } else {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "Console statements in inline scripts".into(),
                description: format!(
                    "Found {} console statement{} in inline scripts in the local preview. This is factual for the preview output but does not establish a production problem: release minification may remove them, the runtime may deliberately capture them, and console calls can be useful diagnostics. Review their arguments for sensitive data and intended release behavior.",
                    console_count,
                    if console_count != 1 { "s" } else { "" }
                ),
                status: CheckStatus::Warn,
                severity: Severity::Low,
                fix_prompt: Some("Review each inline console call and the production artifact; remove, redact, or route only calls that are unintended or expose sensitive context.".into()),
                manual_fix: Some("Build the exact release artifact and inspect remaining console calls. Keep intentional diagnostics when the product/runtime needs them, but avoid credentials, tokens, personal data, full request bodies, and noisy high-frequency output. If removing calls mechanically, verify argument expressions have no required side effects and preserve error telemetry through an approved path.".into()),
                raw_data: Some(serde_json::json!({ "count": console_count, "samples": samples })),
                confidence: crate::checks::IssueConfidence::NeedsReview,
                confidence_reason: Some("Console calls were observed only in inline local-preview scripts; production transformation, runtime collection, execution frequency, and argument sensitivity were not evaluated.".into()),
                why_it_matters: Some("Unintended production console output can expose sensitive diagnostic context or create support noise, while deliberate sanitized diagnostics may be appropriate.".into()),
            }]
        }
    }
}

/// Detects TODO/FIXME/HACK/XXX comments in rendered HTML.
pub struct TodoCommentsCheck;

static TODO_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<!--\s*(?:TODO|FIXME|HACK|XXX|BUG|TEMP|TEMPORARY)\b[^>]*-->").unwrap()
});

impl Check for TodoCommentsCheck {
    fn id(&self) -> &str {
        "config.todo_comments"
    }
    fn category(&self) -> ScanCategory {
        ScanCategory::Polish
    }

    fn run(&self, ctx: &PageContext) -> Vec<CheckResult> {
        if !ctx.is_localhost {
            return vec![];
        }

        let matches: Vec<String> = TODO_PATTERN
            .find_iter(&ctx.body)
            .map(|m| {
                let s = m.as_str();
                if s.len() > 80 {
                    let cut = crate::checks::floor_char_boundary(s, 77);
                    format!("{}…", &s[..cut])
                } else {
                    s.to_string()
                }
            })
            .collect();

        if matches.is_empty() {
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "No TODO/FIXME comments in HTML".into(),
                description: "No development comments found in the rendered HTML.".into(),
                status: CheckStatus::Pass,
                severity: Severity::Low,
                fix_prompt: None,
                manual_fix: None,
                raw_data: None,
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: None,
            }]
        } else {
            let sample: Vec<String> = matches
                .iter()
                .take(5)
                .map(|value| crate::log_sanitizer::redact_issue_evidence(value))
                .collect();
            vec![CheckResult {
                check_id: self.id().into(),
                category: self.category(),
                title: "TODO/FIXME comments in rendered HTML".into(),
                description: format!(
                    "Found {} development comment{} visible in the HTML source.",
                    matches.len(),
                    if matches.len() != 1 { "s" } else { "" }
                ),
                status: CheckStatus::Warn,
                severity: Severity::Low,
                fix_prompt: Some("Review the matched HTML comments; resolve inaccurate or sensitive notes and retain only deliberate, non-sensitive maintenance context.".into()),
                manual_fix: Some("Read each matched comment in context. Resolve unfinished behavior that affects launch, move actionable work to the project tracker when appropriate, and remove stale or sensitive notes. A useful non-sensitive comment can remain; stripping comments is optional and is not a substitute for fixing the underlying work.".into()),
                raw_data: Some(serde_json::json!({ "count": matches.len(), "samples": sample })),
                confidence: crate::checks::IssueConfidence::High,
                confidence_reason: None,
                why_it_matters: Some("HTML source comments are retrievable by visitors and can reveal stale implementation notes or unfinished work, but their presence is not itself a user-visible defect.".into()),
            }]
        }
    }
}

mod deployment_content;
pub use deployment_content::{DevDependenciesCheck, EnvLeakCheck, PlaceholderContentCheck};

/// Get all pre-deploy checks
pub fn all_predeploy_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(LocalhostRefsCheck),
        Box::new(SourceMapsCheck),
        Box::new(DebugModeCheck),
        Box::new(ConsoleLogCheck),
        Box::new(TodoCommentsCheck),
        Box::new(DevDependenciesCheck),
        Box::new(PlaceholderContentCheck),
        Box::new(EnvLeakCheck),
    ]
}

#[cfg(test)]
mod tests;
