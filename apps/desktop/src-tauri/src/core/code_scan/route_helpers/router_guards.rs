//! Clears auth findings only for covered sensitive registrations and rate findings only for routes following proven global limiter mounts.
//! Gate evidence follows local definitions and response propagation within each scanned module; unresolved exports and external callees remain unproven.

use super::*;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::LazyLock;

#[path = "router_guards/imported.rs"]
mod imported;
#[path = "router_guards/js_spans.rs"]
mod js_spans;
use js_spans::literal;

fn compile(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static router guard regex") // allow-expect: compile-time literal regex
}

static ROUTER_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(
        r"(?im)(?:^|[;{}(,\s])([A-Za-z0-9_$]*(?:app|router|server|hono|elysia|fastify|route))\s*\.\s*(get|post|put|patch|delete|options|head|all|use)\s*\(",
    )
});
static OTHER_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(r"\.\s*(get|post|put|patch|delete|options|head|all|use|on|route)\s*\(")
});
static IMPORT_PREFIX: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"(?:\bfrom|\bimport\s*\(?)\s*$"));
static IDENTIFIER: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"^[A-Za-z_$][\w$]*$"));
static REDIRECT_ONLY: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(
        r#"^\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*))\s*=>\s*([A-Za-z_$][\w$]*)\.redirect\s*\(\s*(["'`][^"'`${}\r\n]*["'`])\s*\)\s*$"#,
    )
});

const PATH_WORDS: &[&str] = &[
    "admin",
    "billing",
    "settings",
    "account",
    "internal",
    "backoffice",
];

static WORKER_FETCH: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"\bfetch\s*\([^)]*\)\s*(?::\s*[\w$.<>]+\s*)?\{"));
static BRANCH: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\b(?:if|switch)\s*\("));

fn sensitive_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    PATH_WORDS
        .iter()
        .chain(["subscription", "payment", "role", "permission"].iter())
        .any(|word| path_has_word(&path, word))
}

fn covered(spans: &[Range<usize>], literal: &Range<usize>) -> bool {
    spans
        .iter()
        .any(|span| span.start <= literal.start && literal.end <= span.end)
}

fn record_first(first: &mut Option<usize>, offset: usize) {
    *first = Some(first.map_or(offset, |previous| previous.min(offset)));
}

pub(super) fn apply_router_guard_overrides(files: &[SourceFile], issues: &mut Vec<CodeIssue>) {
    let sources = files
        .iter()
        .map(|file| (file.relative_path.as_str(), file))
        .collect::<HashMap<_, _>>();
    issues.retain_mut(|issue| {
        let auth = issue.id.starts_with("sensitive-auth:");
        let rate = issue.id.starts_with("public-endpoint-rate-limit:");
        if !(auth || rate) || !is_js_source_path(&issue.relative_path) {
            return true;
        }
        let Some(file) = sources.get(issue.relative_path.as_str()) else {
            return true;
        };
        let structure = file_analysis::blank_non_code_for_env(file);
        let imports = imported::imported_guards(file, &structure, &sources);
        let file_sensitive = PATH_WORDS
            .iter()
            .any(|word| path_has_word(&file.relative_path.to_ascii_lowercase(), word));
        let entrypoints = structure.replace([';', '}'], "\n");
        let mut first_unprotected = ROUTE_HANDLER_MARKER_PATTERNS
            .iter()
            .filter(|(label, _)| *label != "a router verb call")
            .flat_map(|(_, pattern)| [pattern.find(&structure), pattern.find(&entrypoints)])
            .flatten()
            .map(|found| found.start())
            .min();
        let mut sensitive = false;
        let mut malformed = first_unprotected.is_some();
        let mut mounts = HashMap::new();
        let mut auth_spans = Vec::new();
        let mut limited_spans = Vec::new();
        let mut parsed_calls = HashSet::new();
        let mut all_limited = true;
        let mut routes = 0usize;
        for call in ROUTER_CALL.captures_iter(&structure) {
            let (Some(full), Some(receiver), Some(verb)) = (call.get(0), call.get(1), call.get(2))
            else {
                continue;
            };
            parsed_calls.insert(full.end() - 1);
            let Some((arguments, close)) = js_spans::arguments(&structure, full.end()) else {
                record_first(&mut first_unprotected, receiver.start());
                malformed = true;
                continue;
            };
            let handler = arguments
                .last()
                .map(|span| file.content[span.clone()].trim())
                .unwrap_or("");
            if verb.as_str().eq_ignore_ascii_case("use") {
                let global = arguments.len() == 1
                    || (arguments.len() == 2
                        && literal(&file.content[arguments[0].clone()]) == Some("*"));
                if global && imports.get(handler).is_some_and(|guard| guard.rate_limit) {
                    mounts.entry(receiver.as_str()).or_insert(receiver.start());
                }
                continue;
            }
            routes += 1;
            let span = full.end()..close;
            if mounts
                .get(receiver.as_str())
                .is_some_and(|offset| *offset < receiver.start())
            {
                limited_spans.push(span.clone());
            } else {
                all_limited = false;
            }
            let path = arguments
                .first()
                .and_then(|argument| literal(&file.content[argument.clone()]));
            if !(file_sensitive || path.is_none_or(sensitive_path)) {
                continue;
            }
            sensitive = true;
            if imports.get(handler).is_some_and(|guard| guard.auth) || redirect_only(handler) {
                auth_spans.push(span);
            } else {
                record_first(&mut first_unprotected, receiver.start());
            }
        }
        for capture in OTHER_CALL.captures_iter(&structure) {
            let Some(call) = capture.get(0) else {
                continue;
            };
            if parsed_calls.contains(&(call.end() - 1)) {
                continue;
            }
            let path_index = usize::from(capture[1].eq_ignore_ascii_case("on"));
            let unknown =
                js_spans::arguments(&structure, call.end()).is_none_or(|(arguments, _)| {
                    arguments
                        .get(path_index)
                        .is_none_or(|span| literal(&file.content[span.clone()]).is_none())
                });
            if unknown {
                malformed = true;
                record_first(&mut first_unprotected, call.start());
            }
        }
        for handler in WORKER_FETCH.find_iter(&structure) {
            let unknown = js_spans::matching(&structure, handler.end() - 1)
                .is_none_or(|end| BRANCH.is_match(&structure[handler.end()..end]));
            if unknown {
                malformed = true;
                record_first(&mut first_unprotected, handler.start());
            }
        }
        for span in js_spans::quoted_spans(&structure) {
            if IMPORT_PREFIX.is_match(&structure[..span.start]) {
                continue;
            }
            let value = &file.content[span.start + 1..span.end - 1];
            if !value.starts_with('/') {
                continue;
            }
            let is_sensitive = file_sensitive || sensitive_path(value);
            if is_sensitive && !covered(&auth_spans, &span) {
                record_first(&mut first_unprotected, span.start);
            }
            if (is_sensitive || has_any(value, &PUBLIC_RISK_ENDPOINT_PATTERNS))
                && !covered(&limited_spans, &span)
            {
                all_limited = false;
            }
        }
        if auth {
            if sensitive && !malformed && first_unprotected.is_none() {
                return false;
            }
            if let Some(offset) = first_unprotected {
                issue.line = Some(line_number(&file.content, offset));
                issue.source_excerpt = excerpt_for_line(&file.content, issue.line);
            }
        }
        !(rate && !malformed && routes > 0 && all_limited)
    });
}

fn redirect_only(handler: &str) -> bool {
    REDIRECT_ONLY.captures(handler).is_some_and(|capture| {
        capture
            .get(1)
            .or_else(|| capture.get(2))
            .is_some_and(|parameter| parameter.as_str() == &capture[3])
            && literal(&capture[4]).is_some()
    })
}
