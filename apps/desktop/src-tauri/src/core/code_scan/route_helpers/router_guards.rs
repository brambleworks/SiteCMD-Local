use super::*;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

fn compile(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static router guard regex") // allow-expect: compile-time literal regex
}

static ROUTER_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(
        r"(?im)(?:^|[;{}(,\s])([A-Za-z0-9_$]*(?:app|router|server|hono|elysia|fastify|route))\s*\.\s*(get|post|put|patch|delete|options|head|all|use)\s*\(",
    )
});
static NAMED_IMPORT: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r#"(?s)\bimport\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']"#));
static IDENTIFIER: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"^[A-Za-z_$][\w$]*$"));
static REDIRECT_ONLY: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(
        r#"^\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*))\s*=>\s*([A-Za-z_$][\w$]*)\.redirect\s*\(\s*(["'`][^"'`${}\r\n]*["'`])\s*\)\s*$"#,
    )
});
static AUTH_REFUSAL: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(r"\bredirect\s*\(|(?:\bstatus\s*[:(]\s*|\bsendStatus\s*\(\s*|,\s*)(?:401|403)\b")
});

#[derive(Default)]
struct GuardEvidence {
    auth: bool,
    rate_limit: bool,
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
        let imports = imported_guards(file, &structure, &sources);
        let mut sensitive = false;
        let mut malformed = false;
        let mut first_unprotected = None;
        let mut limited = HashSet::new();
        let mut receivers = HashSet::new();
        for call in ROUTER_CALL.captures_iter(&structure) {
            let (Some(full), Some(receiver), Some(verb)) = (call.get(0), call.get(1), call.get(2))
            else {
                continue;
            };
            let verb = verb.as_str();
            let Some(arguments) = arguments(&file.content, &structure, full.end()) else {
                first_unprotected.get_or_insert(receiver.start());
                malformed = true;
                continue;
            };
            if verb.eq_ignore_ascii_case("use") {
                let global = arguments.len() == 1
                    || (arguments.len() == 2 && literal(arguments[0]) == Some("*"));
                if global
                    && arguments
                        .last()
                        .and_then(|name| imports.get(*name))
                        .is_some_and(|guard| guard.rate_limit)
                {
                    limited.insert(receiver.as_str());
                }
                continue;
            }
            receivers.insert(receiver.as_str());
            let path = arguments.first().and_then(|argument| literal(argument));
            let is_sensitive = path.is_none_or(|path| {
                let lower = path.to_ascii_lowercase();
                [
                    "admin",
                    "billing",
                    "settings",
                    "account",
                    "internal",
                    "backoffice",
                ]
                .iter()
                .any(|word| path_has_word(&lower, word))
            });
            if !is_sensitive {
                continue;
            }
            sensitive = true;
            let guarded = arguments.last().is_some_and(|handler| {
                imports.get(*handler).is_some_and(|guard| guard.auth) || redirect_only(handler)
            });
            if !guarded {
                first_unprotected.get_or_insert(receiver.start());
            }
        }
        if auth {
            if sensitive && first_unprotected.is_none() {
                return false;
            }
            if let Some(offset) = first_unprotected {
                issue.line = Some(line_number(&file.content, offset));
                issue.source_excerpt = excerpt_for_line(&file.content, issue.line);
            }
        }
        !(rate && !malformed && !receivers.is_empty() && receivers.is_subset(&limited))
    });
}

fn imported_guards(
    file: &SourceFile,
    structure: &str,
    sources: &HashMap<&str, &SourceFile>,
) -> HashMap<String, GuardEvidence> {
    let mut imports = HashMap::new();
    for capture in NAMED_IMPORT.captures_iter(&file.content) {
        let Some(matched) = capture.get(0) else {
            continue;
        };
        if !structure[matched.start()..].starts_with("import") {
            continue;
        }
        let Some(module) = resolve_module(&file.relative_path, &capture[2], sources) else {
            continue;
        };
        let code = file_analysis::blank_non_code_for_env(module);
        let auth = (has_any(&code, &AUTH_PATTERNS) || has_any(&code, &SESSION_LOOKUP_PATTERNS))
            && AUTH_REFUSAL.is_match(&code);
        let rate_limit = has_any(&code, &RATE_LIMIT_PATTERNS);
        for specifier in capture[1].split(',') {
            let parts = specifier.split_whitespace().collect::<Vec<_>>();
            let local = match parts.as_slice() {
                [name] => *name,
                [_, "as", alias] => *alias,
                _ => continue,
            };
            if IDENTIFIER.is_match(local) {
                imports.insert(local.to_string(), GuardEvidence { auth, rate_limit });
            }
        }
    }
    imports
}

fn resolve_module<'a>(
    router: &str,
    specifier: &str,
    sources: &HashMap<&str, &'a SourceFile>,
) -> Option<&'a SourceFile> {
    if !specifier.starts_with("./") && !specifier.starts_with("../") {
        return None;
    }
    let parent = router.rsplit_once('/').map_or("", |(parent, _)| parent);
    let joined = format!("{parent}/{specifier}");
    let mut components = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            _ => components.push(part),
        }
    }
    let path = components.join("/");
    if let Some(file) = sources.get(path.as_str()) {
        return Some(file);
    }
    for extension in JS_SOURCE_EXTENSIONS {
        for candidate in [
            format!("{path}.{extension}"),
            format!("{path}/index.{extension}"),
        ] {
            if let Some(file) = sources.get(candidate.as_str()) {
                return Some(file);
            }
        }
    }
    None
}

fn literal(value: &str) -> Option<&str> {
    let quote = *value.as_bytes().first()?;
    if !matches!(quote, b'\'' | b'"' | b'`')
        || value.len() < 2
        || value.as_bytes().last() != Some(&quote)
    {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    (!inner.contains(['\\', '\'', '"', '`']) && !inner.contains("${")).then_some(inner)
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

fn arguments<'a>(content: &'a str, structure: &str, after: usize) -> Option<Vec<&'a str>> {
    let mut start = after;
    let mut depth = 0usize;
    let mut quote = None;
    let mut arguments = Vec::new();
    for (offset, byte) in structure.as_bytes().iter().copied().enumerate().skip(after) {
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' if depth == 0 => {
                let last = content[start..offset].trim();
                if !last.is_empty() || arguments.is_empty() {
                    arguments.push(last);
                }
                return Some(arguments);
            }
            b')' | b']' | b'}' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                arguments.push(content[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    None
}
