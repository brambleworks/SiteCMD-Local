//! Recognize guards on redirect destinations, not unrelated file-wide signals.

use super::handler_spans::HandlerSpans;
use super::js_sinks::{blank_js, call_arg_window, first_arg};
use super::*;
use crate::constants::{
    CODE_SCAN_REDIRECT_ARGUMENT_BYTES, CODE_SCAN_REDIRECT_MAX_DEPTH, CODE_SCAN_REDIRECT_MAX_TARGETS,
};
use std::sync::LazyLock;

fn pattern(source: &str) -> regex::Regex {
    regex::Regex::new(source).expect("static redirect pattern") // allow-expect: compile-time literal regex
}

static REDIRECT_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    pattern(r"\b(?:(?:Response|NextResponse|res)\s*\.\s*)?(?:redirect|permanentRedirect)\s*\(")
});
static CHECKOUT_FIELD: LazyLock<regex::Regex> =
    LazyLock::new(|| pattern(r"\b(?:success_url|cancel_url)\s*:\s*"));
static ASSIGNMENT: LazyLock<regex::Regex> = LazyLock::new(|| {
    pattern(
        r"(?m)(?:\b(?P<declaration>const|let|var)\s+|(?:^|[;{}\n)])\s*)(?P<name>[A-Za-z_$][\w$]*)(?P<member>(?:\.[A-Za-z_$][\w$]*)*)\s*=\s*",
    )
});
static DESTINATION: LazyLock<regex::Regex> =
    LazyLock::new(|| pattern(r"^(?P<name>[A-Za-z_$][\w$]*)(?:\.href|\.toString\(\))?$"));
static ORIGIN_BRANCH: LazyLock<regex::Regex> = LazyLock::new(|| {
    pattern(
        r"\bif\s*\(\s*(?P<name>[A-Za-z_$][\w$]*)\.origin\s*===\s*(?P<origin>[^;(){}\r\n]+?)\s*\)\s*\{?\s*(?:return\s+)?$",
    )
});
static ORIGIN_REJECTION: LazyLock<regex::Regex> = LazyLock::new(|| {
    pattern(
        r"(?:^|[;{}])\s*if\s*\(\s*(?P<name>[A-Za-z_$][\w$]*)\.origin\s*!==\s*(?P<origin>[^;(){}\r\n]+?)\s*\)\s*\{\s*(?:throw|return)\b[^{};]+;\s*\}\s*(?:return\s+)?$",
    )
});
static NORMALIZER: LazyLock<regex::Regex> =
    LazyLock::new(|| pattern(r"^(?P<name>[A-Za-z_$][\w$]*)\s*\("));
static URL_CONSTRUCTOR: LazyLock<regex::Regex> = LazyLock::new(|| pattern(r"^new\s+URL\s*\("));
static REQUEST_URL: LazyLock<regex::Regex> =
    LazyLock::new(|| pattern(r"^new\s+URL\s*\(\s*(?:req|request)\.url\s*\)$"));
static REQUEST_URL_READ: LazyLock<regex::Regex> =
    LazyLock::new(|| pattern(r"^\s*\.\s*(?:origin\b|searchParams\s*\.\s*(?:get|getAll|has)\s*\()"));
static ENV_ORIGIN: LazyLock<regex::Regex> =
    LazyLock::new(|| pattern(r"^process\.env\.[A-Za-z_$][\w$]*$"));
static IDENTIFIER: LazyLock<regex::Regex> = LazyLock::new(|| pattern(r"[A-Za-z_$][\w$]*"));

struct GuardContext<'a> {
    source: &'a str,
    structure: String,
}

pub(super) fn has_guarded_redirects(source: &str, checkout: bool) -> bool {
    let context = GuardContext {
        source,
        structure: blank_js(source, true),
    };
    let mut targets = Vec::new();
    for call in REDIRECT_CALL.find_iter(&context.structure) {
        let Some(window) = complete_call_window(&context.structure, call.end()) else {
            return false;
        };
        if targets.len() == CODE_SCAN_REDIRECT_MAX_TARGETS {
            return false;
        }
        let arguments = &source[call.end()..call.end() + window.len() - 1];
        targets.push((first_arg(arguments).trim(), call.start()));
    }
    if checkout {
        for field in CHECKOUT_FIELD.find_iter(&context.structure) {
            if targets.len() == CODE_SCAN_REDIRECT_MAX_TARGETS {
                return false;
            }
            targets.push((first_arg(&source[field.end()..]).trim(), field.start()));
        }
    }
    !targets.is_empty()
        && targets
            .into_iter()
            .all(|(value, at)| context.safe_value(value, at, 0))
}

/// Offset of a request-derived redirect field that shares a route handler with
/// a redirect destination that is neither constant nor locally guarded.
pub(super) fn unguarded_request_redirect(source: &str) -> Option<usize> {
    let mut fields = USER_CONTROLLED_REDIRECT_PATTERNS
        .iter()
        .flat_map(|pattern| pattern.find_iter(source).map(|found| found.start()))
        .collect::<Vec<_>>();
    fields.sort_unstable();
    let context = GuardContext {
        source,
        structure: blank_js(source, true),
    };
    let handlers = HandlerSpans::new(&context.structure);
    let mut targets = 0;
    for call in REDIRECT_CALL.find_iter(&context.structure) {
        let Some(&field) = fields
            .iter()
            .find(|&&field| !handlers.separate(field, call.start()))
        else {
            continue;
        };
        let Some(window) = complete_call_window(&context.structure, call.end()) else {
            return Some(field);
        };
        targets += 1;
        let target = first_arg(&source[call.end()..call.end() + window.len() - 1]).trim();
        if targets > CODE_SCAN_REDIRECT_MAX_TARGETS || !context.safe_value(target, call.start(), 0)
        {
            return Some(field);
        }
    }
    None
}

impl GuardContext<'_> {
    fn safe_value(&self, value: &str, at: usize, depth: usize) -> bool {
        if depth >= CODE_SCAN_REDIRECT_MAX_DEPTH || value.len() > CODE_SCAN_REDIRECT_ARGUMENT_BYTES
        {
            return false;
        }
        let value = value.trim();
        if literal(value).is_some() {
            return true;
        }
        if let Some(parts) = template_interpolations(value) {
            return parts
                .into_iter()
                .all(|part| self.safe_value(part, at, depth + 1));
        }
        let structure = blank_js(value, true);
        if let Some(question) = structure.find('?') {
            if let Some(colon) = structure[question + 1..].find(':') {
                let colon = question + 1 + colon;
                return self.safe_value(&value[question + 1..colon], at, depth + 1)
                    && self.safe_value(&value[colon + 1..], at, depth + 1);
            }
        }
        if let Some(call) = NORMALIZER.captures(&structure) {
            let name = &call["name"];
            if !name.starts_with("is")
                && has_any(name, &REDIRECT_ALLOWLIST_PATTERNS)
                && call.get(0).is_some_and(|matched| {
                    complete_call_window(&structure, matched.end())
                        .is_some_and(|window| matched.end() + window.len() == structure.len())
                })
            {
                return true;
            }
        }
        let value = value.strip_suffix(".toString()").unwrap_or(value);
        if let Some(constructor) = URL_CONSTRUCTOR.find(value) {
            if let Some(arguments) = value[constructor.end()..].strip_suffix(')') {
                let target = first_arg(arguments);
                if let Some(base) = arguments[target.len()..].strip_prefix(',') {
                    return self.safe_value(target, at, depth + 1)
                        && self.trusted_origin(base.trim(), at);
                }
            }
            return false;
        }
        let Some(target) = DESTINATION.captures(value) else {
            return false;
        };
        let name = &target["name"];
        self.origin_guard(name, at) || self.safe_binding(name, at, depth + 1)
    }

    fn origin_guard(&self, name: &str, at: usize) -> bool {
        [&*ORIGIN_BRANCH, &*ORIGIN_REJECTION]
            .into_iter()
            .filter_map(|guard| guard.captures(&self.structure[..at]))
            .any(|matched| {
                let origin = matched.name("origin").expect("origin capture"); // allow-expect: fixed pattern capture
                matched
                    .name("name")
                    .is_some_and(|found| found.as_str() == name)
                    && self.trusted_origin(&self.source[origin.range()], at)
            })
    }

    fn trusted_origin(&self, value: &str, at: usize) -> bool {
        let value = value.trim();
        if let Some(value) = literal(value) {
            return url::Url::parse(value)
                .is_ok_and(|url| matches!(url.scheme(), "http" | "https"));
        }
        if ENV_ORIGIN.is_match(value) {
            return true;
        }
        let Some(name) = value.strip_suffix(".origin") else {
            return false;
        };
        let Some(bindings) = self.bindings(name, at) else {
            return false;
        };
        let start = bindings[0].0;
        bindings.len() == 1
            && REQUEST_URL.is_match(bindings[0].1)
            && IDENTIFIER
                .find_iter(&self.structure[start..at])
                .filter(|found| {
                    found.as_str() == name
                        && found.start() != 0
                        && !self.structure[..start + found.start()]
                            .trim_end()
                            .ends_with('.')
                })
                .all(|found| REQUEST_URL_READ.is_match(&self.structure[start + found.end()..at]))
    }

    fn safe_binding(&self, name: &str, at: usize, depth: usize) -> bool {
        let Some(bindings) = self.bindings(name, at) else {
            return false;
        };
        let start = bindings[0].0;
        if IDENTIFIER
            .find_iter(&self.structure[start..at])
            .any(|found| {
                found.as_str() == name
                    && !bindings
                        .iter()
                        .any(|(position, _)| *position == start + found.start())
            })
        {
            return false;
        }
        bindings
            .iter()
            .all(|(position, value)| self.safe_value(value, *position, depth))
    }

    fn bindings(&self, name: &str, at: usize) -> Option<Vec<(usize, &str)>> {
        let matches = ASSIGNMENT
            .captures_iter(&self.structure[..at])
            .filter(|matched| &matched["name"] == name)
            .collect::<Vec<_>>();
        let declaration = matches.iter().rposition(|matched| {
            matched.name("declaration").is_some()
                && matched.name("name").is_some_and(|name| {
                    scope_contains(
                        &self.structure,
                        scope_start(&self.structure, name.start()),
                        at,
                    )
                })
        })?;
        matches[declaration..]
            .iter()
            .map(|matched| {
                if !matched["member"].is_empty() {
                    return None;
                }
                let start = matched.get(0)?.end();
                if matches!(self.structure.as_bytes().get(start), Some(b'=' | b'>')) {
                    return None;
                }
                let end = start + self.structure[start..at].find(';')?;
                Some((
                    matched.name("name")?.start(),
                    self.source[start..end].trim(),
                ))
            })
            .collect()
    }
}

fn complete_call_window(structure: &str, after: usize) -> Option<&str> {
    let window = call_arg_window(structure, after, CODE_SCAN_REDIRECT_ARGUMENT_BYTES);
    let depth = window.bytes().fold(1isize, |depth, byte| match byte {
        b'(' => depth + 1,
        b')' => depth - 1,
        _ => depth,
    });
    (depth == 0 && window.ends_with(')')).then_some(window)
}

fn literal(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"' | b'`')
        || bytes.len() < 2
        || bytes.last() != Some(&quote)
        || value.contains("${")
    {
        return None;
    }
    let structure = blank_js(value, true);
    structure[1..structure.len() - 1]
        .trim()
        .is_empty()
        .then(|| &value[1..value.len() - 1])
}

/// Interpolated expressions of a single template literal, or `None` when the
/// value is not one template or nests quotes inside an interpolation.
fn template_interpolations(value: &str) -> Option<Vec<&str>> {
    let body = value.strip_prefix('`')?.strip_suffix('`')?;
    let bytes = body.as_bytes();
    let mut parts = Vec::new();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\\' => index += 2,
            b'`' => return None,
            b'$' if bytes.get(index + 1) == Some(&b'{') => {
                let start = index + 2;
                let mut depth = 1;
                let mut end = start;
                while depth > 0 {
                    match bytes.get(end)? {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        b'`' | b'"' | b'\'' => return None,
                        _ => {}
                    }
                    end += 1;
                }
                parts.push(&body[start..end - 1]);
                index = end;
            }
            _ => index += 1,
        }
    }
    Some(parts)
}

fn scope_start(structure: &str, at: usize) -> usize {
    let mut depth = 0;
    for (position, byte) in structure.as_bytes()[..at].iter().enumerate().rev() {
        match byte {
            b'}' => depth += 1,
            b'{' if depth == 0 => return position + 1,
            b'{' => depth -= 1,
            _ => {}
        }
    }
    0
}

fn scope_contains(structure: &str, start: usize, at: usize) -> bool {
    if start == 0 {
        return true;
    }
    let mut depth = 1;
    for byte in &structure.as_bytes()[start..at] {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            return false;
        }
    }
    true
}
