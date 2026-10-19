use super::*;
use definitions::{definitions, Definition};

#[path = "definitions.rs"]
mod definitions;

static NAMED_IMPORT: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r#"(?s)\bimport\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']"#));
static CALL: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\("));
static RETURN: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\breturn\s*$"));
static STATUS: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"\bstatus\s*:\s*(?:401|403)\b"));
static FORWARD: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"^(?:return\s+)?(?:await\s+)?([A-Za-z_$][\w$]*)\s*\("));
static ASSIGN: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(r"^\s*(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(")
});
static PROPAGATE: LazyLock<regex::Regex> = LazyLock::new(|| {
    compile(
        r"^\s*;?\s*if\s*\(\s*([A-Za-z_$][\w$]*)\s+instanceof\s+Response\s*\)\s*\{?\s*return\s+([A-Za-z_$][\w$]*)\s*;",
    )
});

#[derive(Default)]
pub(super) struct GuardEvidence {
    pub(super) auth: bool,
    pub(super) rate_limit: bool,
}

pub(super) fn imported_guards(
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
        let definitions = definitions(&code);
        let mut gated = definitions
            .iter()
            .filter(|definition| authenticates(module, &code, definition))
            .map(|definition| definition.name.as_str())
            .collect::<HashSet<_>>();
        loop {
            let forwarded = definitions
                .iter()
                .filter(|definition| {
                    !gated.contains(definition.name.as_str())
                        && forwards_gate(&code, definition, &gated)
                })
                .map(|definition| definition.name.as_str())
                .collect::<Vec<_>>();
            if forwarded.is_empty() {
                break;
            }
            gated.extend(forwarded);
        }
        for specifier in capture[1].split(',') {
            let parts = specifier.split_whitespace().collect::<Vec<_>>();
            let (export, local) = match parts.as_slice() {
                [name] => (*name, *name),
                [name, "as", alias] => (*name, *alias),
                _ => continue,
            };
            if !IDENTIFIER.is_match(local) {
                continue;
            }
            let definition = definitions
                .iter()
                .find(|definition| definition.exported && definition.name == export);
            imports.insert(
                local.to_string(),
                GuardEvidence {
                    auth: definition
                        .is_some_and(|definition| gated.contains(definition.name.as_str())),
                    rate_limit: definition.is_some_and(|definition| {
                        has_any(&code[definition.body.clone()], &RATE_LIMIT_PATTERNS)
                    }),
                },
            );
        }
    }
    imports
}

fn authenticates(module: &SourceFile, code: &str, definition: &Definition) -> bool {
    let body = &code[definition.body.clone()];
    AUTH_PATTERNS
        .iter()
        .filter(|pattern| pattern.as_str() != r"\buserId\b")
        .chain(SESSION_LOOKUP_PATTERNS.iter())
        .flat_map(|pattern| pattern.find_iter(body))
        .any(|identity| {
            let start = definition.body.start + identity.end();
            let mut end = (start + 400).min(definition.body.end);
            while !code.is_char_boundary(end) {
                end -= 1;
            }
            CALL.captures_iter(&code[start..end]).any(|call| {
                let Some(full) = call.get(0) else {
                    return false;
                };
                let call_start = start + full.start();
                if !RETURN.is_match(&code[start..call_start]) {
                    return false;
                }
                let Some((args, close)) = js_spans::arguments(code, start + full.end()) else {
                    return false;
                };
                if close > end {
                    return false;
                }
                let name = call[1].rsplit('.').next().unwrap_or("").trim();
                if name == "redirect" {
                    return args.first().is_some_and(|argument| {
                        sign_in_target(&module.content[argument.clone()], &code[argument.clone()])
                    });
                }
                matches!(
                    name,
                    "problem" | "text" | "json" | "status" | "sendStatus" | "code" | "Response"
                ) && args.iter().any(|argument| {
                    let value = code[argument.clone()].trim();
                    matches!(value, "401" | "403")
                        || (value.starts_with('{') && STATUS.is_match(value))
                })
            })
        })
}

fn sign_in_literal(value: &str) -> bool {
    let value = value.trim();
    let Some(quote) = value.as_bytes().first() else {
        return false;
    };
    if !matches!(quote, b'\'' | b'"' | b'`')
        || value.len() < 2
        || value.as_bytes().last() != Some(quote)
    {
        return false;
    }
    ["/sign-in", "/signin", "/login", "/log-in", "/auth"]
        .iter()
        .any(|prefix| {
            value[1..value.len() - 1]
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with(['/', '?', '#']))
        })
}

fn sign_in_target(content: &str, structure: &str) -> bool {
    if sign_in_literal(content) {
        return true;
    }
    let mut branches = Vec::new();
    let mut quote = None;
    let mut depth = 0usize;
    for (offset, byte) in structure.bytes().enumerate() {
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'?' | b':' if depth == 0 => branches.push(offset),
            _ => {}
        }
    }
    matches!(branches.as_slice(), [question, colon] if structure.as_bytes()[*question] == b'?' && structure.as_bytes()[*colon] == b':' && sign_in_literal(&content[question+1..*colon]) && sign_in_literal(&content[colon+1..]))
}

fn forwards_gate(code: &str, definition: &Definition, gated: &HashSet<&str>) -> bool {
    let body = code[definition.body.clone()].trim();
    if let Some(call) = FORWARD.captures(body) {
        if (definition.expression || body.starts_with("return ")) && gated.contains(&call[1]) {
            return true;
        }
    }
    let Some(assignment) = ASSIGN.captures(body) else {
        return false;
    };
    if !gated.contains(&assignment[2]) {
        return false;
    }
    let Some(full) = assignment.get(0) else {
        return false;
    };
    let Some((_, close)) = js_spans::arguments(body, full.end()) else {
        return false;
    };
    PROPAGATE
        .captures(&body[close + 1..])
        .is_some_and(|propagate| propagate[1] == assignment[1] && propagate[2] == assignment[1])
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
    let replacements: &[&str] = match Path::new(&path)
        .extension()
        .and_then(|value| value.to_str())
    {
        Some("js") => &["ts", "tsx"],
        Some("mjs") => &["mts"],
        Some("cjs") => &["cts"],
        _ => &[],
    };
    for extension in replacements {
        let candidate = Path::new(&path)
            .with_extension(extension)
            .to_string_lossy()
            .to_string();
        if let Some(file) = sources.get(candidate.as_str()) {
            return Some(file);
        }
    }
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
