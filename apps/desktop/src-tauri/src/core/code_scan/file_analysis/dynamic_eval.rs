use super::*;

static JS_REQUEST_VALUE_ASSIGNMENT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(
    || {
        regex::Regex::new(
            r"(?m)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:await\s+)?(?:req(?:uest)?\.(?:json|text|formData)\s*\(|req(?:uest)?\.(?:body|query|params)\b|searchParams\.get\s*\()",
        )
        .expect("static JS request assignment regex") // allow-expect: compile-time literal regex
    },
);

static JS_DIRECT_REQUEST_VALUE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?:\breq(?:uest)?\.(?:body|query|params)\b|\bsearchParams\.get\s*\()")
            .expect("static JS request value regex") // allow-expect: compile-time literal regex
    });

/// Request-variable names come from the scanned file, so their matcher cannot
/// be a shared static. Names are grouped into alternations instead, so a file
/// with thousands of request variables still compiles a bounded number of
/// patterns rather than one pattern that could exceed the regex size limit.
pub(super) const REQUEST_VAR_MATCHER_CHUNK: usize = 256;

/// Compile the request-variable matchers for one file. `\b(?:a|b)\b` accepts
/// exactly the strings that `\ba\b` or `\bb\b` accept, so grouping the names
/// does not change which arguments are considered request-derived.
pub(super) fn request_var_matchers(
    names: &std::collections::BTreeSet<String>,
) -> Vec<regex::Regex> {
    names
        .iter()
        .collect::<Vec<_>>()
        .chunks(REQUEST_VAR_MATCHER_CHUNK)
        .filter_map(|chunk| {
            let alternation = chunk
                .iter()
                .map(|name| regex::escape(name))
                .collect::<Vec<_>>()
                .join("|");
            regex::Regex::new(&format!(r"\b(?:{})\b", alternation)).ok()
        })
        .collect()
}

/// Find dynamic evaluation fed directly or locally from parsed request data.
pub(super) fn request_derived_dynamic_eval_line(content: &str) -> Option<u32> {
    let structure = super::super::js_sinks::blank_js(content, true);
    let scan = super::super::js_sinks::blank_js(content, false);
    let request_vars = JS_REQUEST_VALUE_ASSIGNMENT
        .captures_iter(&structure)
        .filter_map(|capture| capture.get(1).map(|name| name.as_str().to_string()))
        .collect::<std::collections::BTreeSet<_>>();
    // Compiled once per file: the arguments change per evaluation call, the
    // variable names do not.
    let request_var_matchers = request_var_matchers(&request_vars);

    for matched in EVAL_EXEC_PATTERNS
        .iter()
        .flat_map(|pattern| pattern.find_iter(&structure))
    {
        let arguments = super::super::js_sinks::call_arg_window(&scan, matched.end(), 600);
        if JS_DIRECT_REQUEST_VALUE.is_match(arguments) || has_any(arguments, &request_var_matchers)
        {
            return Some(line_number(&structure, matched.start()));
        }
    }
    None
}
