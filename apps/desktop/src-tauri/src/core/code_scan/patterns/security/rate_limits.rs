use std::sync::LazyLock;

static UPSTREAM_LIMIT_HEADER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"["'`](?i:x-ratelimit-(?:limit|remaining|reset|used)(?:-[a-z0-9_]+)*|ratelimit(?:-(?:policy|limit|remaining|reset))?)["'`]"#)
        .expect("static upstream limit-header regex") // allow-expect: compile-time literal regex
});

pub(in crate::core::code_scan) fn has_rate_limit_evidence(content: &str) -> bool {
    let scanned = UPSTREAM_LIMIT_HEADER.replace_all(content, " ");
    RATE_LIMIT_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(&scanned))
}

pub(in crate::core::code_scan) static RATE_LIMIT_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        let compile = |source| regex::Regex::new(source).expect("static rate-limit regex"); // allow-expect: compile-time literal patterns
        vec![
            compile(r"\b[A-Z0-9_]*RATE_?LIMIT[A-Z0-9_]*\s*\.\s*limit\s*\("),
            compile(r"rate[-_ ]?limit"),
            compile(r"ratelimit"),
            compile(r"express-rate-limit"),
            compile(r"upstash/ratelimit"),
            compile(r"\blimiter\b"),
            compile(r"\bthrottle\b"),
            compile(r"\bslowDown\b"),
            compile(r"\bgov(ernor|ernor)\b"),
        ]
    });
