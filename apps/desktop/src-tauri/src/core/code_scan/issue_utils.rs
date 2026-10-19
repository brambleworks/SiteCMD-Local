use super::*;
use regex::Regex;
use std::fmt::Write as _;
use std::sync::LazyLock;

static SECRET_ENV_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?P<key>[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASS|PWD|DATABASE_URL|DB_URL|PRIVATE|CREDENTIAL|AUTH)[A-Z0-9_]*)\s*=\s*(?P<value>"[^"\n]*"|'[^'\n]*'|[^\s#]+)"#,
    )
    .expect("static secret env assignment regex") // allow-expect: compile-time literal regex
});

static SECRET_CODE_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    // `mid` allows an optional closing quote on the key so the JSON/MCP form
    // `"apiKey": "..."` is masked the same as the bare `apiKey = "..."` form.
    Regex::new(
        r#"(?i)\b(?P<key>api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|database[_-]?url|authorization|secret|password)\b(?P<mid>["']?\s*[:=]\s*)(?P<value>["'`][^"'`\n]{8,}["'`]|[A-Za-z0-9_./:+\-]{8,})"#,
    )
    .expect("static secret code assignment regex") // allow-expect: compile-time literal regex
});

static DATABASE_URL_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?P<scheme>postgres(?:ql)?|mysql(?:2)?|mariadb)://(?P<user>[^:\s/@]+):(?P<password>[^@\s]+)@"#)
        .expect("static database credential regex") // allow-expect: compile-time literal regex
});

/// Credentials embedded in arbitrary URL userinfo, including Git dependency
/// URLs. Provider-token patterns cannot cover private registries or opaque
/// usernames/passwords, so mask the whole userinfo segment.
static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)[^/\s@]+@")
        .expect("static URL userinfo regex") // allow-expect: compile-time literal regex
});

static TOKEN_REDACTION_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r#"(?i)\b(?P<prefix>sk[-_](?:live|test)[-_])[A-Za-z0-9]{12,}"#)
                .expect("static stripe token regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
        (
            Regex::new(r#"\bAKIA[0-9A-Z]{16}\b"#).expect("static aws key regex"), // allow-expect: compile-time literal regex
            "AKIA***",
        ),
        (
            Regex::new(r#"(?i)\b(?P<prefix>gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}\b"#)
                .expect("static github token regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
        (
            Regex::new(r#"(?i)\b(?P<prefix>glpat-)[A-Za-z0-9\-_]{12,}\b"#)
                .expect("static gitlab token regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
        (
            Regex::new(r#"(?i)\b(?P<prefix>xox[baprs]-)[A-Za-z0-9\-]{10,}\b"#)
                .expect("static slack token regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
        (
            Regex::new(r#"(?i)\b(?P<prefix>SG\.)[A-Za-z0-9\-_]{22,}\b"#)
                .expect("static sendgrid token regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
        // OpenAI/Anthropic-style keys (including the `sk-proj-`/`sk-svcacct-`/
        // `sk-ant-` variants). Mirrors the bare-token shapes MCP_SECRET_PATTERNS
        // flags, so anything the config-secret check reports can be redacted.
        (
            Regex::new(r#"\b(?P<prefix>sk-(?:proj-|svcacct-|ant-)?)[A-Za-z0-9_-]{16,}"#)
                .expect("static openai/anthropic token regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
        // Google API keys.
        (
            Regex::new(r#"\b(?P<prefix>AIza)[0-9A-Za-z\-_]{16,}"#)
                .expect("static google api key regex"), // allow-expect: compile-time literal regex
            "${prefix}***",
        ),
    ]
});

static CLIENT_COMPONENT_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^[ \t]*["']use client["'][ \t]*;?[ \t]*(?:(?://[^\r\n]*)|(?:/\*[^\r\n]*\*/))?[ \t]*\r?$"#,
    )
        .expect("static client component directive regex") // allow-expect: compile-time literal regex
});

pub(super) fn build_issue(
    slug: &str,
    category: &str,
    severity: Severity,
    title: &str,
    description: &str,
    file: &SourceFile,
    line: Option<u32>,
    evidence: Option<String>,
    likely_fix: Option<String>,
    verify_hint: Option<String>,
) -> CodeIssue {
    // Grade confidence per slug: direct observations are Confirmed, bounded
    // inferences are High, and runtime/context-dependent heuristics remain
    // NeedsReview so the UI and score preserve the evidence distinction.
    let (confidence, confidence_reason) =
        crate::core::confidence_policy::code_issue_confidence(slug);
    CodeIssue {
        id: format!("{}:{}", slug, file.relative_path),
        // Populated in the audit_project_with_progress finalize pass via resolve_check_id.
        check_id: String::new(),
        category: category.to_string(),
        severity,
        title: title.to_string(),
        description: description.to_string(),
        relative_path: file.relative_path.clone(),
        absolute_path: file.absolute_path.to_string_lossy().to_string(),
        line,
        source_excerpt: excerpt_for_line(&file.content, line),
        // Redact evidence structurally (not per-call-site): any analyzer that
        // interpolates a secret-like value into `evidence` gets the same
        // masking the source excerpt already receives.
        evidence: evidence.map(|value| redact_sensitive_excerpt_line(&value)),
        why_now: Some(
            code_issue_rationale(slug)
                // Literal rule slugs require dedicated rationale; dynamic slugs
                // fall back to their issue description.
                .unwrap_or(description)
                .into(),
        ),
        likely_fix,
        confidence,
        confidence_reason: confidence_reason.map(|s| s.to_string()),
        verify_hint,
    }
}

/// Redaction boundary for evidence built outside `build_issue`.
pub(crate) fn redact_evidence(value: impl AsRef<str>) -> String {
    redact_sensitive_excerpt_line(value.as_ref())
}

/// Return the shared confidence-policy grade in the owned form used by inline
/// `CodeIssue` values.
pub(super) fn policy_confidence(slug: &str) -> (crate::checks::IssueConfidence, Option<String>) {
    let (confidence, reason) = crate::core::confidence_policy::code_issue_confidence(slug);
    (confidence, reason.map(|reason| reason.to_string()))
}

pub(super) fn has_any(content: &str, patterns: &[regex::Regex]) -> bool {
    patterns.iter().any(|pattern| pattern.is_match(content))
}

#[path = "issue_utils/sink_context.rs"]
mod sink_context;
pub(super) use sink_context::{executable_sink_matches, has_any_unquoted};

pub(super) fn count_matches(content: &str, patterns: &[regex::Regex]) -> usize {
    patterns
        .iter()
        .map(|pattern| pattern.find_iter(content).count())
        .sum()
}

pub(super) fn first_match_line(content: &str, patterns: &[regex::Regex]) -> Option<u32> {
    patterns.iter().find_map(|pattern| {
        pattern
            .find(content)
            .map(|m| line_number(content, m.start()))
    })
}

pub(super) fn first_match_line_single(content: &str, pattern: &regex::Regex) -> Option<u32> {
    pattern
        .find(content)
        .map(|m| line_number(content, m.start()))
}

pub(super) fn find_line(content: &str, needle: &str) -> Option<u32> {
    content
        .find(needle)
        .map(|index| line_number(content, index))
}

pub(super) fn client_component_directive_line(content: &str) -> Option<u32> {
    CLIENT_COMPONENT_DIRECTIVE
        .find_iter(content)
        .find(|matched| is_directive_prologue_prefix(&content[..matched.start()]))
        .map(|matched| line_number(content, matched.start()))
}

fn is_directive_prologue_prefix(mut prefix: &str) -> bool {
    loop {
        prefix = prefix.trim_start_matches(|character: char| {
            character.is_whitespace() || character == '\u{feff}'
        });
        if prefix.is_empty() {
            return true;
        }
        if let Some(comment) = prefix.strip_prefix("//") {
            prefix = comment
                .find('\n')
                .map(|end| &comment[end + 1..])
                .unwrap_or("");
            continue;
        }
        if let Some(comment) = prefix.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else {
                return false;
            };
            prefix = &comment[end + 2..];
            continue;
        }

        let Some(quote) = prefix
            .chars()
            .next()
            .filter(|quote| matches!(quote, '\'' | '"'))
        else {
            return false;
        };
        let mut escaped = false;
        let mut closing_index = None;
        for (index, character) in prefix[quote.len_utf8()..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
            } else if character == quote {
                closing_index = Some(quote.len_utf8() + index + character.len_utf8());
                break;
            }
        }
        let Some(end) = closing_index else {
            return false;
        };
        prefix = &prefix[end..];
        prefix = prefix.trim_start_matches([' ', '\t']);
        if let Some(rest) = prefix.strip_prefix(';') {
            prefix = rest;
        }
    }
}

pub(super) fn first_llm_usage_line(content: &str) -> Option<u32> {
    first_match_line(content, &LLM_PATTERNS)
        .or_else(|| find_line(content, "openai"))
        .or_else(|| find_line(content, "anthropic"))
        .or_else(|| find_line(content, "gemini"))
}

pub(super) fn excerpt_for_line(content: &str, line: Option<u32>) -> Option<String> {
    let line = line? as usize;
    if line == 0 {
        return None;
    }

    // Streamed: this runs once per emitted issue, and collecting every line of
    // the file into a Vec first cost O(file lines) per issue.
    let target_index = line - 1;
    let start = line.saturating_sub(2);
    let end = line + 1;
    let mut excerpt = String::new();
    let mut target_seen = false;

    for (index, line) in content.lines().enumerate() {
        if index >= end {
            break;
        }
        if index == target_index {
            target_seen = true;
        }
        if index >= start {
            let rendered_line = redact_sensitive_excerpt_line(line.trim_end());
            let _ = writeln!(excerpt, "{:>4} | {}", index + 1, rendered_line);
        }
    }

    // A line beyond the file has no extractable context.
    if !target_seen {
        return None;
    }

    let excerpt = excerpt.trim_end().to_string();
    if excerpt.is_empty() {
        None
    } else {
        Some(excerpt)
    }
}

/// Detect base64-shaped PEM body lines that token redaction would miss.
fn looks_like_pem_body_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() >= 40
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
}

fn redact_sensitive_excerpt_line(line: &str) -> String {
    if line.contains("-----BEGIN") || line.contains("-----END") || looks_like_pem_body_line(line) {
        return "[redacted: possible key material]".to_string();
    }
    let mut redacted = URL_USERINFO.replace_all(line, "${scheme}***@").into_owned();
    redacted = DATABASE_URL_CREDENTIALS
        .replace_all(&redacted, "${scheme}://${user}:***@")
        .into_owned();
    redacted = SECRET_ENV_ASSIGNMENT
        .replace_all(&redacted, "${key}=***")
        .into_owned();
    redacted = SECRET_CODE_ASSIGNMENT
        .replace_all(&redacted, "${key}${mid}***")
        .into_owned();
    for (pattern, replacement) in TOKEN_REDACTION_PATTERNS.iter() {
        redacted = pattern.replace_all(&redacted, *replacement).into_owned();
    }
    redacted
}

pub(super) fn file_content_for_relative<'a>(
    files: &'a [SourceFile],
    relative_path: &str,
) -> &'a str {
    files
        .iter()
        .find(|file| file.relative_path == relative_path)
        .map(|file| file.content.as_str())
        .unwrap_or("")
}

pub(super) fn line_number(content: &str, byte_index: usize) -> u32 {
    content[..byte_index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1
}

pub(super) fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{client_component_directive_line, excerpt_for_line};

    #[test]
    fn recognizes_valid_client_directives_across_quote_and_line_endings() {
        assert_eq!(
            client_component_directive_line("'use client';\nexport {}"),
            Some(1)
        );
        assert_eq!(
            client_component_directive_line(
                "// header\r\n\"use client\"; /* boundary */\r\nexport {}"
            ),
            Some(2)
        );
        assert_eq!(
            client_component_directive_line("const note = 'use client';"),
            None
        );
        assert_eq!(
            client_component_directive_line("import x from 'x';\n'use client';\nexport {}"),
            None,
            "a string after an import is not a directive prologue"
        );
    }

    #[test]
    fn attribute_context_php_sinks_count_as_unquoted() {
        use super::super::patterns::DANGEROUS_HTML_PATTERNS;
        use super::has_any_unquoted;
        let fires = |source: &str| has_any_unquoted(source, &DANGEROUS_HTML_PATTERNS);
        // A preceding HTML attribute quote is markup, not the sink being
        // quoted as data: the short echo tag and Blade raw braces stay live.
        assert!(fires(r#"<input value="<?= $_GET['q'] ?>">"#));
        assert!(fires(r#"<a href="<?= $_GET['next'] ?>">go</a>"#));
        assert!(fires(r#"<img alt="{!! $_GET['bio'] !!}">"#));
        // Backtick-quoted doc-comment samples remain rule data.
        assert!(!fires(r#"// e.g. `<?= $_GET['q'] ?>` must be escaped"#));
        assert!(!fires(r#"// e.g. `{!! $_GET['bio'] !!}` is raw output"#));
        // Code-only sinks keep full quote suppression (self-match, A3).
        assert!(!fires(r#"const marker = "dangerouslySetInnerHTML";"#));
        assert!(!fires(r#"// sample: `echo "please include $_GET[x]"`"#));
        // A live echo sink still fires.
        assert!(fires("<?php echo '<h1>' . $_GET['q'] . '</h1>';"));
    }

    #[test]
    fn security_regression_masks_token_evidence_suffix() {
        use super::redact_sensitive_excerpt_line;
        assert_eq!(
            redact_sensitive_excerpt_line("AKIAIOSFODNN7EXAMPLE"),
            "AKIA***"
        );
        // Deliberate fake Stripe-shaped token, not a real key.
        let stripe = redact_sensitive_excerpt_line("sk_live_abcdefghijklmnop1234"); // gitleaks:allow
        assert!(stripe.contains("sk_live_***"), "got {stripe}");
        assert!(!stripe.contains("1234"), "secret suffix leaked: {stripe}");
    }

    #[test]
    fn security_regression_masks_json_key_and_bare_tokens() {
        use super::redact_sensitive_excerpt_line;
        let json = redact_sensitive_excerpt_line(
            r#"      "apiKey": "sk-ant-abcdefghijklmnopqrstuvwxyz123456""#, // gitleaks:allow
        );
        assert!(
            !json.contains("abcdefghijklmnopqrstuvwxyz123456"),
            "json key value leaked: {json}"
        );
        let bare_openai = redact_sensitive_excerpt_line("sk-proj-ABCDEFGHIJKLMNOP1234567890"); // gitleaks:allow
        assert!(bare_openai.contains("sk-proj-***"), "got {bare_openai}");
        assert!(
            !bare_openai.contains("ABCDEFGHIJKLMNOP1234567890"),
            "bare token suffix leaked: {bare_openai}"
        );
        let bare_google = redact_sensitive_excerpt_line("AIzaSyABCDEFGHIJKLMNOP1234567890xyz"); // gitleaks:allow
        assert!(bare_google.contains("AIza***"), "got {bare_google}");
    }

    #[test]
    fn security_regression_masks_generic_url_userinfo() {
        use super::redact_sensitive_excerpt_line;
        let redacted = redact_sensitive_excerpt_line(
            "git+https://build-user:not-a-provider-token@git.example.test/acme/ui.git",
        );
        assert_eq!(redacted, "git+https://***@git.example.test/acme/ui.git");
        assert!(!redacted.contains("build-user"));
        assert!(!redacted.contains("not-a-provider-token"));
    }

    #[test]
    fn security_regression_pem_blocks_never_reach_source_excerpts() {
        let key_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"; // gitleaks:allow
        let source = format!(
            "const label = 'service account';\n-----BEGIN PRIVATE KEY-----\n{key_body}\n-----END PRIVATE KEY-----\n" // gitleaks:allow
        );

        // Anchored on the armor header: the window spans the body line.
        let excerpt = excerpt_for_line(&source, Some(2)).expect("pem excerpt");
        assert!(
            !excerpt.contains(key_body),
            "private-key bytes leaked into the excerpt: {excerpt}"
        );
        assert!(!excerpt.contains("BEGIN PRIVATE KEY"), "got {excerpt}");
        assert!(excerpt.contains("[redacted: possible key material]"));

        // Anchored on the body line itself: still fully redacted.
        let excerpt = excerpt_for_line(&source, Some(3)).expect("pem body excerpt");
        assert!(
            !excerpt.contains(key_body),
            "private-key bytes leaked into the excerpt: {excerpt}"
        );

        // The single-line JSON form (\n-joined private_key field) contains the
        // armor header inline and is redacted wholesale too.
        use super::redact_sensitive_excerpt_line;
        let json_line = r#""private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg""#;
        assert_eq!(
            redact_sensitive_excerpt_line(json_line),
            "[redacted: possible key material]"
        );
    }

    #[test]
    fn security_regression_redacts_secret_like_values_from_source_excerpts() {
        let source = concat!(
            "DATABASE_URL=postgresql://app_user:plain-text-password@db.example.com/app\n",
            "const apiKey = 'sk_live_abcdefghijklmnopqrstuvwxyz1234567890';\n",
            "const publicLabel = 'safe to show';\n",
        );

        let excerpt = excerpt_for_line(source, Some(2)).expect("source excerpt");

        assert!(excerpt.contains("DATABASE_URL=***"));
        assert!(excerpt.contains("apiKey = ***"));
        assert!(excerpt.contains("publicLabel = 'safe to show'"));
        assert!(!excerpt.contains("plain-text-password"));
        assert!(!excerpt.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
    }
}
