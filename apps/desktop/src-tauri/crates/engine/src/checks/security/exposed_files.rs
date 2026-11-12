//! Probes sensitive paths and requires file-specific response signatures.
//!
//! Catch-all responses and failed probes never prove exposure or absence.

use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};
use crate::evaluation::SweepReading;
use crate::probe::{BodyLimit, ProbeRequest};

mod content_validation;
use content_validation::{classify_env_body, expected_file_signature, EnvBodyVerdict};

/// Namespace for the per-path ids this check builds from [`SENSITIVE_PATHS`].
/// The ids are dynamic, so the capability manifest covers them with one
/// family entry keyed by exactly this prefix rather than a row per path.
pub const CHECK_ID_PREFIX: &str = "security.exposed_files.";

/// Characters sampled from probe bodies for signatures after leading comments.
pub(crate) const PROBE_SIGNATURE_SAMPLE_CHARS: usize = 4096;

/// Sensitive path, description, and severity.
pub const SENSITIVE_PATHS: &[(&str, &str, Severity)] = &[
    (
        "/.env",
        ".env-format environment configuration",
        Severity::Critical,
    ),
    (
        "/.git/HEAD",
        "Git repository HEAD reference",
        Severity::Medium,
    ),
    (
        "/.git/config",
        "Git repository configuration",
        Severity::Medium,
    ),
    (
        "/wp-config.php",
        "WordPress configuration source",
        Severity::Critical,
    ),
    ("/.DS_Store", "macOS directory metadata", Severity::Low),
    ("/.htaccess", "Apache configuration file", Severity::Medium),
    ("/web.config", "IIS/ASP.NET configuration", Severity::Medium),
    ("/phpinfo.php", "PHP information page", Severity::Medium),
    ("/debug.log", "Debug log output", Severity::Medium),
    ("/error.log", "Error log output", Severity::Medium),
    ("/backup.sql", "SQL database backup", Severity::Critical),
    (
        "/backup.zip",
        "ZIP archive at a common backup path",
        Severity::High,
    ),
    ("/database.sql", "SQL database dump", Severity::Critical),
];

/// GET one sensitive path with the recorded-alone sweep policy.
pub fn sensitive_path_request(origin: &str, path: &str) -> ProbeRequest {
    ProbeRequest::get(format!("{origin}{path}")).limit(BodyLimit::Sweep)
}

/// High-signal secret identifier names not owned by value-shaped key checks.
const SOURCE_SECRET_IDENTIFIERS: &[(&str, &str)] = &[
    ("database_url", "database URL identifier"),
    ("db_password", "database password identifier"),
    ("aws_secret", "AWS secret identifier"),
    ("stripe_secret", "Stripe secret identifier"),
];

/// Name what actually happened to the inconclusive probes: an answered request
/// with an unrecognized body is a routing observation, not a network problem.
fn inconclusive_causes(signature_mismatch: usize, inconclusive: usize) -> String {
    let unreachable = inconclusive.saturating_sub(signature_mismatch);
    let mut causes = Vec::new();
    if signature_mismatch > 0 {
        causes.push(format!(
            "{signature_mismatch} answered HTTP 200 without the expected file signature, which a catch-all route commonly does"
        ));
    }
    if unreachable > 0 {
        causes.push(format!(
            "{unreachable} did not return a response this scan could grade, so re-run from a network that can reach the target reliably"
        ));
    }
    causes.join("; ")
}

/// Combine source and path results without passing inconclusive probes.
pub fn summarize_exposed_files(
    source_advisory: Option<CheckResult>,
    path_rows: Vec<CheckResult>,
    unjoined_probes: usize,
) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let has_source_advisory = source_advisory.is_some();
    if let Some(result) = source_advisory {
        results.push(result);
    }

    let mut exposed_count = 0;
    let mut inconclusive_count = unjoined_probes;
    let mut signature_mismatch_count = 0;
    for row in path_rows {
        if row.status == CheckStatus::Fail {
            exposed_count += 1;
        } else if row.status == CheckStatus::Skipped {
            inconclusive_count += 1;
            if inconclusive_reason_of(&row) == Some(InconclusiveReason::SignatureMismatch) {
                signature_mismatch_count += 1;
            }
        }
        results.push(row);
    }

    if exposed_count == 0 && !has_source_advisory {
        let complete = inconclusive_count == 0;
        results.push(CheckResult {
            check_id: "security.exposed_files.summary".into(),
            category: ScanCategory::Security,
            title: if complete {
                "Sensitive file probes completed".into()
            } else {
                "Sensitive file probes incomplete".into()
            },
            description: if complete {
                format!(
                    "All {} sensitive-path probes completed; none returned content matching the requested file's signature.",
                    SENSITIVE_PATHS.len()
                )
            } else {
                format!(
                    "No matching sensitive-file exposure was found, but {} of {} probes were inconclusive: {}.",
                    inconclusive_count,
                    SENSITIVE_PATHS.len(),
                    inconclusive_causes(signature_mismatch_count, inconclusive_count)
                )
            },
            status: if complete {
                CheckStatus::Pass
            } else {
                CheckStatus::Skipped
            },
            severity: Severity::Low,
            fix_prompt: None,
            manual_fix: None,
            raw_data: Some(serde_json::json!({
                "paths_probed": SENSITIVE_PATHS.len(),
                "inconclusive": inconclusive_count,
                "signature_mismatch": signature_mismatch_count,
            })),
            confidence: if complete {
                crate::checks::IssueConfidence::High
            } else {
                crate::checks::IssueConfidence::NeedsReview
            },
            confidence_reason: if complete {
                None
            } else {
                Some("At least one path did not return enough evidence for a pass or exposure finding.".into())
            },
            why_it_matters: None,
        });
    }

    results
}

/// Advisory for secret-named identifiers; no secret value is verified.
pub fn source_secrets_result(html: &str) -> Option<CheckResult> {
    let script_content = extract_script_content(html);
    let script_lower = script_content.to_ascii_lowercase();

    let mut matched: Vec<&str> = SOURCE_SECRET_IDENTIFIERS
        .iter()
        .filter(|(pattern, _)| script_lower.contains(pattern))
        .map(|(_, label)| *label)
        .collect();
    matched.dedup();

    if matched.is_empty() {
        return None;
    }

    // Grab a short snippet around the first match for context
    let first_pattern = SOURCE_SECRET_IDENTIFIERS
        .iter()
        .find(|(p, _)| script_lower.contains(p))
        .map(|(p, _)| *p)
        .unwrap_or("");
    let snippet = secret_match_snippet(&script_content, first_pattern);

    Some(CheckResult {
        check_id: "security.exposed_files.source_secrets".into(),
        category: ScanCategory::Security,
        title: "Secret-named identifiers in page scripts".into(),
        description: format!(
            "Found {} secret-named identifier{} in inline scripts: {}.{} These are name references only - no secret value was verified. Actual key values are covered by the exposed API keys and hardcoded secrets checks.",
            matched.len(),
            if matched.len() == 1 { "" } else { "s" },
            matched.join(", "),
            if !snippet.is_empty() {
                format!(" Near: \"{}…\"", snippet.trim())
            } else {
                String::new()
            }
        ),
        status: CheckStatus::Warn,
        severity: Severity::Medium,
        fix_prompt: None,
        manual_fix: Some(format!(
            "Review why {} appear{} in client-side scripts. If a real credential is wired into the frontend, move it to a server-side environment variable and proxy the call through your backend. If the identifier only names a client-safe value, no change is needed.",
            matched.join(", "),
            if matched.len() == 1 { "s" } else { "" }
        )),
        raw_data: Some(serde_json::json!({ "matched_patterns": matched })),
        confidence: crate::checks::IssueConfidence::NeedsReview,
        confidence_reason: Some(
            "Only an identifier name was matched in script source; the scan did not verify that a secret value is present.".into(),
        ),
        why_it_matters: Some(
            "A secret-named identifier can be a harmless property reference or evidence that a server credential entered a client bundle. Reviewing the value flow distinguishes those cases.".into(),
        ),
    })
}

/// Grade one sensitive-path probe outcome. Verifies actual content for
/// every 200: SPA catch-all hosts return 200 + an HTML shell for ANY path,
/// so status-only probes reported paths as "Exposed" on every such site.
pub fn grade_path_probe(
    path: &str,
    description: &str,
    severity: &Severity,
    reading: &SweepReading,
) -> CheckResult {
    let Some(status_code) = reading.status else {
        return inconclusive_probe_result(
            path,
            *severity,
            InconclusiveReason::NoUsableResponse,
            "The request failed before an HTTP response was received, so public exposure was not determined.",
        );
    };
    let content_type = reading
        .content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let content_length = reading.content_length;

    if status_code != 200 {
        return if matches!(status_code, 401 | 403 | 404 | 410) {
            not_exposed_result(
                path,
                *severity,
                format!(
                    "{} returned HTTP {}; it was not publicly retrievable during this probe.",
                    path, status_code
                ),
            )
        } else {
            inconclusive_probe_result(
                path,
                *severity,
                InconclusiveReason::NoUsableResponse,
                &format!("{} returned HTTP {}; that response does not establish whether the file exists or is publicly retrievable.", path, status_code),
            )
        };
    }

    let body = match reading.sample.as_deref() {
        Some(body) => body,
        None => {
            return inconclusive_probe_result(
                path,
                *severity,
                InconclusiveReason::NoUsableResponse,
                "HTTP 200 was returned, but the response body could not be read within the scan limits; exposure was not determined.",
            );
        }
    };

    if body.trim().is_empty() || content_length == Some(0) {
        return not_exposed_result(
            path,
            *severity,
            format!(
                "{} returned HTTP 200 with an empty body; no file content was exposed.",
                path
            ),
        );
    }
    if is_html_soft_404(path, &content_type, body) {
        return not_exposed_result(
            path,
            *severity,
            format!("{} returned the site's HTML catch-all/error page, not content matching the requested file.", path),
        );
    }
    let Some(signature) = expected_file_signature(path, &content_type, body) else {
        return inconclusive_probe_result(
            path,
            *severity,
            InconclusiveReason::SignatureMismatch,
            &format!("{} returned HTTP 200, but the sampled body did not match the expected content signature. The scan did not report the file as exposed; review unusual catch-all routing if this persists.", path),
        );
    };

    let effective_severity =
        if path == "/.env" && classify_env_body(body) == EnvBodyVerdict::EnvFormatOnly {
            Severity::High
        } else {
            *severity
        };
    let impact = match effective_severity {
        Severity::Critical => "The matched response contains a sensitive configuration or database artifact. If its credential or data values are current, an unauthenticated visitor can copy them and use the access they confer.",
        Severity::High => "The matched response is a public configuration or backup artifact. Its actual impact depends on the archive or values it contains, but it may disclose source, configuration, credentials, or data.",
        Severity::Medium => "The matched artifact can disclose repository, server, or diagnostic details that reduce an attacker's uncertainty; the concrete impact depends on its contents and surrounding controls.",
        Severity::Low => "The matched metadata can reveal file and directory names. That is usually limited information disclosure, but it can help map the deployed site.",
    };
    CheckResult {
        check_id: format!("{CHECK_ID_PREFIX}{}", sanitize_check_id(path)),
        category: ScanCategory::Security,
        title: format!("Publicly accessible sensitive path: {}", path),
        description: format!(
            "GET {} returned HTTP 200, and the sampled response matched {}. Detected artifact: {}. {}",
            path,
            signature,
            description,
            // Only the classes that can hold credentials get the credential
            // caveat; a .DS_Store or a HEAD ref carries none.
            if matches!(effective_severity, Severity::Critical | Severity::High) {
                "The scan did not validate whether any contained credential is active or inspect the complete file."
            } else {
                "The scan did not inspect the complete file."
            }
        ),
        status: CheckStatus::Fail,
        severity: effective_severity,
        fix_prompt: None,
        manual_fix: Some(blocked_access_fix(path)),
        raw_data: Some(serde_json::json!({
            "path": path,
            "status_code": status_code,
            "content_length": content_length,
            "matched_signature": signature,
            "sample_bytes": body.len(),
        })),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: Some(format!(
            "An unauthenticated GET returned HTTP 200 and the sampled body matched the file-specific signature: {}. Contents beyond the sample and credential validity were not assessed.",
            signature
        )),
        why_it_matters: Some(impact.into()),
    }
}

fn not_exposed_result(path: &str, severity: Severity, description: String) -> CheckResult {
    CheckResult {
        check_id: format!("{CHECK_ID_PREFIX}{}", sanitize_check_id(path)),
        category: ScanCategory::Security,
        title: format!("{} not publicly exposed", path),
        description,
        status: CheckStatus::Pass,
        severity,
        fix_prompt: None,
        manual_fix: None,
        raw_data: None,
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// Why a probe produced no verdict. The summary reports an answered-but-
/// unrecognized response differently from one that never arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InconclusiveReason {
    /// HTTP 200 whose body did not match the file's signature.
    SignatureMismatch,
    /// No response, or a status that establishes nothing either way.
    NoUsableResponse,
}

impl InconclusiveReason {
    fn as_evidence(self) -> &'static str {
        match self {
            Self::SignatureMismatch => "signature_mismatch",
            Self::NoUsableResponse => "no_usable_response",
        }
    }
}

/// Read an inconclusive row's reason back out of its evidence. An unrecognized
/// value returns None rather than defaulting to a transport failure: guessing
/// there would recreate the conflation this check was fixed to stop making.
fn inconclusive_reason_of(row: &CheckResult) -> Option<InconclusiveReason> {
    match row
        .raw_data
        .as_ref()?
        .get("inconclusive_reason")?
        .as_str()?
    {
        "signature_mismatch" => Some(InconclusiveReason::SignatureMismatch),
        "no_usable_response" => Some(InconclusiveReason::NoUsableResponse),
        _ => None,
    }
}

fn inconclusive_probe_result(
    path: &str,
    severity: Severity,
    reason: InconclusiveReason,
    detail: &str,
) -> CheckResult {
    CheckResult {
        check_id: format!("{CHECK_ID_PREFIX}{}", sanitize_check_id(path)),
        category: ScanCategory::Security,
        title: format!("{} exposure check inconclusive", path),
        description: detail.into(),
        status: CheckStatus::Skipped,
        severity,
        fix_prompt: None,
        manual_fix: Some(format!(
            "Repeat an unauthenticated GET request to {} from the same network. Confirm the response is 403, 404, or 410 and that no sensitive content is returned; do not copy any returned secret values into tickets or chat.",
            path
        )),
        raw_data: Some(serde_json::json!({
            "path": path,
            "inconclusive_reason": reason.as_evidence(),
        })),
        confidence: crate::checks::IssueConfidence::NeedsReview,
        confidence_reason: Some("The probe did not produce enough matching response evidence for a pass or an exposure finding.".into()),
        why_it_matters: None,
    }
}

/// Stack-specific instructions that block public access to the exact probed path.
fn blocked_access_fix(path: &str) -> String {
    format!(
        "Block public access to {path}. Apply ONE of these depending on your stack:\n\
         • Nginx: `location {path} {{ return 404; }}`\n\
         • Apache (.htaccess): `Redirect 404 {path}` (matches nested paths too)\n\
         • Caddy: `respond {path} 404`\n\
         • Vercel: remove the file from the deployment output (move it out of `public/`); static files that ship with the deploy cannot be blocked afterwards\n\
         • Netlify (_redirects): `{path} /404 404!`\n\
         • Cloudflare Pages: add a Worker route or _redirects entry; the file should not be in your build output at all\n\
         • Static-site / framework: move the file OUT of the public/static/dist directory so it never gets deployed. After fixing, repeat an unauthenticated GET and confirm a 403, 404, or 410; a HEAD-only check can miss servers that handle GET differently. Do not paste any returned secrets into tickets or chat.",
        path = path,
    )
}

/// Detects HTML catch-all responses masquerading as exposed sensitive files.
/// `phpinfo.php` is excluded because its legitimate response is HTML.
fn is_html_soft_404(path: &str, content_type: &str, body_snippet: &str) -> bool {
    if !content_type.contains("text/html") || path.contains("phpinfo") {
        return false;
    }
    let lower = body_snippet.to_lowercase();
    lower.contains("<html")
        || lower.contains("<!doctype")
        || lower.contains("not found")
        || lower.contains("404")
}

fn sanitize_check_id(path: &str) -> String {
    path.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_lowercase()
}

fn secret_match_snippet(script_content: &str, pattern: &str) -> String {
    let lower = script_content.to_ascii_lowercase();
    let Some(position) = lower.find(pattern) else {
        return String::new();
    };
    let start = crate::checks::floor_char_boundary(script_content, position.saturating_sub(20));
    let end = crate::checks::ceil_char_boundary(
        script_content,
        (position + pattern.len() + 40).min(script_content.len()),
    );
    script_content[start..end]
        .chars()
        .take(80)
        .collect::<String>()
        .replace('\n', " ")
        .replace('\r', "")
}

/// Extracts all content from <script> tags (concatenated)
fn extract_script_content(html: &str) -> String {
    let mut result = String::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        // Find the end of opening tag
        if let Some(gt) = lower[abs_start..].find('>') {
            let content_start = abs_start + gt + 1;
            if let Some(end) = lower[content_start..].find("</script") {
                let content_end = content_start + end;
                if content_end > content_start {
                    result.push(' ');
                    result.push_str(&html[content_start..content_end]);
                }
                // Advance past the matched prefix; truncated tags may omit `>`.
                search_from = content_end + "</script".len();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    result
}

/// Byte-offset regressions for the HTML slicing this check does. They stay in
/// this file because the repo guardrail requires the coverage beside the code.
#[cfg(test)]
mod unicode_offset_tests {
    use super::*;

    #[test]
    fn script_extraction_preserves_offsets_after_unicode_case_expansion() {
        let html = format!(
            "<html><body>{}<script>const db_password = 'public-example';</script></body></html>",
            "İ".repeat(32)
        );

        assert_eq!(
            extract_script_content(&html).trim(),
            "const db_password = 'public-example';"
        );
    }
    #[test]
    fn secret_snippet_uses_valid_unicode_boundaries() {
        let script = format!("{}db_password = 'public-example';", "é".repeat(11));

        let snippet = secret_match_snippet(&script, "db_password");

        assert!(snippet.contains("db_password"));
        assert!(snippet.is_char_boundary(snippet.len()));
    }
}

#[cfg(test)]
mod tests;
