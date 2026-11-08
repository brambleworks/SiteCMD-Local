//! RFC 9116 security.txt planning and verdicts. Availability failures remain
//! review states rather than confirmed absence.

use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};
use crate::probe::{ProbeOutcome, ProbeRequest};
use serde::{Deserialize, Serialize};

/// Canonical ID for the portable security.txt verdict.
pub const CHECK_ID: &str = "security.security_txt";

struct SecurityTxtFields {
    contact_count: usize,
    valid_contact_count: usize,
    expires_values: Vec<String>,
    expired: Option<bool>,
    expires_too_far: Option<bool>,
    canonical_values: Vec<String>,
}

#[cfg(test)]
#[path = "security_txt_extended_tests.rs"]
mod extended_tests;

/// A retrieved security.txt candidate, ready for grading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedSecurityTxt {
    pub body: String,
    pub final_url: String,
    pub content_type: Option<String>,
    pub body_bytes: usize,
    pub utf8_valid: bool,
}

/// Check-level classification of one security.txt probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SecurityTxtFetch {
    Found(FetchedSecurityTxt),
    Missing { status: u16 },
    Unavailable { status: u16 },
    Failed { detail: String },
}

/// Classify a transport outcome the way the desktop's fetch always has:
/// 404/410 mean the file is absent, any other non-2xx is unavailability,
/// and a transport failure (including a failed body read) is a failed probe.
pub fn classify_security_txt_probe(outcome: ProbeOutcome) -> SecurityTxtFetch {
    match outcome {
        ProbeOutcome::Failure(failure) => SecurityTxtFetch::Failed {
            detail: failure.detail,
        },
        ProbeOutcome::Response(response) => match (response.status, response.body) {
            (404 | 410, _) => SecurityTxtFetch::Missing {
                status: response.status,
            },
            (status, Some(body)) if (200..300).contains(&status) => {
                SecurityTxtFetch::Found(FetchedSecurityTxt {
                    body: body.text,
                    final_url: response.final_url,
                    content_type: response.content_type,
                    body_bytes: body.bytes,
                    utf8_valid: body.utf8_valid,
                })
            }
            (status, _) => SecurityTxtFetch::Unavailable { status },
        },
    }
}

/// GET security.txt under the ordinary probe cap with a success-only body.
pub fn security_txt_request(url: &str) -> ProbeRequest {
    ProbeRequest::get(url)
}

/// RFC 9116 and legacy security.txt probe URLs for one origin.
pub fn security_txt_urls(base: &str) -> (String, String) {
    (
        format!("{base}/.well-known/security.txt"),
        format!("{base}/security.txt"),
    )
}

/// Next action after evaluating the well-known security.txt response.
pub enum SecurityTxtStep {
    Done(Vec<CheckResult>),
    ProbeLegacy { well_known_status: u16 },
}

fn contact_uri_is_valid(value: &str) -> bool {
    let Ok(uri) = url::Url::parse(value.trim()) else {
        return false;
    };
    if uri.scheme().eq_ignore_ascii_case("http") {
        return false;
    }
    if uri.scheme().eq_ignore_ascii_case("https") {
        return uri.host_str().is_some();
    }
    !uri.path().is_empty()
}

fn parse_security_txt(body: &str, now: chrono::DateTime<chrono::Utc>) -> SecurityTxtFields {
    let mut contacts = Vec::new();
    let mut expires_values = Vec::new();
    let mut canonical_values = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("contact:") {
            let value = trimmed["contact:".len()..].trim();
            if !value.is_empty() {
                contacts.push(value.to_string());
            }
        } else if lower.starts_with("expires:") {
            let value = trimmed["expires:".len()..].trim();
            if !value.is_empty() {
                expires_values.push(value.to_string());
            }
        } else if lower.starts_with("canonical:") {
            let value = trimmed["canonical:".len()..].trim();
            if !value.is_empty() {
                canonical_values.push(value.to_string());
            }
        }
    }

    let parsed_expiration = (expires_values.len() == 1)
        .then(|| chrono::DateTime::parse_from_rfc3339(&expires_values[0]).ok())
        .flatten();
    let expired = parsed_expiration.map(|timestamp| timestamp <= now);
    let expires_too_far =
        parsed_expiration.map(|timestamp| timestamp > now + chrono::Duration::days(365));

    SecurityTxtFields {
        contact_count: contacts.len(),
        valid_contact_count: contacts
            .iter()
            .filter(|value| contact_uri_is_valid(value))
            .count(),
        expires_values,
        expired,
        expires_too_far,
        canonical_values,
    }
}

fn missing_security_txt_result(
    check_id: &str,
    well_known_status: u16,
    legacy_probe: serde_json::Value,
) -> CheckResult {
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
        title: "No security.txt at the standard path".into(),
        description: "The standardized /.well-known/security.txt path returned 404 or 410. The site may expose a disclosure contact elsewhere, but this scan did not find an RFC 9116 file at the location automated tools are required to check.".into(),
        status: CheckStatus::Warn,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: Some("Serve a UTF-8 plain-text file over HTTPS at `/.well-known/security.txt`. Include at least one valid `Contact:` URI and exactly one RFC 3339 `Expires:` timestamp, preferably less than a year in the future. If `/security.txt` is retained for legacy clients, redirect it to the well-known URL and verify the final media type and body.".into()),
        raw_data: Some(serde_json::json!({
            "well_known_status": well_known_status,
            "legacy_probe": legacy_probe,
        })),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: Some("security.txt provides a standardized, machine-readable vulnerability-disclosure route. Its absence does not prove that the organization has no contact channel, but it makes consistent automated discovery and freshness validation less reliable.".into()),
    }
}

fn unavailable_security_txt_result(
    check_id: &str,
    status: CheckStatus,
    title: String,
    description: String,
    raw_data: serde_json::Value,
) -> CheckResult {
    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
        title,
        description,
        status,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: (status == CheckStatus::Warn).then(|| "Recheck the well-known URL from an ordinary logged-out client and inspect edge, authentication, bot, and catch-all routing. Serve the file publicly over HTTPS as UTF-8 `text/plain`; if the response was a transient server error, fix that availability problem and re-scan before concluding the file is absent.".into()),
        raw_data: Some(raw_data),
        confidence: crate::checks::IssueConfidence::NeedsReview,
        confidence_reason: Some("The probe did not retrieve a successful security.txt body, so this scan cannot distinguish a transient response, bot/edge policy, or transport failure from the site's steady-state configuration.".into()),
        why_it_matters: None,
    }
}

/// Evaluate the well-known probe: either the verdict is complete, or a
/// definite 404/410 requires the legacy-path probe next.
pub fn evaluate_well_known(
    check_id: &str,
    base: &str,
    fetch: SecurityTxtFetch,
    evaluation_time: chrono::DateTime<chrono::Utc>,
) -> SecurityTxtStep {
    match fetch {
        SecurityTxtFetch::Found(fetched) => SecurityTxtStep::Done(vec![found_result(
            check_id,
            base,
            fetched,
            false,
            evaluation_time,
        )]),
        SecurityTxtFetch::Missing { status } => SecurityTxtStep::ProbeLegacy {
            well_known_status: status,
        },
        SecurityTxtFetch::Unavailable { status } => {
            SecurityTxtStep::Done(vec![unavailable_security_txt_result(
                check_id,
                CheckStatus::Warn,
                format!("security.txt returned HTTP {}", status),
                format!("The standardized security.txt URL returned HTTP {}. That response is directly observed, but one request cannot establish whether the file is persistently unavailable or an edge, bot, authentication, or transient server policy produced it.", status),
                serde_json::json!({"location": "/.well-known/security.txt", "status": status}),
            )])
        }
        SecurityTxtFetch::Failed { detail } => {
            let detail = crate::log_sanitizer::bounded_issue_evidence(&detail);
            SecurityTxtStep::Done(vec![unavailable_security_txt_result(
                check_id,
                CheckStatus::Skipped,
                "security.txt probe did not complete".into(),
                "The standardized security.txt request failed before a usable HTTP response was received, so this scan makes no presence or format claim. Re-scan to distinguish a transient transport problem from a persistent access issue.".into(),
                serde_json::json!({"location": "/.well-known/security.txt", "probe_error": detail}),
            )])
        }
    }
}

/// Evaluate the legacy-path probe that follows a well-known 404/410.
pub fn evaluate_legacy(
    check_id: &str,
    base: &str,
    well_known_status: u16,
    fetch: SecurityTxtFetch,
    evaluation_time: chrono::DateTime<chrono::Utc>,
) -> Vec<CheckResult> {
    match fetch {
        SecurityTxtFetch::Found(fetched) => {
            vec![found_result(check_id, base, fetched, true, evaluation_time)]
        }
        SecurityTxtFetch::Missing { status } => vec![missing_security_txt_result(
            check_id,
            well_known_status,
            serde_json::json!({"outcome": "missing", "status": status}),
        )],
        SecurityTxtFetch::Unavailable { status } => vec![missing_security_txt_result(
            check_id,
            well_known_status,
            serde_json::json!({"outcome": "unavailable", "status": status}),
        )],
        SecurityTxtFetch::Failed { detail } => {
            let detail = crate::log_sanitizer::bounded_issue_evidence(&detail);
            vec![missing_security_txt_result(
                check_id,
                well_known_status,
                serde_json::json!({"outcome": "probe_failed", "detail": detail}),
            )]
        }
    }
}

/// Grade a retrieved file. Everything downstream of the fetch is here, so
/// desktop and hosted produce identical results from identical fetches.
fn found_result(
    check_id: &str,
    base: &str,
    fetched: FetchedSecurityTxt,
    legacy_only: bool,
    evaluation_time: chrono::DateTime<chrono::Utc>,
) -> CheckResult {
    let (well_known, legacy) = security_txt_urls(base);
    let location = if legacy_only {
        "/security.txt"
    } else {
        "/.well-known/security.txt"
    };
    let body_start = fetched.body.trim_start().to_ascii_lowercase();
    let looks_html = body_start.starts_with("<!doctype") || body_start.starts_with("<html");
    let fields = parse_security_txt(&fetched.body, evaluation_time);
    let requested_url = if legacy_only { &legacy } else { &well_known };
    let line_count = fetched.body.lines().count();
    let max_line_chars = fetched
        .body
        .lines()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or_default();
    let (status, severity, title, description, manual_fix, issue_codes) = grade_security_txt(
        &fields,
        location,
        requested_url,
        &fetched.final_url,
        fetched.content_type.as_deref(),
        legacy_only,
        looks_html,
        fetched.body_bytes,
        line_count,
        max_line_chars,
        fetched.utf8_valid,
    );
    let expires_field_count = fields.expires_values.len();
    let expires_values = fields
        .expires_values
        .iter()
        .take(5)
        .map(|value| crate::log_sanitizer::bounded_issue_evidence(value))
        .collect::<Vec<_>>();
    let canonical_count = fields.canonical_values.len();
    let canonical_values = fields
        .canonical_values
        .iter()
        .take(5)
        .map(|value| crate::log_sanitizer::evidence_safe_url_reference(value))
        .collect::<Vec<_>>();
    let conservative_parser_limit_exceeded = fetched.body_bytes > CONSERVATIVE_BODY_BYTES
        || line_count > CONSERVATIVE_LINE_COUNT
        || max_line_chars > CONSERVATIVE_FIELD_CHARS;
    let evidence_needs_review = issue_codes
        .iter()
        .any(|issue| issue == "conservative_parser_limit");

    CheckResult {
        check_id: check_id.into(),
        category: ScanCategory::Security,
            title,
            description,
            status,
            severity,
            fix_prompt: None,
            manual_fix,
            raw_data: Some(serde_json::json!({
                "location": location,
                "final_url": crate::log_sanitizer::evidence_safe_page_url(&fetched.final_url),
                "content_type": fetched.content_type.as_deref().map(crate::log_sanitizer::bounded_issue_evidence),
                "contact_count": fields.contact_count,
                "valid_contact_count": fields.valid_contact_count,
                "expires_field_count": expires_field_count,
                "expires_values": expires_values,
                "expires_values_truncated": expires_field_count > 5,
                "expired": fields.expired,
                "expires_too_far": fields.expires_too_far,
                "canonical_count": canonical_count,
                "canonical_values": canonical_values,
                "canonical_values_truncated": canonical_count > 5,
                "body_bytes": fetched.body_bytes,
                "line_count": line_count,
                "max_line_chars": max_line_chars,
                "utf8_valid": fetched.utf8_valid,
                "conservative_parser_limit_exceeded": conservative_parser_limit_exceeded,
                "validation_issues": issue_codes,
            })),
            confidence: if evidence_needs_review {
                crate::checks::IssueConfidence::NeedsReview
            } else {
                crate::checks::IssueConfidence::High
            },
            confidence_reason: evidence_needs_review.then(|| "The size observation is exact, but RFC 9116 presents these thresholds as optional defensive parser choices rather than a normative file-size or line-length limit.".into()),
            why_it_matters: if status == CheckStatus::Pass {
                None
            } else {
                Some("A valid security.txt gives researchers and automated tools a standardized, current disclosure route. Format, transport, or location defects can make that route ambiguous or unusable, but they do not prove that the organization lacks another contact method.".into())
            },
    }
}

fn content_type_is_plain_text(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let mut parts = content_type.split(';');
    if !parts
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/plain"))
    {
        return false;
    }
    parts.all(|parameter| {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            return true;
        }
        let Some((name, value)) = parameter.split_once('=') else {
            return false;
        };
        !name.trim().eq_ignore_ascii_case("charset")
            || value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
    })
}

fn redirect_crosses_origin(requested_url: &str, final_url: &str) -> bool {
    let (Ok(requested), Ok(final_url)) =
        (url::Url::parse(requested_url), url::Url::parse(final_url))
    else {
        return false;
    };
    requested.origin() != final_url.origin()
}

fn canonical_names_final_url(canonical_values: &[String], final_url: &str) -> bool {
    let Ok(final_url) = url::Url::parse(final_url) else {
        return false;
    };
    canonical_values.iter().any(|value| {
        url::Url::parse(value.trim())
            .ok()
            .is_some_and(|canonical| canonical == final_url)
    })
}

// RFC 9116 section 5.4 presents these as conservative parser choices, not
// normative conformance limits. Crossing one therefore produces a review
// warning rather than claiming that the file violates a MUST requirement.
const CONSERVATIVE_BODY_BYTES: usize = 32 * 1024;
const CONSERVATIVE_FIELD_CHARS: usize = 2_048;
const CONSERVATIVE_LINE_COUNT: usize = 1_000;

/// Grade the observable RFC 9116 transport, location, media type, and two
/// required fields without claiming contact ownership or responsiveness.
fn grade_security_txt(
    fields: &SecurityTxtFields,
    location: &str,
    requested_url: &str,
    final_url: &str,
    content_type: Option<&str>,
    legacy_only: bool,
    looks_html: bool,
    body_bytes: usize,
    line_count: usize,
    max_line_chars: usize,
    utf8_valid: bool,
) -> (
    CheckStatus,
    Severity,
    String,
    String,
    Option<String>,
    Vec<String>,
) {
    let mut issues: Vec<(&str, String)> = Vec::new();

    if fields.contact_count == 0 {
        issues.push((
            "missing_contact",
            "the required Contact field is missing".into(),
        ));
    } else if fields.valid_contact_count == 0 {
        issues.push((
            "invalid_contact",
            "no Contact value is a syntactically valid URI using HTTPS for a web contact".into(),
        ));
    }

    match fields.expires_values.len() {
        0 => issues.push((
            "missing_expires",
            "the required Expires field is missing".into(),
        )),
        1 if fields.expired.is_none() => issues.push((
            "invalid_expires",
            "the Expires value is not a parseable RFC 3339 timestamp".into(),
        )),
        1 if fields.expired == Some(true) => issues.push((
            "expired",
            format!(
                "the Expires timestamp ({}) is in the past",
                fields.expires_values[0]
            ),
        )),
        1 if fields.expires_too_far == Some(true) => issues.push((
            "expires_too_far",
            "the Expires timestamp is more than one year in the future; RFC 9116 recommends a shorter horizon to reduce stale contact data".into(),
        )),
        1 => {}
        count => issues.push((
            "duplicate_expires",
            format!(
                "{} Expires fields are present; RFC 9116 requires exactly one",
                count
            ),
        )),
    }

    if !url::Url::parse(final_url)
        .ok()
        .is_some_and(|url| url.scheme().eq_ignore_ascii_case("https"))
    {
        issues.push((
            "insecure_transport",
            "the final security.txt response was not retrieved over HTTPS".into(),
        ));
    }
    if redirect_crosses_origin(requested_url, final_url) {
        issues.push((
            "cross_origin_redirect",
            "the retrieval crossed to a different origin; RFC 9116 recommends inspecting redirect trust before using the contact data".into(),
        ));
    }
    if !fields.canonical_values.is_empty()
        && !canonical_names_final_url(&fields.canonical_values, final_url)
    {
        issues.push((
            "canonical_mismatch",
            "Canonical fields are present, but none names the final retrieval URL; RFC 9116 says the file should not be trusted in that condition".into(),
        ));
    }
    if !utf8_valid {
        issues.push((
            "invalid_utf8",
            "the response body is not valid UTF-8, which the security.txt format requires".into(),
        ));
    }
    if body_bytes > CONSERVATIVE_BODY_BYTES
        || line_count > CONSERVATIVE_LINE_COUNT
        || max_line_chars > CONSERVATIVE_FIELD_CHARS
    {
        issues.push((
            "conservative_parser_limit",
            format!(
                "the file has {} bytes, {} lines, and a longest line of {} characters; it exceeds at least one conservative parser-review threshold suggested in RFC 9116 security considerations (32 KiB, 1,000 lines, or 2,048 characters per field), which is not itself a MUST-level conformance failure",
                body_bytes, line_count, max_line_chars
            ),
        ));
    }
    if looks_html {
        issues.push((
            "html_response",
            "the response body is HTML rather than security.txt plain text, which commonly indicates a catch-all route".into(),
        ));
    } else if !content_type_is_plain_text(content_type) {
        issues.push((
            "wrong_content_type",
            "the response is not served as UTF-8-compatible text/plain".into(),
        ));
    }
    if legacy_only {
        issues.push((
            "legacy_location",
            "the file exists only at /security.txt after the required /.well-known/security.txt path returned 404 or 410".into(),
        ));
    }

    let issue_codes = issues
        .iter()
        .map(|(code, _)| (*code).to_string())
        .collect::<Vec<_>>();
    if issues.is_empty() {
        return (
            CheckStatus::Pass,
            Severity::Low,
            "security.txt".into(),
            format!("security.txt was retrieved over HTTPS from {} as UTF-8 plain text with at least one syntactically valid Contact URI and exactly one unexpired RFC 3339 Expires value no more than one year ahead. Any declared Canonical URL is consistent with the final retrieval URL. These are targeted observable checks, not full ABNF, OpenPGP-signature, contact ownership, responsiveness, or organizational-scope validation.", location),
            None,
            issue_codes,
        );
    }

    let title = if issues.len() == 1 {
        match issues[0].0 {
            "missing_contact" => "security.txt is missing Contact",
            "invalid_contact" => "security.txt Contact is invalid",
            "missing_expires" => "security.txt is missing Expires",
            "invalid_expires" => "security.txt Expires is invalid",
            "expired" => "security.txt has expired",
            "duplicate_expires" => "security.txt has duplicate Expires fields",
            "expires_too_far" => "security.txt Expires is more than one year ahead",
            "insecure_transport" => "security.txt is not served over HTTPS",
            "cross_origin_redirect" => "security.txt redirects to another origin",
            "canonical_mismatch" => "security.txt Canonical does not match its final URL",
            "invalid_utf8" => "security.txt is not valid UTF-8",
            "conservative_parser_limit" => "security.txt exceeds conservative parser limits",
            "html_response" => "security.txt path returns HTML",
            "wrong_content_type" => "security.txt has the wrong media type",
            "legacy_location" => "security.txt exists only at the legacy path",
            _ => "security.txt validation issue",
        }
    } else {
        "security.txt has validation issues"
    };
    (
        CheckStatus::Warn,
        Severity::Low,
        title.into(),
        format!(
            "security.txt was retrieved from {} (final URL {}). The targeted RFC 9116 checks found: {}. SiteCMD did not perform full ABNF or OpenPGP-signature validation or verify that a contact is controlled and monitored.",
            location,
            crate::log_sanitizer::evidence_safe_page_url(final_url),
            issues
                .iter()
                .map(|(_, detail)| detail.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Some("Serve the file over HTTPS at `/.well-known/security.txt` with a UTF-8 `text/plain` response. Include at least one syntactically valid `Contact:` URI and exactly one RFC 3339 `Expires:` timestamp less than a year in the future; remove duplicates and verify each contact still works. If a `Canonical:` field is present, make sure one value exactly names the trusted final URL. Review and minimize cross-origin redirects, keep the file and individual fields within conservative parser bounds, and use the legacy `/security.txt` path only as a redirect to the well-known URL. Re-fetch the deployed response and inspect its redirect chain, final URL, headers, and body.".into()),
        issue_codes,
    )
}

#[cfg(test)]
#[path = "security_txt_tests.rs"]
mod tests;
