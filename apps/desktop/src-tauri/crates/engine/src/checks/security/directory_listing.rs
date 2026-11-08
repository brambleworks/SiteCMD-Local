//! Portable directory-listing probe plans and verdicts.
//! Each runtime executes bounded probes; this module owns detection and grading.

use crate::checks::{CheckResult, CheckStatus, ScanCategory, Severity};
use crate::evaluation::SweepReading;
use crate::probe::{BodyLimit, ProbeRequest};

/// Common high-risk directories to probe for generated indexes.
pub const PROBE_DIRS: &[&str] = &[
    "/images/",
    "/assets/",
    "/css/",
    "/js/",
    "/uploads/",
    "/static/",
    "/media/",
    "/files/",
    // WordPress
    "/wp-content/uploads/",
    "/wp-content/",
    // Common dump / backup / admin / temp / leftover-from-dev paths
    "/admin/",
    "/backup/",
    "/backups/",
    "/storage/",
    "/public/uploads/",
    "/tmp/",
    "/temp/",
    "/old/",
    "/test/",
];

/// Server-generated directory index signatures, excluding ambiguous prose.
const LISTING_PATTERNS: &[&str] = &[
    "index of /",
    "directory listing for",
    "<title>index of",
    "[to parent directory]",
    "directory contents",
];

/// The localhost-preview result: directory browsing on a dev server says
/// nothing about the deployed site.
pub fn localhost_skip_result() -> CheckResult {
    CheckResult {
        check_id: "security.directory_listing".into(),
        category: ScanCategory::Security,
        title: "Directory listing".into(),
        description: "Skipped on localhost preview. Directory browsing often reflects the local static file server rather than your deployed site.".into(),
        status: CheckStatus::Skipped,
        severity: Severity::Low,
        fix_prompt: None,
        manual_fix: None,
        raw_data: Some(serde_json::json!({"reason": "localhost_preview_server"})),
        confidence: crate::checks::IssueConfidence::High,
        confidence_reason: None,
        why_it_matters: None,
    }
}

/// GET one directory with the recorded-alone sweep policy.
pub fn listing_request(origin: &str, dir: &str) -> ProbeRequest {
    ProbeRequest::get(format!("{origin}{dir}")).limit(BodyLimit::Sweep)
}

/// Grade listings from compact readings; missing or unreadable answers cannot pass.
pub fn grade_listing_probes(readings: Vec<(String, &SweepReading)>) -> CheckResult {
    let answered = readings
        .iter()
        .filter(|(_, reading)| {
            reading
                .status
                .is_some_and(|status| status != 200 || reading.sample.is_some())
        })
        .count();
    let listing_found: Vec<String> = readings
        .into_iter()
        .filter_map(|(dir, reading)| {
            (reading.status == Some(200) && reading.listing).then_some(dir)
        })
        .collect();
    let unanswered = PROBE_DIRS.len().saturating_sub(answered);
    if listing_found.is_empty() && unanswered > 0 {
        let planned = PROBE_DIRS.len();
        let description = if answered == 0 {
            format!("None of the {planned} directories answered, so this scan could not rule out a listing there.")
        } else {
            format!("None of the {answered} directories that answered lists its contents, but {unanswered} of the {planned} did not answer, so this scan could not rule out a listing there.")
        };
        return CheckResult {
            check_id: "security.directory_listing".into(),
            category: ScanCategory::Security,
            title: "Directory listing check incomplete".into(),
            description,
            status: CheckStatus::Skipped,
            severity: Severity::High,
            fix_prompt: None,
            manual_fix: None,
            raw_data: Some(
                serde_json::json!({"answered": answered, "unanswered": unanswered, "planned": planned}),
            ),
            confidence: crate::checks::IssueConfidence::NeedsReview,
            confidence_reason: None,
            why_it_matters: None,
        };
    }
    if listing_found.is_empty() {
        CheckResult {
            check_id: "security.directory_listing".into(),
            category: ScanCategory::Security,
            title: "Directory listing".into(),
            description: format!(
                "No directory listings were detected across the {} common paths we probed.",
                PROBE_DIRS.len()
            ),
            status: CheckStatus::Pass,
            severity: Severity::High,
            fix_prompt: None,
            manual_fix: None,
            raw_data: None,
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: None,
        }
    } else {
        CheckResult {
            check_id: "security.directory_listing".into(),
            category: ScanCategory::Security,
            title: "Directory listing enabled".into(),
            description: format!(
                "Directory listing is enabled on {} path{}: {}.",
                listing_found.len(),
                if listing_found.len() == 1 { "" } else { "s" },
                listing_found.join(", ")
            ),
            status: CheckStatus::Fail,
            severity: Severity::High,
            fix_prompt: None,
            manual_fix: Some(
                "Turn off directory browsing for public asset paths at the web server or hosting layer. If a directory must stay public, serve only the specific files you intend to expose.".into(),
            ),
            raw_data: Some(serde_json::json!({
                "directories_exposed": listing_found,
            })),
            confidence: crate::checks::IssueConfidence::High,
            confidence_reason: None,
            why_it_matters: Some("A browseable directory gives people an instant map of file names and paths you probably did not mean to publish.".into()),
        }
    }
}

/// Whether a successful probe body looks like a server-generated directory index.
pub(crate) fn body_indicates_listing(body: &str) -> bool {
    let body = body.to_lowercase();
    LISTING_PATTERNS.iter().any(|p| body.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation::sweep_reading;
    use crate::probe::{ProbeBody, ProbeOutcome, ProbeResponse};

    #[test]
    fn apache_style_index_page_is_a_listing() {
        let body = r#"<html><head><title>Index of /uploads</title></head>
            <body><h1>Index of /uploads</h1><a href="../">Parent Directory</a></body></html>"#;
        assert!(body_indicates_listing(body));
    }

    #[test]
    fn python_http_server_listing_is_detected() {
        let body = "<html><title>Directory listing for /files/</title><body></body></html>";
        assert!(body_indicates_listing(body));
    }

    #[test]
    fn iis_style_listing_is_detected() {
        let body = "<html><body><pre>[To Parent Directory]<br>invoice-2026.pdf</pre></body></html>";
        assert!(body_indicates_listing(body));
    }

    #[test]
    fn help_page_mentioning_parent_directory_in_prose_is_not_a_listing() {
        let body = r#"<html><head><title>Admin help</title></head>
            <body><h1>Uploading files</h1>
            <p>To move a file up one level, open the parent directory in your file
            manager, then drag the file into the folder above.</p></body></html>"#;
        assert!(!body_indicates_listing(body));
    }

    #[test]
    fn ordinary_page_served_from_a_directory_path_is_not_a_listing() {
        let body = r#"<html><head><title>Gallery</title></head>
            <body><h1>Our work</h1><img src="/images/one.jpg"></body></html>"#;
        assert!(!body_indicates_listing(body));
        assert!(!body_indicates_listing(""));
    }

    #[test]
    fn confirmed_listing_fails_at_high_severity() {
        let result = grade_listing_probes(vec![(
            "/uploads/".into(),
            &sweep_reading(&ProbeOutcome::Response(ProbeResponse {
                status: 200,
                final_url: String::new(),
                content_type: None,
                content_length: None,
                headers: vec![],
                body: Some(ProbeBody {
                    text: "Index of /uploads/".into(),
                    bytes: 18,
                    utf8_valid: true,
                }),
            })),
        )]);
        assert_eq!(result.status, CheckStatus::Fail);
        assert_eq!(result.severity, Severity::High);
        assert!(result.description.contains("/uploads/"));
    }

    #[test]
    fn only_200_bodies_with_index_signatures_count_as_exposed() {
        let listing = ProbeResponse {
            status: 200,
            final_url: "https://example.com/uploads/".into(),
            content_type: Some("text/html".into()),
            content_length: None,
            headers: Vec::new(),
            body: Some(ProbeBody {
                text: "<h1>Index of /uploads</h1>".into(),
                bytes: 26,
                utf8_valid: true,
            }),
        };
        let forbidden = ProbeResponse {
            status: 403,
            final_url: "https://example.com/admin/".into(),
            content_type: None,
            content_length: None,
            headers: Vec::new(),
            body: None,
        };
        let result = grade_listing_probes(vec![
            (
                "/uploads/".into(),
                &sweep_reading(&ProbeOutcome::Response(listing)),
            ),
            (
                "/admin/".into(),
                &sweep_reading(&ProbeOutcome::Response(forbidden)),
            ),
        ]);
        assert_eq!(
            result.raw_data.unwrap()["directories_exposed"],
            serde_json::json!(["/uploads/"])
        );
    }

    #[test]
    fn a_200_without_a_readable_body_cannot_rule_out_a_listing() {
        // Counting a bodiless 200 as answered lets a listing pass from silence.
        let answer = |status, dir: &str| {
            sweep_reading(&ProbeOutcome::Response(ProbeResponse {
                status,
                final_url: format!("https://example.com{dir}"),
                content_type: Some("text/html".into()),
                content_length: None,
                headers: Vec::new(),
                body: None,
            }))
        };
        let readings: Vec<(String, SweepReading)> = PROBE_DIRS
            .iter()
            .enumerate()
            .map(|(i, dir)| ((*dir).into(), answer(if i == 0 { 200 } else { 404 }, dir)))
            .collect();
        let result = grade_listing_probes(
            readings
                .iter()
                .map(|(dir, reading)| (dir.clone(), reading))
                .collect(),
        );
        assert_eq!(result.status, CheckStatus::Skipped);
        assert!(result
            .description
            .contains("but 1 of the 19 did not answer"));
    }

    #[test]
    fn no_directory_answering_says_none_answered() {
        // With nothing answered, "None of the 0 directories that answered" misreads.
        let result = grade_listing_probes(Vec::new());
        assert_eq!(result.status, CheckStatus::Skipped);
        assert_eq!(result.title, "Directory listing check incomplete");
        assert_eq!(
            result.description,
            "None of the 19 directories answered, so this scan could not rule out a listing there."
        );
    }
}
