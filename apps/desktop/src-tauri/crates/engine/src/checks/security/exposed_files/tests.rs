//! Unit tests for the sensitive-path probe verdicts.

use super::*;
use crate::checks::IssueConfidence;
use crate::probe::ProbeOutcome;

fn grade_path_probe(
    path: &str,
    description: &str,
    severity: &Severity,
    outcome: ProbeOutcome,
) -> CheckResult {
    super::grade_path_probe(
        path,
        description,
        severity,
        &crate::evaluation::sweep_reading(&outcome),
    )
}

#[test]
fn script_extraction_survives_truncated_closing_tag() {
    let truncated = "<html><body><script>db_password = 'x';</script";
    let out = extract_script_content(truncated);
    assert!(out.contains("db_password"), "{out}");

    // Malformed close followed by a multibyte char must also not panic.
    let malformed = "<script>secret_value = 1;</scriptФ rest";
    let _ = extract_script_content(malformed);
}

#[test]
fn firebase_config_apikey_is_not_flagged_as_source_secret() {
    let html = r#"<script>const config = { apiKey: "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", authDomain: "x.firebaseapp.com" };</script>"#;
    assert!(source_secrets_result(html).is_none());
}

#[test]
fn stripe_live_key_is_left_to_exposed_keys_check() {
    // sk_live_ keys are flagged (value-shaped, Critical) by
    // security.vibe.exposed_keys; this check must not double-report them.
    let html = r#"<script>const key = "sk_live_1234567890abcdefghijklmn";</script>"#; // gitleaks:allow
    assert!(source_secrets_result(html).is_none());
}

#[test]
fn remaining_identifier_matches_are_needs_review_advisories() {
    let html = r#"<script>fetch(config.database_url); const x = settings.aws_secret;</script>"#;
    let result = source_secrets_result(html).expect("identifiers should match");
    assert_eq!(result.status, CheckStatus::Warn);
    assert_eq!(result.severity, Severity::Medium);
    assert_eq!(result.confidence, IssueConfidence::NeedsReview);
    assert!(result.confidence_reason.is_some());
    assert!(
        result.description.contains("2 secret-named identifiers"),
        "{}",
        result.description
    );
    assert!(
        result.description.contains("no secret value was verified"),
        "{}",
        result.description
    );
}

#[test]
fn single_identifier_match_is_singular_not_one_matches() {
    let html = r#"<script>const conn = config.db_password;</script>"#;
    let result = source_secrets_result(html).expect("identifier should match");
    assert!(
        result.description.contains("1 secret-named identifier in"),
        "{}",
        result.description
    );
    assert!(!result.description.contains("1 matches"));
}

#[test]
fn security_txt_is_owned_by_the_dedicated_check() {
    // The HEAD-only /.well-known/security.txt probe false-passed on SPA
    // catch-all hosts and duplicated security.security_txt findings.
    assert!(
        !SENSITIVE_PATHS
            .iter()
            .any(|(path, _, _)| path.contains("security.txt")),
        "security.txt must not be probed by exposed_files; security_txt.rs owns it"
    );
}

#[test]
fn env_body_with_secret_assignments_is_verified_critical_content() {
    let body =
        "# prod config\nDATABASE_URL=postgres://admin:pw@db:5432/prod\nSMTP_PASSWORD=hunter2\n";
    assert_eq!(classify_env_body(body), EnvBodyVerdict::SecretAssignments);
}

#[test]
fn env_body_without_secret_keys_is_env_format_only() {
    let body = "APP_NAME=myapp\nAPP_COLOR=blue\n";
    assert_eq!(classify_env_body(body), EnvBodyVerdict::EnvFormatOnly);
}

#[test]
fn non_env_bodies_are_not_treated_as_exposed_env_files() {
    // A catch-all route serving prose, JSON, or JS must not produce the
    // cap-listed Critical ".env exposed" verdict.
    assert_eq!(
        classify_env_body("Welcome to our site! Everything is fine."),
        EnvBodyVerdict::NotEnvContent
    );
    assert_eq!(
        classify_env_body("{\"status\":\"ok\",\"version\":\"1.2.3\"}"),
        EnvBodyVerdict::NotEnvContent
    );
    assert_eq!(classify_env_body(""), EnvBodyVerdict::NotEnvContent);
}

#[test]
fn blocked_access_fix_options_actually_block() {
    let fix = blocked_access_fix("/.git/HEAD");
    assert!(
        !fix.contains("x-block"),
        "header-only advice does not block"
    );
    assert!(!fix.contains("<Files"), "Files matches basenames only");
    assert!(!fix.contains("\\n"), "no literal backslash-n in fix text");
    assert!(!fix.contains('\u{2014}'), "no em-dashes in fix text");
    assert!(fix.contains("Redirect 404 /.git/HEAD"));
}

#[test]
fn spa_html_shell_is_soft_404_for_medium_paths() {
    let shell = "<!doctype html><html><head><title>App</title></head><body><div id=\"root\"></div></body></html>";
    assert!(is_html_soft_404(
        "/.DS_Store",
        "text/html; charset=utf-8",
        shell
    ));
    assert!(is_html_soft_404("/error.log", "text/html", shell));
}

#[test]
fn real_file_content_is_not_soft_404() {
    // A genuine.DS_Store or log served as octet-stream/plain must
    // still count as exposed.
    assert!(!is_html_soft_404(
        "/.DS_Store",
        "application/octet-stream",
        "Bud1\u{0}\u{0}\u{0}"
    ));
    assert!(!is_html_soft_404(
        "/error.log",
        "text/plain",
        "[error] PHP Warning: undefined index"
    ));
}

#[test]
fn phpinfo_html_is_not_soft_404() {
    assert!(!is_html_soft_404(
        "/phpinfo.php",
        "text/html",
        "<html><body><h1>PHP Version 8.3</h1></body></html>"
    ));
}

fn probe_200(content_type: &str, body: &str) -> ProbeOutcome {
    ProbeOutcome::Response(crate::probe::ProbeResponse {
        status: 200,
        final_url: String::new(),
        content_type: Some(content_type.into()),
        content_length: Some(body.len() as u64),
        headers: Vec::new(),
        body: Some(crate::probe::ProbeBody {
            text: body.into(),
            bytes: body.len(),
            utf8_valid: true,
        }),
    })
}

#[test]
fn an_answered_probe_without_the_signature_is_not_a_network_problem() {
    let row = grade_path_probe(
        "/phpinfo.php",
        "PHP information page",
        &Severity::Medium,
        probe_200(
            "text/html",
            "<html><body><h1>Page not found</h1></body></html>",
        ),
    );
    assert_eq!(row.status, CheckStatus::Skipped);
    let summary = summarize_exposed_files(None, vec![row], 0)
        .pop()
        .expect("summary row");
    assert!(
        summary
            .description
            .contains("answered HTTP 200 without the expected file signature"),
        "{}",
        summary.description
    );
    assert!(
        !summary.description.contains("network that can reach"),
        "an answered probe is not a reachability problem: {}",
        summary.description
    );
    assert_eq!(
        summary.raw_data.as_ref().expect("evidence")["signature_mismatch"],
        1
    );
}

#[test]
fn an_unanswered_probe_still_reads_as_a_reachability_problem() {
    let row = grade_path_probe(
        "/.env",
        ".env-format environment configuration",
        &Severity::Critical,
        ProbeOutcome::Failure(crate::probe::ProbeFailure {
            class: crate::probe::ProbeFailureClass::Timeout,
            detail: "timed out".into(),
        }),
    );
    let summary = summarize_exposed_files(None, vec![row], 0)
        .pop()
        .expect("summary row");
    assert!(
        summary.description.contains("network that can reach"),
        "{}",
        summary.description
    );
    assert!(!summary
        .description
        .contains("without the expected file signature"));
}

#[test]
fn the_credential_caveat_only_appears_on_credential_bearing_classes() {
    let ds_store = grade_path_probe(
        "/.DS_Store",
        "macOS directory metadata",
        &Severity::Low,
        probe_200(
            "application/octet-stream",
            "\u{0}\u{0}\u{0}\u{1}Bud1\u{0}\u{0}\u{0}\u{0}",
        ),
    );
    assert_eq!(ds_store.status, CheckStatus::Fail);
    assert!(
        ds_store
            .description
            .ends_with("The scan did not inspect the complete file."),
        "{}",
        ds_store.description
    );

    let git_head = grade_path_probe(
        "/.git/HEAD",
        "Git repository HEAD reference",
        &Severity::Medium,
        probe_200("text/plain", "ref: refs/heads/main\n"),
    );
    assert_eq!(git_head.status, CheckStatus::Fail);
    assert!(
        !git_head.description.contains("contained credential"),
        "{}",
        git_head.description
    );

    let env = grade_path_probe(
        "/.env",
        ".env-format environment configuration",
        &Severity::Critical,
        probe_200(
            "text/plain",
            "DATABASE_URL=postgres://u:p@db/app\nAPI_SECRET=abc\n",
        ),
    );
    assert_eq!(env.status, CheckStatus::Fail);
    assert!(
        env.description.contains("contained credential"),
        "{}",
        env.description
    );
}
