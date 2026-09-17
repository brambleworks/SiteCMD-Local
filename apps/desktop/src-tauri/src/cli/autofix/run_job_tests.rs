//! The fix job's unit tests, plus the ones that drive the command
//! against a loopback double of the connected service.

use super::*;
use crate::cli::autofix::repo::init_test_repo;
use crate::connected_service::test_double::respond_in_sequence;
use crate::connected_service::{ClaimedFinding, ClaimedJob};
use sitecmd_engine::sync::ProjectFingerprintKey;

const CLAIM: &str = r#"{"job_id":"job_0123456789abcdef","attempt":1,"purpose":"execute","job_token":"sitecmd_job_execute_00000000000000000000000000000000","expires_at":"2026-09-20T10:30:00.000Z","base_sha":"0123456789abcdef0123456789abcdef01234567","site_url":"https://loop.example.com","repository":"example-org/example-site","default_branch":"main","agent":"claude","findings":[{"check_id":"security.headers.x_content_type_options","identity":"/","class":"template","category":"security","fallback_class":null}]}"#;

const RESULT_RECEIPT: &str = r#"{"job_id":"job_0123456789abcdef","state":"blocked"}"#;

fn claimed(base_sha: &str, findings: Vec<ClaimedFinding>) -> ClaimedJob {
    ClaimedJob {
        agent: "claude".into(),
        attempt: 1,
        base_sha: base_sha.into(),
        committer: None,
        default_branch: "main".into(),
        expires_at: "x".into(),
        findings,
        job_id: "job_0123456789abcdef".into(),
        job_token: "sitecmd_job_execute_00000000000000000000000000000000".into(),
        opt_in_fixers: vec![],
        previous_failure: None,
        purpose: "execute".into(),
        repository: "example-org/example-site".into(),
        site_url: "https://loop.example.com".into(),
    }
}

fn header_finding() -> ClaimedFinding {
    ClaimedFinding {
        category: "security".into(),
        check_id: "security.headers.x_content_type_options".into(),
        class: "template".into(),
        fallback_class: None,
        identity: "/".into(),
    }
}

const ROUTE: &str = "export async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const returnTo = searchParams.get(\"returnTo\") ?? \"/\";\n  return Response.redirect(new URL(returnTo, request.url), 302);\n}\n";

#[test]
fn a_template_finding_becomes_a_staged_patch_for_the_publish_job() {
    let (repo, head) = init_test_repo(&[
        ("vercel.json", "{\n  \"cleanUrls\": true\n}\n"),
        ("package.json", "{\"name\":\"loop\"}"),
    ])
    .unwrap();
    let execution = execute_fix_job(
        &claimed(&head, vec![header_finding()]),
        repo.path(),
        None,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(execution.publish);
    assert!(execution.result.is_none());
    assert!(
        execution.patch.contains("+++ b/vercel.json"),
        "{}",
        execution.patch
    );
    assert!(execution.patch.contains("nosniff"));
    assert_eq!(
        execution.manifest.write_set,
        vec!["vercel.json".to_string()]
    );
    assert_eq!(
        execution.manifest.findings[0].outcome.as_deref(),
        Some("applied")
    );
    assert_eq!(execution.manifest.outcome_code, None);
    assert_eq!(execution.manifest.base_sha, head);
}

#[cfg(unix)]
#[test]
fn a_failing_build_reports_build_failed_and_publishes_nothing() {
    let (repo, head) = init_test_repo(&[
        ("vercel.json", "{}\n"),
        (
            "package.json",
            "{\"scripts\":{\"build\":\"node -e \\\"console.error('refused'); process.exit(1)\\\"\"}}",
        ),
    ])
    .unwrap();
    let mut log = Vec::new();
    let execution = execute_fix_job(
        &claimed(&head, vec![header_finding()]),
        repo.path(),
        None,
        &mut log,
    )
    .unwrap();
    assert!(!execution.publish);
    let result = execution.result.expect("a result to report");
    assert_eq!(result.outcome_code, "build_failed");
    assert_eq!(
        result.summary,
        "Build failed at build with exit status 1; see the Actions log"
    );
    assert!(!result.summary.contains("refused"));
    assert!(result.findings.is_empty());
    assert!(String::from_utf8_lossy(&log).contains("refused"));
    assert_eq!(
        execution.manifest.outcome_code.as_deref(),
        Some("build_failed")
    );
    assert!(execution.patch.is_empty());
}

#[test]
fn a_checkout_not_at_the_base_sha_is_stale() {
    let (repo, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let execution = execute_fix_job(
        &claimed(&"1".repeat(40), vec![header_finding()]),
        repo.path(),
        None,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(execution.result.unwrap().outcome_code, "stale_base");
    assert!(!execution.publish);
}

#[test]
fn an_agent_finding_becomes_a_brief_with_its_location() {
    let (repo, head) = init_test_repo(&[
        ("package.json", "{\"name\":\"loop\"}"),
        ("app/api/signin/route.ts", ROUTE),
    ])
    .unwrap();
    let key = ProjectFingerprintKey::from_bytes([7_u8; 32]);
    let identity = key.location_hash("open-redirect", "app/api/signin/route.ts");
    let finding = ClaimedFinding {
        category: "security".into(),
        check_id: "code_scan.open-redirect".into(),
        class: "agent-easy".into(),
        fallback_class: None,
        identity,
    };
    let execution = execute_fix_job(
        &claimed(&head, vec![finding]),
        repo.path(),
        Some(&key),
        &mut Vec::new(),
    )
    .unwrap();
    assert!(execution.publish);
    assert!(execution.patch.is_empty());
    let brief = execution.manifest.brief.expect("brief");
    assert_eq!(
        brief.findings[0].locations[0].path,
        "app/api/signin/route.ts"
    );
    assert_eq!(
        execution.manifest.findings[0].outcome.as_deref(),
        Some("issue_opened")
    );
}

#[test]
fn a_finding_without_a_fixer_is_declined_with_a_result() {
    let (repo, head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let finding = ClaimedFinding {
        category: "security".into(),
        check_id: "security.headers.hsts".into(),
        class: "template".into(),
        fallback_class: None,
        identity: "/".into(),
    };
    let execution = execute_fix_job(
        &claimed(&head, vec![finding]),
        repo.path(),
        None,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(!execution.publish);
    assert_eq!(execution.result.unwrap().outcome_code, "no_template");
}

#[tokio::test]
async fn the_command_claims_then_reports_missing_secrets() {
    let (repo, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    let outputs = workspace.path().join("outputs.txt");
    let (origin, captured) = respond_in_sequence(vec![
        (CLAIM.to_string(), "200 OK"),
        (RESULT_RECEIPT.to_string(), "200 OK"),
    ])
    .await;
    let args = RunJobArgs {
        artifact_dir: artifact_dir.clone(),
        connect_origin: origin,
        export: ExportSource::Env("SITECMD_TEST_RUN_JOB_MISSING_EXPORT".into()),
        job_id: "job_0123456789abcdef".into(),
        outputs: Some(outputs.clone()),
        passphrase_env: "SITECMD_TEST_RUN_JOB_MISSING_PASSPHRASE".into(),
        path: repo.path().to_path_buf(),
    };

    let (code, summary) = run_with_witness(&args, "witness-token", true)
        .await
        .expect("the command to report rather than fail");

    assert_eq!(code, 1);
    // The printed summary carries the fixed sentence and the local reason,
    // which names the variable and no part of a value.
    assert_eq!(
        summary,
        format!(
            "{MISSING_SECRETS_SUMMARY}\nSITECMD_TEST_RUN_JOB_MISSING_EXPORT is missing or empty"
        )
    );
    assert_eq!(
        std::fs::read_to_string(&outputs).expect("outputs"),
        "publish=false\n"
    );
    assert!(!artifact_dir.join("manifest.json").exists());

    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2);
    let claim = requests[0].to_ascii_lowercase();
    assert!(
        claim.starts_with("post /v1/fix-jobs/job_0123456789abcdef/claim http/1.1"),
        "{claim}"
    );
    assert!(
        claim.contains("x-github-oidc-token: witness-token\r\n"),
        "{claim}"
    );
    assert!(!claim.contains("authorization:"), "{claim}");
    assert!(claim.ends_with(r#"{"purpose":"execute"}"#), "{claim}");
    let report = requests[1].to_ascii_lowercase();
    assert!(
        report.starts_with("post /v1/fix-jobs/job_0123456789abcdef/result http/1.1"),
        "{report}"
    );
    assert!(
        report.contains(
            "authorization: bearer sitecmd_job_execute_00000000000000000000000000000000\r\n"
        ),
        "{report}"
    );
    assert!(
        requests[1].contains(r#""outcome_code":"secrets_missing""#),
        "{}",
        requests[1]
    );
    assert!(requests[1].contains(r#""findings":[]"#), "{}", requests[1]);
    assert!(
        requests[1].contains(MISSING_SECRETS_SUMMARY),
        "{}",
        requests[1]
    );
    // The posted summary is fixed, so it names nothing the repository chose.
    assert!(
        !requests[1].contains("SITECMD_TEST_RUN_JOB_MISSING_EXPORT"),
        "{}",
        requests[1]
    );
    assert_eq!(
        MISSING_SECRETS_SUMMARY,
        "The connection export or passphrase is missing or could not be decrypted; rotate the connection export from the SiteCMD app and update the repository secrets"
    );
}

#[tokio::test]
async fn a_job_that_already_moved_on_does_nothing_and_succeeds() {
    let (repo, _head) = init_test_repo(&[("vercel.json", "{}\n")]).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let artifact_dir = workspace.path().join("artifact");
    let outputs = workspace.path().join("outputs.txt");
    let (origin, captured) = respond_in_sequence(vec![(
        r#"{"error":{"code":"job_state_conflict","message":"the job is not waiting for an execute claim"}}"#
            .to_string(),
        "409 Conflict",
    )])
    .await;
    let args = RunJobArgs {
        artifact_dir: artifact_dir.clone(),
        connect_origin: origin,
        export: ExportSource::Env("SITECMD_TEST_RUN_JOB_MISSING_EXPORT".into()),
        job_id: "job_0123456789abcdef".into(),
        outputs: Some(outputs.clone()),
        passphrase_env: "SITECMD_TEST_RUN_JOB_MISSING_PASSPHRASE".into(),
        path: repo.path().to_path_buf(),
    };

    let (code, summary) = run_with_witness(&args, "witness-token", true)
        .await
        .expect("a job that moved on is not a failure");

    assert_eq!(code, 0);
    assert!(summary.contains("nothing to do"), "{summary}");
    assert_eq!(
        std::fs::read_to_string(&outputs).expect("outputs"),
        "publish=false\n"
    );
    assert!(!artifact_dir.join("manifest.json").exists());
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .starts_with("post /v1/fix-jobs/job_0123456789abcdef/claim http/1.1"),
        "{}",
        requests[0]
    );
}
