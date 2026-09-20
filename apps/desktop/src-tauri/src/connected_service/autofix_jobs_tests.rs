//! Fix-job wire-contract tests.

use super::{FindingOutcomeReport, PullRequestReport, ResultReport};
use crate::connected_service::test_double::respond_once;
use crate::connected_service::ConnectedServiceClient;

const CLAIM: &str = r#"{"job_id":"job_0123456789abcdef","attempt":1,"purpose":"execute","job_token":"sitecmd_job_execute_00000000000000000000000000000000","expires_at":"2026-09-20T10:30:00.000Z","base_sha":"0123456789abcdef0123456789abcdef01234567","site_url":"https://loop.example.com","repository":"example-org/example-site","default_branch":"main","agent":"claude","findings":[{"check_id":"security.headers.x_content_type_options","identity":"/","class":"template","category":"security","fallback_class":null}]}"#;

#[tokio::test]
async fn claim_job_sends_the_oidc_witness_and_no_bearer() {
    let (origin, captured) = respond_once(CLAIM, "200 OK").await;
    let client = ConnectedServiceClient::for_test_origin(&origin, None).expect("client");
    let claimed = client
        .claim_job("job_0123456789abcdef", "execute", "signed.oidc")
        .await
        .expect("claimed");
    assert_eq!(claimed.findings.len(), 1);
    assert_eq!(
        claimed.job_token,
        "sitecmd_job_execute_00000000000000000000000000000000"
    );
    assert!(
        !format!("{claimed:?}").contains("sitecmd_job_execute_0000"),
        "the token must not appear in Debug output"
    );
    let request = captured.await.expect("capture").to_ascii_lowercase();
    assert!(request.starts_with("post /v1/fix-jobs/job_0123456789abcdef/claim http/1.1"));
    assert!(request.contains("x-github-oidc-token: signed.oidc\r\n"));
    assert!(!request.contains("authorization:"));
    assert!(request.ends_with(r#"{"purpose":"execute"}"#));
}

#[tokio::test]
async fn report_job_result_carries_the_job_token_as_bearer() {
    let (origin, captured) = respond_once(
        r#"{"job_id":"job_0123456789abcdef","state":"pr_open"}"#,
        "200 OK",
    )
    .await;
    let client = ConnectedServiceClient::for_test_origin(
        &origin,
        Some("sitecmd_job_publish_11111111111111111111111111111111"),
    )
    .expect("client");
    let receipt = client
        .report_job_result(
            "job_0123456789abcdef",
            &ResultReport {
                attempt: 1,
                findings: vec![FindingOutcomeReport {
                    check_id: "security.headers.x_content_type_options".into(),
                    identity: "/".into(),
                    outcome: "applied".into(),
                }],
                issue_number: None,
                outcome_code: "applied".into(),
                pull_request: Some(PullRequestReport {
                    branch: "sitecmd/x-content-type-options-012345".into(),
                    head_sha: "b".repeat(40),
                    number: 12,
                }),
                summary: "Added the header".into(),
                token_revoked: true,
            },
        )
        .await
        .expect("reported");
    assert_eq!(receipt.state, "pr_open");
    let request = captured.await.expect("capture").to_ascii_lowercase();
    assert!(request.contains("authorization: bearer sitecmd_job_publish_1111"));
    assert!(request.contains(r#""outcome_code":"applied""#));
    assert!(!request.contains("issue_number"));
}

#[tokio::test]
async fn token_doors_return_the_operation_token() {
    let (origin, captured) = respond_once(
        r#"{"token":"ghs_x","expires_at":"2026-09-20T11:00:00Z"}"#,
        "200 OK",
    )
    .await;
    let client = ConnectedServiceClient::for_test_origin(
        &origin,
        Some("sitecmd_job_publish_11111111111111111111111111111111"),
    )
    .expect("client");
    let token = client
        .publish_token("job_0123456789abcdef")
        .await
        .expect("token");
    assert_eq!(token.token, "ghs_x");
    let request = captured.await.expect("capture").to_ascii_lowercase();
    assert!(request.starts_with("post /v1/fix-jobs/job_0123456789abcdef/publish-token"));
    assert!(request.ends_with(r#"{"workflows_write":false}"#));
}

#[tokio::test]
async fn a_refusal_surfaces_the_service_code() {
    let (origin, _captured) = respond_once(
        r#"{"error":{"code":"provenance_rejected","message":"no","request_id":"req_1","details":{"reason":"workflow_mismatch"}}}"#,
        "403 Forbidden",
    )
    .await;
    let client = ConnectedServiceClient::for_test_origin(&origin, None).expect("client");
    let error = client
        .claim_job("job_0123456789abcdef", "execute", "signed.oidc")
        .await
        .expect_err("refused");
    assert_eq!(error.code, "provenance_rejected");
    assert_eq!(
        error.details.as_ref().and_then(|d| d["reason"].as_str()),
        Some("workflow_mismatch")
    );
}
