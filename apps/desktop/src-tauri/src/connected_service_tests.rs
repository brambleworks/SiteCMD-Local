//! Connected-service transport contract tests.

use super::*;
use deployment_ordering::CiSubmissionAttestation;

#[test]
fn error_parser_never_echoes_an_unstructured_response() {
    let error = parse_response::<Value>(
        StatusCode::BAD_GATEWAY,
        br#"upstream body containing sitecmd_cat_secret"#,
    )
    .expect_err("failure");
    assert_eq!(error.code, "request_failed");
    assert!(!error.to_string().contains("sitecmd_cat_secret"));
}

#[test]
fn an_empty_refusal_reads_as_request_failed_with_its_status() {
    let error = parse_response::<Value>(StatusCode::SERVICE_UNAVAILABLE, b"").expect_err("failure");
    assert_eq!(error.code, "request_failed");
    assert_eq!(error.status, 503);
    assert!(error.details.is_none());
}

#[test]
fn an_html_refusal_reads_as_request_failed_with_its_status() {
    let error = parse_response::<Value>(
        StatusCode::BAD_GATEWAY,
        b"<!DOCTYPE html><html><body><h1>502 Bad Gateway</h1></body></html>",
    )
    .expect_err("failure");
    assert_eq!(error.code, "request_failed");
    assert_eq!(error.status, 502);
    assert!(error.details.is_none());
    assert!(!error.to_string().contains("Bad Gateway"));
}

#[test]
fn a_problem_without_detail_keeps_its_code() {
    let error = parse_response::<Value>(
        StatusCode::CONFLICT,
        br#"{"code":"stale_revision","stale_groups":[{"check":"security.csp","current_state":"active","current_state_revision":43}]}"#,
    )
    .expect_err("failure");
    assert_eq!(error.code, "stale_revision");
    assert_eq!(error.stale_groups("security.csp").len(), 1);
}

const STALE_PROBLEM: &[u8] = br#"{"type":"about:blank","title":"Conflict","status":409,"detail":"The lifecycle state changed after revision 41.","code":"stale_revision","request_id":"req_0123456789abcdef","stale_groups":[{"check":"security.csp","current_state":"active","current_state_revision":43}]}"#;

#[test]
fn problem_details_parse_with_their_members_as_details() {
    let error = parse_response::<Value>(StatusCode::CONFLICT, STALE_PROBLEM).expect_err("failure");
    assert_eq!(error.status, 409);
    assert_eq!(error.code, "stale_revision");
    assert_eq!(
        error.message,
        "The lifecycle state changed after revision 41."
    );
    assert_eq!(error.request_id.as_deref(), Some("req_0123456789abcdef"));
    assert!(error.is_stale_revision());
    assert_eq!(error.stale_groups("security.csp").len(), 1);
}

#[test]
fn a_problem_extension_member_reaches_the_reason_match() {
    let error = parse_response::<Value>(
        StatusCode::FORBIDDEN,
        br#"{"type":"about:blank","title":"Forbidden","status":403,"detail":"x","code":"provenance_rejected","request_id":"req_0123456789abcdef","reason":"workflow_mismatch"}"#,
    )
    .expect_err("failure");
    let reason = error
        .details
        .as_ref()
        .and_then(|details| details.get("reason"))
        .and_then(Value::as_str);
    assert_eq!(reason, Some("workflow_mismatch"));
}

#[test]
fn the_retired_error_envelope_reads_as_an_unstructured_refusal() {
    let error = parse_response::<Value>(
        StatusCode::CONFLICT,
        br#"{"error":{"code":"stale_revision","message":"changed","request_id":"req_0123456789abcdef"}}"#,
    )
    .expect_err("failure");
    assert_eq!(error.code, "request_failed");
    assert!(error.details.is_none());
}

#[test]
fn an_inactive_account_is_read_from_the_problem_code() {
    let inactive = parse_response::<Value>(
        StatusCode::FORBIDDEN,
        test_double::ACCOUNT_INACTIVE_PROBLEM.as_bytes(),
    )
    .expect_err("refused");
    assert!(is_account_inactive(&inactive));

    let suspended = parse_response::<Value>(
        StatusCode::FORBIDDEN,
        test_double::ENTITLEMENT_SUSPENDED_PROBLEM.as_bytes(),
    )
    .expect_err("refused");
    assert!(!is_account_inactive(&suspended));
    // A refusal that carried no problem details names no account state.
    let bare = parse_response::<Value>(StatusCode::FORBIDDEN, b"").expect_err("refused");
    assert!(!is_account_inactive(&bare));
}

const NOTICE: &str = "SiteCMD Connect says this account is inactive, so nothing was sent. Renew it from the SiteCMD dashboard to resume.";
const RESULT_NOTICE: &str = "SiteCMD Connect says this account is inactive, so this result was not recorded. Renew it from the SiteCMD dashboard to resume.";
const GATE_NOTICE: &str = "SiteCMD Connect says this account is inactive, so the gate graded nothing. Renew it from the SiteCMD dashboard to resume.";

#[test]
fn the_inactive_notices_are_verbatim_and_name_no_origin() {
    assert_eq!(ACCOUNT_INACTIVE_NOTICE, NOTICE);
    assert_eq!(ACCOUNT_INACTIVE_RESULT_NOTICE, RESULT_NOTICE);
    assert_eq!(ACCOUNT_INACTIVE_GATE_NOTICE, GATE_NOTICE);
    for notice in [
        ACCOUNT_INACTIVE_NOTICE,
        ACCOUNT_INACTIVE_RESULT_NOTICE,
        ACCOUNT_INACTIVE_GATE_NOTICE,
    ] {
        assert!(!notice.contains("://"), "{notice}");
        assert!(!notice.contains("sitecmd.com"), "{notice}");
    }
}

#[test]
fn the_notice_is_annotated_only_under_github_actions() {
    assert_eq!(inactive_output("", NOTICE, false), NOTICE);
    assert_eq!(
        inactive_output("", NOTICE, true),
        format!("{NOTICE}\n::notice title=SiteCMD::{NOTICE}")
    );
    assert_eq!(
        inactive_output("", GATE_NOTICE, true),
        format!("{GATE_NOTICE}\n::notice title=SiteCMD::{GATE_NOTICE}")
    );
}

#[test]
fn what_the_command_already_did_comes_before_the_notice() {
    assert_eq!(
        inactive_output("opened pull request #12", RESULT_NOTICE, false),
        format!("opened pull request #12\n{RESULT_NOTICE}")
    );
    assert_eq!(
        inactive_output("opened pull request #12", RESULT_NOTICE, true),
        format!(
            "opened pull request #12\n{RESULT_NOTICE}\n::notice title=SiteCMD::{RESULT_NOTICE}"
        )
    );
}

const IN_PROGRESS_PROBLEM: &str = r#"{"type":"about:blank","title":"Conflict","status":409,"detail":"A request under this Idempotency-Key is still being processed.","code":"request_in_progress","request_id":"req_0123456789abcdef"}"#;

#[tokio::test]
async fn a_refusal_carries_the_seconds_its_retry_after_names() {
    let (origin, _) = test_double::respond_once_with_headers(
        IN_PROGRESS_PROBLEM,
        "409 Conflict",
        &["Retry-After: 42"],
    )
    .await;
    let client = ConnectedServiceClient::for_test_origin(&origin, Some("t")).expect("client");
    let url = client
        .url(&["v1", "sites", "s", "sync", "ci"])
        .expect("url");
    let error = client
        .request::<Value>(Method::POST, url, Some("key-1"), Some("{}".into()))
        .await
        .expect_err("refused");
    assert_eq!(error.code, "request_in_progress");
    assert_eq!(error.retry_after, Some(42));
}

#[test]
fn a_retry_after_names_a_wait_only_in_whole_seconds() {
    let refused = |value: Option<&str>| {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(value) = value {
            headers.insert(
                reqwest::header::RETRY_AFTER,
                value.parse().expect("header value"),
            );
        }
        problem::refusal(
            StatusCode::CONFLICT,
            &headers,
            IN_PROGRESS_PROBLEM.as_bytes(),
        )
    };
    assert_eq!(refused(Some(" 7 ")).retry_after, Some(7));
    assert_eq!(
        refused(Some("Wed, 21 Oct 2026 07:28:00 GMT")).retry_after,
        None
    );
    assert_eq!(refused(Some("-1")).retry_after, None);
    let bare = refused(None);
    assert_eq!(bare.retry_after, None);
    assert_eq!(bare.code, "request_in_progress");
}

#[tokio::test]
async fn a_request_with_a_body_is_sent_as_json() {
    let (origin, captured) = test_double::respond_once("{}", "200 OK").await;
    let client = ConnectedServiceClient::for_test_origin(&origin, Some("t")).expect("client");
    let url = client.url(&["v1", "account"]).expect("url");
    let _: Value = client
        .request(Method::POST, url, None, Some("{}".into()))
        .await
        .expect("answered");
    let request = captured.await.expect("capture").to_ascii_lowercase();
    assert!(request.contains("\r\ncontent-type: application/json\r\n"));
}

#[test]
fn stale_revision_details_support_batch_and_single_shapes() {
    let batch = ConnectedServiceError {
        status: 409,
        code: "stale_revision".into(),
        message: "changed".into(),
        request_id: None,
        details: Some(Box::new(serde_json::json!({
            "stale_groups": [{
                "check": "security.csp",
                "current_state": "active",
                "current_state_revision": 43
            }]
        }))),
        retry_after: None,
    };
    assert_eq!(
        batch.stale_groups("ignored"),
        vec![StaleGroup {
            check: "security.csp".into(),
            state: "active".into(),
            revision: 43,
        }]
    );
    let single = ConnectedServiceError {
        details: Some(Box::new(serde_json::json!({
            "current_state": "dismissed",
            "current_state_revision": 9
        }))),
        ..batch
    };
    assert_eq!(single.stale_groups("seo.title")[0].check, "seo.title");
}

#[test]
fn site_creation_carries_the_version_1_key_commitment() {
    let body = serde_json::to_value(CreateSiteRequest {
        alias: None,
        fingerprint_key_commitment:
            "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
        url: "https://example.com",
    })
    .expect("encodes");
    assert_eq!(
        body.get("fingerprint_key_commitment")
            .and_then(Value::as_str),
        Some("9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"),
    );
    assert!(body.get("alias").is_none());
}

#[test]
fn site_state_keeps_scope_and_allowance_standing_from_the_service() {
    let state: ConnectedSiteState = serde_json::from_value(serde_json::json!({
        "event_sequence": 8,
        "ordering_authority": {
            "authority_id": "github:1296269:authority",
            "current_deployment_id": "run-41",
            "epoch": 3,
            "kind": "publish_attestation",
            "publish_sequence": 7
        },
        "phase": "connected",
        "scope_effective_route_count": 12,
        "scope_over_plan": true,
        "scope_over_plan_grace_expires_at": "2026-08-20T00:00:00.000Z",
        "scope_overflow_count": 2,
        "scope_route_cap": 10,
        "site_allowance_over_plan": true,
        "site_allowance_over_plan_grace_expires_at": "2026-08-21T00:00:00.000Z",
        "state_revision": 4
    }))
    .expect("state");

    assert!(state.scope_over_plan);
    assert_eq!(state.scope_effective_route_count, 12);
    assert_eq!(state.scope_overflow_count, 2);
    assert_eq!(state.scope_route_cap, 10);
    assert!(state.site_allowance_over_plan);
    assert_eq!(
        state
            .ordering_authority
            .as_ref()
            .map(|authority| authority.authority_id.as_str()),
        Some("github:1296269:authority")
    );
    assert_eq!(
        state.site_allowance_over_plan_grace_expires_at.as_deref(),
        Some("2026-08-21T00:00:00.000Z")
    );
}

#[test]
fn ci_deployment_head_reads_only_the_ordering_cursor_contract() {
    let head: CiDeploymentHead = serde_json::from_value(serde_json::json!({
        "current_deployment_id": "run-41",
        "submission_attestation": "github_oidc",
        "ordering_authority": {
            "activated_at": "2026-08-14T00:00:00.000Z",
            "authority_id": "github:1296269:authority",
            "current_deployment_id": "run-41",
            "epoch": 3,
            "kind": "publish_attestation",
            "publish_sequence": 7
        }
    }))
    .expect("deployment head");

    assert_eq!(head.current_deployment_id.as_deref(), Some("run-41"));
    assert_eq!(
        head.submission_attestation,
        CiSubmissionAttestation::GithubOidc
    );
    let authority = head.ordering_authority.expect("authority");
    assert_eq!(authority.kind, "publish_attestation");
    assert_eq!(authority.epoch, 3);
    assert_eq!(authority.publish_sequence, Some(7));
}

#[test]
fn an_older_deployment_head_defaults_to_the_safe_legacy_oidc_behavior() {
    let head: CiDeploymentHead = serde_json::from_value(serde_json::json!({
        "current_deployment_id": null,
        "ordering_authority": null
    }))
    .expect("legacy deployment head");

    assert_eq!(
        head.submission_attestation,
        CiSubmissionAttestation::GithubOidc
    );
}

#[test]
fn bearer_is_redacted_and_insecure_remote_origins_are_rejected() {
    let client = ConnectedServiceClient::for_endpoint(
        "http://127.0.0.1:8787",
        Some("sitecmd_cat_do_not_log"),
        true,
    )
    .expect("test loopback");
    let debug = format!("{client:?}");
    assert!(!debug.contains("sitecmd_cat_do_not_log"));
    assert!(ConnectedServiceClient::for_endpoint(
        "http://connect.sitecmd.com",
        Some("token"),
        false
    )
    .is_err());
    assert!(ConnectedServiceClient::for_endpoint(
        "https://connect.sitecmd.com/unexpected-base",
        Some("token"),
        false,
    )
    .is_err());
}
