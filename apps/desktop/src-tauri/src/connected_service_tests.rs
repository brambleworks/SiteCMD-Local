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
fn stale_revision_details_support_batch_and_single_shapes() {
    let batch = ConnectedServiceError {
        status: 409,
        code: "stale_revision".into(),
        message: "changed".into(),
        request_id: None,
        details: Some(serde_json::json!({
            "stale_groups": [{
                "check": "security.csp",
                "current_state": "active",
                "current_state_revision": 43
            }]
        })),
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
        details: Some(serde_json::json!({
            "current_state": "dismissed",
            "current_state_revision": 9
        })),
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
