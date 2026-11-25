use super::*;
use crate::connected_service::test_double::respond_in_sequence;
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[derive(serde::Deserialize)]
struct CodeProblem {
    code: String,
    status: u16,
}

pub(super) fn fixture(name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/connect/code-flow");
    serde_json::from_slice(&std::fs::read(root.join(format!("{name}.json"))).unwrap()).unwrap()
}

pub(super) async fn server(
    names: &[&str],
) -> (ConnectedServiceClient, tokio::task::JoinHandle<Vec<String>>) {
    server_wires(names.iter().map(|name| fixture(name)).collect()).await
}

pub(super) async fn server_wires(
    wires: Vec<Value>,
) -> (ConnectedServiceClient, tokio::task::JoinHandle<Vec<String>>) {
    let responses = wires
        .into_iter()
        .map(|value| {
            (
                value["body"].to_string(),
                match value["status"].as_u64().unwrap() {
                    200 => "200 OK",
                    400 => "400 Bad Request",
                    401 => "401 Unauthorized",
                    403 => "403 Forbidden",
                    404 => "404 Not Found",
                    409 => "409 Conflict",
                    429 => "429 Too Many Requests",
                    503 => "503 Service Unavailable",
                    _ => panic!("unexpected fixture status"),
                },
            )
        })
        .collect();
    let (origin, captured) = respond_in_sequence(responses).await;
    (
        ConnectedServiceClient::for_test_origin(&origin, Some("personal-fixture")).unwrap(),
        captured,
    )
}

pub(super) fn baseline() -> BaselineRequest {
    use sitecmd_protocol::coverage::ScanCoverageKind;
    use sitecmd_protocol::sync::{
        CodeBasis, CodeBasisKind, CodeSnapshot, CodeVersions, WireCoverage,
    };
    BaselineRequest {
        schema_version: 1,
        site_id: "site-repo".parse().expect("fixture identifier"),
        snapshot: CodeSnapshot {
            observed_at: 1_754_784_000_000,
            based_on_event_sequence: 0,
            versions: CodeVersions {
                fingerprint_schema: 1,
                fingerprint_key_version: 1,
                canonicalizer: 1,
            },
            manifest_digest: "9e4b0000".repeat(2).parse().expect("fixture identifier"),
            key_commitment: "0f".repeat(32).parse().expect("fixture identifier"),
            code_basis: CodeBasis {
                commit_sha: Some("c0ffee1".parse().expect("fixture identifier")),
                kind: CodeBasisKind::ExactCheckout,
                unvouched: Vec::new(),
            },
            coverage: WireCoverage {
                kind: ScanCoverageKind::Project,
                complete: true,
                routes: Vec::new(),
                checks: Vec::new(),
                exceptions: Vec::new(),
            },
            occurrences: Vec::new(),
        },
    }
}

pub(super) fn authorization() -> DeviceAuthorization {
    serde_json::from_value(fixture("issued")["body"].clone()).unwrap()
}

#[tokio::test]
async fn polling_obeys_pending_and_slow_down_intervals() {
    // Bug: the CLI can poll faster than Connect permits after slow_down.
    let (client, captured) = server(&["pending", "slow-down", "pending", "login"]).await;
    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let observed = sleeps.clone();
    let answer = wait_for_approval(&client, &authorization(), move |duration| {
        observed.lock().unwrap().push(duration.as_secs());
        Box::pin(async {})
    })
    .await
    .unwrap();
    assert!(matches!(answer, PollAnswer::Login { .. }));
    assert_eq!(*sleeps.lock().unwrap(), vec![5, 10, 10]);
    let requests = captured.await.unwrap();
    assert!(requests
        .iter()
        .all(|request| request.starts_with("POST /v1/cli/token ")));
    assert!(requests
        .iter()
        .all(|request| request.contains(r#""device_code":"DEVICECODEFIXTURE""#)));
    assert!(requests
        .iter()
        .all(|request| !request.to_lowercase().contains("authorization:")));
}

#[tokio::test]
async fn polling_stops_on_each_terminal_refusal() {
    // Bug: a refused or exhausted code can keep polling indefinitely.
    for name in ["denied", "expired", "token-limit"] {
        let (client, captured) = server(&[name]).await;
        let answer = wait_for_approval(&client, &authorization(), |_| {
            Box::pin(async { panic!("must stop") })
        })
        .await
        .unwrap();
        assert!(match name {
            "denied" => matches!(answer, PollAnswer::AccessDenied),
            "expired" => matches!(answer, PollAnswer::ExpiredToken),
            "token-limit" => matches!(answer, PollAnswer::TokenLimitReached),
            _ => false,
        });
        assert_eq!(captured.await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn polling_expires_without_a_further_request() {
    // Bug: the CLI can continue after the code's own lifetime has elapsed.
    let (client, captured) = server(&["pending"]).await;
    let mut authorization = authorization();
    authorization.expires_in = 3;
    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let observed = sleeps.clone();
    let answer = wait_for_approval(&client, &authorization, move |duration| {
        observed.lock().unwrap().push(duration);
        Box::pin(async {})
    })
    .await
    .unwrap();
    assert!(matches!(answer, PollAnswer::ExpiredToken));
    {
        let sleeps = sleeps.lock().unwrap();
        assert_eq!(sleeps.len(), 1);
        assert!(sleeps[0] > Duration::ZERO && sleeps[0] <= Duration::from_secs(3));
    }
    assert_eq!(captured.await.unwrap().len(), 1);
}

#[tokio::test]
async fn every_vendored_fixture_deserializes_as_its_wire_type() {
    // Bug: CLI response types can drift from Connect while both test suites pass.
    let provenance = fixture("provenance");
    let files = provenance["files"].as_array().unwrap();
    assert_eq!(files.len(), 26);
    for entry in files {
        let name = entry["file"]
            .as_str()
            .unwrap()
            .strip_suffix(".json")
            .unwrap();
        let value = fixture(name);
        let body = value["body"].clone();
        match name {
            "issued" => {
                serde_json::from_value::<DeviceAuthorization>(body).unwrap();
            }
            "login" | "connect" => {
                serde_json::from_value::<PollAnswer>(body).unwrap();
            }
            "pending" | "slow-down" | "denied" | "expired" | "token-limit" => {
                let (client, captured) = server(&[name]).await;
                let answer = client
                    .poll_token(&authorization().device_code)
                    .await
                    .unwrap();
                assert!(match name {
                    "pending" => matches!(answer, PollAnswer::AuthorizationPending),
                    "slow-down" => matches!(answer, PollAnswer::SlowDown { interval: 10 }),
                    "denied" => matches!(answer, PollAnswer::AccessDenied),
                    "expired" => matches!(answer, PollAnswer::ExpiredToken),
                    "token-limit" => matches!(answer, PollAnswer::TokenLimitReached),
                    _ => false,
                });
                captured.await.unwrap();
            }
            "baseline-applied" | "baseline-bootstrapped" => {
                serde_json::from_value::<BaselineReceipt>(body).unwrap();
            }
            "secrets-token" => {
                serde_json::from_value::<SecretsToken>(body).unwrap();
            }
            "secrets-provisioned"
            | "secrets-provisioned-installed"
            | "secrets-provisioned-setup-pr-closed" => {
                let receipt = serde_json::from_value::<ProvisionedReceipt>(body.clone()).unwrap();
                assert_eq!(
                    receipt.workflow_state,
                    body["workflow_state"].as_str().unwrap()
                );
            }
            _ => {
                let problem: CodeProblem = serde_json::from_value(body).unwrap();
                assert!(!problem.code.is_empty());
                assert_eq!(problem.status, value["status"].as_u64().unwrap() as u16);
            }
        }
    }
}

#[test]
fn debug_output_never_contains_device_or_bearer_secrets() {
    // Bug: derived Debug can reveal authentication and GitHub credentials.
    let auth = authorization();
    assert!(!format!("{auth:?}").contains("DEVICECODEFIXTURE"));
    assert_eq!(format!("{:?}", auth.device_code), "DeviceCode(***)");
    let secrets: SecretsToken =
        serde_json::from_value(fixture("secrets-token")["body"].clone()).unwrap();
    assert!(!format!("{secrets:?}").contains("ghs_FIXTURE"));
    for name in ["login", "connect"] {
        let answer: PollAnswer = serde_json::from_value(fixture(name)["body"].clone()).unwrap();
        assert!(!format!("{answer:?}").contains("FIXTURE"));
    }
}

#[tokio::test]
async fn code_request_sends_build_metadata_and_connect_fields() {
    // Bug: the CLI can send an incomplete approval request or caller-supplied build metadata.
    let (client, captured) = server(&["issued", "issued"]).await;
    client.request_code(&CodeRequest::Login).await.unwrap();
    client
        .request_code(&CodeRequest::Connect {
            url: "https://example.com".parse().unwrap(),
            repository: "owner/repo".parse().unwrap(),
            commitment: "a".repeat(64).parse().unwrap(),
            rotate: true,
        })
        .await
        .unwrap();
    for (index, request) in captured.await.unwrap().iter().enumerate() {
        assert!(request.starts_with("POST /v1/cli/codes "));
        assert!(!request.to_lowercase().contains("authorization:"));
        let body: Value = serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["client"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["client"]["os"], std::env::consts::OS);
        if index == 1 {
            assert_eq!(body["rotate"], true);
            assert_eq!(body["repository"], "owner/repo");
        }
    }
}

#[tokio::test]
async fn connection_routes_use_connection_bearer_and_preserve_baseline() {
    // Bug: setup calls can send the personal bearer or alter the signed baseline.
    let (client, captured) = server(&[
        "baseline-bootstrapped",
        "secrets-token",
        "secrets-provisioned",
    ])
    .await;
    let baseline = baseline();
    let body = serde_json::to_string(&baseline).unwrap();
    assert_eq!(
        client
            .connect_baseline("connection-fixture", &baseline)
            .await
            .unwrap()
            .key_version,
        1
    );
    assert_eq!(
        client
            .connect_secrets_token("connection-fixture")
            .await
            .unwrap()
            .repository,
        "example-org/example-site"
    );
    let receipt = client
        .connect_secrets_provisioned("connection-fixture", true)
        .await
        .unwrap();
    assert!(receipt.provisioned);
    assert_eq!(receipt.workflow_state, "setup_pr_open");
    let requests = captured.await.unwrap();
    for (request, route) in
        requests
            .iter()
            .zip(["baseline", "secrets-token", "secrets-provisioned"])
    {
        assert!(request.starts_with(&format!("POST /v1/connect/{route} ")));
        assert!(request
            .to_lowercase()
            .contains("authorization: bearer connection-fixture"));
    }
    assert!(requests[0].ends_with(&body));
    assert!(requests[2].contains("\"token_revoked\":true"));
}

#[tokio::test]
async fn setup_refusals_keep_machine_codes_and_remove_untrusted_details() {
    // Bug: setup errors can lose actionable codes or echo bearer secrets.
    for name in [
        "baseline-required",
        "connection-spent",
        "secrets-installation-suspended",
        "secrets-not-repository-admin",
        "secrets-setup-ci-token",
        "secrets-setup-setup-pull-request",
        "secrets-setup-unlinking",
        "secrets-unavailable",
        "baseline-recorded",
        "key-commitment-mismatch",
    ] {
        let (client, captured) = server(&[name]).await;
        let error = client
            .connect_secrets_token("connection-fixture")
            .await
            .unwrap_err();
        assert_eq!(error.code, fixture(name)["body"]["code"].as_str().unwrap());
        assert_eq!(
            error.status,
            fixture(name)["status"].as_u64().unwrap() as u16
        );
        assert!(error.details.is_none());
        assert_eq!(
            error.message,
            fixture(name)["body"]["detail"].as_str().unwrap()
        );
        captured.await.unwrap();
    }
    let mut wire = fixture("secrets-setup-ci-token");
    wire["body"]["detail"] = "Cannot write sitecmd_cnx_FIXTURE".into();
    wire["body"]["request_id"] = "sitecmd_pat_FIXTURE".into();
    let (client, captured) = server_wires(vec![wire]).await;
    let error = client
        .connect_secrets_token("sitecmd_cnx_FIXTURE")
        .await
        .unwrap_err();
    assert_eq!(error.code, "ci_token_refused");
    assert!(error.message.is_empty());
    assert!(error.details.is_none() && error.request_id.is_none());
    assert!(!format!("{error:?}").contains("FIXTURE"));
    captured.await.unwrap();
}

#[tokio::test]
async fn revoke_uses_current_personal_bearer_and_accepts_no_content() {
    // Bug: logout can revoke the wrong bearer or reject a successful empty response.
    let (origin, captured) = respond_in_sequence(vec![(String::new(), "204 No Content")]).await;
    let client =
        ConnectedServiceClient::for_test_origin(&origin, Some("personal-fixture")).unwrap();
    client.revoke_current_token().await.unwrap();
    let requests = captured.await.unwrap();
    assert!(requests[0].starts_with("DELETE /v1/account/tokens/current "));
    assert!(requests[0]
        .to_lowercase()
        .contains("authorization: bearer personal-fixture"));
}
