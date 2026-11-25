use super::tests::{baseline, fixture, server_wires};
use super::*;

macro_rules! refusal_case {
    ($name:ident, $code:literal, $variant:ident) => {
        #[tokio::test]
        async fn $name() {
            // Bug: a documented Connect refusal can lose its identity and owner-signed reason.
            let mut wire = fixture("baseline-required");
            wire["body"]["code"] = $code.into();
            wire["body"]["detail"] = "Connect-owned reason.".into();
            let (client, captured) = server_wires(vec![wire]).await;
            let error = client
                .connect_baseline("sitecmd_cnx_FIXTURE", &baseline())
                .await
                .unwrap_err();
            assert_eq!(error.code, $code);
            assert_eq!(error.code_refusal(), Some(CodeRefusal::$variant));
            assert_eq!(error.message, "Connect-owned reason.");
            assert!(error.details.is_none() && error.request_id.is_none());
            captured.await.unwrap();
        }
    };
}
refusal_case!(
    preserves_authorization_pending,
    "authorization_pending",
    AuthorizationPending
);
refusal_case!(preserves_slow_down, "slow_down", SlowDown);
refusal_case!(preserves_access_denied, "access_denied", AccessDenied);
refusal_case!(preserves_expired_token, "expired_token", ExpiredToken);
refusal_case!(
    preserves_token_limit_reached,
    "token_limit_reached",
    TokenLimitReached
);
refusal_case!(
    preserves_baseline_required,
    "baseline_required",
    BaselineRequired
);
refusal_case!(
    preserves_connection_spent,
    "connection_spent",
    ConnectionSpent
);
refusal_case!(
    preserves_baseline_recorded,
    "baseline_recorded",
    BaselineRecorded
);
refusal_case!(
    preserves_key_commitment_mismatch,
    "key_commitment_mismatch",
    KeyCommitmentMismatch
);
refusal_case!(
    preserves_installation_suspended,
    "installation_suspended",
    InstallationSuspended
);
refusal_case!(
    preserves_not_repository_admin,
    "not_repository_admin",
    NotRepositoryAdmin
);
refusal_case!(
    preserves_ci_token_refused,
    "ci_token_refused",
    CiTokenRefused
);
refusal_case!(
    preserves_setup_pull_request_refused,
    "setup_pull_request_refused",
    SetupPullRequestRefused
);
refusal_case!(
    preserves_repository_unlinking,
    "repository_unlinking",
    RepositoryUnlinking
);
refusal_case!(preserves_unavailable, "unavailable", Unavailable);
refusal_case!(preserves_rate_limited, "rate_limited", RateLimited);
refusal_case!(preserves_code_not_found, "code_not_found", CodeNotFound);
refusal_case!(
    preserves_account_inactive,
    "account_inactive",
    AccountInactive
);
refusal_case!(
    preserves_entitlement_suspended,
    "entitlement_suspended",
    EntitlementSuspended
);
refusal_case!(preserves_unauthorized, "unauthorized", Unauthorized);
refusal_case!(preserves_unverified_site, "unverified_site", UnverifiedSite);
refusal_case!(
    preserves_rotation_incomplete,
    "rotation_incomplete",
    RotationIncomplete
);
refusal_case!(
    preserves_unclaimed_key_version,
    "unclaimed_key_version",
    UnclaimedKeyVersion
);
refusal_case!(
    preserves_stale_key_version,
    "stale_key_version",
    StaleKeyVersion
);
refusal_case!(preserves_scope_required, "scope_required", ScopeRequired);
refusal_case!(
    preserves_bootstrap_required,
    "bootstrap_required",
    BootstrapRequired
);
refusal_case!(
    preserves_already_bootstrapped,
    "already_bootstrapped",
    AlreadyBootstrapped
);
refusal_case!(
    preserves_stale_submission,
    "stale_submission",
    StaleSubmission
);
refusal_case!(
    preserves_concurrent_write,
    "concurrent_write",
    ConcurrentWrite
);
refusal_case!(
    preserves_github_not_connected,
    "github_not_connected",
    GithubNotConnected
);
refusal_case!(
    preserves_malformed_request,
    "malformed_request",
    MalformedRequest
);
refusal_case!(
    preserves_erasure_ledger_unavailable,
    "erasure_ledger_unavailable",
    ErasureLedgerUnavailable
);
refusal_case!(preserves_not_found, "not_found", NotFound);
refusal_case!(
    preserves_identity_unavailable,
    "identity_unavailable",
    IdentityUnavailable
);
refusal_case!(
    preserves_payload_too_large,
    "payload_too_large",
    PayloadTooLarge
);
refusal_case!(
    preserves_unsupported_media_type,
    "unsupported_media_type",
    UnsupportedMediaType
);
refusal_case!(
    preserves_account_required,
    "account_required",
    AccountRequired
);
refusal_case!(
    preserves_insufficient_scope,
    "insufficient_scope",
    InsufficientScope
);
refusal_case!(
    preserves_token_site_limited,
    "token_site_limited",
    TokenSiteLimited
);
refusal_case!(
    preserves_signed_in_required,
    "signed_in_required",
    SignedInRequired
);
refusal_case!(preserves_site_not_found, "site_not_found", SiteNotFound);
refusal_case!(
    preserves_repository_not_linked,
    "repository_not_linked",
    RepositoryNotLinked
);
refusal_case!(
    preserves_repository_mismatch,
    "repository_mismatch",
    RepositoryMismatch
);
refusal_case!(
    preserves_already_connected,
    "already_connected",
    AlreadyConnected
);
refusal_case!(
    preserves_no_connection_keys,
    "no_connection_keys",
    NoConnectionKeys
);
refusal_case!(
    preserves_rotation_in_progress,
    "rotation_in_progress",
    RotationInProgress
);
refusal_case!(
    preserves_first_scan_pending,
    "first_scan_pending",
    FirstScanPending
);
refusal_case!(
    preserves_request_in_progress,
    "request_in_progress",
    RequestInProgress
);
refusal_case!(
    preserves_idempotency_conflict,
    "idempotency_conflict",
    IdempotencyConflict
);
refusal_case!(
    preserves_idempotency_key_required,
    "idempotency_key_required",
    IdempotencyKeyRequired
);
refusal_case!(
    preserves_secret_already_issued,
    "secret_already_issued",
    SecretAlreadyIssued
);
refusal_case!(
    preserves_restore_in_progress,
    "restore_in_progress",
    RestoreInProgress
);

#[tokio::test]
async fn undocumented_codes_cannot_introduce_server_text_into_errors() {
    // Bug: unrecognized problem codes can launder arbitrary server text into CLI errors.
    let mut wire = fixture("baseline-required");
    wire["body"]["code"] = "unknown_refusal".into();
    wire["body"]["detail"] = "untrusted-fixture".into();
    wire["body"]["request_id"] = "untrusted-fixture".into();
    let (client, captured) = server_wires(vec![wire]).await;
    let error = client
        .connect_baseline("sitecmd_cnx_FIXTURE", &baseline())
        .await
        .unwrap_err();
    assert_eq!(error.code, "request_failed");
    assert!(error.message.is_empty());
    assert!(!format!("{error:?}").contains("untrusted-fixture"));
    captured.await.unwrap();
}

#[tokio::test]
async fn documented_details_are_printable_bounded_and_never_echo_tokens() {
    // Bug: a documented refusal can echo a bearer, terminal controls or unbounded text.
    let detail = format!("\x1b\0\n{}", "é".repeat(600));
    let mut wire = fixture("baseline-required");
    wire["body"]["detail"] = detail.into();
    let (client, captured) = server_wires(vec![wire]).await;
    let error = client
        .connect_baseline("sitecmd_cnx_FIXTURE", &baseline())
        .await
        .unwrap_err();
    assert_eq!(error.message, "é".repeat(500));
    captured.await.unwrap();
    for kind in ["ci", "job", "pat", "cnx"] {
        let secret = format!("sitecmd_{kind}_FIXTURE");
        for detail in [
            format!("Refused {secret}"),
            format!("{} {secret}", "x".repeat(501)),
            secret.replace("sitecmd_", "sitecmd_\0"),
        ] {
            let mut wire = fixture("baseline-required");
            wire["body"]["detail"] = detail.into();
            wire["body"]["request_id"] = secret.clone().into();
            wire["body"]["title"] = secret.clone().into();
            let (client, captured) = server_wires(vec![wire]).await;
            let error = client
                .connect_baseline("sitecmd_cnx_FIXTURE", &baseline())
                .await
                .unwrap_err();
            assert!(
                error.message.is_empty(),
                "a token-shaped detail must be refused"
            );
            assert!(!format!("{error:?}").contains(&secret));
            assert!(error.details.is_none() && error.request_id.is_none());
            captured.await.unwrap();
        }
    }
}

#[tokio::test]
async fn a_success_status_cannot_disguise_a_problem_as_a_poll_answer() {
    // Bug: a 200 problem response can masquerade as an ordinary approval refusal.
    let mut wire = fixture("denied");
    wire["status"] = 200.into();
    let (client, captured) = server_wires(vec![wire]).await;
    let error = client
        .poll_token(&super::tests::authorization().device_code)
        .await
        .unwrap_err();
    assert_eq!(error.code, "malformed_response");
    captured.await.unwrap();
}

#[tokio::test]
async fn a_minted_token_is_retained_when_the_response_crosses_the_local_deadline() {
    // Bug: an approval at the expiry boundary can discard a newly minted live token.
    let (client, captured) = super::tests::server(&["login"]).await;
    let mut authorization = super::tests::authorization();
    authorization.expires_in = 1;
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let answer = wait_for_approval_with_clock(
        &client,
        &authorization,
        |_| Box::pin(async {}),
        || {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                Duration::ZERO
            } else {
                Duration::from_secs(2)
            }
        },
    )
    .await
    .unwrap();
    assert!(matches!(answer, PollAnswer::Login { .. }));
    captured.await.unwrap();
}

#[test]
fn display_fields_reject_insecure_verification_links_and_remove_terminal_controls() {
    // Bug: device-flow display text can introduce insecure links and terminal control sequences.
    let mut body = fixture("issued")["body"].clone();
    body["verification_uri"] = "http://example.com/device".into();
    assert!(serde_json::from_value::<DeviceAuthorization>(body.clone()).is_err());
    body["verification_uri"] = "https://example.com/device".into();
    body["user_code"] = "BCDF-\nGHJK\u{202e}".into();
    let authorization: DeviceAuthorization = serde_json::from_value(body).unwrap();
    assert_eq!(authorization.user_code, "BCDF-GHJK");
    let mut login = fixture("login")["body"].clone();
    login["account_name"] = "Account\n\u{202e} Name".into();
    let answer: PollAnswer = serde_json::from_value(login).unwrap();
    let PollAnswer::Login { account_name, .. } = answer else {
        panic!("expected login");
    };
    assert_eq!(account_name.as_deref(), Some("Account Name"));
}
