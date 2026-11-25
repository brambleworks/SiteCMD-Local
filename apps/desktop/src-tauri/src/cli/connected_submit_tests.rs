//! Tests for what a pipeline reads when a write is refused, and for the
//! preview that sends nothing.

use super::*;

use crate::cli::test_support::{clean_checkout, exported_site, through, CI_TOKEN, ENVIRONMENT_URL};
use crate::connected_service::deployment_ordering::CiSubmissionAttestation;
use crate::connected_service::deployment_ordering::ConnectedOrderingAuthority;
use crate::connected_service::test_double::{
    request_line, respond_in_sequence, ACCOUNT_INACTIVE_PROBLEM, ENTITLEMENT_SUSPENDED_PROBLEM,
};
use crate::connected_service::{ACCOUNT_INACTIVE_NOTICE, ACCOUNT_INACTIVE_RESULT_NOTICE};
use crate::db::Database;
use sitecmd_protocol::sync::ProjectFingerprintKey;

const SITE_ID: &str = "site_cli_submit";

// A variable this suite never sets, so "the send stopped at the missing
// credential" is a fact about the code path rather than about the machine.
const UNSET_TOKEN_ENV: &str = "SITECMD_CI_TOKEN_FOR_TEST";
const MISSING_EXPORT: &str = "/nonexistent/connection.json";

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn error(code: &str, message: &str) -> ConnectedServiceError {
    ConnectedServiceError {
        status: 409,
        code: code.into(),
        message: message.into(),
        request_id: Some("req_9f2".parse().expect("fixture identifier")),
        details: None,
        retry_after: None,
    }
}

fn facts() -> DeploymentFacts {
    DeploymentFacts {
        provider_deployment_id: "run-42".parse().expect("fixture identifier"),
        commit_sha: "c0ffee1".parse().expect("fixture identifier"),
        git_ref: None,
        target: None,
        previous_sha: None,
        provider_created_at: None,
        published: false,
        ordering: None,
    }
}

fn deployment_head(current: Option<&str>) -> CiDeploymentHead {
    CiDeploymentHead {
        current_deployment_id: current.map(str::to_string),
        submission_attestation: CiSubmissionAttestation::GithubOidc,
        ordering_authority: Some(ConnectedOrderingAuthority {
            authority_id: "github:1296269:authority"
                .parse()
                .expect("fixture identifier"),
            current_deployment_id: current.map(str::to_string),
            epoch: 3,
            kind: "publish_attestation".parse().expect("fixture identifier"),
            publish_sequence: Some(7),
        }),
    }
}

fn submit_args() -> SubmitArgs {
    SubmitArgs {
        connection_export: PathBuf::from(MISSING_EXPORT),
        passphrase_env: "SITECMD_CONNECTION_PASSPHRASE"
            .parse()
            .expect("fixture identifier"),
        token_env: UNSET_TOKEN_ENV.parse().expect("fixture identifier"),
        db_path: None,
        project_path: None,
        deployment: facts(),
        dry_run: true,
    }
}

#[test]
fn a_refusal_names_the_code_the_reason_and_the_next_action() {
    // N8: baseline setup remediation must name the dashboard after desktop setup was removed.
    let rendered = refusal(
        &error(
            "bootstrap_required",
            "This site has no baseline yet; CI evidence has nothing to inform.",
        ),
        "submission",
        "SITECMD_CI_TOKEN",
    );

    assert!(rendered.contains("bootstrap_required"), "{rendered}");
    assert!(rendered.contains("no baseline yet"), "{rendered}");
    assert!(rendered.contains("SiteCMD dashboard"), "{rendered}");
    assert!(rendered.contains("req_9f2"), "{rendered}");
}

#[test]
fn a_refusal_carries_neither_the_token_nor_the_tenant_content_it_was_handed() {
    let leaky = ConnectedServiceError {
        status: 409,
        code: "deployment_conflict".parse().expect("fixture identifier"),
        message: "This provider deployment identity already exists with different immutable facts."
            .into(),
        request_id: Some("req_9f2".parse().expect("fixture identifier")),
        details: Some(Box::new(serde_json::json!({
            "existing": {
                "commit_sha": "deadbeefcafe",
                "ref": "refs/heads/customer-secret-branch",
                "target": "customer-production"
            }
        }))),
        retry_after: None,
    };

    let rendered = refusal(&leaky, "submission", "SITECMD_CI_TOKEN");

    assert!(!rendered.contains(CI_TOKEN), "{rendered}");
    assert!(!rendered.contains("sitecmd_ci_"), "{rendered}");
    assert!(!rendered.contains("customer-secret-branch"), "{rendered}");
    assert!(!rendered.contains("customer-production"), "{rendered}");
    assert!(!rendered.contains("deadbeefcafe"), "{rendered}");
    // Still actionable despite carrying none of it.
    assert!(rendered.contains("one id per deploy"), "{rendered}");
}

#[test]
fn an_unknown_refusal_still_prints_the_services_own_words() {
    let rendered = refusal(
        &error("some_future_code", "Something this build has not learned."),
        "deployment",
        "SITECMD_CI_TOKEN",
    );
    assert!(rendered.contains("some_future_code"), "{rendered}");
    assert!(rendered.contains("has not learned"), "{rendered}");
}

#[test]
fn in_progress_issued_secret_and_media_type_refusals_name_a_next_action() {
    for code in [
        "request_in_progress",
        "secret_already_issued",
        "unsupported_media_type",
    ] {
        let action = next_action(&error(code, "refused"), "SITECMD_CI_TOKEN");
        assert!(
            action
                .as_deref()
                .is_some_and(|sentence| !sentence.is_empty()),
            "{code} has no next action"
        );
    }
}

#[test]
fn fingerprint_key_refusals_point_to_sitecmd_connect() {
    // Fingerprint-key recovery needs the site URL and writes both secrets.
    for code in [
        "stale_key_version",
        "key_commitment_mismatch",
        "unclaimed_key_version",
        "rotation_incomplete",
    ] {
        let action = next_action(&error(code, "refused"), UNSET_TOKEN_ENV);
        assert_eq!(
            action.as_deref(),
            Some(
                "The connection export in this pipeline was made under a different project fingerprint key. From the repository checkout, run `sitecmd connect <url>` with the site's URL. To replace the keys for an existing connection, run `sitecmd connect <url> --rotate`. After approval, SiteCMD writes SITECMD_CONNECTION_EXPORT and SITECMD_CONNECTION_PASSPHRASE to the repository's GitHub Actions secrets."
            ),
            "{code}"
        );
    }
}

#[test]
fn an_in_progress_refusal_names_the_wait_its_retry_after_gave() {
    let mut in_progress = error("request_in_progress", "refused");
    in_progress.retry_after = Some(42);
    let action = next_action(&in_progress, "SITECMD_CI_TOKEN").expect("a next action");
    assert!(
        action.contains("re-run this step after 42 seconds."),
        "{action}"
    );
    assert!(!action.contains("few minutes"), "{action}");

    in_progress.retry_after = Some(1);
    let action = next_action(&in_progress, "SITECMD_CI_TOKEN").expect("a next action");
    assert!(action.contains("after 1 second."), "{action}");

    // No header: the order of a lease, which is what the service holds.
    let bare = next_action(&error("request_in_progress", "refused"), "SITECMD_CI_TOKEN")
        .expect("a next action");
    assert!(
        bare.contains("re-run this step in a few minutes."),
        "{bare}"
    );
}

#[test]
fn a_throttled_refusal_names_the_wait_its_retry_after_gave() {
    let mut throttled = error("rate_limited", "refused");
    throttled.retry_after = Some(30);
    let action = next_action(&throttled, "SITECMD_CI_TOKEN").expect("a next action");
    assert!(action.contains("Retry after 30 seconds."), "{action}");
}

#[test]
fn an_already_issued_secret_says_where_to_revoke_it_and_names_it() {
    let mut issued = error("secret_already_issued", "refused");
    issued.details = Some(Box::new(serde_json::json!({
        "code": "secret_already_issued",
        "issued": { "kind": "ci_token", "id": "cit_0123456789abcdef" }
    })));
    let action = next_action(&issued, "SITECMD_CI_TOKEN").expect("a next action");
    assert!(action.contains("SiteCMD dashboard"), "{action}");
    assert!(action.contains("cit_0123456789abcdef"), "{action}");

    let unnamed = next_action(
        &error("secret_already_issued", "refused"),
        "SITECMD_CI_TOKEN",
    )
    .expect("a next action");
    assert!(unnamed.contains("SiteCMD dashboard"), "{unnamed}");
}

#[test]
fn a_rejected_credential_points_at_the_variable_that_holds_it() {
    let rendered = refusal(
        &error("unauthorized", "This request carried no credential."),
        "submission",
        "ACME_SITECMD_TOKEN",
    );
    assert!(rendered.contains("ACME_SITECMD_TOKEN"), "{rendered}");
}

#[test]
fn an_oidc_pin_refusal_tells_the_operator_what_to_check() {
    let rendered = refusal(
        &error(
            "provenance_rejected",
            "The presented OIDC token does not establish the pinned provenance.",
        ),
        "submission",
        "SITECMD_CI_TOKEN",
    );
    assert!(
        rendered.contains("repository, workflow, ref, and commit"),
        "{rendered}"
    );
    assert!(rendered.contains("mint a new CI token"), "{rendered}");

    let mut ref_mismatch = error(
        "provenance_rejected",
        "The presented OIDC token does not establish the pinned provenance.",
    );
    ref_mismatch.details = Some(Box::new(serde_json::json!({ "reason": "ref_mismatch" })));
    let rendered = refusal(&ref_mismatch, "submission", "SITECMD_CI_TOKEN");
    assert!(rendered.contains("trusted ref"), "{rendered}");
}

#[test]
fn deployment_facts_are_checked_before_anything_is_opened() {
    // I4: malformed flags must fail before any connection file is opened.
    let error = crate::deployment_input::DeploymentInput {
        provider_deployment_id: "run-42".into(),
        commit_sha: "not-a-sha".into(),
        ..Default::default()
    }
    .finish()
    .expect_err("invalid SHA is rejected at flag entry");
    assert_eq!(
        error,
        "--commit must be a commit SHA of 7 to 64 lowercase hex digits"
    );
}

#[test]
fn a_deploy_without_a_site_says_which_flags_name_one() {
    let error = block_on(run_deploy(DeployArgs {
        site_id: None,
        connection_export: None,
        passphrase_env: "SITECMD_CONNECTION_PASSPHRASE"
            .parse()
            .expect("fixture identifier"),
        token_env: UNSET_TOKEN_ENV.parse().expect("fixture identifier"),
        deployment: facts(),
    }))
    .expect_err("no site");
    assert!(error.contains("--site"), "{error}");
    assert!(error.contains("--connection-export"), "{error}");
}

#[test]
fn the_first_ci_publish_advances_the_authoritys_seeded_sequence() {
    let mut deployment = facts();

    apply_publish_ordering_from_head(&deployment_head(None), &mut deployment)
        .expect("publish ordering");

    assert!(deployment.published);
    assert_eq!(
        deployment.ordering,
        Some(PublishOrdering {
            authority_id: "github:1296269:authority"
                .parse()
                .expect("fixture identifier"),
            epoch: 3,
            kind: "publish_sequence".parse().expect("fixture identifier"),
            predecessor_deployment_id: None,
            publish_sequence: Some(8),
        })
    );
}

#[test]
fn a_later_ci_publish_names_the_exact_current_deployment_as_predecessor() {
    let mut deployment = facts();

    apply_publish_ordering_from_head(&deployment_head(Some("run-41")), &mut deployment)
        .expect("publish ordering");

    let ordering = deployment.ordering.expect("ordering");
    assert_eq!(
        ordering.predecessor_deployment_id.as_deref(),
        Some("run-41")
    );
    assert_eq!(ordering.publish_sequence, None);
}

#[test]
fn retrying_the_current_deployment_does_not_invent_a_second_publish_fact() {
    let mut deployment = facts();

    apply_publish_ordering_from_head(&deployment_head(Some("run-42")), &mut deployment)
        .expect("idempotent retry");

    assert!(!deployment.published);
    assert!(deployment.ordering.is_none());
}

#[test]
fn a_credential_without_the_selected_authority_records_history_without_failing() {
    let mut deployment = facts();
    let no_authority = CiDeploymentHead {
        current_deployment_id: Some("provider-run-41".parse().expect("fixture identifier")),
        submission_attestation: CiSubmissionAttestation::Unattested,
        ordering_authority: None,
    };

    apply_publish_ordering_from_head(&no_authority, &mut deployment)
        .expect("generic CI remains history-grade");

    assert!(!deployment.published);
    assert!(deployment.ordering.is_none());
}

#[test]
fn a_governing_submission_outside_github_actions_is_refused_rather_than_downgraded() {
    let mut deployment = facts();

    let error = apply_submission_publish_ordering(&deployment_head(None), false, &mut deployment)
        .expect_err("a governing submission needs the witness");

    assert!(error.contains("GitHub Actions"), "{error}");
    assert!(error.contains("id-token: write"), "{error}");
    // The way out, and a real one: the deployments door accepts this
    // credential's publish claim unattested.
    assert!(error.contains("sitecmd deploy"), "{error}");
}

#[test]
fn a_governing_submission_inside_github_actions_claims_its_ordering() {
    let mut deployment = facts();

    apply_submission_publish_ordering(&deployment_head(None), true, &mut deployment)
        .expect("an attested governing submission");

    assert!(deployment.published);
    assert_eq!(
        deployment.ordering.expect("ordering").publish_sequence,
        Some(8)
    );
}

#[test]
fn a_generic_credential_off_github_still_submits_unattested_evidence() {
    // Nothing to claim, so nothing to refuse. Generic CI is permanently
    // non-governing, and presence evidence from it is the lane it belongs in.
    let mut deployment = facts();
    let no_authority = CiDeploymentHead {
        current_deployment_id: Some("provider-run-41".parse().expect("fixture identifier")),
        submission_attestation: CiSubmissionAttestation::Unattested,
        ordering_authority: None,
    };

    apply_submission_publish_ordering(&no_authority, false, &mut deployment)
        .expect("generic CI remains history-grade without failing");

    assert!(!deployment.published);
    assert!(deployment.ordering.is_none());
}

#[test]
fn submitting_evidence_for_the_current_head_needs_no_witness() {
    let mut deployment = facts();

    apply_submission_publish_ordering(&deployment_head(Some("run-42")), false, &mut deployment)
        .expect("evidence for the deployment already current");

    assert!(!deployment.published);
    assert!(deployment.ordering.is_none());
}

#[test]
fn the_preview_names_the_ordering_members_a_live_governing_run_would_add() {
    let notice = publish_ordering_preview_notice(&facts()).expect("a preview without ordering");

    assert!(notice.contains("published"), "{notice}");
    assert!(notice.contains("ordering"), "{notice}");
    assert!(notice.contains("authority_id"), "{notice}");
    assert!(notice.contains("epoch"), "{notice}");
    assert!(notice.contains("publish_sequence"), "{notice}");
    assert!(notice.contains("predecessor_deployment_id"), "{notice}");
}

#[test]
fn a_preview_that_states_its_own_ordering_has_nothing_left_to_disclose() {
    let mut stated = facts();
    apply_publish_ordering_from_head(&deployment_head(None), &mut stated).expect("ordering");

    assert!(publish_ordering_preview_notice(&stated).is_none());
}

#[test]
fn an_unseeded_or_contradictory_cursor_cannot_invent_publish_order() {
    let mut unseeded = deployment_head(None);
    unseeded
        .ordering_authority
        .as_mut()
        .expect("authority")
        .publish_sequence = None;
    let error =
        apply_publish_ordering_from_head(&unseeded, &mut facts()).expect_err("activation barrier");
    assert!(error.contains("activation barrier"), "{error}");

    let mut contradictory = deployment_head(Some("run-41"));
    contradictory
        .ordering_authority
        .as_mut()
        .expect("authority")
        .current_deployment_id = Some("run-40".parse().expect("fixture identifier"));
    let error = apply_publish_ordering_from_head(&contradictory, &mut facts())
        .expect_err("contradictory cursor");
    assert!(error.contains("contradictory"), "{error}");
}

#[cfg(unix)]
#[test]
fn connected_checkout_accepts_a_ci_workspace_outside_home() {
    let repo = tempfile::tempdir_in("/tmp").expect("CI workspace");
    let root = repo.path().canonicalize().expect("canonical workspace");
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
        .canonicalize()
        .expect("canonical HOME");
    assert!(!root.starts_with(home), "fixture must live outside HOME");
    std::fs::write(
        root.join("package.json"),
        "{\"name\": \"outside-home-ci-fixture\", \"version\": \"1.0.0\"}\n",
    )
    .expect("project marker");

    let database = tempfile::tempdir().expect("database directory");
    let db = Database::open(database.path().join("sitecmd.db")).expect("database");
    let connection = ImportedSiteConnection {
        site_id: SITE_ID.parse().expect("fixture identifier"),
        environment_scope_key: ENVIRONMENT_URL.parse().expect("fixture identifier"),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN],
    };

    scan_this_checkout(&db, &connection, Some(&root)).expect("connected audit outside HOME");
}

#[test]
fn an_audited_checkout_renders_as_the_ci_submission_the_service_reads() {
    let (_repo, root, head) = clean_checkout();
    let database = tempfile::tempdir().expect("db tempdir");
    let db = Database::open(database.path().join("sitecmd.db")).expect("database");
    let connection = ImportedSiteConnection {
        site_id: SITE_ID.parse().expect("fixture identifier"),
        environment_scope_key: ENVIRONMENT_URL.parse().expect("fixture identifier"),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN],
    };

    let audit = scan_this_checkout(&db, &connection, Some(&root)).expect("audit");
    let snapshot =
        build_candidate_snapshot(&db, &connection, &audit, Some(&head)).expect("snapshot");
    assert_eq!(
        snapshot.code_basis.kind,
        sitecmd_protocol::sync::CodeBasisKind::ExactCheckout
    );
    assert_eq!(snapshot.code_basis.commit_sha, Some(head.parse().unwrap()));

    let deployment = DeploymentFacts {
        commit_sha: head.parse().unwrap(),
        ..facts()
    };
    let rendered =
        crate::connected_ci::ci_submission_body(SITE_ID, &snapshot, &deployment).expect("render");
    let body: serde_json::Value = serde_json::from_str(&rendered).expect("body JSON");
    assert_eq!(body["site_id"], SITE_ID);
    assert_eq!(body["deployment"]["commit_sha"], head.as_str());
    assert_eq!(body["snapshot"]["code_basis"]["kind"], "exact_checkout");
    assert!(body.get("submission_sequence").is_none());

    assert!(!rendered.contains("app.js"), "{rendered}");
    assert!(!rendered.contains(&root.to_string_lossy().to_string()));
}

#[test]
fn a_gate_candidate_claims_no_relationship_to_a_deployment() {
    // The same checkout without a deployment to compare against: a branch is
    // not a deployment, so the basis is unknown and resolves nothing.
    let (_repo, root, _head) = clean_checkout();
    let database = tempfile::tempdir().expect("db tempdir");
    let db = Database::open(database.path().join("sitecmd.db")).expect("database");
    let connection = ImportedSiteConnection {
        site_id: SITE_ID.parse().expect("fixture identifier"),
        environment_scope_key: ENVIRONMENT_URL.parse().expect("fixture identifier"),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN],
    };

    let audit = scan_this_checkout(&db, &connection, Some(&root)).expect("audit");
    let snapshot = build_candidate_snapshot(&db, &connection, &audit, None).expect("snapshot");
    assert_eq!(
        snapshot.code_basis.kind,
        sitecmd_protocol::sync::CodeBasisKind::Unknown
    );
}

#[test]
fn standin_connected_snapshots_exclude_findings_acknowledged_by_project_policy() {
    // A finding acknowledged by local project policy can still reach Connect.
    let (_repo, root, _head) = clean_checkout();
    let route = root.join("app/api/evaluate/fixture-findings.txt");
    std::fs::create_dir_all(route.parent().expect("route parent")).expect("route directory");
    std::fs::write(
        &route,
        "Synthetic finding covered by the checked-in policy.\n",
    )
    .expect("vulnerable route fixture");
    let sitecmd_dir = root.join(".sitecmd");
    std::fs::create_dir_all(&sitecmd_dir).expect("sitecmd directory");
    std::fs::write(
        sitecmd_dir.join("config.json"),
        r#"{
  "version": 1,
  "url": "https://example.com",
  "name": "connected suppression fixture",
  "code_scan": {
    "suppressions": [
      {
        "match": {
          "path": "app/api/evaluate/fixture-findings.txt",
          "rule": "code_scan.standin.rule"
        },
        "reason": "The intentionally vulnerable file is a connected snapshot fixture."
      }
    ]
  }
}"#,
    )
    .expect("suppression config");
    let database = tempfile::tempdir().expect("db tempdir");
    let db = Database::open(database.path().join("sitecmd.db")).expect("database");
    let connection = ImportedSiteConnection {
        site_id: SITE_ID.parse().expect("fixture identifier"),
        environment_scope_key: ENVIRONMENT_URL.parse().expect("fixture identifier"),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN],
    };

    let summary = scan_this_checkout(&db, &connection, Some(&root)).expect("audit");
    let snapshot = build_candidate_snapshot(&db, &connection, &summary, None).expect("snapshot");

    assert_eq!(summary.ignored_findings, 1);
    assert_eq!(summary.stale_suppressions, 0);
    assert_eq!(summary.configured_suppressions, 1);
    let suppressed_location = ProjectFingerprintKey::from_bytes([7; 32])
        .location_hash("standin.rule", "app/api/evaluate/fixture-findings.txt");
    assert!(snapshot
        .occurrences
        .iter()
        .all(|finding| finding.location_hash.as_str() != suppressed_location));
}

#[test]
fn the_preview_never_asks_for_the_credential_that_could_send() {
    let error = block_on(run_submit(SubmitArgs {
        dry_run: true,
        ..submit_args()
    }))
    .expect_err("missing export");
    assert!(error.contains(MISSING_EXPORT), "{error}");
    assert!(!error.contains(UNSET_TOKEN_ENV), "{error}");
}

#[test]
fn the_send_demands_the_credential_before_it_audits_anything() {
    let error = block_on(run_submit(SubmitArgs {
        dry_run: false,
        ..submit_args()
    }))
    .expect_err("missing token");
    assert!(error.contains(UNSET_TOKEN_ENV), "{error}");
    assert!(!error.contains(MISSING_EXPORT), "{error}");
}

// A head that names no ordering authority, so a send claims no publish order
// and asks GitHub for no witness.
const UNATTESTED_HEAD: &str = r#"{"current_deployment_id":null,"submission_attestation":"unattested","ordering_authority":null}"#;

fn live_submit_args(
    workspace: &std::path::Path,
    variable_prefix: &str,
    project_path: Option<PathBuf>,
    commit_sha: &str,
) -> SubmitArgs {
    let (connection_export, passphrase_env, token_env) =
        exported_site(workspace, SITE_ID, variable_prefix);
    SubmitArgs {
        connection_export,
        passphrase_env,
        token_env,
        db_path: Some(workspace.join("sitecmd.db")),
        project_path,
        deployment: DeploymentFacts {
            commit_sha: commit_sha.parse().unwrap(),
            ..facts()
        },
        dry_run: false,
    }
}

fn deploy_args(variable_prefix: &str) -> DeployArgs {
    let token_env = format!("{variable_prefix}_TOKEN");
    std::env::set_var(&token_env, CI_TOKEN);
    DeployArgs {
        site_id: Some(SITE_ID.parse().expect("fixture identifier")),
        connection_export: None,
        passphrase_env: "SITECMD_CONNECTION_PASSPHRASE"
            .parse()
            .expect("fixture identifier"),
        token_env,
        deployment: facts(),
    }
}

#[tokio::test]
async fn a_submission_for_an_inactive_account_exits_zero_with_the_notice() {
    let workspace = tempfile::tempdir().expect("workspace");
    let args = live_submit_args(
        workspace.path(),
        "SITECMD_TEST_SUBMIT_INACTIVE",
        None,
        "c0ffee1",
    );
    let (origin, captured) = respond_in_sequence(vec![(
        ACCOUNT_INACTIVE_PROBLEM
            .parse()
            .expect("fixture identifier"),
        "403 Forbidden",
    )])
    .await;

    let output = run_submit_with(args, through(&origin))
        .await
        .expect("an inactive account is not a failure");

    assert!(output.contains(ACCOUNT_INACTIVE_NOTICE), "{output}");
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        request_line(&requests[0]),
        "GET /v1/sites/site_cli_submit/deployment-head HTTP/1.1"
    );
}

#[tokio::test]
async fn evidence_refused_as_inactive_says_the_result_was_not_recorded() {
    let (_repo, root, head) = clean_checkout();
    let workspace = tempfile::tempdir().expect("workspace");
    let args = live_submit_args(
        workspace.path(),
        "SITECMD_TEST_EVIDENCE_INACTIVE",
        Some(root),
        &head,
    );
    let (origin, captured) = respond_in_sequence(vec![
        (
            UNATTESTED_HEAD.parse().expect("fixture identifier"),
            "200 OK",
        ),
        (
            ACCOUNT_INACTIVE_PROBLEM
                .parse()
                .expect("fixture identifier"),
            "403 Forbidden",
        ),
    ])
    .await;

    let output = run_submit_with(args, through(&origin))
        .await
        .expect("an inactive account is not a failure");

    // The refused request carried the evidence, so "nothing was sent" would
    // be untrue.
    assert!(
        output.starts_with(ACCOUNT_INACTIVE_RESULT_NOTICE),
        "{output}"
    );
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        request_line(&requests[1]),
        "POST /v1/sites/site_cli_submit/sync/ci HTTP/1.1"
    );
}

#[tokio::test]
async fn a_suspended_subscription_still_fails_the_submission() {
    let workspace = tempfile::tempdir().expect("workspace");
    let args = live_submit_args(
        workspace.path(),
        "SITECMD_TEST_SUBMIT_SUSPENDED",
        None,
        "c0ffee1",
    );
    let (origin, _captured) = respond_in_sequence(vec![(
        ENTITLEMENT_SUSPENDED_PROBLEM
            .parse()
            .expect("fixture identifier"),
        "403 Forbidden",
    )])
    .await;

    let error = run_submit_with(args, through(&origin))
        .await
        .expect_err("a suspended subscription still fails the step");

    assert!(error.contains("(entitlement_suspended)"), "{error}");
    assert!(error.contains("This subscription is suspended"), "{error}");
    assert!(!error.contains(ACCOUNT_INACTIVE_NOTICE), "{error}");
}

#[tokio::test]
async fn a_deployment_for_an_inactive_account_exits_zero_with_the_notice() {
    let (origin, captured) = respond_in_sequence(vec![(
        ACCOUNT_INACTIVE_PROBLEM
            .parse()
            .expect("fixture identifier"),
        "403 Forbidden",
    )])
    .await;

    let output = run_deploy_with(
        deploy_args("SITECMD_TEST_DEPLOY_INACTIVE"),
        through(&origin),
    )
    .await
    .expect("an inactive account is not a failure");

    assert!(output.contains(ACCOUNT_INACTIVE_NOTICE), "{output}");
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        request_line(&requests[0]),
        "GET /v1/sites/site_cli_submit/deployment-head HTTP/1.1"
    );
}

#[tokio::test]
async fn a_deployment_record_refused_as_inactive_says_it_was_not_recorded() {
    let (origin, captured) = respond_in_sequence(vec![
        (
            UNATTESTED_HEAD.parse().expect("fixture identifier"),
            "200 OK",
        ),
        (
            ACCOUNT_INACTIVE_PROBLEM
                .parse()
                .expect("fixture identifier"),
            "403 Forbidden",
        ),
    ])
    .await;

    let output = run_deploy_with(
        deploy_args("SITECMD_TEST_RECORD_INACTIVE"),
        through(&origin),
    )
    .await
    .expect("an inactive account is not a failure");

    assert!(
        output.starts_with(ACCOUNT_INACTIVE_RESULT_NOTICE),
        "{output}"
    );
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        request_line(&requests[1]),
        "POST /v1/sites/site_cli_submit/deployments HTTP/1.1"
    );
}

#[tokio::test]
async fn a_published_deployment_refused_at_its_only_door_says_it_was_not_recorded() {
    // Explicit ordering skips the head read, so the record, which carries the
    // deployment, is the first and only door.
    let mut args = deploy_args("SITECMD_TEST_PUBLISHED_INACTIVE");
    apply_publish_ordering_from_head(&deployment_head(None), &mut args.deployment)
        .expect("publish ordering");
    let (origin, captured) = respond_in_sequence(vec![(
        ACCOUNT_INACTIVE_PROBLEM
            .parse()
            .expect("fixture identifier"),
        "403 Forbidden",
    )])
    .await;

    let output = run_deploy_with(args, through(&origin))
        .await
        .expect("an inactive account is not a failure");

    assert!(
        output.starts_with(ACCOUNT_INACTIVE_RESULT_NOTICE),
        "{output}"
    );
    let requests = captured.await.expect("capture");
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(
        request_line(&requests[0]),
        "POST /v1/sites/site_cli_submit/deployments HTTP/1.1"
    );
}

#[tokio::test]
async fn a_suspended_subscription_still_fails_the_deployment() {
    let (origin, _captured) = respond_in_sequence(vec![(
        ENTITLEMENT_SUSPENDED_PROBLEM
            .parse()
            .expect("fixture identifier"),
        "403 Forbidden",
    )])
    .await;

    let error = run_deploy_with(
        deploy_args("SITECMD_TEST_DEPLOY_SUSPENDED"),
        through(&origin),
    )
    .await
    .expect_err("a suspended subscription still fails the step");

    assert!(error.contains("(entitlement_suspended)"), "{error}");
    assert!(error.contains("This subscription is suspended"), "{error}");
}

fn module_observations(
    rule: &str,
    lines: &[u32],
    claimed_count: usize,
) -> Result<Vec<ObservedOccurrence>, String> {
    let (wire, audit) = module_audit(rule, lines, claimed_count);
    submission_observations(&wire, &audit, sitecmd_engine_host::load().unwrap().info())
}

fn module_audit(rule: &str, lines: &[u32], claimed_count: usize) -> (AuditReport, SuppressedAudit) {
    use crate::core::audit::{CodeIssue, CodeScanReport};
    use sitecmd_protocol::engine_abi::AuditIssue;
    use sitecmd_protocol::vocab::{IssueConfidence, Severity};

    let engine = sitecmd_engine_host::load().unwrap();
    let check_id = &engine.info().code_rule(rule).unwrap().check_id;
    let report = CodeScanReport {
        checked_at: "2025-01-01T00:00:00Z".into(),
        framework: None,
        issue_count: claimed_count,
        critical_count: 0,
        high_count: claimed_count,
        medium_count: 0,
        low_count: 0,
        issues: lines
            .iter()
            .map(|line| CodeIssue {
                id: format!("{rule}:src/app.js:{line}"),
                check_id: check_id.clone(),
                category: "security".into(),
                severity: Severity::High,
                title: "Finding title".into(),
                description: "Finding description".into(),
                relative_path: "src/app.js".into(),
                absolute_path: "/checkout/src/app.js".into(),
                line: Some(*line),
                evidence: None,
                why_now: None,
                likely_fix: None,
                confidence: IssueConfidence::Confirmed,
                confidence_reason: None,
                verify_hint: None,
            })
            .collect(),
        skipped_scopes: Default::default(),
    };
    let wire = AuditReport {
        checked_at: report.checked_at.clone(),
        framework: None,
        issue_count: claimed_count,
        critical_count: 0,
        high_count: claimed_count,
        medium_count: 0,
        low_count: 0,
        issues: report
            .issues
            .iter()
            .cloned()
            .map(AuditIssue::try_from)
            .collect::<Result<_, _>>()
            .unwrap(),
        skipped_scopes: Default::default(),
        coverage: Vec::new(),
    };
    let directory = tempfile::tempdir().unwrap();
    let audit =
        crate::cli::audit_suppressions::apply_project_suppressions_at(directory.path(), report, 0)
            .unwrap();
    (wire, audit)
}

#[test]
fn submission_ignores_a_module_count() {
    // A covert channel from module to network
    let observations = module_observations("standin.rule", &[2, 8], 999).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].identity.instance_count, 2);
    assert_eq!(
        observations[0].severity,
        sitecmd_protocol::vocab::Severity::High
    );
    assert_eq!(
        observations[0].confidence,
        sitecmd_protocol::vocab::IssueConfidence::Confirmed
    );
}

#[test]
fn submission_refuses_an_unknown_rule_id() {
    // A covert channel from module to network
    let engine = sitecmd_engine_host::load().unwrap();
    let (mut wire, audit) = module_audit(&engine.info().code_rules[0].id, &[1], 1);
    wire.issues[0].rule_id = "unregistered-fixture-rule".into();
    assert_eq!(
        submission_observations(&wire, &audit, engine.info()).unwrap_err(),
        "The engine reported an unknown Code Scan rule."
    );
}

#[test]
fn standin_location_hash_never_depends_on_line() {
    // A covert channel from module to network
    let key = ProjectFingerprintKey::from_bytes([7; sitecmd_protocol::sync::FINGERPRINT_KEY_LEN]);
    let basis = crate::db::connected_payload::ConnectedCodeBasis {
        commit_sha: None,
        kind: sitecmd_protocol::sync::CodeBasisKind::Unknown,
    };
    let location_hash = |line| {
        let observations = module_observations("standin.rule", &[line], 1).unwrap();
        crate::db::connected_payload::code_occurrence(&observations[0], &key, &basis)
            .unwrap()
            .location_hash
    };
    let original = location_hash(1);
    assert_eq!(original, location_hash(71));
    assert_eq!(
        original.as_str(),
        key.location_hash("standin.rule", "src/app.js")
    );
}

#[test]
fn standin_submission_uses_the_canonical_check_for_the_rule() {
    // A covert channel from module to network
    let (mut wire, audit) = module_audit("standin.rule", &[1], 1);
    wire.issues[0].check_id = "code_scan.untrusted-check".into();
    let observations =
        submission_observations(&wire, &audit, sitecmd_engine_host::load().unwrap().info())
            .unwrap();
    assert_eq!(observations[0].identity.check_id, "code_scan.standin.rule");
}

#[test]
fn submission_counts_a_repeated_finding_once() {
    // A covert channel from module to network
    let observations = module_observations("standin.rule", &[2, 2, 2], 3).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].identity.instance_count, 1);
}

#[test]
fn submission_counts_distinct_same_line_findings() {
    // Merging distinct same-line findings undercounts what the service grades.
    let (mut wire, mut audit) = module_audit("standin.rule", &[1, 1, 1], 3);
    for ((wire, native), dependency) in wire
        .issues
        .iter_mut()
        .zip(&mut audit.report.issues)
        .zip(["one", "two", "three"])
    {
        native.id = format!("standin.rule:{dependency}:src/app.js:1");
        wire.id.clone_from(&native.id);
    }
    let observations =
        submission_observations(&wire, &audit, sitecmd_engine_host::load().unwrap().info())
            .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].identity.instance_count, 3);
}

#[test]
fn submission_refuses_an_inconsistent_retained_index() {
    // A covert channel from module to network
    let engine = sitecmd_engine_host::load().unwrap();
    let mut rules = engine.info().clone();
    let original_rule = rules.code_rules[0].id.clone();
    let (mut wire, mut audit) = module_audit(&original_rule, &[1, 2], 2);
    let mut other_rule = rules.code_rules[0].clone();
    other_rule.id = "another-fixture-rule".into();
    other_rule.check_id = "code_scan.another-fixture-rule".into();
    rules.code_rules.push(other_rule);

    let assert_inconsistent = |wire: &AuditReport, audit: &SuppressedAudit| {
        assert_eq!(
            submission_observations(wire, audit, &rules).unwrap_err(),
            INCONSISTENT_CODE_RULE
        );
    };
    audit.retained_indices.swap(0, 1);
    assert_inconsistent(&wire, &audit);
    audit.retained_indices.swap(0, 1);
    wire.issues[0].rule_id = "another-fixture-rule".into();
    assert_inconsistent(&wire, &audit);
    wire.issues[0].rule_id = original_rule;
    audit.retained_indices[0] = wire.issues.len();
    assert_inconsistent(&wire, &audit);
    audit.retained_indices.pop();
    assert_inconsistent(&wire, &audit);
}
