//! Tests for what a pipeline reads when a write is refused, and for the
//! preview that sends nothing.

use super::*;

use crate::cli::test_support::{clean_checkout, exported_site, through, CI_TOKEN, ENVIRONMENT_URL};
use crate::connected_service::deployment_ordering::CiSubmissionAttestation;
use crate::connected_service::test_double::{
    request_line, respond_in_sequence, ACCOUNT_INACTIVE_PROBLEM, ENTITLEMENT_SUSPENDED_PROBLEM,
};
use crate::connected_service::{
    ConnectedOrderingAuthority, ACCOUNT_INACTIVE_NOTICE, ACCOUNT_INACTIVE_RESULT_NOTICE,
};
use crate::db::{ConnectedSubmissionRequest, Database};
use sitecmd_engine::sync::ProjectFingerprintKey;

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
        request_id: Some("req_9f2".into()),
        details: None,
        retry_after: None,
    }
}

fn facts() -> DeploymentFacts {
    DeploymentFacts {
        provider_deployment_id: "run-42".into(),
        commit_sha: "c0ffee1".into(),
        ..DeploymentFacts::default()
    }
}

fn deployment_head(current: Option<&str>) -> CiDeploymentHead {
    CiDeploymentHead {
        current_deployment_id: current.map(str::to_string),
        submission_attestation: CiSubmissionAttestation::GithubOidc,
        ordering_authority: Some(ConnectedOrderingAuthority {
            authority_id: "github:1296269:authority".into(),
            current_deployment_id: current.map(str::to_string),
            epoch: 3,
            kind: "publish_attestation".into(),
            publish_sequence: Some(7),
        }),
    }
}

fn submit_args() -> SubmitArgs {
    SubmitArgs {
        connection_export: PathBuf::from(MISSING_EXPORT),
        passphrase_env: "SITECMD_CONNECTION_PASSPHRASE".into(),
        token_env: UNSET_TOKEN_ENV.into(),
        db_path: None,
        project_path: None,
        deployment: facts(),
        dry_run: true,
    }
}

#[test]
fn a_refusal_names_the_code_the_reason_and_the_next_action() {
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
    assert!(rendered.contains("desktop app"), "{rendered}");
    assert!(rendered.contains("req_9f2"), "{rendered}");
}

#[test]
fn a_refusal_carries_neither_the_token_nor_the_tenant_content_it_was_handed() {
    let leaky = ConnectedServiceError {
        status: 409,
        code: "deployment_conflict".into(),
        message: "This provider deployment identity already exists with different immutable facts."
            .into(),
        request_id: Some("req_9f2".into()),
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
    assert!(action.contains("desktop app"), "{action}");
    assert!(action.contains("cit_0123456789abcdef"), "{action}");

    let unnamed = next_action(
        &error("secret_already_issued", "refused"),
        "SITECMD_CI_TOKEN",
    )
    .expect("a next action");
    assert!(unnamed.contains("desktop app"), "{unnamed}");
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
    let error = block_on(run_submit(SubmitArgs {
        deployment: DeploymentFacts {
            commit_sha: "not-a-sha".into(),
            ..facts()
        },
        ..submit_args()
    }))
    .expect_err("invalid sha");
    assert!(error.contains("--commit"), "{error}");
}

#[test]
fn a_deploy_without_a_site_says_which_flags_name_one() {
    let error = block_on(run_deploy(DeployArgs {
        site_id: None,
        connection_export: None,
        passphrase_env: "SITECMD_CONNECTION_PASSPHRASE".into(),
        token_env: UNSET_TOKEN_ENV.into(),
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
            authority_id: "github:1296269:authority".into(),
            epoch: 3,
            kind: "publish_sequence".into(),
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
        current_deployment_id: Some("provider-run-41".into()),
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
        current_deployment_id: Some("provider-run-41".into()),
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
        .current_deployment_id = Some("run-40".into());
    let error = apply_publish_ordering_from_head(&contradictory, &mut facts())
        .expect_err("contradictory cursor");
    assert!(error.contains("contradictory"), "{error}");
}

// A database holding one registered environment, which is what the snapshot
// builder resolves a project against.
fn registered_project() -> (tempfile::TempDir, Database, i64) {
    let directory = tempfile::tempdir().expect("tempdir");
    let db = Database::open(directory.path().join("sitecmd.db")).expect("database");
    let project_id = db
        .upsert_project("CLI Submit", directory.path().to_str().expect("path"), None)
        .expect("project");
    db.add_environment(
        project_id,
        ENVIRONMENT_URL,
        "Production",
        "production",
        "test",
    )
    .expect("environment");
    (directory, db, project_id)
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
        site_id: SITE_ID.into(),
        environment_scope_key: ENVIRONMENT_URL.into(),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
    };

    scan_this_checkout(&db, &connection, Some(&root)).expect("connected audit outside HOME");
}

#[test]
fn a_candidate_is_built_without_a_producer_sequence_at_all() {
    let (_directory, db, project_id) = registered_project();
    let snapshot = db
        .build_connected_code_snapshot(
            project_id,
            ENVIRONMENT_URL,
            ConnectedSubmissionRequest {
                site_id: SITE_ID.into(),
                submission_sequence: 0,
                include_groups: true,
                fingerprint_key: Some(ProjectFingerprintKey::from_bytes(
                    [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
                )),
                fingerprint_key_version: 1,
                pending_rotation: None,
                deployed_commit: None,
            },
        )
        .expect("a candidate needs no producer sequence");
    // No code scan has been recorded, so there is no snapshot to return; what
    // matters is that the builder answered rather than refusing the request.
    assert!(snapshot.is_none());
}

#[test]
fn an_audited_checkout_renders_as_the_ci_submission_the_service_reads() {
    let (_repo, _home, root, head) = clean_checkout();
    let database = tempfile::tempdir().expect("db tempdir");
    let db = Database::open(database.path().join("sitecmd.db")).expect("database");
    let connection = ImportedSiteConnection {
        site_id: SITE_ID.into(),
        environment_scope_key: ENVIRONMENT_URL.into(),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
    };

    scan_this_checkout(&db, &connection, Some(&root)).expect("audit");
    let snapshot = build_candidate_snapshot(&db, &connection, Some(&head)).expect("snapshot");
    assert_eq!(
        snapshot.code_basis.kind,
        sitecmd_engine::sync::CodeBasisKind::ExactCheckout
    );
    assert_eq!(snapshot.code_basis.commit_sha, Some(head.clone()));

    let deployment = DeploymentFacts {
        commit_sha: head.clone(),
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
    let (_repo, _home, root, _head) = clean_checkout();
    let database = tempfile::tempdir().expect("db tempdir");
    let db = Database::open(database.path().join("sitecmd.db")).expect("database");
    let connection = ImportedSiteConnection {
        site_id: SITE_ID.into(),
        environment_scope_key: ENVIRONMENT_URL.into(),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
    };

    scan_this_checkout(&db, &connection, Some(&root)).expect("audit");
    let snapshot = build_candidate_snapshot(&db, &connection, None).expect("snapshot");
    assert_eq!(
        snapshot.code_basis.kind,
        sitecmd_engine::sync::CodeBasisKind::Unknown
    );
}

#[test]
fn connected_snapshots_exclude_findings_acknowledged_by_project_policy() {
    let (_repo, _home, root, _head) = clean_checkout();
    let route = root.join("app/api/evaluate/route.ts");
    std::fs::create_dir_all(route.parent().expect("route parent")).expect("route directory");
    std::fs::write(
        &route,
        "export async function POST(request: Request) {\n  const body = await request.json();\n  return Response.json(eval(body.formula));\n}\n",
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
          "path": "app/api/evaluate/route.ts",
          "rule": "code_scan.eval-exec-injection"
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
        site_id: SITE_ID.into(),
        environment_scope_key: ENVIRONMENT_URL.into(),
        fingerprint_key_version: 1,
        fingerprint_key: [7; sitecmd_engine::sync::FINGERPRINT_KEY_LEN],
    };

    let summary = scan_this_checkout(&db, &connection, Some(&root)).expect("audit");
    let snapshot = build_candidate_snapshot(&db, &connection, None).expect("snapshot");

    assert_eq!(summary.ignored_findings, 1);
    assert_eq!(summary.stale_suppressions, 0);
    assert_eq!(summary.configured_suppressions, 1);
    assert!(snapshot
        .occurrences
        .iter()
        .all(|finding| finding.check != "code_scan.eval-exec-injection"));
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
            commit_sha: commit_sha.into(),
            ..facts()
        },
        dry_run: false,
    }
}

fn deploy_args(variable_prefix: &str) -> DeployArgs {
    let token_env = format!("{variable_prefix}_TOKEN");
    std::env::set_var(&token_env, CI_TOKEN);
    DeployArgs {
        site_id: Some(SITE_ID.into()),
        connection_export: None,
        passphrase_env: "SITECMD_CONNECTION_PASSPHRASE".into(),
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
    let (origin, captured) =
        respond_in_sequence(vec![(ACCOUNT_INACTIVE_PROBLEM.into(), "403 Forbidden")]).await;

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
    let (_repo, _home, root, head) = clean_checkout();
    let workspace = tempfile::tempdir().expect("workspace");
    let args = live_submit_args(
        workspace.path(),
        "SITECMD_TEST_EVIDENCE_INACTIVE",
        Some(root),
        &head,
    );
    let (origin, captured) = respond_in_sequence(vec![
        (UNATTESTED_HEAD.into(), "200 OK"),
        (ACCOUNT_INACTIVE_PROBLEM.into(), "403 Forbidden"),
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
        ENTITLEMENT_SUSPENDED_PROBLEM.into(),
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
    let (origin, captured) =
        respond_in_sequence(vec![(ACCOUNT_INACTIVE_PROBLEM.into(), "403 Forbidden")]).await;

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
        (UNATTESTED_HEAD.into(), "200 OK"),
        (ACCOUNT_INACTIVE_PROBLEM.into(), "403 Forbidden"),
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
    let (origin, captured) =
        respond_in_sequence(vec![(ACCOUNT_INACTIVE_PROBLEM.into(), "403 Forbidden")]).await;

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
        ENTITLEMENT_SUSPENDED_PROBLEM.into(),
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
