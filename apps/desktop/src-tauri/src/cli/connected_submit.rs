//! Connected-service CI submission and deployment publication.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::connected_ci::{ci_submission_body, DeploymentFacts, PublishOrdering};
use crate::connected_export::{decrypt_site_connection, ImportedSiteConnection};
use crate::connected_service::{CiDeploymentHead, ConnectedServiceClient, ConnectedServiceError};
use crate::db::Database;

use super::connected::{build_candidate_snapshot, read_connection_export, scan_this_checkout};
use super::{settle, ConnectStop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitArgs {
    pub connection_export: PathBuf,
    pub passphrase_env: String,
    pub token_env: String,
    pub db_path: Option<PathBuf>,
    pub project_path: Option<PathBuf>,
    pub deployment: DeploymentFacts,
    /// Render the exact submission and send nothing.
    pub dry_run: bool,
}

/// Deployment-only arguments avoid exposing the project fingerprint key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployArgs {
    pub site_id: Option<String>,
    pub connection_export: Option<PathBuf>,
    pub passphrase_env: String,
    pub token_env: String,
    pub deployment: DeploymentFacts,
}

/// Explain why a governing submission needs GitHub OIDC and how another runner
/// can submit unattested evidence without silently losing ordering authority.
const GOVERNING_SUBMISSION_NEEDS_OIDC: &str = "\
This CI token governs the site's publish ordering, and the connected service accepts a governing \
submission only from GitHub Actions presenting an OIDC witness. Run this step from the workflow \
the token was minted for, with `permissions: id-token: write`. On any other runner, record the \
publish fact first with `sitecmd deploy --deployment-id <ID> --commit <SHA>`, then re-run this \
submission: once that deployment is the site's head, its code evidence submits as unattested \
presence instead of silently losing the ordering it was about to claim.";

fn read_secret(variable: &str, purpose: &str) -> Result<Zeroizing<String>, String> {
    let value = Zeroizing::new(
        std::env::var(variable).map_err(|_| format!("set {variable} to {purpose}"))?,
    );
    if value.trim().is_empty() {
        return Err(format!("{variable} is empty"));
    }
    Ok(value)
}

fn open_connection(
    export: &std::path::Path,
    passphrase_env: &str,
) -> Result<ImportedSiteConnection, String> {
    let serialized = read_connection_export(export)?;
    let passphrase = read_secret(passphrase_env, "the connection export passphrase")?;
    decrypt_site_connection(&serialized, &passphrase)
}

fn open_database(db_path: Option<PathBuf>) -> Result<Database, String> {
    let db_path = db_path
        .or_else(super::default_desktop_db_path)
        .ok_or_else(|| "could not locate the SiteCMD desktop database".to_string())?;
    crate::app_identity::validate_private_file_target(&db_path)
        .map_err(|error| format!("refused unsafe SiteCMD database path: {error}"))?;
    Database::open(db_path)
}

/// Audit and submit this checkout rather than stale desktop state.
/// Dry runs omit credential-derived publish ordering and print only local data.
pub async fn run_submit(args: SubmitArgs) -> Result<String, String> {
    run_submit_with(args, ConnectedServiceClient::configured).await
}

/// `run_submit` through the client `connect` builds from the CI token, which
/// is what lets the wire tests point it at a local double.
async fn run_submit_with(
    args: SubmitArgs,
    connect: impl Fn(&str) -> Result<ConnectedServiceClient, String>,
) -> Result<String, String> {
    settle(submit(args, connect).await, |notice| notice)
}

async fn submit(
    mut args: SubmitArgs,
    connect: impl Fn(&str) -> Result<ConnectedServiceClient, String>,
) -> Result<String, ConnectStop> {
    args.deployment.validate()?;
    // Fail on a missing send credential before running the project audit.
    let token = if args.dry_run {
        None
    } else {
        Some(read_secret(
            &args.token_env,
            "the CI token minted for this site",
        )?)
    };
    let connection = open_connection(&args.connection_export, &args.passphrase_env)?;
    let client = token
        .as_ref()
        .map(|token| connect(token.trim()))
        .transpose()?;
    let head = if let Some(client) = &client {
        Some(
            client
                .ci_deployment_head(&connection.site_id)
                .await
                .map_err(|error| stop(&error, "submission capability read", &args.token_env))?,
        )
    } else {
        None
    };
    let oidc_token = if let (Some(client), Some(head)) = (&client, &head) {
        client
            .github_actions_oidc_token(head.submission_attestation)
            .await
            .map_err(|error| format!("GitHub OIDC attestation failed: {error}"))?
    } else {
        None
    };
    if let Some(head) = &head {
        apply_submission_publish_ordering(head, oidc_token.is_some(), &mut args.deployment)?;
    }
    args.deployment.validate()?;

    let db = open_database(args.db_path)?;
    let audit_summary = scan_this_checkout(&db, &connection, args.project_path.as_deref())?;
    if let Some(notice) = audit_summary.notice() {
        eprintln!("{notice}");
    }
    let snapshot = build_candidate_snapshot(&db, &connection, Some(&args.deployment.commit_sha))?;
    let findings = snapshot.occurrences.len();
    let basis = snapshot.code_basis.kind;
    let body = ci_submission_body(&connection.site_id, &snapshot, &args.deployment)?;

    let Some(client) = client else {
        // Keep preview wire bytes on stdout and notices on stderr.
        if let Some(notice) = publish_ordering_preview_notice(&args.deployment) {
            eprintln!("{notice}");
        }
        return Ok(body);
    };

    let receipt = client
        .submit_ci_evidence(
            &connection.site_id,
            &body,
            oidc_token.as_ref().map(|token| token.as_str()),
        )
        .await
        .map_err(|error| stop(&error, "submission", &args.token_env).unrecorded(""))?;

    let deployment = if receipt.created_deployment() {
        "recorded"
    } else {
        "already known"
    };
    // Preserve only service-stated fields; invented defaults would assert
    // statuses or sequence positions the response never provided.
    let mut lines = vec![
        format!(
            "Submitted {findings} code finding(s) for deployment {} ({}).",
            args.deployment.provider_deployment_id, args.deployment.commit_sha,
        ),
        format!("  basis: {}", basis_label(basis)),
        format!("  deployment: {deployment}"),
        format!(
            "  service status: {}",
            receipt.status.as_deref().unwrap_or("not stated")
        ),
    ];
    if let Some(event_sequence) = receipt.event_sequence {
        lines.push(format!("  site event sequence: {event_sequence}"));
    }
    Ok(lines.join("\n"))
}

/// Explain credential-derived ordering omitted from an otherwise exact preview.
/// Explicit ordering flags make the notice unnecessary.
fn publish_ordering_preview_notice(deployment: &DeploymentFacts) -> Option<&'static str> {
    if deployment.published || deployment.ordering.is_some() {
        return None;
    }
    Some(
        "Note: these are the bytes before server-derived ordering. A preview holds no credential, \
         so it cannot read this site's deployment head. A live run by a credential that governs \
         the site's publishing workflow reads that head and adds `published: true` plus an \
         `ordering` block (`kind`, `authority_id`, `epoch`, and exactly one of `publish_sequence` \
         or `predecessor_deployment_id`). Supply the explicit ordering flags to preview those \
         members exactly.",
    )
}

/// Tell the service a deployment happened, with no scan attached.
pub async fn run_deploy(args: DeployArgs) -> Result<String, String> {
    run_deploy_with(args, ConnectedServiceClient::configured).await
}

/// `run_deploy` through the client `connect` builds from the CI token, which
/// is what lets the wire tests point it at a local double.
async fn run_deploy_with(
    args: DeployArgs,
    connect: impl Fn(&str) -> Result<ConnectedServiceClient, String>,
) -> Result<String, String> {
    settle(deploy(args, connect).await, |notice| notice)
}

async fn deploy(
    mut args: DeployArgs,
    connect: impl Fn(&str) -> Result<ConnectedServiceClient, String>,
) -> Result<String, ConnectStop> {
    args.deployment.validate()?;
    let site_id = match (&args.site_id, &args.connection_export) {
        (Some(site_id), _) => site_id.clone(),
        // Cloned rather than moved: the connection zeroizes its fingerprint
        // key on drop, and moving a field out would forfeit that.
        (None, Some(export)) => open_connection(export, &args.passphrase_env)?
            .site_id
            .clone(),
        (None, None) => {
            return Err("name the site with --site, or point at its --connection-export".into())
        }
    };
    let token = read_secret(&args.token_env, "the CI token minted for this site")?;

    let client = connect(token.trim())?;
    apply_current_publish_ordering(&client, &site_id, &mut args.deployment, &args.token_env)
        .await?;
    args.deployment.validate()?;
    let receipt = client
        .record_ci_deployment(&site_id, &args.deployment)
        .await
        .map_err(|error| stop(&error, "deployment", &args.token_env).unrecorded(""))?;

    let outcome = if receipt.created {
        "Recorded"
    } else {
        "Already recorded"
    };
    let currency = if receipt.current {
        "advanced the current head"
    } else {
        "retained as history"
    };
    Ok(format!(
        "{outcome} deployment {} ({}); ordering {}, {currency}.",
        receipt.deployment.provider_deployment_id,
        receipt.deployment.commit_sha,
        receipt.deployment.ordering,
    ))
}

/// Apply publish ordering and reject unattested governing submissions together.
fn apply_submission_publish_ordering(
    head: &CiDeploymentHead,
    attested: bool,
    deployment: &mut DeploymentFacts,
) -> Result<(), String> {
    apply_publish_ordering_from_head(head, deployment)?;
    if deployment.ordering.is_some() && !attested {
        return Err(GOVERNING_SUBMISSION_NEEDS_OIDC.into());
    }
    Ok(())
}

async fn apply_current_publish_ordering(
    client: &ConnectedServiceClient,
    site_id: &str,
    deployment: &mut DeploymentFacts,
    token_env: &str,
) -> Result<(), ConnectStop> {
    if deployment.published || deployment.ordering.is_some() {
        return Ok(());
    }
    let head = client
        .ci_deployment_head(site_id)
        .await
        .map_err(|error| stop(&error, "deployment ordering read", token_env))?;
    Ok(apply_publish_ordering_from_head(&head, deployment)?)
}

fn apply_publish_ordering_from_head(
    head: &CiDeploymentHead,
    deployment: &mut DeploymentFacts,
) -> Result<(), String> {
    if deployment.published || deployment.ordering.is_some() {
        return Ok(());
    }
    let Some(authority) = head.ordering_authority.as_ref() else {
        // Generic CI credentials can still record deployment history and
        // unattested evidence. The service only exposes the publish cursor
        // when this credential's mint-time pins own the selected authority.
        return Ok(());
    };
    if authority.kind != "publish_attestation" {
        return Ok(());
    }
    if authority.current_deployment_id != head.current_deployment_id {
        return Err(
            "the connected service returned contradictory deployment-ordering cursors".into(),
        );
    }
    if head.current_deployment_id.as_deref() == Some(deployment.provider_deployment_id.as_str()) {
        // An idempotent retry needs no new ordering claim. The existing record
        // already carries the accepted promotion fact and remains current.
        return Ok(());
    }
    let epoch = u64::try_from(authority.epoch)
        .map_err(|_| "the connected service returned an invalid ordering epoch".to_string())?;
    if epoch == 0 {
        return Err("the connected service returned an invalid ordering epoch".into());
    }
    let (publish_sequence, predecessor_deployment_id) = match &head.current_deployment_id {
        Some(predecessor) => (None, Some(predecessor.clone())),
        None => {
            let watermark = authority.publish_sequence.ok_or_else(|| {
                "this deployment authority is still behind its activation barrier; select or seed the governing CI workflow in the desktop app first"
                    .to_string()
            })?;
            let watermark = u64::try_from(watermark).map_err(|_| {
                "the connected service returned an invalid publish sequence".to_string()
            })?;
            let next = watermark.checked_add(1).ok_or_else(|| {
                "the connected service's publish sequence is exhausted".to_string()
            })?;
            (Some(next), None)
        }
    };
    deployment.published = true;
    deployment.ordering = Some(PublishOrdering {
        authority_id: authority.authority_id.clone(),
        epoch,
        kind: "publish_sequence".into(),
        predecessor_deployment_id,
        publish_sequence,
    });
    Ok(())
}

fn basis_label(kind: sitecmd_engine::sync::CodeBasisKind) -> &'static str {
    use sitecmd_engine::sync::CodeBasisKind;
    match kind {
        // Named as the desktop's own claim rather than the CI door's attested
        // `exact`: the service assigns provenance on this door, and a clean
        // checkout at the deployed commit is still only a self-report.
        CodeBasisKind::ExactCheckout => "clean checkout of the deployed commit",
        CodeBasisKind::Compatible => "a compatible ancestor of the deployed commit",
        CodeBasisKind::Stale => "older than the deployed commit",
        CodeBasisKind::Unknown => "no known relationship to the deployed commit",
    }
}

/// A refusal as the command's stop. An inactive account is read before the
/// refusal is described, so it never reaches `next_action`.
fn stop(error: &ConnectedServiceError, door: &str, token_env: &str) -> ConnectStop {
    ConnectStop::refused(error, |error| refusal(error, door, token_env))
}

/// Format a refusal without exposing tenant-bearing `details`.
/// Adds CLI-specific recovery guidance to the service message.
fn refusal(error: &ConnectedServiceError, door: &str, token_env: &str) -> String {
    let mut lines = vec![format!(
        "The connected service refused this {door} ({}).",
        error.code
    )];
    if !error.message.is_empty() {
        lines.push(format!("  {}", error.message));
    }
    if let Some(action) = next_action(error, token_env) {
        lines.push(format!("  {action}"));
    }
    if let Some(request_id) = &error.request_id {
        // The one identifier worth carrying into a support conversation, and
        // the service's own handle rather than anything of the tenant's.
        lines.push(format!("  request: {request_id}"));
    }
    lines.join("\n")
}

fn next_action(error: &ConnectedServiceError, token_env: &str) -> Option<String> {
    // The refusals whose next step names a variable or the service's own id
    // are answered before the table of fixed sentences.
    if error.code == "unauthorized" {
        return Some(format!(
            "The CI token in {token_env} is unknown or revoked. Mint a fresh one for this site in the desktop app and replace the secret."
        ));
    }
    // The two refusals that say when to come back name the wait the service's
    // Retry-After gave.
    if error.code == "request_in_progress" {
        let wait = retry_wait(error.retry_after, "in a few minutes");
        return Some(format!(
            "An earlier run of this step with the same payload is still being applied. Nothing new was applied; re-run this step {wait}."
        ));
    }
    if error.code == "rate_limited" {
        let wait = retry_wait(error.retry_after, "after the interval the service named");
        return Some(format!("This site is sending too fast. Retry {wait}."));
    }
    if error.code == "secret_already_issued" {
        let issued = error
            .details
            .as_ref()
            .and_then(|details| details.pointer("/issued/id"))
            .and_then(serde_json::Value::as_str)
            .map(|id| format!(" ({id})"))
            .unwrap_or_default();
        return Some(format!(
            "This request already created a secret{issued}, which is shown only once. Revoke it in the desktop app and create a new one."
        ));
    }
    let action = match error.code.as_str() {
        "entitlement_suspended" => {
            "This subscription is suspended, so the service has stopped watching its sites. Restore it and re-run this step."
        }
        "not_found" => {
            "This token is bound to one site, and it is not the site this command named. Check that the CI token and the connection came from the same site."
        }
        "bootstrap_required" => {
            "Connect this site in the desktop app and let it sync once. CI evidence informs a baseline; it cannot create one."
        }
        "deployment_conflict" => {
            "A deployment identity or causal publish position already carries different facts. Keep one id per deploy and do not reuse a publish sequence or predecessor edge for two deployments."
        }
        "deployment_authority_mismatch" => {
            "This CI token does not own the selected publishing workflow. Export or mint the token for the workflow selected in the desktop app, then replace the pipeline secret."
        }
        "provenance_rejected" => {
            match error
                .details
                .as_ref()
                .and_then(|details| details.get("reason"))
                .and_then(serde_json::Value::as_str)
            {
                Some("repository_mismatch" | "repository_id_mismatch") => {
                    "This job does not match the trusted repository. If the repository was transferred or renamed, mint a new CI token in the desktop app and replace the secret."
                }
                Some("workflow_mismatch") => {
                    "This job does not match the trusted workflow. Run the submission from the workflow chosen when this CI token was created, or mint a new token for this workflow."
                }
                Some("ref_mismatch") => {
                    "This job does not match the trusted ref. Run it from the pinned branch or tag, or mint a new CI token with the intended ref."
                }
                Some("sha_mismatch") => {
                    "The submitted --commit is not the commit GitHub attested. Pass the checked-out GITHUB_SHA."
                }
                Some("token_pins_no_workflow") => {
                    "This CI token has no trusted workflow. Mint a new token in the desktop app with Repository and Trusted workflow filled in."
                }
                _ => {
                    "Check that this job's repository, workflow, ref, and commit match the pins chosen in the desktop app. If the repository was transferred or renamed, mint a new CI token and replace the secret."
                }
            }
        }
        "idempotency_conflict" => {
            "This submission's key was already used for a different request. Nothing was applied. Re-run the step; the key is derived from the payload, so a genuine retry cannot land here."
        }
        "unsupported_media_type" => {
            "The service could not read this request's body type. Install the current CLI release."
        }
        "concurrent_write" => "Another write landed first and nothing was applied. Re-run this step.",
        "stale_key_version" | "key_commitment_mismatch" | "unclaimed_key_version"
        | "rotation_incomplete" => {
            "The connection export in this pipeline was made under a different project fingerprint key. Export a fresh connection from the desktop app and replace the secret."
        }
        "malformed_request" => {
            "The service could not read this payload. That usually means the CLI is older than the service's schema; install the current release."
        }
        "transport_failed" | "response_failed" | "unsafe_endpoint" => {
            "The service was not reached, so nothing was applied. Re-run this step."
        }
        _ => return None,
    };
    Some(action.to_string())
}

/// When to retry: after the whole seconds a Retry-After named, or `fallback`
/// where it named none.
fn retry_wait(seconds: Option<u64>, fallback: &str) -> String {
    match seconds {
        Some(1) => "after 1 second".into(),
        Some(seconds) => format!("after {seconds} seconds"),
        None => fallback.into(),
    }
}

#[cfg(test)]
#[path = "connected_submit_tests.rs"]
mod tests;
