//! Provision a repository's connection secrets after a dashboard approval.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::future::BoxFuture;
use sitecmd_protocol::sync::ProjectFingerprintKey;
use zeroize::Zeroizing;

use super::autofix::github_api::GitHubApi;
use super::connect_repo;
use super::connect_seal::seal_for_github;
use super::connected::{build_candidate_snapshot, scan_this_checkout};
use crate::connected_codes::{
    printable, wait_for_approval, BaselineRequest, BaselineStatus, CodeRefusal, CodeRequest,
    PollAnswer, ProvisionedReceipt, SecretsToken,
};
use crate::connected_export::{encrypt_site_connection, ImportedSiteConnection};
use crate::connected_service::{ConnectedServiceClient, ConnectedServiceError};
use crate::db::Database;

const ADDRESS: &str = "The address must be the site's https address, such as https://example.com.";
const WRITE_REFUSED: &str = "GitHub refused to write the secrets. Check that the SiteCMD app may manage this repository's secrets, then run the same command again.";
const DENIED: &str = "The request was denied in SiteCMD. Nothing was saved.";
const EXPIRED: &str =
    "The code expired before it was approved. Run the command again for a new code.";

/// Setup attaches to a dashboard-created, verified site without persisting secrets locally.
pub struct ConnectArgs {
    pub url: String,
    pub repository: Option<String>,
    pub rotate: bool,
    pub connect_origin: Option<String>,
    pub path: Option<PathBuf>,
}

/// Use one origin key for the temporary audit and its eventual snapshot.
pub fn normalized_origin(url: &str) -> Result<String, String> {
    let url = url::Url::parse(url).map_err(|_| ADDRESS)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(ADDRESS.into());
    }
    let host = url.host_str().ok_or(ADDRESS)?;
    Ok(format!("https://{}", host.to_lowercase()))
}

// Command text controls are rejected independently of parsed URL components.
fn validated_site_origin(value: &str) -> Result<String, String> {
    if value.chars().any(char::is_control) {
        return Err(ADDRESS.into());
    }
    normalized_origin(value)
}

/// Denial and expiry are terminal answers; setup and transport failures exit 2.
pub fn failure_exit_code(error: &str) -> u8 {
    if matches!(error, DENIED | EXPIRED) {
        1
    } else {
        2
    }
}

/// Audit, obtain approval, record the baseline and provision the approved repository.
pub async fn run_connect(args: ConnectArgs) -> Result<String, String> {
    // Local input refusals precede even endpoint selection.
    validated_site_origin(&args.url)?;
    let (root, _) = connect_repo::checkout(args.path.as_deref())?;
    connect_repo::repository(&root, args.repository.as_deref())?;
    let (origin, _) = super::login::connect_origin(args.connect_origin.as_deref())?;
    // Both code doors are public; personal credentials never enter this setup flow.
    let client = ConnectedServiceClient::for_endpoint(&origin, None, cfg!(test))
        .map_err(|_| "could not prepare SiteCMD connection setup")?;
    let result = connect_with(
        &args,
        &client,
        &GitHubApi::new(),
        &mut std::io::stderr(),
        |delay| Box::pin(tokio::time::sleep(delay)),
    )
    .await;
    crate::audit_log::record(
        "cli_connect",
        serde_json::json!({}),
        if result.is_ok() { "ok" } else { "error" },
    );
    result
}

async fn connect_with(
    args: &ConnectArgs,
    client: &ConnectedServiceClient,
    github: &GitHubApi,
    stderr: &mut impl Write,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
) -> Result<String, String> {
    let origin = validated_site_origin(&args.url)?;
    let host = origin.trim_start_matches("https://");
    let (root, head) = connect_repo::checkout(args.path.as_deref())?;
    let repository = connect_repo::repository(&root, args.repository.as_deref())?;
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| "could not generate connection keys")?;
    let commitment = ProjectFingerprintKey::from_bytes(*key).commitment();
    let mut connection = Zeroizing::new(ImportedSiteConnection {
        site_id: String::new(),
        environment_scope_key: origin.clone(),
        fingerprint_key_version: 1,
        fingerprint_key: *key,
    });
    let directory = tempfile::tempdir().map_err(|_| "could not prepare the checkout audit")?;
    let db = Database::open(directory.path().join("audit.db"))?;
    notice(stderr, "Auditing this checkout.")?;
    let audit = scan_this_checkout(&db, &connection, Some(&root))?;
    let request = match (
        origin.as_str().try_into(),
        repository.as_str().try_into(),
        commitment.as_str().try_into(),
    ) {
        (Ok(url), Ok(repository), Ok(commitment)) => CodeRequest::Connect {
            url,
            repository,
            commitment,
            rotate: args.rotate,
        },
        _ => return Err("could not request a SiteCMD connection code".into()),
    };
    let authorization = client
        .request_code(&request)
        .await
        .map_err(|_| "could not request a SiteCMD connection code")?;
    let heading = if args.rotate {
        format!(
            "To replace {host}'s connection keys, open {} and enter this code:",
            authorization.verification_uri
        )
    } else {
        format!(
            "To connect {repository} to {host}, open {} and enter this code:",
            authorization.verification_uri
        )
    };
    notice(
        stderr,
        &format!(
            "{heading}\n{}\nThe code works for 15 minutes. Waiting for you to approve it.",
            authorization.user_code
        ),
    )?;
    let answer = wait_for_approval(client, &authorization, |delay| {
        Box::pin(tokio::time::sleep(delay))
    })
    .await
    .map_err(|_| "could not wait for SiteCMD connection approval")?;
    let (connection_token, site_url, approved_repository) = match answer {
        PollAnswer::Connect {
            connection_token,
            site_id,
            site_url,
            key_version,
            repository: approved,
        } => {
            connection.fingerprint_key_version = u16::try_from(key_version)
                .ok()
                .filter(|v| *v > 0)
                .ok_or("SiteCMD returned an invalid connection key version")?;
            validated_site_origin(&site_url)
                .map_err(|_| "SiteCMD returned an invalid site address")?;
            if connect_repo::repository_name(&approved).is_none()
                || !approved.eq_ignore_ascii_case(&repository)
                || site_id.is_empty()
            {
                return Err("SiteCMD returned an unexpected connection approval".into());
            }
            connection.site_id = site_id;
            (connection_token, site_url, approved)
        }
        PollAnswer::AccessDenied => return Err(DENIED.into()),
        PollAnswer::ExpiredToken => return Err(EXPIRED.into()),
        _ => return Err("SiteCMD returned an unexpected connection approval".into()),
    };
    let display_repository = printable(&approved_repository, 200);
    // The audit's origin remains its lookup key; Connect's entry URL belongs only in the export.
    let snapshot = build_candidate_snapshot(&db, &connection, &audit, Some(&head))?;
    let body = BaselineRequest {
        schema_version: sitecmd_protocol::sync::SCHEMA_VERSION,
        site_id: connection
            .site_id
            .as_str()
            .try_into()
            .map_err(|_| "SiteCMD returned an unexpected connection approval")?,
        snapshot,
    };
    let receipt = client
        .connect_baseline(&connection_token, &body)
        .await
        .map_err(|error| baseline_refusal(&error, &display_repository))?;
    if receipt.key_version != i64::from(connection.fingerprint_key_version) {
        return Err("SiteCMD returned an unexpected baseline key version".into());
    }
    let baseline_notice = match receipt.status {
        BaselineStatus::Bootstrapped => {
            format!("Sent this checkout's findings as {host}'s first code baseline.")
        }
        BaselineStatus::Applied => "Sent this checkout's findings under the new key.".into(),
    };
    notice(stderr, &baseline_notice)?;
    let token = client
        .connect_secrets_token(&connection_token)
        .await
        .map_err(|error| secrets_refusal(&error, &display_repository))?;
    // Every returned installation token is revoked, including local preparation and GitHub failures.
    let written = write_secrets(github, &token, &approved_repository, &connection, &site_url).await;
    let revoked = github.revoke_installation_token(&token.token).await;
    written?;
    let receipt = record_provisioned(
        client,
        &connection_token,
        revoked,
        &display_repository,
        sleep,
    )
    .await?;
    let final_line = if args.rotate {
        format!("Replaced {host}'s connection keys. The old export and passphrase no longer work.")
    } else {
        match receipt.workflow_state.as_str() {
            "installed" => format!("{display_repository} is connected, and SiteCMD's workflow is in place."),
            "setup_pr_closed" => "The setup pull request was closed without merging. SiteCMD cannot run fixes until its workflow is in place.".into(),
            _ => format!("{display_repository} is connected. SiteCMD's workflow runs once you merge its setup pull request."),
        }
    };
    let pending = if receipt.provisioned {
        ""
    } else {
        "\nSiteCMD could not write SITECMD_CI_TOKEN yet. It tries again on its own."
    };
    Ok(format!("Wrote SITECMD_CONNECTION_EXPORT and SITECMD_CONNECTION_PASSPHRASE to {display_repository}'s Actions secrets.{pending}\n{final_line}"))
}

fn notice(output: &mut impl Write, line: &str) -> Result<(), String> {
    writeln!(output, "{line}")
        .and_then(|_| output.flush())
        .map_err(|_| "could not display SiteCMD connection progress".into())
}

fn baseline_refusal(error: &ConnectedServiceError, repository: &str) -> String {
    let reason = if matches!(
        error.code_refusal(),
        Some(
            CodeRefusal::CodeNotFound
                | CodeRefusal::AuthorizationPending
                | CodeRefusal::SlowDown
                | CodeRefusal::AccessDenied
                | CodeRefusal::ExpiredToken
                | CodeRefusal::BaselineRecorded
                | CodeRefusal::BaselineRequired
                | CodeRefusal::ConnectionSpent
                | CodeRefusal::GithubNotConnected
                | CodeRefusal::StaleKeyVersion
                | CodeRefusal::KeyCommitmentMismatch
                | CodeRefusal::UnclaimedKeyVersion
                | CodeRefusal::RotationIncomplete
        )
    ) {
        printable(&error.message, 500)
    } else {
        String::new()
    };
    if reason.is_empty() {
        return format!("SiteCMD couldn't save this repository's first scan. Nothing was written to {repository}. Try the same command again.");
    }
    format!("SiteCMD couldn't save this repository's first scan: {reason} Nothing was written to {repository}. Run the same command again once that's fixed.")
}

fn secrets_refusal(error: &ConnectedServiceError, repository: &str) -> String {
    match error.code_refusal() {
        Some(CodeRefusal::NotRepositoryAdmin) => format!("Your GitHub account is not an admin of {repository} now, so SiteCMD gave no token for its secrets. An admin of it can run the same command again."),
        Some(CodeRefusal::Unavailable) => "SiteCMD could not reach GitHub. Run the same command again later.".into(),
        _ => setup_refusal(error, repository),
    }
}

fn setup_refusal(error: &ConnectedServiceError, repository: &str) -> String {
    let detail = match error.code_refusal() {
        Some(CodeRefusal::InstallationSuspended) => return format!("The SiteCMD app's access to {repository} is suspended on GitHub. Unsuspend it there, then run the same command again."),
        Some(
            CodeRefusal::CiTokenRefused
                | CodeRefusal::SetupPullRequestRefused
                | CodeRefusal::RepositoryUnlinking
                | CodeRefusal::BaselineRequired
                | CodeRefusal::ConnectionSpent
                | CodeRefusal::GithubNotConnected
        ) => printable(&error.message, 500),
        _ => String::new(),
    };
    if detail.is_empty() {
        format!("SiteCMD couldn't finish connecting {repository}. Run the same command again.")
    } else {
        detail
    }
}

async fn record_provisioned(
    client: &ConnectedServiceClient,
    token: &str,
    revoked: bool,
    repository: &str,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
) -> Result<ProvisionedReceipt, String> {
    let mut attempt = 1;
    loop {
        match client.connect_secrets_provisioned(token, revoked).await {
            Ok(receipt) => return Ok(receipt),
            Err(error) => {
                // allow-inline-duration: Connect's Retry-After header supplies whole protocol seconds.
                let delay = error
                    .retry_after
                    .map(Duration::from_secs)
                    .unwrap_or(crate::constants::CONNECTED_PROVISIONED_RETRY_DELAY);
                if error.status == 503
                    && error.code_refusal() == Some(CodeRefusal::Unavailable)
                    && attempt < crate::constants::CONNECTED_PROVISIONED_MAX_ATTEMPTS
                    && delay <= crate::constants::CONNECTED_PROVISIONED_MAX_RETRY_DELAY
                {
                    attempt += 1;
                    sleep(delay).await;
                } else {
                    return Err(setup_refusal(&error, repository));
                }
            }
        }
    }
}

async fn write_secrets(
    github: &GitHubApi,
    token: &SecretsToken,
    repository: &str,
    connection: &ImportedSiteConnection,
    site_url: &str,
) -> Result<(), String> {
    if !token.repository.eq_ignore_ascii_case(repository) {
        return Err(WRITE_REFUSED.into());
    }
    let mut random = Zeroizing::new([0; 32]);
    getrandom::fill(random.as_mut()).map_err(|_| "could not generate a connection passphrase")?;
    let passphrase = Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice()));
    let export = Zeroizing::new(encrypt_site_connection(
        &connection.site_id,
        site_url,
        connection.fingerprint_key_version,
        connection.fingerprint_key,
        &passphrase,
    )?);
    let result = async {
        let (key_id, public_key) = github
            .repository_public_key(&token.token, repository)
            .await?;
        let sealed_export = seal_for_github(&public_key, export.as_bytes())?;
        let sealed_passphrase = seal_for_github(&public_key, passphrase.as_bytes())?;
        github
            .put_repository_secret(
                &token.token,
                repository,
                "SITECMD_CONNECTION_EXPORT",
                &sealed_export,
                &key_id,
            )
            .await?;
        github
            .put_repository_secret(
                &token.token,
                repository,
                "SITECMD_CONNECTION_PASSPHRASE",
                &sealed_passphrase,
                &key_id,
            )
            .await
    }
    .await;
    result.map_err(|_| WRITE_REFUSED.into())
}

#[cfg(test)]
#[path = "connect_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "connect_fix_tests.rs"]
mod fix_tests;

#[cfg(test)]
#[path = "connect_fix2_tests.rs"]
mod fix2_tests;

#[cfg(test)]
#[path = "connect_fix3_tests.rs"]
mod fix3_tests;

#[cfg(test)]
#[path = "connect_workflow_tests.rs"]
mod workflow_tests;
