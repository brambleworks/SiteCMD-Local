//! Personal-token sign-in and sign-out through a dashboard-approved code.

use std::io::Write;
use std::time::Duration;

use futures_util::future::BoxFuture;

use super::credential_store::{CredentialStore, OriginSource, StoreLocation, StoredToken};
use crate::connected_codes::{wait_for_approval_interruptible, CodeRequest, PollAnswer};
use crate::connected_service::ConnectedServiceClient;
use std::sync::Arc;

mod interrupt;
mod persist;
mod storage;
mod words;
use interrupt::Interrupt;
use storage::{revoke, store_name, LoginStore};

const DENIED: &str = "The request was denied in SiteCMD. Nothing was saved.";
const EXPIRED: &str =
    "The code expired before it was approved. Run the command again for a new code.";
const TOKEN_LIMIT: &str = "Your SiteCMD account already holds the most personal tokens it may. Revoke one on your account's Personal tokens page, then sign in again.";
pub(super) const NO_ORIGIN: &str =
    "No SiteCMD Connect is set. Pass --connect-origin or set SITECMD_CONNECT_ORIGIN.";
const ENVIRONMENT_NOTICE: &str = "SITECMD_TOKEN is set in this shell, and logout leaves that token as it is. Unset the variable, or revoke the token on your account's Personal tokens page.";

/// Optional explicit origin for either authentication command.
pub struct LoginArgs {
    pub connect_origin: Option<String>,
}

/// Resolve a user-selected or build-supplied origin, without reading a repository.
pub fn connect_origin(flag: Option<&str>) -> Result<(String, OriginSource), String> {
    let environment = match std::env::var("SITECMD_CONNECT_ORIGIN") {
        Ok(value) if !value.trim().is_empty() => Some(value),
        Ok(_) => None,
        Err(std::env::VarError::NotPresent) => None,
        Err(_) if flag.is_some() => None,
        Err(_) => return Err("SITECMD_CONNECT_ORIGIN must be a UTF-8 HTTPS origin".into()),
    };
    resolve_origin(
        flag,
        environment.as_deref(),
        option_env!("SITECMD_CONNECTED_ENDPOINT"),
        cfg!(test),
    )
}

fn resolve_origin(
    flag: Option<&str>,
    environment: Option<&str>,
    build: Option<&str>,
    allow_http_loopback: bool,
) -> Result<(String, OriginSource), String> {
    let (value, source) = if let Some(value) = flag {
        (value, OriginSource::Command)
    } else if let Some(value) = environment.filter(|value| !value.trim().is_empty()) {
        (value, OriginSource::Environment)
    } else if let Some(value) = build {
        (value, OriginSource::Build)
    } else {
        return Err(NO_ORIGIN.into());
    };
    let client = ConnectedServiceClient::for_endpoint(value, None, allow_http_loopback)
        .map_err(|_| "SiteCMD Connect must be an HTTPS origin without user information")?;
    Ok((client.origin(), source))
}

/// An empty interruption error exits 130; other errors retain the CLI refusal statuses.
pub fn failure_exit_code(error: &str) -> u8 {
    if error.is_empty() {
        return 130;
    }
    if matches!(error, DENIED | EXPIRED | TOKEN_LIMIT) {
        1
    } else {
        2
    }
}

/// Request approval, persist the minted token, and retire earlier stored tokens.
pub async fn run_login(args: LoginArgs) -> Result<String, String> {
    let (origin, source) = connect_origin(args.connect_origin.as_deref())?;
    let store = Arc::new(CredentialStore::open_for_origin(&origin, source));
    let interrupt = Interrupt::new();
    let _guard = interrupt.listen().await?;
    let result = login_with_interrupt(
        &origin,
        &store,
        &mut std::io::stderr(),
        |delay| Box::pin(tokio::time::sleep(delay)),
        &interrupt,
    )
    .await;
    audit_result("cli_login", &result);
    result
}

/// Revoke persisted tokens and remove local credentials independently of shell overrides.
pub async fn run_logout(args: LoginArgs) -> Result<String, String> {
    let (origin, source) = connect_origin(args.connect_origin.as_deref())?;
    let store = Arc::new(CredentialStore::open_for_origin(&origin, source));
    let result = logout_with(&origin, &store, &mut std::io::stderr()).await;
    audit_result("cli_logout", &result);
    result
}

fn audit_result(operation: &str, result: &Result<String, String>) {
    crate::audit_log::record(
        operation,
        serde_json::json!({}),
        if result.is_ok() { "ok" } else { "error" },
    );
}

#[cfg(test)]
async fn login_with(
    origin: &str,
    store: &impl LoginStore,
    stderr: &mut impl Write,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
) -> Result<String, String> {
    login_with_interrupt(origin, store, stderr, sleep, &Interrupt::new()).await
}

async fn login_with_interrupt(
    origin: &str,
    store: &impl LoginStore,
    stderr: &mut impl Write,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
    interrupt: &Interrupt,
) -> Result<String, String> {
    #[cfg(test)]
    let mut stdout = std::io::sink();
    #[cfg(not(test))]
    let mut stdout = std::io::stdout();
    login_with_output(origin, store, &mut stdout, stderr, sleep, interrupt).await
}

async fn login_with_output(
    origin: &str,
    store: &impl LoginStore,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    sleep: impl Fn(Duration) -> BoxFuture<'static, ()>,
    interrupt: &Interrupt,
) -> Result<String, String> {
    let previous = store
        .tokens()
        .map_err(|_| "could not read all stored SiteCMD credentials")?;
    let client = ConnectedServiceClient::for_endpoint(origin, None, cfg!(test))
        .map_err(|_| "could not prepare SiteCMD sign-in")?;
    let authorization = client
        .request_code(&CodeRequest::Login)
        .await
        .map_err(|_| "could not request a SiteCMD sign-in code")?;
    writeln!(stderr, "To sign in, open {} and enter this code:\n{}\nThe code works for 15 minutes. Waiting for you to approve it.", authorization.verification_uri, authorization.user_code)
        .and_then(|_| stderr.flush())
        .map_err(|_| "could not display the SiteCMD sign-in code")?;
    let answer = wait_for_approval_interruptible(
        &client,
        &authorization,
        |delay| {
            let sleeping = sleep(delay);
            let interrupt = interrupt.clone();
            Box::pin(async move {
                tokio::select! { _ = sleeping => {}, _ = interrupt.cancelled() => {} }
            })
        },
        || interrupt.triggered(),
    )
    .await
    .map_err(|error| {
        if error.is_empty() {
            error
        } else {
            "could not wait for SiteCMD sign-in approval".into()
        }
    })?;
    let (replacement, account) = match answer {
        PollAnswer::Login {
            token,
            token_id,
            account_name,
        } => (
            StoredToken { token, token_id },
            account_name.unwrap_or_else(|| "your SiteCMD account".into()),
        ),
        PollAnswer::AccessDenied => return Err(DENIED.into()),
        PollAnswer::ExpiredToken => return Err(EXPIRED.into()),
        PollAnswer::TokenLimitReached => return Err(TOKEN_LIMIT.into()),
        _ => return Err("SiteCMD returned an unexpected sign-in answer".into()),
    };
    persist::finish_login(
        origin,
        store,
        persist::ApprovedLogin {
            replacement,
            account,
            previous,
        },
        stdout,
        stderr,
        interrupt,
    )
    .await
}

async fn logout_with(
    origin: &str,
    store: &Arc<CredentialStore>,
    stderr: &mut impl Write,
) -> Result<String, String> {
    if std::env::var_os("SITECMD_TOKEN").is_some() {
        writeln!(stderr, "{ENVIRONMENT_NOTICE}")
            .map_err(|_| "could not display SITECMD_TOKEN notice")?;
    }
    let tokens = store
        .tokens()
        .map_err(|_| "could not read all stored SiteCMD credentials")?;
    if tokens.is_empty() {
        return Ok("No SiteCMD sign-in is saved on this computer.".into());
    }
    let locations = store.stored_locations()?;
    let revoked = revoke(origin, &tokens).await;
    store
        .delete()
        .map_err(|_| "could not remove stored SiteCMD credentials")?;
    let name = locations
        .iter()
        .map(store_name)
        .collect::<Vec<_>>()
        .join(" and ");
    if revoked {
        Ok(format!(
            "Signed out. The token is revoked and removed from {name}."
        ))
    } else {
        Err(format!("The token was removed from {name}, but SiteCMD could not revoke it. Revoke it on your account's Personal tokens page."))
    }
}

#[cfg(test)]
#[path = "login/test_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "login/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "login/regression_tests.rs"]
mod regression_tests;

#[cfg(test)]
#[path = "login/interrupt_tests.rs"]
mod interrupt_tests;

#[cfg(test)]
#[path = "login/fix2_tests.rs"]
mod fix2_tests;

#[cfg(test)]
#[path = "login/pre_save_tests.rs"]
mod pre_save_tests;

#[cfg(all(test, unix))]
#[path = "login/force_exit_tests.rs"]
mod force_exit_tests;

#[cfg(all(test, unix))]
#[path = "login/committed_exit_tests.rs"]
mod committed_exit_tests;
