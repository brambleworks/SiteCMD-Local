//! Documented CLI-code refusals and printable, secret-free Connect detail.

use crate::connected_service::{local_error, ConnectedServiceError};
use regex::Regex;
use std::sync::LazyLock;

macro_rules! documented_refusals {
    ($($variant:ident => $code:literal),+ $(,)?) => {
        /// Every refusal documented for CLI code, connection setup and their admission guards.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum CodeRefusal { $($variant),+ }

        impl CodeRefusal {
            pub fn from_code(code: &str) -> Option<Self> {
                match code { $($code => Some(Self::$variant),)+ _ => None }
            }

            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $code,)+ }
            }
        }
    };
}

documented_refusals! {
    AuthorizationPending => "authorization_pending",
    SlowDown => "slow_down",
    AccessDenied => "access_denied",
    ExpiredToken => "expired_token",
    TokenLimitReached => "token_limit_reached",
    BaselineRequired => "baseline_required",
    ConnectionSpent => "connection_spent",
    BaselineRecorded => "baseline_recorded",
    KeyCommitmentMismatch => "key_commitment_mismatch",
    InstallationSuspended => "installation_suspended",
    NotRepositoryAdmin => "not_repository_admin",
    CiTokenRefused => "ci_token_refused",
    SetupPullRequestRefused => "setup_pull_request_refused",
    RepositoryUnlinking => "repository_unlinking",
    Unavailable => "unavailable",
    RateLimited => "rate_limited",
    CodeNotFound => "code_not_found",
    AccountInactive => "account_inactive",
    EntitlementSuspended => "entitlement_suspended",
    Unauthorized => "unauthorized",
    UnverifiedSite => "unverified_site",
    RotationIncomplete => "rotation_incomplete",
    UnclaimedKeyVersion => "unclaimed_key_version",
    StaleKeyVersion => "stale_key_version",
    ScopeRequired => "scope_required",
    BootstrapRequired => "bootstrap_required",
    AlreadyBootstrapped => "already_bootstrapped",
    StaleSubmission => "stale_submission",
    ConcurrentWrite => "concurrent_write",
    GithubNotConnected => "github_not_connected",
    MalformedRequest => "malformed_request",
    ErasureLedgerUnavailable => "erasure_ledger_unavailable",
    NotFound => "not_found",
    IdentityUnavailable => "identity_unavailable",
    PayloadTooLarge => "payload_too_large",
    UnsupportedMediaType => "unsupported_media_type",
    AccountRequired => "account_required",
    InsufficientScope => "insufficient_scope",
    TokenSiteLimited => "token_site_limited",
    SignedInRequired => "signed_in_required",
    SiteNotFound => "site_not_found",
    RepositoryNotLinked => "repository_not_linked",
    RepositoryMismatch => "repository_mismatch",
    AlreadyConnected => "already_connected",
    NoConnectionKeys => "no_connection_keys",
    RotationInProgress => "rotation_in_progress",
    FirstScanPending => "first_scan_pending",
    RequestInProgress => "request_in_progress",
    IdempotencyConflict => "idempotency_conflict",
    IdempotencyKeyRequired => "idempotency_key_required",
    SecretAlreadyIssued => "secret_already_issued",
    RestoreInProgress => "restore_in_progress",
}

impl ConnectedServiceError {
    pub fn code_refusal(&self) -> Option<CodeRefusal> {
        CodeRefusal::from_code(&self.code)
    }
}

static NON_PRINTABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[^\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}]")
        .unwrap_or_else(|_| unreachable!("constant printable-character pattern"))
});
static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:sitecmd_(?:ci|job|pat|cnx)_|gh[opsur]_|github_pat_)[A-Za-z0-9_-]+")
        .unwrap_or_else(|_| unreachable!("constant token pattern"))
});

pub(crate) fn printable(value: &str, limit: usize) -> String {
    let clean = NON_PRINTABLE.replace_all(value, "");
    if TOKEN.is_match(&clean) {
        return String::new();
    }
    clean.chars().take(limit).collect()
}

pub(super) fn code_error(error: ConnectedServiceError) -> ConnectedServiceError {
    let (code, message) = match error.code_refusal() {
        Some(refusal) => (refusal.as_str(), printable(&error.message, 500)),
        None => match error.code.as_str() {
            "transport_failed" => (
                "transport_failed",
                "the connected service could not be reached".into(),
            ),
            "unsafe_endpoint" => (
                "unsafe_endpoint",
                "connected-service endpoint was refused".into(),
            ),
            "response_failed" => (
                "response_failed",
                "the connected service response could not be read".into(),
            ),
            "malformed_response" => (
                "malformed_response",
                "the connected service returned an invalid response".into(),
            ),
            _ => ("request_failed", String::new()),
        },
    };
    ConnectedServiceError {
        status: error.status,
        retry_after: error.retry_after,
        message,
        ..local_error(code, "")
    }
}
