//! Shared constants for timeouts, limits, and configuration values.

use std::time::Duration;

/// Upper bound for a normal operation on the serialized database worker.
pub const DB_OP_TIMEOUT: Duration = Duration::from_secs(60);

/// Default timeout for external API calls (integrations, registries)
pub const API_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for lightweight API calls (UptimeRobot, Plausible simple endpoints)
pub const API_TIMEOUT_SHORT: Duration = Duration::from_secs(10);

/// Shortest interval between hosted scan status reads.
pub const HOSTED_SCAN_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Longest wait for a hosted scan to finish.
pub const HOSTED_SCAN_WAIT_LIMIT: Duration = Duration::from_secs(20 * 60);

/// GitHub's OIDC token response is one small JSON object containing a JWT.
/// Bound it independently from website scan bodies so a compromised runner
/// endpoint cannot make a CI process buffer an arbitrary response.
pub const GITHUB_OIDC_RESPONSE_MAX_BYTES: u64 = 64 * 1024;

/// Timeout for reading HTTP response body
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Batch size for OSV.dev vulnerability API requests
pub const OSV_BATCH_SIZE: usize = 1000;

pub const OSV_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum response body size (10 MB). Responses larger than this are rejected.
pub const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024;

/// Cumulative retained source and configuration text admitted by one Code Scan.
pub const CODE_SCAN_MAX_TEXT_BYTES: u64 = 64_000_000;
/// Maximum `.sitecmd/config.json` size accepted by CLI and deep-link imports.
pub const MAX_CLI_CONFIG_BYTES: u64 = 64 * 1024;
/// Maximum `.sitecmd/last-scan.json` size accepted by CLI and deep-link imports.
pub const MAX_CLI_SCAN_BYTES: u64 = MAX_BODY_SIZE;

/// Default HTTP client timeout for integration API calls and registry lookups.
pub const HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Local database inspection must not stall Code Scan during socket setup.
pub const CODE_SCAN_DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Shared outbound User-Agent built from the shipped version.
pub static USER_AGENT: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| sitecmd_protocol::agent::user_agent(env!("CARGO_PKG_VERSION")));

/// Maximum hostnames retained by the process-wide DNS cache.
pub const DNS_CACHE_MAX_ENTRIES: u64 = 1_024;

/// Lifetime of a process-wide cached DNS answer.
pub const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// A local git operation in the fix engine (apply, commit, rev-parse).
pub const AUTOFIX_GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// A git operation that talks to GitHub (fetch, push).
pub const AUTOFIX_GIT_NETWORK_TIMEOUT: Duration = Duration::from_secs(300);

/// The package manager install the fix job runs before the build check.
pub const AUTOFIX_INSTALL_TIMEOUT: Duration = Duration::from_secs(600);

/// The repository's own build script in the fix job.
pub const AUTOFIX_BUILD_TIMEOUT: Duration = Duration::from_secs(900);

/// How much of a build or git log the fix engine keeps in memory.
pub const AUTOFIX_MAX_LOG_BYTES: usize = 256 * 1024;

/// The provisioning report remains retryable after an unavailable response.
pub const CONNECTED_PROVISIONED_MAX_ATTEMPTS: usize = 3;
/// Retry delay when Connect supplies no Retry-After header.
pub const CONNECTED_PROVISIONED_RETRY_DELAY: Duration = Duration::from_secs(1);
/// A longer server wait ends this invocation without retrying early.
pub const CONNECTED_PROVISIONED_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A duplicate action key may return a settled execution for this long after
/// completion. Planned and running executions are always reusable; a terminal
/// key older than this is rejected and can never start new collection.
pub const SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS: i64 = 15 * 60;

#[cfg(test)]
mod tests {
    #[test]
    fn the_user_agent_ships_the_real_version_and_points_at_its_documentation() {
        let user_agent = super::USER_AGENT.as_str();
        assert_eq!(
            user_agent,
            format!(
                "SiteCMD/{} (+{})",
                env!("CARGO_PKG_VERSION"),
                sitecmd_protocol::agent::SCANNER_DOCS_URL
            )
        );
        assert!(!user_agent.contains("0.1.0"));
    }
}
