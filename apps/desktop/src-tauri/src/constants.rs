//! Shared constants for timeouts, limits, and configuration values.

use std::time::Duration;

/// Upper bound for a normal operation on the serialized database worker.
pub const DB_OP_TIMEOUT: Duration = Duration::from_secs(60);

/// Longer bound for backup copy and migration work.
pub const DB_RESTORE_TIMEOUT: Duration = Duration::from_secs(600);

/// Default timeout for external API calls (integrations, registries)
pub const API_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for lightweight API calls (UptimeRobot, Plausible simple endpoints)
pub const API_TIMEOUT_SHORT: Duration = Duration::from_secs(10);

/// Maximum telemetry or crash-report payload accepted from the renderer.
/// Both channels are opt-in and use small JSON/envelope batches; the bound
/// prevents a compromised renderer from turning the narrow egress broker into
/// an unbounded allocator.
pub const TELEMETRY_REQUEST_MAX_BYTES: usize = 1024 * 1024;

/// Maximum response body retained by the telemetry egress broker.
pub const TELEMETRY_RESPONSE_MAX_BYTES: u64 = 1024 * 1024;

/// Maximum bearer-token header accepted by the telemetry egress broker.
pub const TELEMETRY_AUTHORIZATION_MAX_BYTES: usize = 4096;

/// GitHub's OIDC token response is one small JSON object containing a JWT.
/// Bound it independently from website scan bodies so a compromised runner
/// endpoint cannot make a CI process buffer an arbitrary response.
pub const GITHUB_OIDC_RESPONSE_MAX_BYTES: u64 = 64 * 1024;

/// TTL for in-memory API response cache (moka)
pub const CACHE_TTL_SECS: u64 = 1800; // 30 minutes

/// Maximum redirects to follow when checking redirect chains
pub const MAX_REDIRECT_HOPS: usize = 10;

/// Per-check timeout for async checks (HTTP probes, link checking)
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for reading HTTP response body
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum sitemap file size before we truncate (5MB)
pub const MAX_SITEMAP_SIZE: u64 = 5 * 1024 * 1024;

/// SQLite sentinel for secrets held in the OS keychain.
pub const KEYRING_PLACEHOLDER: &str = "***keyring***";

/// Headless-browser delay between axe injection and result polling.
pub const AXE_INJECT_DELAY: Duration = Duration::from_millis(1000);

/// Total budget for axe-core to produce results in the analyzer webview.
pub const AXE_RESULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Interval between axe-core poll attempts. Each attempt is one cheap eval +
/// title read, so polling fast costs little and stops as soon as axe finishes.
pub const AXE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Interval between polls for one chunk of a payload crossing the title
/// bridge. The value already exists on the page, so only the eval round trip
/// remains, and a tight poll keeps a several-hundred-chunk axe report to a
/// second or two.
pub const TITLE_BRIDGE_CHUNK_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Budget for one requested chunk to arrive across the title bridge.
pub const TITLE_BRIDGE_CHUNK_TIMEOUT: Duration = Duration::from_secs(3);

/// Shared privacy and size caps for retained axe evidence.
pub const AXE_NODE_EVIDENCE_LIMIT: usize = AXE_EVIDENCE_CAPS.nodes;
pub const AXE_NODE_TARGET_PARTS_LIMIT: usize = AXE_EVIDENCE_CAPS.target_parts;
pub const AXE_NODE_SELECTOR_MAX_CHARS: usize = AXE_EVIDENCE_CAPS.selector_chars;
pub const AXE_NODE_HTML_MAX_CHARS: usize = AXE_EVIDENCE_CAPS.html_chars;
pub const AXE_FAILURE_SUMMARY_MAX_CHARS: usize = AXE_EVIDENCE_CAPS.failure_summary_chars;

const AXE_EVIDENCE_CAPS: sitecmd_engine::browser::AxeEvidenceCaps =
    sitecmd_engine::browser::AxeEvidenceCaps::DEFAULT;

/// Timeout for Google OAuth callback flow
pub const OAUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Native confirmation deadline, kept below `HUMAN_CONFIRMATION_TIMEOUT_MS` so
/// the backend can report dialog failures before the frontend bridge gives up.
pub const SENSITIVE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(150);

/// A localhost OAuth callback request must send its headers promptly. The
/// overall flow remains open for `OAUTH_TIMEOUT`, so malformed or slow local
/// connections cannot monopolize the listener.
pub const OAUTH_CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// OAuth token and device-flow responses are small JSON documents. Bound them
/// independently from scan bodies so a compromised provider cannot exhaust
/// memory while credentials are being exchanged.
pub const OAUTH_RESPONSE_MAX_BYTES: u64 = 256 * 1024;

/// Batch size for OSV.dev vulnerability API requests
pub const OSV_BATCH_SIZE: usize = 1000;

/// Registry metadata documents are bounded per ecosystem. A scanned
/// repository's manifests choose which packages are looked up, so a hostile
/// manifest must not be able to point the sweep at an unbounded document.
/// npm and PyPI serve every historical version in one document, so their
/// caps are generous; the rest are small per-package records.
pub const NPM_PACKUMENT_MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const PYPI_RESPONSE_MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const PACKAGIST_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const CRATES_IO_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const WORDPRESS_API_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const DRUPAL_API_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const OSV_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const RUBYGEMS_RESPONSE_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const GO_PROXY_RESPONSE_MAX_BYTES: u64 = 1024 * 1024;

/// Integration API documents. Each provider's largest legitimate response
/// (a paged issue list, a 500-row analytics report, a Lighthouse JSON) sits
/// well under its cap; the cap only stops a broken or hostile endpoint from
/// streaming unbounded bytes into a scan.
pub const GITHUB_API_RESPONSE_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const JIRA_API_RESPONSE_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub const CLOUDFLARE_API_RESPONSE_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const BING_API_RESPONSE_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const PLAUSIBLE_RESPONSE_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const UPTIMEROBOT_RESPONSE_MAX_BYTES: u64 = 2 * 1024 * 1024;
/// GA4 and Search Console reports share one cap.
pub const GOOGLE_API_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const PAGESPEED_RESPONSE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Error bodies are surfaced to the user as a message fragment; a few
/// kilobytes is all that fragment can use.
pub const INTEGRATION_ERROR_BODY_MAX_BYTES: u64 = 64 * 1024;

/// License activation, validation, and deactivation responses are one small
/// JSON object each.
pub const LICENSE_API_RESPONSE_MAX_BYTES: u64 = 64 * 1024;

/// Maximum response body size (10 MB). Responses larger than this are rejected.
pub const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum body size for secondary checks that only inspect small text markers.
pub const MAX_PROBE_BODY_SIZE: u64 = 512 * 1024;

/// Sensitive-path probe sample large enough to include delayed file markers.
pub const PROBE_SIGNATURE_SAMPLE_CHARS: usize = 4096;

/// Maximum body size for each stylesheet fetched by the polish scanner.
pub const MAX_STYLESHEET_BODY_SIZE: u64 = 2 * 1024 * 1024;

/// Maximum distinct stylesheet URLs one scan execution keeps in memory. Eight
/// stylesheets are fetched per page, so this holds the shared set of a large
/// multi-page scan without growing with the page count.
pub const MAX_STYLESHEET_CACHE_ENTRIES: usize = 64;

/// Maximum total cached stylesheet bytes held for one scan execution, sized to
/// eight stylesheets at the per-stylesheet body cap.
pub const MAX_STYLESHEET_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum dependency manifest or lockfile size accepted by Updates and Code Scan.
pub const MAX_DEPENDENCY_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Cumulative retained source and configuration text admitted by one Code Scan.
pub const CODE_SCAN_MAX_TEXT_BYTES: u64 = 64_000_000;
/// Maximum redirect destinations considered by local guard recognition.
pub const CODE_SCAN_REDIRECT_MAX_TARGETS: usize = 32;
/// Maximum binding hops followed by local redirect guard recognition.
pub const CODE_SCAN_REDIRECT_MAX_DEPTH: usize = 6;
/// Maximum redirect argument span accepted by local guard recognition.
pub const CODE_SCAN_REDIRECT_ARGUMENT_BYTES: usize = 512;
/// Maximum `.sitecmd/config.json` size accepted by CLI and deep-link imports.
pub const MAX_CLI_CONFIG_BYTES: u64 = 64 * 1024;
/// Maximum `.sitecmd/last-scan.json` size accepted by CLI and deep-link imports.
pub const MAX_CLI_SCAN_BYTES: u64 = MAX_BODY_SIZE;

/// Default HTTP client timeout for integration API calls and registry lookups.
pub const HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Short timeout for secondary HTTP probes in check modules (redirects, exposed files, etc.).
pub const CHECK_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for link-checking probes (slightly longer than CHECK_PROBE_TIMEOUT for slow external hosts).
pub const CHECK_LINK_TIMEOUT: Duration = Duration::from_secs(8);

/// Very short timeout for quick liveness probes (checklist probes, connectivity checks).
pub const PROBE_QUICK_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum in-flight probe requests to one origin (scheme, host, port) from
/// this process, enforced at the probe seam in `checks::probe_adapter`.
///
/// Sized between the failure it prevents and the deadline it has to fit.
///
/// The failure: every probe to an HTTPS origin rides one multiplexed HTTP/2
/// connection, and h2 tears that connection down (GOAWAY ENHANCE_YOUR_CALM,
/// "too_many_data_frames") once enough sub-256-byte DATA frames sit buffered
/// on streams whose bodies nobody has read, which is what a status-only probe
/// leaves behind between its response head arriving and the body being
/// dropped. Measured against the origin that first showed this
/// (visityourteam.com, Next.js behind Cloudflare, 98 open-redirect probes):
/// the sweep answers 98 of 98 at bounds 8, 16, 24, 32 and 48, and only the
/// unbounded shape at 98 trips the guard (83 and 89 of 98 answered). Sixteen
/// therefore sits a factor of three below the highest bound measured safe.
///
/// The deadline: a whole scan's same-origin probe traffic shares this bound
/// inside one `CHECK_TIMEOUT` window, and the largest source is not the
/// open-redirect sweep but internal link probing. `BROKEN_LINK_INTERNAL_SAMPLE`
/// is 100 same-origin links, each a HEAD plus, when the HEAD errors, a GET
/// confirmation, so the worst case is roughly 100 HEAD + 100 GET + 98 sweep
/// probes plus about 30 others: 230 to 330, not 130. Measured on a 120-link
/// loopback page whose origin waits 500 ms before every response, with the
/// sweep running concurrently, the broken-links check finishes in 19.2 s at a
/// bound of 8 (past `CHECK_TIMEOUT`, so the check is skipped as timed out),
/// 13.2 s at 16 and 11.6 s at 24. Above 16 the curve flattens, because the
/// links check's own `BROKEN_LINK_INTERNAL_CONCURRENCY` of 10 becomes the
/// limit; below 16 this seam is the limit and eats the check's deadline.
///
/// Keeping this at or above `BROKEN_LINK_INTERNAL_CONCURRENCY` also keeps the
/// two knobs from fighting: a smaller bound here silently narrows the link
/// check's own concurrency, leaving a setting that no longer does anything.
pub const PROBE_HOST_CONCURRENCY: usize = 16;

/// Holds the paragraph above to something the compiler checks. Below the link
/// check's own concurrency this seam becomes the narrower of the two knobs,
/// which makes that setting dead configuration and moves the check's deadline
/// somewhere its module never mentions.
const _: () = assert!(
    PROBE_HOST_CONCURRENCY >= sitecmd_engine::checks::seo::links::BROKEN_LINK_INTERNAL_CONCURRENCY,
    "PROBE_HOST_CONCURRENCY must not be lower than BROKEN_LINK_INTERNAL_CONCURRENCY"
);

/// Local database inspection must not stall Code Scan during socket setup.
pub const CODE_SCAN_DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Shared outbound User-Agent built from the shipped version.
pub static USER_AGENT: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| sitecmd_engine::agent::user_agent(env!("CARGO_PKG_VERSION")));

/// Maximum entries in the API response cache.
pub const CACHE_MAX_ENTRIES: u64 = 500;

/// Maximum hostnames retained by the process-wide DNS cache.
pub const DNS_CACHE_MAX_ENTRIES: u64 = 1_024;

/// Lifetime of a process-wide cached DNS answer.
pub const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Hard cap on rows returned per get_alerts call; the table is retention-
/// swept but a burst of alerts must still not ship an unbounded IPC payload.
pub const MAX_ALERT_ROWS: u32 = 500;

/// Retention windows for the daily data sweep (db/retention.rs): the stores
/// no scan-retention path covers. Deliberate keeps (documented in
/// db/retention.rs): fix_attempts, report_history, regressions,
/// signal_baselines.
pub const DISMISSED_ALERT_RETENTION_DAYS: i64 = 30;
pub const EVENT_RETENTION_DAYS: i64 = 180;
pub const RESOLVED_SIGNAL_RETENTION_DAYS: i64 = 90;
/// Planned/running scan executions older than this are abandoned crash
/// remnants. Completed history is retained by the execution policy instead.
pub const ABANDONED_SCAN_EXECUTION_RETENTION_DAYS: i64 = 30;
/// Anomaly-detection raw samples; baselines aggregate over much shorter
/// windows, so 90 days of raw history is generous.
pub const SIGNAL_HISTORY_RETENTION_DAYS: i64 = 90;
/// Causal fix-feedback observations feed long-horizon confidence learning;
/// kept a full year before aging out.
pub const CAUSAL_OBSERVATION_RETENTION_DAYS: i64 = 365;
/// Live-score history rows (write-on-change, so volume stays low); a full
/// year keeps the headline trend meaningful, matching the causal-observation
/// horizon.
pub const SCORE_SNAPSHOT_RETENTION_DAYS: i64 = 365;
/// Rows returned per get_score_snapshot_history call: the recent trend the
/// UI plots, not the full retained year.
pub const SCORE_SNAPSHOT_HISTORY_LIMIT: u32 = 90;

/// Interval between data-retention sweeps (also runs once at startup).
pub const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Initial backoff after a supervised scheduler tick panics. Kept short so a
/// sporadic panic doesn't silence the scheduler for a long time. Doubles up to
/// `SUPERVISED_MAX_BACKOFF` on repeated failures.
pub const SUPERVISED_INITIAL_BACKOFF: Duration = Duration::from_millis(50);

/// Cap on the supervisor backoff. Five minutes keeps a hopelessly broken
/// scheduler from spinning the CPU.
pub const SUPERVISED_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Cap for waiting on the analyzer webview's ready state.
pub const WEBVIEW_PAGE_LOAD_WAIT: Duration = Duration::from_secs(8);

/// Cap for waiting on the analyzer webview's private-network rules to compile
/// and install. Same budget as the page-load wait today, but a separate knob:
/// rule compilation and page readiness fail for unrelated reasons, and the
/// analyzer fails closed when this one expires.
pub const WEBVIEW_RULES_INSTALL_WAIT: Duration = Duration::from_secs(8);

/// Interval between analyzer webview polls (readyState probes, CWV title reads).
pub const WEBVIEW_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Settle time after the page load completes before CWV metrics are read, so
/// late LCP candidates and layout shifts still land in the observer buffers.
pub const WEBVIEW_POST_LOAD_SETTLE: Duration = Duration::from_millis(1000);

/// Maximum wait for the CWV read script to publish metrics via the title channel.
pub const WEBVIEW_CWV_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// PageSpeed Insights tolerates slow synchronous reports; allow a long upper
/// bound before giving up on a single PSI fetch.
pub const PSI_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard cap on a project shell command's wall clock. Two minutes keeps a hung
/// build script from blocking the runtime worker pool indefinitely.
pub const PROJECT_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// Hard cap for draining stdout/stderr after a project command exits or is
/// stopped. Descendant processes can inherit output pipes after their parent
/// dies, so the pipe readers need an independent timeout.
pub const PROJECT_COMMAND_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Polling cadence for the integration scheduler tick that walks the
/// adapter set and the immediate-poll channel.
pub const INTEGRATION_SCHEDULER_TICK: Duration = Duration::from_secs(30);

/// Initial delay before the saved-scan scheduler begins running due schedules
/// after process start. Lets app startup settle before triggering scans.
pub const INITIAL_SCHEDULE_DELAY: Duration = Duration::from_secs(30);

/// Polling cadence for the saved-scan scheduler. Re-checks the schedules table
/// for due entries on this interval.
pub const SCHEDULE_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Retry cadence for locally committed connected-scope replacements. The loop
/// also runs immediately at startup.
pub const CONNECTED_SCOPE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// A duplicate action key may return a settled execution for this long after
/// completion. Planned and running executions are always reusable; a terminal
/// key older than this is rejected and can never start new collection.
pub const SCAN_IDEMPOTENCY_RETRY_WINDOW_SECS: i64 = 15 * 60;

/// Polling cadence for the fix-attempt watcher loop that expires stale
/// attempts and settles agent verification requests.
pub const FIX_ATTEMPT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Polling cadence for the agent-request watcher that fulfils MCP start_fix
/// and run_scan rows and refreshes the desktop heartbeat file.
pub const AGENT_REQUEST_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Queued agent requests nobody fulfilled within a day are expired, matching
/// the fix-attempt expiry window.
pub const AGENT_REQUEST_EXPIRY_MS: i64 = 24 * 60 * 60 * 1000;

/// A heartbeat older than this means the desktop app is not running. Any
/// reader of the heartbeat file must apply the same staleness window.
pub const DESKTOP_HEARTBEAT_STALE_MS: i64 = 30 * 1000;

/// Hard cap on a `claude` CLI invocation (MCP registration). The CLI can hang
/// on first-run prompts when stdin is closed, so registration must not block
/// the app indefinitely.
pub const AGENT_CLI_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling cadence while waiting for an agent CLI invocation to exit.
pub const AGENT_CLI_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Hard cap for collecting an agent CLI's stdout/stderr after it exits.
/// Mirrors PROJECT_COMMAND_OUTPUT_DRAIN_TIMEOUT: pipe readers need their own
/// bound because descendants can inherit the pipes.
pub const AGENT_CLI_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// The MCP status probe launches the exact persisted server spec and performs
/// one read-only SQLite query. It should finish quickly even on slower disks.
pub const MCP_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Polling cadence while waiting for the MCP status probe to exit.
pub const MCP_HEALTH_CHECK_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Timeout for a single DNS record lookup (SPF/DMARC/DKIM/MX/CAA/DNSKEY)
/// during the web scan's domain checks.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// Timeout for the RDAP domain-expiry lookup (one bootstrap redirect plus
/// the registry response).
pub const RDAP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

/// How many page assets (images, scripts, stylesheets) the asset sampler
/// fetches to measure real transfer sizes. Bounded so a media-heavy page
/// cannot turn one scan into hundreds of requests.
pub const ASSET_SAMPLE_LIMIT: usize = 30;

/// Concurrent asset-sampler fetches (mirrors the broken-links semaphore).
pub const ASSET_FETCH_CONCURRENCY: usize = 10;

// Intelligence catalog bounds are security limits for untrusted remote data,
// independent of signature verification.

/// Largest catalog pack accepted, compressed bytes on the wire. Sized well
/// above the current corpus so a legitimate release never trips it, and far
/// below anything that could exhaust memory on a small machine.
pub const CATALOG_MAX_PACK_BYTES: usize = 8 * 1024 * 1024;

/// Largest number of guide entries in one pack. The engine ships a bounded
/// number of checks, so a pack claiming vastly more is malformed by
/// construction.
pub const CATALOG_MAX_ENTRIES: usize = 5_000;

/// Largest number of remediation steps in a single guide, and the longest a
/// single step may be. Both bound what one entry can push into the renderer.
pub const CATALOG_MAX_STEPS_PER_GUIDE: usize = 40;
pub const CATALOG_MAX_STEP_CHARS: usize = 2_000;

/// Largest number of framework-specific variants one guide may carry.
pub const CATALOG_MAX_FRAMEWORK_VARIANTS: usize = 32;

/// Longest accepted check id and framework key. Both are matched against
/// engine-generated identifiers, which are far shorter than this.
pub const CATALOG_MAX_KEY_CHARS: usize = 128;

/// How long a catalog pack download may take. Longer than an API call because
/// it transfers megabytes, and still bounded so a stalled CDN cannot hold the
/// update task open indefinitely.
pub const CATALOG_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest activation-service response body accepted. Real responses are a
/// token and a tier, under a kilobyte; the bound only exists so a broken or
/// hostile endpoint cannot stream unbounded bytes into memory.
pub const CATALOG_ACTIVATION_MAX_RESPONSE_BYTES: u64 = 16 * 1024;

/// Catalog refresh cadence after the initial launch-time fetch.
pub const CATALOG_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Delay before the first catalog refresh after launch, keeping the fetch off
/// the startup critical path.
pub const CATALOG_REFRESH_INITIAL_DELAY: Duration = Duration::from_secs(30);

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
                sitecmd_engine::agent::SCANNER_DOCS_URL
            )
        );
        assert!(!user_agent.contains("0.1.0"));
    }
}
