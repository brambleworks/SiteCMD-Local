# Runtime

`sitecmd-runtime` is the CLI's library: command behavior, the Code Scan host, the local SQLite
store, shared HTTP transport and outbound URL policy, credentials, and the client for the
connected service. Its manifest is `../crates/runtime/Cargo.toml`; this folder is its source.

## Code map

- `runtime.rs`: the crate root and module list.
- `cli/`: what each `sitecmd` command does. Guide: `cli/AGENTS.md`.
- `core/`: the Code Scan host, project listing, host facts, fixes, Git, and scan vocabulary.
  Guide: `core/AGENTS.md`.
- `db/`: the SQLite store and its migrations. Guide: `db/AGENTS.md`.
- `connected_service.rs` and `connected_service/`: the bounded, authenticated HTTP client for the
  connected service. `connected_service/request_body.rs` admits only audited request types,
  `connected_service/request_url.rs` builds paths and queries from typed parts,
  `connected_service/problem.rs` reads RFC 9457 refusals, and `connected_service/autofix_jobs.rs`
  and `connected_service/deployment_ordering.rs` hold the fix-job and CI-ordering calls.
- `connected_codes.rs` and `connected_codes/`: device authorization for `sitecmd login` and
  one-use connection setup codes.
- `connected_export.rs`: the encrypted connection export that carries a site's fingerprint key.
- `connected_ci.rs`, `connected_workflow.rs`, `deployment_input.rs`: CI submission, gate, and
  deployment contracts, payload decisions, and deployment flag parsing.
- `http_client.rs` and `http_client/loopback_tls.rs`: the shared pooled clients and bounded body
  readers.
- `network_policy.rs`: SSRF validation for scan targets, redirects, sitemaps, and callbacks.
- `dns_cache.rs`: the bounded process-wide DNS cache behind the clients.
- `audit_log.rs`: the JSONL audit log for sensitive operations.
- `app_identity.rs`: the per-user storage directory and owner-only file writes.
- `constants.rs`: timeouts, limits, and tuning values.
- `time.rs`: the native clock helpers `now_utc` and `now_millis`.
- `updates/`: an OSV vulnerability lookup for installed packages that no command calls.
- `*_tests.rs` and `test_home.rs`: tests and home-directory fixtures.

## Entry points

The binary in `../crates/cli/` calls the `pub` functions in `cli/` modules, such as
`cli::scan::run`, `cli::audit::run_audit_with_output`, and `cli::connected::run_gate`. Other crates
in this repository do not depend on the runtime.

## How it works

Commands that reach the connected service go through `connected_service.rs`, which uses
`http_client::credentialed_service_client`, caps responses, and turns refusals into
`ConnectedServiceError`. `ConnectedServiceClient::configured` uses the endpoint baked in at build
time from `SITECMD_CONNECTED_ENDPOINT` (see `../build_config.rs`); `for_origin` targets an origin
that a command or Action input names.

Personal tokens are stored per origin in the platform keyring or a private file
(`cli/credential_store.rs`). `SITECMD_TOKEN` is used only for an origin named on the command line,
the build's own endpoint, or a matching `SITECMD_CONNECT_ORIGIN`, never for an origin read from
repository configuration.

Local site scans fetch only loopback pages through `http_client::for_local_scan`; public sites
are scanned by the hosted scanner through the connected service.

## Invariants

- Use the shared HTTP clients. `cli/` and `core/` never construct a reqwest client:
  `/tools/scripts/audit/forbid-adhoc-rust-patterns.sh` (marker `allow-ad-hoc-client` for a
  reviewed exception). Other modules follow the same rule by convention, not checked.
- Validate scan targets, redirects, callbacks, webhooks, and sitemap fetches through
  `network_policy::validate_url` with the correct policy (convention, not checked). DNS answers
  are re-checked against the policy, and non-localhost names that resolve to loopback are
  refused: `/tools/scripts/lib/guardrail-code-scan-security-rules.mjs`.
- rustls client configs bind a crypto provider with `builder_with_provider`:
  `/tools/scripts/lib/guardrail-rustls-provider-rules.mjs`.
- `tracing::instrument` never records raw or secret-like fields:
  `/tools/scripts/lib/guardrail-runtime-boundary-rules.mjs`. A `Display` impl never calls an
  instrumented function: `/tools/scripts/lib/guardrail-rust-display-log-rules.mjs`.
- App-data and log directories and database, audit, and secret files stay owner-only, and file
  writes refuse symlinks: `/tools/scripts/lib/guardrail-private-storage-rules.mjs`.
- Connected requests serialize only audited request types; `connected_service/request_body.rs`
  is pinned by digest in `/tools/scripts/lib/guardrail-connected-request-rules.mjs`.
- Dashboard-only Connect calls stay out of this client:
  `/tools/scripts/lib/guardrail-connected-setup-rules.mjs`.
- Durations live in `constants.rs`: `/tools/scripts/lib/guardrail-rust-ratchets.mjs`.
- Log only URL prefixes, domains, and hostnames.
  `/tools/scripts/lib/guardrail-runtime-boundary-rules.mjs` refuses `tracing::instrument`
  fields named `url` or `path`; the log macros themselves are convention, not checked.

## Testing

From `/apps/desktop/src-tauri`, with the stand-in built and the environment from `../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-runtime
cargo test --locked -p sitecmd-runtime network_policy
```

Connected-service tests run against loopback doubles in `connected_service/test_double.rs`; no
account or external network is needed.

## Boundaries

- Depends on `../crates/protocol/` for wire types and `../crates/engine-host/` for the engine
  module.
- The connected service is the server side of `connected_service.rs`; its contract is
  `/docs/engineering/connected-service/connected-protocol-spec.md`.

## Guide triggers

- `../crates/runtime/Cargo.toml`
- `../crates/runtime/build.rs`
- `runtime.rs`
- `connected_service.rs`
- `connected_service/request_body.rs`
- `http_client.rs`
- `network_policy.rs`
- `constants.rs`
- `connected_codes.rs`
- `connected_export.rs`
- `app_identity.rs`
