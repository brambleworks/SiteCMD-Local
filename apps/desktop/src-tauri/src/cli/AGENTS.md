# Runtime commands

The runtime's `cli` module holds what each `sitecmd` command does. The binary in
`../../crates/cli/` parses arguments and calls these functions; this module reads and writes
the scanned project's .sitecmd folder, talks to the connected service, and prints reports.

## Code map

- `mod.rs`: reading and writing the project's .sitecmd/config.json, the default local store
  path, and `ConnectStop`, which turns a Connect refusal into a command result.
- `scan.rs`, `lane.rs`, `local_redirects.rs`: `sitecmd scan`. `lane.rs` picks the local or hosted
  lane and confines local fetches to loopback.
- `hosted/`: the account, request, polling, and report flow for public sites on the hosted scanner.
- `audit.rs`, `audit_suppressions.rs`, `audit_interrupt.rs`: `sitecmd audit`, its report formats,
  baselines, the suppressions in the project's .sitecmd/config.json, and SIGINT handling.
- `rules.rs`: `sitecmd rules`. `engine.rs`: `sitecmd engine info`.
- `autofix/`: `sitecmd autofix apply`, and `run-job` and `publish-job`, the two halves of a fix job
  inside GitHub Actions. `autofix/github_api.rs` calls api.github.com; `autofix/exit_check.rs`
  checks the text sent to GitHub against the file answers.
- `login.rs`, `login/`, `credential_store.rs`, `credential_store/`: `sitecmd login` and `logout`,
  and per-origin token storage in the keyring or a private file.
- `connect.rs`, `connect_repo.rs`, `connect_seal.rs`: `sitecmd connect`, which writes a site's
  connection secrets into its GitHub repository after a dashboard approval.
- `connected.rs`: `sitecmd connected --dry-run` and `sitecmd gate`. `connected_submit.rs`:
  `sitecmd connected --submit` and `sitecmd deploy`.
- `init.rs`, `fix.rs`, `watch.rs`, `check.rs`: `sitecmd init`, `fix`, `watch`, and `check`.
- `export.rs` and `export/`: the artifacts a full local scan writes to the project's .sitecmd
  folder, including last-scan.json, issues.md, issues.json, and rules.md.
- `impact.rs`, `output.rs`: impact classification and terminal-only suppression details.

## Entry points

`pub` functions called from `../../crates/cli/src/main.rs` and its dispatch files, such as
`scan::run`, `audit::run_audit_with_output`, `autofix::run`, `connected::run_gate`,
`connected_submit::run_submit`, `connected_submit::run_deploy`, `fix::run`, `watch::run`,
`check::run`, and `init::run`.

## How it works

- **Scan.** `lane::Target::resolve` resolves the URL. A local-development origin whose addresses
  are all loopback takes the local lane: the page is fetched through the loopback client and the
  engine module evaluates it. Anything else takes the hosted lane, which needs a signed-in token
  and reads or requests a scan through the connected service. A full local scan outside JSON
  mode writes the .sitecmd artifacts.
- **Audit.** `audit.rs` calls `crate::core::audit`, applies suppressions and baselines, renders
  the chosen format, and reports whether `--fail-on` was crossed.
- **Connected and gate.** The local store in `../db/` builds the payload. `--dry-run` prints the
  exact serialized submission without sending it; `gate` asks the connected service which
  findings are new against the site's baseline.
- **Login.** A device code is approved in the dashboard; the token is stored for that origin.

## Invariants

- Command errors are sanitized; production code here never uses `.map_err(|e| e.to_string())`,
  and never constructs a reqwest client: `/tools/scripts/audit/forbid-adhoc-rust-patterns.sh`.
- Scan artifacts use the shared bounded readers and atomic writer:
  `/tools/scripts/lib/guardrail-sitecmd-artifact-rules.mjs`.
  `fix_refuses_a_linked_scan_cache` in `fix.rs` checks linked reads.
  `artifact_writer_refuses_a_linked_config_directory` and
  `artifact_writer_replaces_the_link_without_changing_its_target` in `export/artifacts.rs`
  check linked writes.
- Local checks reuse fresh caches on the configured origin: the tests
  `fresh_scan_cache_is_reused_for_the_requested_url_and_same_origin_redirect`,
  `cache_for_a_different_url_requires_a_scan`, and `future_scan_timestamp_is_stale` in `check.rs`.
- Autofix brief publication checks the audited location against the project fingerprint key:
  `brief_refuses_a_different_file_for_the_claimed_identity` in `autofix/brief_publish.rs` and
  `missing_export_rejects_the_brief_without_requesting_an_issue_token` in
  `autofix/publish_job_tests.rs`.
- Autofix reports structured outcomes to Connect and keeps diagnostics in the caller's logs:
  `artifact_rejection_sends_structured_result_without_manifest_diagnostics` in
  `autofix/publish_job_tests.rs`.
- Code Scan outputs omit source excerpts and code lines:
  `/tools/scripts/lib/guardrail-code-scan-security-rules.mjs`.
- Autofix uses only the public engine host and protocol APIs:
  `/tools/scripts/lib/guardrail-code-scan-host-boundary.mjs`.
- The dry run renders the exact submission without allocating a sequence: the
  `dry_run_renders_the_exact_submission_without_allocating_a_sequence` test in `connected.rs`.
- `SITECMD_TOKEN` never applies to an origin read from repository configuration:
  `credential_store/tests.rs`.
- Connection exports carry the fingerprint key but no installation token or plaintext site
  metadata: the `export_round_trips_without_a_credential_or_plaintext_metadata` test in
  `../connected_export.rs`.
- Messages that tell the reader to run `sitecmd <name>` name a real subcommand:
  `/tools/scripts/lib/guardrail-cli-surface-rules.mjs`.

## Testing

From `/apps/desktop/src-tauri`, with the stand-in built and the environment from `../../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-runtime cli::
cargo test --locked -p sitecmd-cli
```

Hosted and connected tests use loopback doubles; no account or external network is needed.

## Boundaries

- The connected service: every call goes through `../connected_service.rs`, specified in
  `/docs/engineering/connected-service/connected-protocol-spec.md`.
- GitHub: `connect` and `autofix` call api.github.com, and CI submissions and fix jobs request
  GitHub Actions OIDC tokens. `connect` writes encrypted repository secrets; autofix publication
  sends patches and issues only to the site's own repository.
- `/.github/actions/sitecmd-gate/` runs `sitecmd gate`; `/README.md` documents every command here.

## Guide triggers

- `mod.rs`
- `scan.rs`
- `lane.rs`
- `audit.rs`
- `connected.rs`
- `connected_submit.rs`
- `credential_store.rs`
- `connect.rs`
- `login.rs`
- `export.rs`
- `autofix/mod.rs`
- `hosted/mod.rs`
