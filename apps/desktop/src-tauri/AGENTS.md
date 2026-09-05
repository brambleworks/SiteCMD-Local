# AGENTS.md

Rust-backend guidance for SiteCMD. Read the root guide for product, repository,
and IPC rules. This directory is a Cargo workspace containing the desktop app,
shared native runtime, portable engine, wasm wrapper, fuzz harness, and standalone CLI.

## Commands

```bash
cargo test
cargo test -- test_name
cargo test --workspace
cargo clippy --workspace
cargo build
pnpm tauri:dev
pnpm guardrails:repo
```

Bare Cargo commands target only the current package unless `--workspace` is
specified. Rust changes require restarting `pnpm tauri:dev`.

## Database

SQLite runs on a dedicated worker thread. All access goes through
`Database::execute` or `Database::execute_mut` with a `move` closure. Never hold
a mutex, connection, or database borrow across `.await`.

Domain methods belong in `db/{domain}.rs` as `impl Database` blocks. Keep
`db/mod.rs` focused on the worker, open path, and shared types.

- Bind SQL values with `params!` or `named_params!`; never interpolate values.
- Reusable row decoding belongs in `db/from_row.rs`.
- Multi-step dependent writes use one `execute_mut` transaction.
- Schema changes use numbered SQL files in `db/migrations/`.
- Migrations and their version records commit atomically.
- Supply integer epoch milliseconds from Rust. Do not add SQL wall-clock
  defaults.
- Update the generated schema snapshot through its self-healing test. MCP tests
  seed from that snapshot.
- Session-aware queries must not filter `session_id IS NULL`.

## Checks and the portable engine

`sitecmd-engine` owns portable verdict semantics:

- shared vocabularies, issue identity, coverage, scope, profiles, and release
  stamps;
- the SiteCMD Score model and golden score corpus;
- all pure synchronous checks;
- probe plans, typed outcomes, and pure verdict functions;
- browser payload and fact schemas;
- connected submission types and capability manifest.

The engine has no clock, filesystem, network, environment, or Tauri dependency.
Callers inject evaluation time and runtime facts. The wasm push gates enforce
the portable boundary.

To add a check:

1. Put portable verdict logic in the engine's category module.
2. Add only transport or runtime adaptation to the desktop check tree.
3. Register it through the category registry.
4. Add the capability-manifest row or dynamic family.
5. Add the local baseline fix guide. Maintainers coordinate private catalog
   content separately before an official release.
6. Update the appropriate golden check, probe, or browser corpus.

The public walkthrough is `../../../../docs/engineering/adding-a-detector.md`;
building and testing a detector requires only this repository.

Do not hardcode aggregate check counts in guidance. Generated product facts and
manifest completeness tests own the inventory.

Async transport uses typed probe plans. The desktop adapter classifies timeout,
body-cap, redirect, and transport outcomes; the hosted adapter must produce the
same facts. External-corpus checks use an explicit answered or unavailable
shape. TLS uses `TlsFacts` and separate expiry, hostname, chain, and protocol
check ids.

Sitemap discovery and sitemap checks share the sitemap-document parser and
candidate policy. Redirect checks share the redirect walker. Never fork their
state machines in a desktop shell.

## Scans and scoring

Web Scan is one engine with category-filter modes. Product-facing frontend modes
remain Full, Web, and Code. Multi-page analysis produces session-scoped findings
with explicit pass or skipped outcomes so coverage can prove execution.

`compute_current_score` is the only user-facing SiteCMD Score authority. It
operates on canonical, lifecycle-filtered issue groups. Raw Web Scan category
scores remain historical diagnostics. Scan source must not change issue
priority.

Issue payloads carry `IssueConfidence` or intentionally inherit the documented
default. New producers should supply a reason when confidence is not obvious.

Scan cancellation uses `ScanControlState`. Product scan entry points create one
`scan_execution` with Web and Code child runs. Scheduled and manual runs share
the same admission, persistence, cancellation, and terminal-event path.

## Tauri commands and capabilities

For every command:

1. add the command in the matching domain module;
2. expose it through `commands/mod.rs`;
3. register it in `lib.rs` `invoke_handler!`;
4. add its name to `build.rs` `APP_COMMANDS`; and
5. grant the generated permission in the narrowest capability.

Registration does not grant reachability. Filesystem, destructive data,
external-connector, and project-execution operations use the privileged broker,
not direct main-window permission. Keep each broker scope's dispatch contract
test: stale-token rejection, scope-labelled unknown command, and allowlist
parity.

Sensitive confirmation expires in Rust before the renderer deadline. Only one
confirmation dialog may be in flight because a timed-out blocking dialog cannot
be cancelled.

Commands return `Result<T, String>`. Sanitize external errors before they cross
IPC. Internal layers should keep domain error types.

## Connected service

The desktop implements the stateful producer side of the connected protocol:

- release stamps and pair-precise coverage on persisted runs;
- durable producer sequence and event watermark;
- revision-guarded lifecycle outbox;
- canonical submission builder and read-only inspector;
- bootstrap derivation from current groups plus lifecycle overrides;
- key rotation and encrypted connection export;
- scan-scope delivery and connected state pull.

Installation tokens and project fingerprint keys use the credential store and
never belong in SQLite backups. Connection exports include the fingerprint key
but never the installation token. The inspector and CLI dry run render the exact
payload without allocating a sequence or sending it.

Local scope is not limited by a connected plan. Connected scope limits return an
explicit refusal; never silently truncate a local scan.

Verified-good profile acceptance and dismissal are distinct operations.
Acceptance is guarded by profile revision and value digest. A stale decision is
reported, not retried against unseen state.

## Network and credentials

- Use `http_client::for_url`. Do not construct ad-hoc reqwest clients without a
  reviewed, guardrail-marked transport requirement.
- Validate scan targets, redirects, callbacks, webhooks, and sitemap fetches
  through `network_policy::validate_url` with the correct policy.
- The webview gate covers targets and every frame's navigation, not just the
  main frame: wry passes subframe navigation actions through the same policy
  hook, so the analyzer distinguishes a redirect hop from a subframe load by
  main-frame commit state rather than by what the gate is handed. Platform
  content rules block private-network subresources by IP literal and local
  name on macOS and Windows only; a public hostname resolving to a private
  address, WebRTC candidate gathering, and every Linux subresource are not
  covered. Public privacy copy must preserve those distinctions.
- Release API keys and OAuth tokens use the credential abstraction. Never add a
  production SQLite credential fallback. A plaintext credential still sitting in
  SQLite is refused and replaced with the keychain placeholder, so the
  integration reports reconnect instead of running on a secret the keychain
  never accepted.
- A debug build uses the OS keychain unless `SITECMD_DEV_PLAINTEXT_SECRETS=1`
  opts it into the plaintext `dev-secrets.json` store. `tools/scripts/dev.sh`
  sets that to `1` by default, because macOS ties keychain access to the
  calling binary's signature and an ad-hoc dev build gets a new hash on every
  rebuild: each background credential read prompts for a password and no
  "Always Allow" survives the next build. Set the variable to `0` to exercise
  the keychain path deliberately. The two stores are separate, so a secret
  saved under one is invisible under the other until it is re-entered. Tests
  always use the in-memory debug store and never touch the keychain.
- Webhook HMAC uses `webhooks::compute_webhook_signature` and its OpenSSL
  reference vectors.
- Code Scan commands canonicalize and bound project paths through
  `core::code_scan::validate_project_path`.

## CLI and Code Scan

`crates/cli/` is the headless release package. Its `scan` command runs Web Scan,
and `audit` runs the full Code Scan engine. It compiles with app default features
disabled so Tauri and GUI dependencies cannot enter the binary or desktop
bundle.

The CLI, desktop, and CI adapters use progress callbacks rather than embedding
an `AppHandle` in engine code. Dev-only binaries stay under `examples/`, never
`src/bin/`.

Code Scan canonical ids never contain paths. Producer rule, canonical check id,
and occurrence location are separate. Database inspection is explicit and
local-only: local SQLite files, loopback database targets, or local Unix sockets.
Never inspect a hosted or production database.

## Constants and migrations

Timeouts, intervals, and tuning values live in `constants.rs`. Guardrail-marked
inline durations are limited to genuinely module-intrinsic values.

The current migration chain starts at the redesigned baseline. New migrations
must preserve transactionality and regenerate `db/schema_snapshot.sql` through
the schema test. Use cascading foreign keys only when their complete cleanup is
covered by a test.

## Integrations and background work

The integration enum contains Plausible, Cloudflare, UptimeRobot, GA4, Search
Console, Bing, GitHub, and Jira. GitHub Issues shares GitHub credentials;
PageSpeed Insights is a supporting metrics client, not an integration enum
variant.

Cache integration responses through `api_cache` and its centralized TTL and
capacity constants.

Background schedulers run under the supervised-loop helpers. They must recover
from a failed tick with bounded backoff and record terminal failures. The tray
reflects active scans; closing the window hides it rather than exiting.

## Observability and security

- Instrument top-level commands with structured fields while skipping secrets.
- Record sensitive operations through `audit_log::record` after success or
  failure. Log prefixes, domains, and hostnames, never raw secrets or PII.
- The panic hook records structured and audit output before delegating.
- Use `licensing::access::effective_tier_from_state_at` for clock-injected grace
  boundary tests.
- Keep the Tauri main window on the smallest practical capability set.

## Correlation contract

Rust owns correlation computation and persistence. The resolver enriches issue
groups, generated JSON assets supply stable graph and fix-location data, and the
MCP server mirrors the stored algorithms for read-only tools. Output-shape
changes require Rust, generated assets, MCP tools, and parity tests in the same
change.

Performance tests hold dossier resolution and deploy preview to their documented
p95 budgets. The emergency correlation flag must remain test-serialized through
the environment lock.
