# AGENTS.md

Rust workspace guidance for SiteCMD. Read the root guide for product and
repository rules. This workspace contains the CLI, native runtime, portable
engine, WASM wrappers, protocol types, and fuzz harness.

## Commands

```bash
cargo test
cargo test -- test_name
cargo test --workspace
cargo clippy --workspace
cargo build
pnpm guardrails:repo
```

Use `--workspace` when verifying changes across crates.

Build the stand-in from the repository root before running the public workspace tests.

```bash
fnm exec --using=26.13.1 node tools/scripts/build-standin.mjs
cd apps/desktop/src-tauri
export SITECMD_ENGINE_WASM="$PWD/target/standin/sitecmd_engine_standin.wasm"
export SITECMD_ENGINE_UNPINNED=1
cargo test --workspace
```

The host also accepts `engine/local-engine.wasm` at the repository root as the
default module path. Local builds use `SITECMD_ENGINE_UNPINNED=1` until
`engine.lock` is available.

Code Scan runs per-file analysis on up to eight module instances, defaulting
to the available parallelism clamped to 1 through 8. Set
`SITECMD_ENGINE_WORKERS` to an unsigned decimal integer for benchmarking or
CI. The host clamps valid values to 1 through 8 and refuses invalid values.

## Database

SQLite runs on a dedicated worker thread. All access goes through
`Database::execute` or `Database::execute_mut` with a `move` closure. Never hold
a mutex, connection, or database borrow across `.await`.

Domain methods belong in `db/{domain}.rs` as `impl Database` blocks. Keep
`db/mod.rs` focused on the worker, open path, and shared types.

- Bind SQL values with `params!` or `named_params!`; never interpolate values.
- Keep row decoding next to the queries that use it.
- Multi-step dependent writes use one `execute_mut` transaction.
- Schema changes use numbered SQL files in `db/migrations/`.
- Migrations and their version records commit atomically.
- Supply integer epoch milliseconds from Rust. Do not add SQL wall-clock
  defaults.
- Session-aware queries must not filter `session_id IS NULL`.

## Checks and the portable engine

The engine module owns check verdicts, coverage, and scoring. Callers supply
evaluation time and typed facts. The module has no clock, filesystem, network,
or environment access.

Async transport uses typed probe plans. The hosted adapter classifies timeout,
body-cap, redirect, and transport outcomes. External-corpus checks use an
explicit answered or unavailable shape. TLS uses `TlsFacts` and separate
expiry, hostname, chain, and protocol check ids.

Sitemap discovery and sitemap checks share the sitemap-document parser and
candidate policy. Redirect checks share the redirect walker. Never fork their
state machines in a runtime adapter.

## Scans and scoring

Web Scan modes select check categories. Multi-page analysis produces
session-scoped findings with explicit pass or skipped outcomes so coverage can
prove execution. Raw Web Scan category scores are historical diagnostics.

Issue payloads carry `IssueConfidence` or intentionally inherit the documented
default. New producers should supply a reason when confidence is not obvious.

Connection exports include the fingerprint key. Installation tokens belong in
the credential store. The CLI dry run renders a payload without allocating a
sequence or sending it.

## Network and credentials

- Use the existing shared client for the transport. The local lane uses
  `http_client::for_local_scan` with checked addresses. Do not construct ad-hoc
  reqwest clients without a reviewed, guardrail-marked transport requirement.
- Validate scan targets, redirects, callbacks, webhooks, and sitemap fetches
  through `network_policy::validate_url` with the correct policy.
- Local database inspection stays inside the audited project for SQLite and
  uses local transports for PostgreSQL.
- Log prefixes, domains, and hostnames. Keep raw secrets and PII out of logs.
