# Local database

The runtime's `db` module is the CLI's local SQLite store. Scan executions record intent, scan
runs and findings hold immutable evidence, and work items plus issue states hold the mutable
projection. The connected commands build their payloads from it.

## Code map

- `mod.rs`: `Database`, the worker thread that owns the one connection, `open`, and the shared
  types. `execute` and `execute_mut` run a closure on the worker within `DB_OP_TIMEOUT`.
- `migrations.rs` and `migrations/`: the ordered SQL migrations, embedded with `include_str!`,
  and the runner. `migrations*_tests.rs` test them.
- `scan_executions.rs`, `scan_runs.rs`, `scan_run_projection.rs`: scan intent, immutable runs and
  findings, and the work-item projection.
- `issue_states.rs`: lifecycle reconciliation when a finding reappears.
- `code_scans.rs`, `projects.rs`, `engine_release.rs`: Code Scan runs, project registration, and
  module release stamps.
- `connected_payload.rs`, `connected_payload_wire.rs`, `connected_bootstrap.rs`,
  `connected_producer.rs`, `connected_sites.rs`: connected payloads, bootstrap projections,
  submission ordering, and site bindings.
- `error.rs`: `DbError`. `helpers.rs`: internal helpers. `types.rs`: timestamp decoding.
- `test_helpers.rs`: temporary-file database fixtures.

## Entry points

- `Database::open(path)`, called by the commands listed under Boundaries. The default path is
  `SITECMD_DB_PATH` or a file named sitecmd.db under the per-user storage directory from
  `../app_identity.rs`.
- Domain methods are `impl Database` blocks in each domain file.

## How it works

`open` creates the directory, opens the file in WAL mode, and runs pending migrations on the
connection before it starts the worker. A schema older than the unified scan cutover is backed
up first; a schema newer than this build is moved aside and recreated. The connection then
moves to a `db-worker` thread, and every operation is a closure sent to it.

## Invariants

- The worker owns the only connection, so all access goes through `Database::execute` or
  `Database::execute_mut`, whose closures must be `Send + 'static`: the compiler enforces this.
  Never hold a mutex guard across `.await`: Clippy's default `await_holding_lock`, under CI's
  `-D warnings`. Never hold a connection or database borrow across `.await` (convention, not
  checked).
- Domain methods belong in their domain file, such as `scan_runs.rs`, as `impl Database` blocks,
  and `mod.rs` stays focused on the worker, the open path, and shared types (convention, not
  checked).
- Bind SQL values with `params!` or `named_params!`, never interpolation, and keep row decoding
  next to the queries that use it (convention, not checked).
- Multi-step dependent writes use one `execute_mut` transaction (convention, not checked).
- Schema changes are new numbered files in `migrations/`, each registered in `migrations.rs`: the
  `every_migration_sql_file_is_registered` test in `migrations_tests.rs`. A migration and its
  version record commit atomically: `failed_migration_rolls_back_ddl_and_version_together` there.
- Supply integer epoch milliseconds from Rust, never SQL wall-clock defaults. Migrations after the
  baseline never use `datetime('now')` or `date('now')`: `no_new_migration_uses_datetime_now_defaults`
  in `migrations_tests.rs`.
- Session-aware queries must not filter `session_id IS NULL` (convention, not checked).
- The database layer returns `DbError`, never `.map_err(|e| e.to_string())`:
  `/tools/scripts/audit/forbid-adhoc-rust-patterns.sh`.
- Production code uses `scan_executions`, `scan_runs`, and `scan_findings`, never legacy scan
  tables, and canonical Code check IDs stay rule-level:
  `/tools/scripts/lib/guardrail-unified-scan-rules.mjs`.
- Every scan run insert carries the module release stamp loaded inside run persistence:
  `/tools/scripts/lib/guardrail-scan-run-stamp-rules.mjs`.
- Site bindings hold no credential, and submission ordering keeps one installation identity and
  counter: `/tools/scripts/lib/guardrail-connected-outbox-rules.mjs` and
  `/tools/scripts/lib/guardrail-submission-ordering-rules.mjs`.
- Re-observed verifications follow `proves_absence()`:
  `/tools/scripts/lib/guardrail-issue-state-rules.mjs`.
- The database file is owner-only: `/tools/scripts/lib/guardrail-private-storage-rules.mjs`.

## Testing

From `/apps/desktop/src-tauri`, with the stand-in built and the environment from `../../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-runtime db::
```

Tests use temporary files from `test_helpers.rs`; no database server is needed.

## Boundaries

- Payloads built here use `sitecmd_protocol::sync` types and must satisfy
  `/docs/engineering/connected-service/connected-protocol-spec.md`.
- `../cli/connected.rs`, `../cli/connected_submit.rs`, and `../cli/connect.rs` open the store.
- `/.github/actions/sitecmd-gate/action.yml` points `SITECMD_DB_PATH` at a runner-temporary file.

## Guide triggers

- `mod.rs`
- `migrations.rs`
- `migrations/*.sql`
- `connected_payload.rs`
- `scan_runs.rs`
- `scan_executions.rs`
- `issue_states.rs`
- `connected_producer.rs`
- `connected_sites.rs`
