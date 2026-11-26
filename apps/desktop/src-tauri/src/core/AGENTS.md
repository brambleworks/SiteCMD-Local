# Code Scan host and scan core

The runtime's `core` module is the host side of Code Scan: it walks a project within budgets,
gathers the facts the engine module may ask for, answers the module's wants from the project,
and turns the module's report into source-free output. It also holds fix-template support, Git
access, and the Web Scan vocabulary.

## Code map

- `audit/`: Code Scan entry points. `audit/mod.rs` runs an audit; `audit/audit_session.rs` drives
  the module session; `audit/session_host.rs` and `audit/session_host/` answer wants and build the
  report; `audit/fingerprints.rs` holds versioned occurrence fingerprints; `audit/publication.rs`
  holds the source-free projections for output that leaves the terminal; `audit/report_format.rs`
  and `audit/report_views.rs` render the formats.
- `project_listing.rs` and `project_listing/`: the bounded inventory of a project tree.
- `scan_scope.rs`: ignore and scope decisions for the walker.
- `safe_fs.rs`, `filesystem.rs`: bounded reads from untrusted project trees.
- `engine_facts/`: host facts offered to the session: file inventory, npm manifests and
  lockfiles, Git hook activation, path presence, and local database offers.
- `engine_io.rs`: `ProjectIo`, the `HostIo` implementation that answers wants from the project.
- `database_targets.rs` and `database_targets/`: local database discovery from dotenv files,
  used only with `--inspect-local-databases`.
- `database_snapshot/`: read-only SQLite and PostgreSQL schema snapshots for offered targets.
- `fix_templates/`: host support for template fixes: host detection, file writers, the fix
  job's build check, and its deny-by-default subprocess environment. `fixes.rs` adapts fix
  text and template requests to the module.
- `git.rs`: hardened Git commands for tracked-file checks and checkout provenance.
- `code_provenance.rs`, `engine_release.rs`: checkout identity and module release provenance for
  Code Scan evidence.
- `scan_types.rs`: Web Scan results; it re-exports the protocol vocabulary.
- `normalized_scan.rs`, `scan_execution.rs`: shared persistence shapes and scan intent.
- `localhost.rs`: local environment helpers.
- `test_support.rs`, `postgres_test_support.rs`: fixtures behind the `test-support` feature.

## Entry points

- `audit/mod.rs`: `audit_project` and its variants. `../cli/audit.rs` calls
  `audit_with_interrupt_at`, `../cli/connected.rs` calls `connected_audit_at`, and autofix calls
  `audit_observing_files`.
- `project_listing::list_project`: the validated project walk.
- `engine_io::ProjectIo`: passed to `sitecmd_engine_host::wants::answer`.

## How it works

1. `list_project` walks the root, skipping the directories in the engine host's
   `walker_pruning`, and records files within file-count, byte, and depth budgets.
2. `engine_facts::session_request` builds the `SessionBegin` request and the file offers. With
   `--inspect-local-databases` it also offers local database targets.
3. `audit/audit_session.rs` begins an `Audit` task and loops: each want is answered through
   `ProjectIo`, and `AnalyzeFiles` wants go to the module's per-file workers, until `Done`.
4. `audit/session_host/report.rs` checks the report against the module's rule inventory and builds the
   `CodeScanReport`. Formats and published projections carry the rule, file, and line, never
   source text.

## Invariants

- Host reads go through the shared bounded readers, fact imports follow an explicit allowlist,
  and autofix uses only public engine host and protocol APIs:
  `/tools/scripts/lib/guardrail-code-scan-host-boundary.mjs`.
- File collection keeps file-count, total-byte, and depth budgets; SQLite inspection stays inside
  the project and refuses symlink escapes; outputs omit source excerpts and code lines:
  `/tools/scripts/lib/guardrail-code-scan-security-rules.mjs`.
- Project detection uses shared bounded reads: `/tools/scripts/lib/guardrail-project-metadata-rules.mjs`.
- Dependency manifests and lockfiles stay under the dependency byte limit, and
  `engine_facts/npm.rs` never calls `read_to_string`: `/tools/scripts/lib/guardrail-update-rules.mjs`.
- `core` never references `crate::commands`: `/tools/scripts/lib/guardrail-core-layering-rules.mjs`.
- No reqwest client is constructed here: `/tools/scripts/audit/forbid-adhoc-rust-patterns.sh`.
- PostgreSQL inspection reaches only loopback hosts or local sockets, and remote targets are
  refused: the tests in `database_targets.rs` and `engine_io_tests.rs`.
- Fix-job subprocesses receive only `PATH`, `HOME`, and `CI`: the tests in
  `fix_templates/subprocess.rs`.

## Testing

From `/apps/desktop/src-tauri`, with the stand-in built and the environment from `../../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-runtime core::
```

The live PostgreSQL test is ignored by default. To run it, point `SITECMD_POSTGRES_TEST_URL` at a
localhost maintenance database and run
`cargo test --locked -p sitecmd-runtime postgres_live -- --ignored`.

## Boundaries

- The engine module, through `sitecmd-engine-host`: the module decides findings, and this module
  decides what the module may read. `/docs/engineering/engine-boundary.md` walks through it.
- The want and fact types come from `../../crates/protocol/src/engine_abi/`.
- `../cli/` calls the audit entry points; `../db/` stores the resulting runs.

## Guide triggers

- `audit/mod.rs`
- `audit/audit_session.rs`
- `audit/session_host.rs`
- `audit/publication.rs`
- `project_listing.rs`
- `engine_io.rs`
- `engine_facts/mod.rs`
- `safe_fs.rs`
- `scan_scope.rs`
- `database_targets.rs`
- `git.rs`
- `fix_templates/subprocess.rs`
