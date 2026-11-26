# Rust workspace

The Cargo workspace for the open `sitecmd` CLI: the binary, its runtime, the wire protocol, and
the host that runs the sandboxed engine module. Each crate has its own guide; read it before
editing that crate.

## Code map

- `Cargo.toml`: the members (`crates/protocol`, `crates/engine-host`, `crates/engine-host/standin`,
  `crates/runtime`, `crates/cli`) and the build profiles, including `wasm-release` for Wasm builds.
- `Cargo.lock`: the locked graph. CI fetches, builds, and tests with `--locked`.
- `rust-toolchain.toml`: the pinned toolchain, its components, and the release and Wasm targets.
- `deny.toml`: cargo-deny policy for advisories, licenses, bans, and sources.
- `clippy.toml`: Clippy thresholds.
- `build_config.rs`: included by the runtime build script. It bakes `SITECMD_CONNECTED_ENDPOINT`
  from the environment, or from a .env file at the repository root when one exists.
- `crates/cli/`: the `sitecmd_cli` binary. Guide: `crates/cli/AGENTS.md`.
- `crates/runtime/`: the manifest and build script of `sitecmd-runtime`, whose source is `src/`.
  Guide: `src/AGENTS.md`.
- `crates/engine-host/`: loads and runs the engine module; `crates/engine-host/standin/` is the
  synthetic module used in tests. Guide: `crates/engine-host/AGENTS.md`.
- `crates/protocol/`: wire types shared by the CLI, the engine module, and the connected service.
  Guide: `crates/protocol/AGENTS.md`.
- `src/`: the runtime source, with guides in `src/cli/AGENTS.md`, `src/core/AGENTS.md`, and
  `src/db/AGENTS.md`.
- `tests/fixtures/`: shared fixtures: connection code-flow checkouts, fix-template checkouts, sync
  cases, and the wire identifier corpus in `tests/fixtures/parity/wire_identifiers.json`.

## Entry points

- `crates/cli/src/main.rs`: `fn main` of the `sitecmd_cli` binary.
- `crates/engine-host/build.rs`: reads, pins, precompiles, and embeds the engine module.
- `crates/runtime/build.rs`: runs `build_config.rs`.
- `/tools/scripts/sitecmd.mjs`: `pnpm sitecmd -- <args>` builds and runs the CLI from a checkout.

## How it works

1. `crates/engine-host/build.rs` reads the module named by `SITECMD_ENGINE_WASM`, or the one
   `pnpm engine:fetch` writes under `/engine/`. Unless `SITECMD_ENGINE_UNPINNED=1`, it refuses a
   module whose SHA-256 differs from `/engine.lock`. It precompiles the module with Wasmtime for
   the build target and embeds both the original and the compiled bytes.
2. `crates/cli` parses arguments and calls command functions in `sitecmd_runtime::cli`. Those use
   `src/core/` for Code Scan, `src/db/` for the local store, and `src/connected_service.rs` for the
   connected service.
3. The engine module owns check verdicts, coverage, and scoring. Callers supply evaluation time
   and typed facts. The module has no clock, filesystem, network, or environment access; it sees
   only what the host hands it.

Code Scan runs per-file analysis on up to eight module instances, defaulting to the available
parallelism clamped to 1 through 8. Set `SITECMD_ENGINE_WORKERS` to an unsigned decimal integer
for benchmarking or CI. The host clamps valid values to 1 through 8 and refuses invalid values.

## Invariants

- Open crates depend only on each other and on crates.io, and only the engine host depends on
  Wasmtime, with default features off: `/tools/scripts/lib/guardrail-engine-host-rules.mjs`, run
  by `pnpm audit:deps:rust-policy`.
- `wasmtime-wasi` and `wasi-common` stay banned in `deny.toml`; the fixture in
  `/tools/scripts/testdata/deny-wasi/` proves the ban rejects them
  (`/tools/scripts/audit/check-rust-dependency-policy.mjs`).
- No engine source path or engine crate name enters the tree:
  `/tools/scripts/lib/publication-history-rules.mjs`, run by the public tree check.
- The CLI and runtime versions match each other and `Cargo.lock`, and every member declares
  `rust-version = "1.95.0"`: `/tools/scripts/lib/guardrail-version-sync-rules.mjs`. Bump versions
  with `pnpm release <version>`.
- The toolchain pin stays explicit: `/tools/scripts/audit/check-rust-toolchain.mjs`.
- Rust files stay within line budgets (`/tools/scripts/lib/guardrail-rust-loc-rules.mjs`), and
  bare `.expect()` and inline `Duration::from_*` stay within their ratchets
  (`/tools/scripts/lib/guardrail-rust-ratchets.mjs`). Split code instead of raising a budget.
- Code under `crates/` takes time from its caller, never an ambient clock:
  `/tools/scripts/lib/guardrail-ambient-clock-rules.mjs`, which scans only `crates/`. The runtime
  reads the clock through `src/time.rs` (convention, not checked).

## Testing

Build the stand-in from the repository root, then run the workspace from this folder so rustup
applies the pinned toolchain:

```bash
fnm exec --using="$(cat .nvmrc)" node tools/scripts/build-standin.mjs
cd apps/desktop/src-tauri
export SITECMD_ENGINE_WASM="$PWD/target/standin/sitecmd_engine_standin.wasm"
export SITECMD_ENGINE_UNPINNED=1
cargo test --locked --workspace
cargo clippy --locked --all-targets --workspace -- -D warnings
cargo fmt --check --all
```

Add `-p <package>` for one crate and `-- <test_name>` for one test. CI also runs doctests with
`cargo test --locked --doc --workspace` and checks the workspace on Rust 1.95.0.

## Boundaries

- The engine module comes from the engine release that `/engine.lock` pins by version, URL, and
  SHA-256. `pnpm engine:fetch` downloads and verifies it; release builds embed it. Tests use the
  stand-in module instead, which is why the commands above set `SITECMD_ENGINE_UNPINNED=1`.
- The ABI between this workspace and the module is `crates/protocol/src/engine_abi/`.
- The connected service implements the other side of the wire types in `crates/protocol/src/sync/`,
  specified in `/docs/engineering/connected-service/connected-protocol-spec.md`.
- The release workflow, which is not in this tree, builds `sitecmd-cli` for the targets in
  `rust-toolchain.toml`; `/packaging/npm/` and `/install.sh` distribute the result.

## Guide triggers

- `Cargo.toml`
- `Cargo.lock`
- `rust-toolchain.toml`
- `deny.toml`
- `clippy.toml`
- `build_config.rs`
- `crates/*/Cargo.toml`
- `crates/*/build.rs`
- `crates/engine-host/standin/Cargo.toml`
- `tests/fixtures/parity/wire_identifiers.json`
