# Engine host and stand-in module

`sitecmd-engine-host` embeds the sandboxed engine module in the CLI, checks it, and runs it under
Wasmtime with no imports, bounded memory, and deadlines. `standin/` is `sitecmd-engine-standin`, a
synthetic module with the same ABI that tests and CI use in place of the real one.

## Code map

- `Cargo.toml`: the package. Wasmtime is pinned exactly with default features off; the `compile`
  feature enables Cranelift for `load_bytes`.
- `build.rs`: the build script. `build_input.rs` resolves and pins the module bytes;
  `build_support.rs` holds the Wasmtime configuration shared by build and load.
- `src/lib.rs`: the public API: `load`, `Engine`, `EngineError`, `ModuleSession`, `Interrupt`,
  the limits, `redact_evidence`, and the `wants` and `walker_pruning` modules.
- `src/load.rs`: loads the embedded precompiled module, verifies the digest, refuses imports, and
  starts the epoch clock that enforces deadlines.
- `src/session.rs`: instantiates a guest with store limits, frames requests and answers through
  guest memory, checks the ABI version, and drives `session_begin` and `session_continue`.
- `src/wants.rs`: the `HostIo` trait, `ReadBudget`, and `answer`, which turns one module want
  into a host answer or a refusal.
- `src/workers.rs`: splits `analyze_files` work into batches across worker instances.
- `src/walker_pruning.rs`: directory names and path prefixes that project walks skip.
- `src/*_tests.rs`: unit tests, including hand-written WAT modules for refusal cases.
- `standin/src/lib.rs` and `standin/src/audit.rs`: the stand-in's exports and its synthetic audit.
- `standin/corpus.json`: cases the stand-in answers; `tests/standin_corpus.rs` runs them.

## Entry points

- `load()` returns the embedded `Engine` once per process.
- `Engine::session` and `Engine::session_with_cancellation` open a `ModuleSession`; `begin` and
  `resume` advance it, and `analyze_files` runs per-file analysis.
- `Engine::local_site_evaluate` runs one local page evaluation under `LOCAL_SITE_DEADLINE`.
- `wants::answer` answers a want through a caller's `HostIo`.
- `embedded_module()` returns the original `.wasm` bytes for `sitecmd engine info --save`.

## How it works

1. At build time, `build.rs` reads the module (see `../../AGENTS.md`), checks its SHA-256 against
   `/engine.lock` unless unpinned, precompiles it for the target, and writes both forms to
   `OUT_DIR` for `include_bytes!`.
2. `load` checks the embedded `.wasm` against the build digest, deserializes the precompiled
   module, refuses any import, and reads `engine_info`. A module whose `abi_version` differs from
   `ENGINE_ABI_VERSION` fails with `EngineError::AbiMismatch`.
3. A session sends a `SessionBegin` task. The module answers with `Step::Wants` or `Step::Done`.
   The caller answers each want, usually through `wants::answer` with its own `HostIo`, and calls
   `resume` until `Done`.
4. `AnalyzeFiles` wants run through `ModuleSession::analyze_files`, which spreads the files over
   up to eight worker instances chosen by `SITECMD_ENGINE_WORKERS` or the available parallelism.
5. Every store allows one memory up to `MODULE_MEMORY_LIMIT`, one table up to
   `MODULE_TABLE_ELEMENT_LIMIT`, and one instance. Answers larger than `MODULE_ANSWER_LIMIT` are
   refused before parsing. An `Interrupt`, a cancellation callback, or a deadline stops the guest.

## Invariants

- A module with any import, a digest mismatch, an ABI mismatch, a second table, or growth past
  the limits is refused, and interrupts and deadlines stop a spinning module: `src/load_tests.rs`.
- The build and runtime share one Wasmtime configuration, so a precompiled module for another
  configuration is refused: the tests in `src/load.rs`.
- This is the only crate that depends on Wasmtime, with default features off and only the
  allowed features: `/tools/scripts/lib/guardrail-engine-host-rules.mjs`.
- Its dependencies come from crates.io or the protocol path:
  `/tools/scripts/lib/guardrail-protocol-contents-rules.mjs`.
- Dependency manifests and lockfiles are read under the dependency byte limit in `src/wants.rs`:
  `/tools/scripts/lib/guardrail-update-rules.mjs`.
- The stand-in answers every case in `standin/corpus.json` the way the host expects:
  `tests/standin_corpus.rs`.

## Testing

From `/apps/desktop/src-tauri`, with the stand-in built and the environment from
`../../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-engine-host -p sitecmd-engine-standin
```

Rebuild the stand-in with `node tools/scripts/build-standin.mjs` from the repository root after
changing `standin/`; the host embeds whatever `SITECMD_ENGINE_WASM` names at build time.

## Boundaries

- The engine module: release builds embed the module pinned in `/engine.lock`, which comes from
  outside this repository. Its exports and messages follow
  `../protocol/src/engine_abi/`, and `ENGINE_ABI_VERSION` there must match the module.
- The stand-in: `/tools/scripts/build-standin.mjs` builds it with the `wasm-release` profile into
  the workspace's target/standin folder, and CI and local tests embed that file.
- The runtime implements `HostIo` in `../../src/core/engine_io.rs` and drives sessions from
  `../../src/core/audit/`.
- `/docs/engineering/engine-boundary.md` explains this boundary to readers who want to verify it.

## Guide triggers

- `Cargo.toml`
- `build.rs`
- `build_input.rs`
- `build_support.rs`
- `src/lib.rs`
- `src/load.rs`
- `src/session.rs`
- `src/wants.rs`
- `src/workers.rs`
- `src/walker_pruning.rs`
- `standin/Cargo.toml`
- `standin/src/lib.rs`
- `standin/corpus.json`
