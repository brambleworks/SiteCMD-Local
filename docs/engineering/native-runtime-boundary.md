# Native runtime boundary

The native Rust packages form a one-way dependency graph:

```text
sitecmd (Tauri desktop) ──┐
                        ├── sitecmd-runtime ── sitecmd-engine
sitecmd-cli ─────────────┘
sitecmd-engine-wasm ─────────────────────────── sitecmd-engine
sitecmd-engine-fuzz ─────────────────────────── sitecmd-engine
```

`sitecmd-runtime` owns native HTTP and URL policy, filesystem scanning, SQLite
and migrations, scoring, connected-service clients, CLI operations, and the
scan worker runtime. It has no Tauri dependency. Its optional `browser` feature
adds headless Chrome acquisition for the CLI.

The desktop package owns app startup, IPC, capabilities, webviews, the OS
keychain, and background adapters. The `desktop_core`, `desktop_integrations`,
`desktop_licensing`, and `desktop_ssl_probe` modules adapt shared runtime
contracts. Their re-exports preserve existing desktop call sites without
compiling a second copy of the shared implementation or database types.

The runtime crate currently points its library at `src/runtime.rs`. Shared
modules retain their established source paths under `src/` so detector guides,
source inventories, and fixtures stay stable during the extraction. Dependency
ownership follows the crate root, not the directory name. New shared code must
be reachable from `runtime.rs` and must not import a desktop adapter. A future
directory move can be mechanical once those source-path consumers are migrated.

Both native build scripts use `build_config.rs` to bake the same public release
configuration. Runtime, CLI, and desktop versions are stamped together so user
agents, engine provenance, and exported reports identify the shipped release.
License write-generation state also lives in the runtime, so a database restore
invalidates a desktop validation already in flight.

Verify the headless dependency boundary and shared tests from the Rust workspace:

```bash
cd apps/desktop/src-tauri
cargo tree --locked -p sitecmd-cli --edges normal,build
cargo check --locked -p sitecmd-cli --all-targets
cargo test --locked --workspace
```

The CLI tree must contain `sitecmd-runtime` and `sitecmd-engine`, and must not
contain the `sitecmd` desktop package, Tauri, Wry, or GTK. Workspace tests cover
shared behavior once in the runtime and desktop behavior in the Tauri package.

The `test-support` feature exposes temporary database fixtures and operation
counters through desktop dev-dependencies. Production builds leave it disabled.
