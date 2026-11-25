# Native workspace tests

The public Rust workspace tests the CLI, runtime, protocol, and engine host
against the stand-in module. Build it from the repository root before running
the tests.

```bash
fnm exec --using=26.13.1 node tools/scripts/build-standin.mjs
cd apps/desktop/src-tauri
export SITECMD_ENGINE_WASM="$PWD/target/standin/sitecmd_engine_standin.wasm"
export SITECMD_ENGINE_UNPINNED=1
cargo test --locked --workspace
```

The pinned Rust toolchain is selected from the workspace directory. For a
targeted run, add `-p` and the package name.
