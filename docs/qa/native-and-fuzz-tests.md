# Native desktop and scanner input tests

The Playwright suite checks frontend flows using the Tauri test adapter. The
native smoke suite starts the built desktop application with Linux WebKitGTK,
its real SQLite worker, command capabilities, and bundled MCP server.

## Native smoke

On Ubuntu 24.04, install the normal Tauri build dependencies plus
`webkit2gtk-driver`, `xvfb`, and `dbus-x11`. Then run from the repository root:

```bash
cargo install tauri-driver --version 2.0.6 --locked
pnpm install --frozen-lockfile
pnpm --filter @sitecmd/desktop exec tauri build --debug --no-bundle --config src-tauri/tauri.contributor.conf.json
xvfb-run -a dbus-run-session -- pnpm e2e:native
```

The suite checks startup, main-webview capability refusals, project creation,
a Code Scan dispatched through MCP, persisted issue state after a process
restart, and verification after removing a known TLS configuration finding.
It assigns temporary XDG data, config, and cache directories under
`.artifacts/native-smoke/`. It stops only its own WebDriver process group.
Each run leaves a result JSON with completed steps and the outcome, plus a desktop
log. Driver and assertion errors appear in the test output. The CI job uploads
the JSON and desktop log; it does not upload the database or source fixture.

`SITECMD_SMOKE_BINARY` and `SITECMD_SMOKE_MCP` can point to an existing build.
The default paths use the debug desktop and the repository's MCP bundle.
This Linux check complements platform builds; it does not verify macOS or
Windows windowing, keychains, signing, or installer behavior.

## Scanner fuzzing

The `sitecmd-engine-fuzz` workspace crate exercises HTML page bodies, robots
directives and sitemap XML, and serialized evaluation requests. Successful
evaluations must serialize deterministically. Invalid input must return an
error or a result without panicking. Stable regression tests replay the
checked-in golden corpus and malformed Unicode inputs during ordinary
workspace tests, without a nightly toolchain.

For coverage-guided fuzzing, run from the repository root:

```bash
rustup toolchain install nightly-2026-09-01 --profile minimal
cargo +nightly-2026-09-01 install cargo-fuzz --version 0.13.2 --locked
node tools/scripts/seed-engine-fuzz.mjs
cd apps/desktop/src-tauri
cargo +nightly-2026-09-01 fuzz run --fuzz-dir crates/engine-fuzz --features fuzzing sitemap_input -- -max_total_time=30 -max_len=65536 -timeout=10 -rss_limit_mb=2048
```

Repeat with `page_input` and `evaluation_payload`. CI runs each target for
30 seconds on relevant pull requests and five minutes in the weekly job.
Nightly and cargo-fuzz versions are pinned so a toolchain update is deliberate.
The evolving corpus and crash artifacts are ignored by Git. Minimize a crash
with `cargo fuzz tmin`, add a regression test to the affected parser, and seed
the minimized input when it exercises a distinct input shape.

`pnpm cov:rust` and the manual `rust-coverage` workflow include every workspace
crate, including CLI, runtime, engine, WASM adapter, and stable fuzz regressions.
