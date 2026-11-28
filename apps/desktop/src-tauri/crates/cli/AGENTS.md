# CLI binary

The `sitecmd-cli` package builds the `sitecmd_cli` binary that ships as `sitecmd`. It parses
arguments, prints help, picks exit codes, and calls command functions in `sitecmd-runtime`. Command
behavior lives in the runtime; see `../../src/cli/AGENTS.md`.

## Code map

- `Cargo.toml`: the package. It depends on `sitecmd-runtime`, `env_logger`, and `tokio` only.
- `src/main.rs`: `fn main`, the subcommand dispatcher, and the argument parsers for `init`,
  `scan`, `fix`, `watch`, `check`, `connected`, `deploy`, and `gate`.
- `src/audit_dispatch.rs`, `src/autofix_dispatch.rs`, `src/connect_dispatch.rs`,
  `src/login_dispatch.rs`, `src/rules_dispatch.rs`: dispatch for commands whose parsing lives in
  the runtime or needs its own file.
- `src/help.rs`: the main and per-command help text.
- `src/validators.rs`: shared value parsers for scores, seconds, and category keys.
- `src/tests.rs`: unit tests of the parsers.
- `tests/`: integration tests that run the built binary; `tests/support/` holds their helpers,
  including local site and page servers for local scans.

## Entry points

- `fn main` in `src/main.rs`. With no arguments it prints help. `--version` and `-V` print
  `sitecmd <version>`, with a `+unpinned` suffix when the embedded module was not pinned. A first
  argument starting with `--` runs an implicit `scan`.
- Subcommands dispatched by `match first.as_str()`: `init`, `login`, `logout`, `connect`, `audit`,
  `rules`, `engine`, `autofix`, `scan`, `fix`, `watch`, `check`, `connected`, `deploy`, `gate`,
  and `help`.

## How it works

1. `main` reads `std::env::args`, initializes `env_logger` on stderr at `warn` by default, and
   matches the first argument.
2. The parser for that command builds the runtime's argument struct, such as
   `sitecmd_runtime::cli::scan::ScanArgs`. `--help` and `-h` print help and exit 0.
3. Asynchronous commands run on one Tokio runtime from `build_runtime` in `src/main.rs`.
4. Results print to stdout and errors to stderr as `Error: ...`; a failed local scan prints
   `Scan failed: ...`.

Exit codes:

- 0: success.
- 1: a threshold such as `--fail-on` failed or the gate blocked; or, in `login` and `connect`,
  the approval was denied or expired (and in `login`, the account already holds its maximum of
  personal tokens). The `failure_exit_code` functions in `../../src/cli/login.rs` and
  `../../src/cli/connect.rs` decide this.
- 2: a usage error or a refused command.
- 130: an interrupted `audit` or `login`.

## Invariants

- The package stays free of desktop and Tauri dependencies, depends on `sitecmd-runtime` by path,
  and never depends on `headless_chrome` or `hickory-resolver`:
  `/tools/scripts/lib/guardrail-cli-surface-rules.mjs`.
- README.md documents every dispatched command, and every command and flag it documents exists
  in the parsers: `/tools/scripts/lib/cli-documentation.mjs`, tested in
  `/tools/scripts/cli-documentation.test.mjs`. A new command or flag needs a README.md entry.
- A message that tells the reader to run `sitecmd <name>` names a dispatched subcommand:
  `/tools/scripts/lib/guardrail-cli-surface-rules.mjs`.
- `scan` has no `--type` option; categories go through `--categories` with the ten category keys:
  `src/tests.rs`.
- Help never attributes the local store to the removed desktop app: `tests/no_desktop_handoff.rs`.
- A release binary never prints `+unpinned`, and `engine info --json` reports the digest in
  `/engine.lock`: `/tools/scripts/verify-engine-pin.mjs`, tested by `/tools/scripts/engine-pin.test.mjs`.
  `/.github/workflows/release.yml` runs it on every release target.

## Testing

From `/apps/desktop/src-tauri`, with the stand-in built and the environment from
`../../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-cli
cargo clippy --locked --manifest-path crates/cli/Cargo.toml --all-targets -- -D warnings
```

The integration tests find the binary through `CARGO_BIN_EXE_sitecmd_cli` or
`NEXTEST_BIN_EXE_sitecmd_cli`. From the repository root, `node tools/scripts/cli-smoke.mjs
--standin` smoke-tests a built debug binary.

## Boundaries

- Depends on `sitecmd-runtime` (`../runtime/Cargo.toml`) for every command.
- README.md, `/tools/scripts/sitecmd.mjs`, the installers, and the Actions in `/.github/actions/`
  call this binary. `/.github/workflows/release.yml` builds and packages it as `sitecmd`.
- `/packaging/npm/cli/bin/sitecmd.js` launches the binary from the platform npm package.

## Guide triggers

- `Cargo.toml`
- `src/main.rs`
- `src/*_dispatch.rs`
- `src/help.rs`
- `src/validators.rs`
