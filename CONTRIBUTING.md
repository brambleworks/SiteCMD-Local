# Contributing to SiteCMD

## Current contribution policy

Issues and discussion are welcome. Unsolicited code contributions are not accepted yet, and pull requests are limited to invited collaborators while the public maintenance process is established.

Before opening an issue, search for an existing report and include the smallest reproducible example you can share safely. Do not include source code, credentials, private URLs, scan findings, or customer data that you are not authorized to publish.

Report security vulnerabilities privately according to [SECURITY.md](SECURITY.md), not in a public issue.

## What lives here, and what does not

This repository is everything that runs on a user's machine: the desktop app, the CLI, the MCP server, and the scan engine with every current detector. That is the part the privacy claims are about, so it is the part that is open. Detectors, checks, and engine behavior are the code most worth discussing, and a bug report against a check is the most useful issue you can file; use the [False positive](https://github.com/brambleworks/SiteCMD/issues/new?template=false_positive.yml) form so it carries the check id, scan type, and sanitized evidence.

Two things are deliberately elsewhere and are not accepted here:

- **The maintained intelligence catalog.** Fix-guide content is separately licensed commercial content and is authored in the SiteCMD-Web repository, not in this one. Baseline remediation content that ships inside the app does live here.
- **Connected-service internals.** The hosted scanner, the connected API, and the delivery workers run on SiteCMD infrastructure and their code lives in SiteCMD-Web. Their implementation specifications are public in `docs/engineering/connected-service/` so the wire contract a client speaks can be reviewed; the service code that fulfills them is not accepted here. The payload builder that decides what a connected client sends belongs on this side of the line on purpose, so what leaves the machine stays reviewable.

The source-publication decision record, maintained privately alongside the connected-service internals, owns that boundary and why it falls where it does.

## Repo layout

- `apps/desktop/` - Tauri v2 desktop app (Rust backend + React frontend). The main product.
- `apps/mcp-server/` - TypeScript MCP server for AI editor integration.
- `docs/` - maintained engineering, product, QA, and operations documentation.
- `tools/` - repository tooling, guardrails, and maintained benchmarks.

The marketing and documentation site, the public scanner, and the deployable Cloudflare Workers (release delivery, telemetry, catalog, activation, connected service) live in the separate SiteCMD-Web repository. `product-facts.json` is the one channel across that boundary; regenerate it with `pnpm facts:generate` after changing any of its sources.

## Local setup

- `pnpm install`
- `bash tools/scripts/dev.sh` - restarts the Tauri desktop app cleanly, freeing its dev ports first.
- `pnpm tauri:dev` - desktop app only, without the restart handling.

Start with [Adding a detector](docs/engineering/adding-a-detector.md) to follow
one existing check from input through verdict, fixtures, registration, and local
guidance. The complete exercise uses only this public repository.

`pnpm sitecmd -- <arguments>` runs the shipped Rust CLI from this checkout, with
the pinned toolchain and the caller's working directory. For example:

```bash
pnpm sitecmd -- --version
pnpm sitecmd -- scan --url https://example.com
pnpm sitecmd -- audit . --format json
```

Desktop navigation uses `pnpm sitecmd -- open <page>`. Previous checkout-only
shortcuts such as `pnpm sitecmd -- dashboard` become
`pnpm sitecmd -- open dashboard`; `scan` now runs the scanner. The installed
headless CLI does not provide the checkout wrapper's `open` convenience command.

## Quality gates

- `pnpm typecheck` - every workspace.
- `pnpm test` - desktop, MCP, and repository guardrail tests.
- `pnpm lint` - ESLint across the workspace.
- `cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --all -- --check` - Rust formatting.
- `cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --workspace --all-targets -- -D warnings` - Rust lint across every crate and target.
- `pnpm verify:push` - the full push gate, and the one that decides whether a change is ready.
- Lefthook runs the relevant subset on `pre-commit` and `pre-push`.

## Branch + commit conventions

- Invited collaborators work from short-lived branches using `feature/`,
  `bugfix/`, `hotfix/`, `release/`, or `docs/` plus a short kebab-case name.
- Commit subjects use a capitalized imperative verb and a specific object, such
  as `Add verified site baselines` or `Update GitHub Actions dependencies`.
  Keep them to 10 words and 60 characters, with no type prefix, scope, ticket
  prefix, or ending punctuation. Bodies are optional and reserved for short,
  non-obvious reasoning rather than file lists or test output.
- The default branch is `main`, and the release tooling and workflows pin that name. Never push directly to it: every change, including dependency and documentation updates, goes through a pull request and the required checks.
- Use squash merge so the default branch stays linear and each merged pull request has one reviewable commit. Configure the squash message to use only the validated pull-request title.

## What CI checks

- Frontend: typecheck, eslint, vitest, knip (unused exports), size-limit.
- Rust: cargo fmt, clippy `-D warnings`, cargo test. The `rust-coverage`
  workflow is an informational, manually dispatched snapshot and is not a
  required merge check.
- MCP server: typecheck, lint, build, test.
- Repository guardrails: `pnpm guardrails:repo`, which is where most conventions in this file are actually enforced.
- Release pipeline: builds a universal macOS app plus native Linux and Windows artifacts; publishes to R2; gated on the knip export budget and repository guardrails.

## Architecture rules (the ones that bite if forgotten)

- Tauri commands return `Result<T, String>`. Use `sanitize_error()` from `commands/mod.rs` to strip filesystem paths from errors before they reach the frontend.
- All HTTP through `http_client::for_url(...)` - never `reqwest::Client::new()`. CI guardrail enforces this in `src/checks`, `src/core`, `src/commands`.
- DB access through `db.execute(move |conn| ...)`. Never hold a Mutex across `.await`.
- Destructive / FS / connector / project-execution commands go through the privileged-command broker (`commands/privileged_command_broker/`), not direct main-window permissions.
- All API keys in OS keychain via `keyring.rs`. Never SQLite.
- The complete local workbench has no feature gate. Subscription tiers remain
  visible for connected-service and catalog entitlement, which the service
  enforces server-side.

## Where to find more

- `AGENTS.md` (root) - full architecture overview (the `CLAUDE.md` files are thin compatibility pointers to these).
- `apps/desktop/AGENTS.md` and `apps/desktop/src-tauri/AGENTS.md` - frontend and Rust patterns and gotchas.
- `docs/README.md` - maintained engineering, product, QA, and operations documentation.

See [GOVERNANCE.md](GOVERNANCE.md) for decision-making and maintainer responsibilities.
