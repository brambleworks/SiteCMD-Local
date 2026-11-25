# Contributing to SiteCMD

## Current contribution policy

Issues and discussion are welcome. Unsolicited code contributions are not accepted yet, and pull requests are limited to invited collaborators while the public maintenance process is established.

Before opening an issue, search for an existing report and include the smallest reproducible example you can share safely. Do not include source code, credentials, private URLs, scan findings, or customer data that you are not authorized to publish.

Report security vulnerabilities privately according to [SECURITY.md](SECURITY.md), not in a public issue.

## What lives here, and what does not

This repository is the part of SiteCMD that runs on a user's machine and touches their files and network: the CLI, and the host that runs SiteCMD's engine module. That's the part the privacy claims are about, so it's the part that's open. The checks are compiled into the module from SiteCMD's private source, so changes to checks aren't accepted here. A report against a check is still the most useful issue you can file: use the [False positive](https://github.com/brambleworks/SiteCMD-Local/issues/new?template=false_positive.yml) form so it carries the check id, scan type, and sanitized evidence.

Two things are deliberately elsewhere and are not accepted here:

- **The maintained intelligence catalog.** Fix-guide content is separately licensed commercial content and is authored privately, not in this one.
- **Connected-service internals.** The hosted scanner, the connected API, and the delivery workers run on SiteCMD infrastructure, and their code is private. Their implementation specifications are public in `docs/engineering/connected-service/` so the wire contract a client speaks can be reviewed; the service code that fulfills them is not accepted here. The payload builder that decides what a connected client sends belongs on this side of the line on purpose, so what leaves the machine stays reviewable.

## Repo layout

- `apps/desktop/src-tauri/` - Rust workspace for the CLI.
- `docs/` - maintained engineering, product, QA, and operations documentation.
- `tools/` - repository tooling, guardrails, and release scripts.

The marketing and documentation site, the public scanner page, and the delivery workers live outside this repository.

## Local setup

Start with [the engine boundary](docs/engineering/engine-boundary.md), which follows one audit from the file walk through the engine module's answers to the report.

Install the prerequisites in [README.md](README.md#prerequisites), then run:

- `pnpm install` - install workspace dependencies and hooks.

`pnpm sitecmd -- <arguments>` runs the shipped Rust CLI from this checkout, with
the pinned toolchain and the caller's working directory. For example:

```bash
pnpm sitecmd -- --version
pnpm sitecmd -- scan --url https://example.com
pnpm sitecmd -- audit . --format json
```

## Quality gates

- `pnpm test` - repository guardrail tests.
- `pnpm lint` - ESLint across the workspace.
- `pnpm format:check` - repository formatting.
- `pnpm guardrails:repo` - architecture, publication, and repository policy checks.
- `pnpm verify:push` - optional local verification. Run after committing to check commit and Rust toolchain policy.
- Lefthook runs the relevant subset on `pre-commit` and checks history sent to public remotes on `pre-push`.

Run direct Rust checks from the native workspace so rustup selects its pinned toolchain:

```bash
cd apps/desktop/src-tauri
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Branch + commit conventions

- Invited collaborators work from short-lived branches using `feature/`,
  `bugfix/`, `hotfix/`, `release/`, or `docs/` plus a short kebab-case name.
- Commit subjects use a capitalized imperative verb and a specific object, such
  as `Add verified site baselines` or `Update GitHub Actions dependencies`.
  Keep them to 10 words and 60 characters, with no type prefix, scope, ticket
  prefix, or ending punctuation. Bodies are optional and reserved for short,
  non-obvious reasoning rather than file lists or test output.
- Open a pull request against `main` in `brambleworks/SiteCMD-Local`. GitHub runs the required checks on the pull request. Approved pull requests merge by squash.

## What CI checks

- Repository tooling: ESLint, Vitest, and Knip.
- Rust: cargo fmt, clippy `-D warnings`, cargo test. Coverage snapshots are available on demand.
- Repository guardrails: `pnpm guardrails:repo`, which is where most conventions in this file are actually enforced.
- Release pipeline: builds CLI archives for macOS, Linux, and Windows; publishes to R2; gated on the knip export budget and repository guardrails.

## Architecture rules (the ones that bite if forgotten)

- All HTTP through `http_client::for_url(...)` - never `reqwest::Client::new()`. CI guardrail enforces this in `src/checks` and `src/core`.
- DB access through `db.execute(move |conn| ...)`. Never hold a Mutex across `.await`.
- The complete local workbench has no feature gate. Subscription tiers remain
  visible for connected-service and catalog entitlement, which the service
  enforces server-side.

## Where to find more

- `AGENTS.md` (root) - full architecture overview (the `CLAUDE.md` files are thin compatibility pointers to these).
- `apps/desktop/src-tauri/AGENTS.md` - Rust workspace guidance.
- `docs/README.md` - maintained engineering, product, QA, and operations documentation.

See [GOVERNANCE.md](GOVERNANCE.md) for decision-making and maintainer responsibilities.
