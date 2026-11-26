# AGENTS.md

Canonical repository guidance for maintainers and coding agents. This is the public repository
for the open `sitecmd` CLI. Read this file, then the guide for the area you edit; the index below
lists every guide.

## Product contract

- **Web Scan** runs live-site checks. The CLI accepts the ten product category
  keys through `--categories`. Internal scan profiles use `scan_type`.
- **Code Scan** audits a linked source tree and returns `CodeScanReport` and
  `CodeIssue` data. It is separate from Web Scan.
- Local scans, issue detail, fix guides, prompts, and reports are free.
  Paid entitlement is enforced by the connected service.
- Product surfaces show one SiteCMD Score. Source-specific scores are
  historical engine data.

The CLI ships as `sitecmd` and runs Web Scan and the full Code Scan audit. SiteCMD's checks run
in the sandboxed engine module, which is not in this repository; the CLI embeds the module that
`engine.lock` pins.

## Repository map

- `apps/desktop/src-tauri/`: the Cargo workspace for the CLI, runtime, protocol, and engine host.
- `docs/`: maintained engineering, product, QA, and operations truth.
- `packaging/npm/`: the @sitecmd/cli npm distribution skeleton. Binaries and
  real versions are stamped in only by the release workflow's publish-npm job;
  the checked-in packages stay on the 0.0.0-dev placeholder
  (`tools/scripts/lib/guardrail-npm-cli-rules.mjs` pins the shape).
- `tools/scripts/`: repository guardrails, publication checks, and release tooling.
- `.github/`: the CI workflows, the setup and gate Actions, release scripts, and repository
  settings contracts.
- `engine.lock`: the engine module's version, URL, and SHA-256. `pnpm engine:fetch` downloads
  the module into `engine/`.
- `install.sh`: the standalone installer that sitecmd.com/install.sh serves.

The engine module's source, the marketing site, and the connected-service workers live outside
this repository. This repository does not import them.

Every surface asserting what's free, paid, or transmitted must appear in the
maintained-surface matrix, `docs/engineering/connected-service/maintained-surfaces.md`.
Public documents must not link to private records.

Generated plans, review transcripts, design exports, browser captures, and
session artifacts are not committed. Promote durable conclusions into a
maintained document.

## Guides

Each guide has a `CLAUDE.md` beside it that contains only `@AGENTS.md`. When a change touches a
file that a guide lists under Guide triggers, review that guide in the same change.

| Area                             | Guide                                                 |
| -------------------------------- | ----------------------------------------------------- |
| Rust workspace                   | `apps/desktop/src-tauri/AGENTS.md`                    |
| CLI binary                       | `apps/desktop/src-tauri/crates/cli/AGENTS.md`         |
| Engine host and stand-in module  | `apps/desktop/src-tauri/crates/engine-host/AGENTS.md` |
| Protocol                         | `apps/desktop/src-tauri/crates/protocol/AGENTS.md`    |
| Runtime                          | `apps/desktop/src-tauri/src/AGENTS.md`                |
| Runtime commands                 | `apps/desktop/src-tauri/src/cli/AGENTS.md`            |
| Code Scan host and scan core     | `apps/desktop/src-tauri/src/core/AGENTS.md`           |
| Local database                   | `apps/desktop/src-tauri/src/db/AGENTS.md`             |
| Repository tooling               | `tools/scripts/AGENTS.md`                             |
| Documentation                    | `docs/AGENTS.md`                                      |
| CI, Actions, and release scripts | `.github/AGENTS.md`                                   |
| npm distribution                 | `packaging/npm/AGENTS.md`                             |

## Commands

Run commands from the repository root, on the Node version in `.nvmrc`.

```bash
pnpm install

pnpm test
pnpm lint
pnpm format
pnpm guardrails:repo
pnpm knip
```

`pnpm test` runs the guardrail tests (`pnpm guardrails:repo:test`). The Rust tests need the
stand-in module; `apps/desktop/src-tauri/AGENTS.md` has the commands.

GitHub CI is required for merge. Run `pnpm verify:push` for optional local
verification.
`pnpm verify:push:all` reports every failing tier in one run.

Hooks are load-bearing. Pre-commit runs fast lint, format, Rust format,
and secret checks. Commit-msg enforces the plain-English message contract and
budget ratchet. Pre-push checks history sent to public remotes. Never bypass a
hook or guardrail without explicit permission.

## Architecture boundaries

### Data and scoring

- SQLite runs on its dedicated worker thread (convention, not checked), and database closures
  must be `Send + 'static`, which the compiler enforces. No mutex guard is held across `.await`:
  Clippy's default `await_holding_lock`, under CI's `-D warnings`.
- SQL values use `rusqlite::params!` or named parameters, never interpolation (convention, not
  checked).
- Session queries must not filter `session_id IS NULL` (convention, not checked).
- Validate outbound targets through `network_policy::validate_url` (convention, not checked).

### Shared sources

Use the existing authority instead of copying logic:

- HTTP clients: `http_client::for_local_scan`, `http_client::credentialed_service_client`, and `http_client::client`;
- outbound URL policy: `network_policy::validate_url`;
- sensitive-operation logging: `audit_log::record`;
- Code Scan path validation: `core::project_listing::list_project`;
- backend timeouts and tuning: `apps/desktop/src-tauri/src/constants.rs`;
- severity and category vocabulary: `apps/desktop/src-tauri/crates/protocol/src/vocab.rs`.

Guardrails reject common copies, including ad-hoc HTTP clients and inline duration literals,
and pin the canonical severity and category helpers. Split code before raising a line budget. A
legitimate budget increase requires a `[budget-raised: <reason> (#123)]` line in the commit
message that names a tracked issue or pull request; `tools/scripts/check-budget-ratchet.mjs`
enforces it.

## Code and comment style

- Prefer clear names and structure over comments. Comments explain a
  non-obvious reason, invariant, or external contract (convention, not checked).
- Keep implementation comments to one concise sentence when possible. Design
  history and incident narratives belong in maintained docs or Git history
  (convention, not checked).
- Comments carry no filler phrases such as "basically" or "note that":
  `tools/scripts/lib/guardrail-comment-quality-rules.mjs`.
- Rust uses `//!` for module docs, `///` for item contracts, and `//` for local
  implementation notes. TypeScript uses `/** */` for exported API docs and `//`
  for implementation notes (convention, not checked).
- Do not add decorative rulers, commented-out code, audit labels, dated
  postmortems, or references to superseded implementations (convention, not
  checked).
- Tests communicate scenarios through names and assertions, not comment essays
  (convention, not checked).
- Do not introduce U+2014 em dashes anywhere in code, comments, strings, or
  Markdown. `tools/scripts/lib/guardrail-em-dash-rules.mjs` checks the guides,
  docs, tooling scripts, and Rust source.

## Process

### Agent context efficiency

- Search narrowly with `rg` before reading source; request only the relevant
  sections. Read applicable guidance once per task unless it changes.
- Keep routine tool output near 2,000 tokens. Save verbose test and build logs
  to a temporary file and inspect summaries or failure excerpts. Increase the
  output budget when correctness requires more context.
- Load only skills needed for the task. Use bounded specialist assignments only
  when delegation is requested; avoid broad agent fan-out for focused changes.
- Run the required checks after the final relevant edit. Repeat checks when a
  change or failure invalidates their results, not for unchanged progress updates.

### Delivery

1. Branch names use a type prefix and a short kebab-case description separated by a slash, with one of
   `feature`, `bugfix`, `hotfix`, `release`, or `docs`. Add a ticket after the
   prefix when applicable (convention, not checked).
2. Commit subjects use a capitalized imperative verb and specific object. Keep
   them to 10 words and 60 characters. Do not use Conventional Commit, scope,
   ticket, or colon prefixes. Keep any body short and limited to non-obvious
   reasoning. `tools/scripts/check-commit-message.mjs` enforces this in the
   commit-msg hook, and `tools/scripts/pr-title.mjs` checks pull request titles.
3. Never push, change visibility, create or close issues or pull requests, or
   post externally without explicit permission.
4. Dependency overrides are a last resort. Prefer updating the parent
   dependency. Every override needs an advisory or `non-security:` rationale and
   a `# reviewed: YYYY-MM-DD` line. Avoid exact pins unless explicitly marked
   `pinned-exact:` and justified. `tools/scripts/lib/guardrail-supply-chain-rules.mjs`
   enforces the rationale, review date, and exact-pin marker.

Open public pull requests against `main` in brambleworks/SiteCMD-Local.
GitHub runs the required checks on the pull request.

## Guide triggers

- `package.json`
- `pnpm-workspace.yaml`
- `lefthook.yml`
- `engine.lock`
