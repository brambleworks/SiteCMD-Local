# AGENTS.md

Canonical repository guidance for maintainers and coding agents. Read the
Rust workspace guide before editing that surface.

## Product contract

- **Web Scan** runs live-site checks. The CLI accepts the ten product category
  keys through `--categories`. Internal scan profiles use `scan_type`.
- **Code Scan** audits a linked source tree and returns `CodeScanReport` and
  `CodeIssue` data. It is separate from Web Scan.
- Local scans, issue detail, fix guides, prompts, and reports are free.
  Paid entitlement is enforced by the connected service.
- Product surfaces show one SiteCMD Score. Source-specific scores are
  historical engine data.

The CLI ships as `sitecmd` and runs Web Scan and the full Code Scan audit.

## Repository map

- `apps/desktop/src-tauri/`: CLI, runtime, protocol, and engine Cargo workspace.
- `docs/`: maintained engineering, product, QA, and operations truth.
- `packaging/npm/`: the @sitecmd/cli npm distribution skeleton. Binaries and
  real versions are stamped in only by the release workflow's publish-npm job;
  the checked-in packages stay on the 0.0.0-dev placeholder
  (guardrail-npm-cli-rules.mjs pins the shape).
- `tools/`: repository guardrails and release tooling.

The marketing site and connected-service workers live in the private
SiteCMD-Web repository. This repository does not import them.

Every surface asserting what's free, paid, or transmitted must appear in the
maintained-surface matrix.
Public documents must not link to private records.

Generated plans, review transcripts, design exports, browser captures, and
session artifacts are not committed. Promote durable conclusions into a
maintained document.

## Commands

Run commands from the repository root.

```bash
pnpm install

pnpm test
pnpm guardrails:repo:test
(cd apps/desktop/src-tauri && cargo test --workspace)

pnpm lint
pnpm format
pnpm guardrails:repo
pnpm knip
```

GitHub CI is required for merge. Run `pnpm verify:push` for optional local
verification.
`pnpm verify:push:all` reports every failing tier in one run.

Hooks are load-bearing. Pre-commit runs fast lint, format, Rust format,
and secret checks. Commit-msg enforces the plain-English message contract and
budget ratchet. Pre-push checks history sent to public remotes. Never bypass a
hook or guardrail without explicit permission.

## Architecture boundaries

### Data and scoring

- SQLite runs on its dedicated worker thread. Database closures are `move`, and
  no mutex is held across `.await`.
- SQL values use `rusqlite::params!` or named parameters, never interpolation.
- Session queries must not filter `session_id IS NULL`.
- Validate outbound targets through `network_policy::validate_url`.

### Shared sources

Use the existing authority instead of copying logic:

- HTTP clients: `http_client::for_local_scan`, `http_client::credentialed_service_client`, and `http_client::client`;
- outbound URL policy: `network_policy::validate_url`;
- sensitive-operation logging: `audit_log::record`;
- Code Scan path validation: `core::project_listing::list_project`;
- backend timeouts and tuning: `constants.rs`.

Guardrails reject common copies, including severity maps, score thresholds, ad-hoc HTTP clients, and inline
duration literals. Split code before raising a line budget. A legitimate budget
increase requires the documented `[budget-raised: reason]` commit trailer.

## Code and comment style

- Prefer clear names and structure over comments. Comments explain a
  non-obvious reason, invariant, or external contract.
- Keep implementation comments to one concise sentence when possible. Design
  history and incident narratives belong in maintained docs or Git history.
- Rust uses `//!` for module docs, `///` for item contracts, and `//` for local
  implementation notes. TypeScript uses `/** */` for exported API docs and `//`
  for implementation notes.
- Do not add decorative rulers, commented-out code, audit labels, dated
  postmortems, or references to superseded implementations.
- Tests communicate scenarios through names and assertions, not comment essays.
- Do not introduce U+2014 em dashes anywhere in code, comments, strings, or
  Markdown.

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

1. Branch names use `<type>/<short-kebab-case-description>` with one of
   `feature`, `bugfix`, `hotfix`, `release`, or `docs`. Add a ticket after the
   prefix when applicable.
2. Commit subjects use a capitalized imperative verb and specific object. Keep
   them to 10 words and 60 characters. Do not use Conventional Commit, scope,
   ticket, or colon prefixes. Keep any body short and limited to non-obvious
   reasoning.
3. Never push, change visibility, create or close issues or pull requests, or
   post externally without explicit permission.
4. Dependency overrides are a last resort. Prefer updating the parent
   dependency. Every override needs an advisory or `non-security:` rationale and
   a `# reviewed: YYYY-MM-DD` line. Avoid exact pins unless explicitly marked
   `pinned-exact:` and justified.

Open public pull requests against `main` in `brambleworks/SiteCMD-Local`.
GitHub runs the required checks on the pull request.

## Build constraints

- `whoami` v2 returns `Result<String, Error>`.
- RustCrypto `hmac` and `sha2` version changes require an explicit decision and
  re-verification of the OpenSSL webhook reference vectors.
