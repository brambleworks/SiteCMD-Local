# AGENTS.md

Canonical repository guidance for maintainers and coding agents. Directory-level
guides add rules for the desktop frontend, Rust backend, and MCP server. Read the
applicable guide before editing that surface.

## Product contract

SiteCMD is a local-first website command center built with Tauri v2, Rust,
React 19, TypeScript, and an authored CSS design-token system.

- **Web Scan** runs live-site checks. Its `scan_type` is a category filter:
  `health`, `security`, `accessibility`, or `polish`.
- **Code Scan** audits a linked source tree and returns `CodeScanReport` and
  `CodeIssue` data. It is separate from Web Scan.
- Frontend modes map as follows: `web` runs a health Web Scan, `code` runs Code
  Scan, and `full` runs Web Scan followed by Code Scan when a source folder is
  linked.
- The complete local workbench is free. Local scans, issue detail, fix guides,
  prompts, reports, and dossier data are never tier-gated. Paid entitlement is
  enforced by the connected service. `Tier` remains for subscription display
  and connected or catalog credentials only.
- Product surfaces show one SiteCMD Score. Rust computes it once from canonical,
  lifecycle-filtered issue groups. Source-specific scores are historical engine
  data, not competing product scores.

The standalone CLI is a separate headless Rust package. It and the desktop depend
on `sitecmd-runtime`; Tauri adapters remain in the desktop package. See
`docs/engineering/native-runtime-boundary.md` for source ownership. It ships as `sitecmd`
and must run Web Scan and the full Code Scan audit without Tauri or a GUI.

## Repository map

- `apps/desktop/`: Tauri desktop app. Read its frontend guide and the nested
  Rust guide as appropriate.
- `apps/mcp-server/`: private Node MCP package bundled with the desktop app.
  Read its local guide before changing tools or database access.
- `docs/`: maintained engineering, product, QA, and operations truth.
- `packaging/npm/`: the @sitecmd/cli npm distribution skeleton. Binaries and
  real versions are stamped in only by the release workflow's publish-npm job;
  the checked-in packages stay on the 0.0.0-dev placeholder
  (guardrail-npm-cli-rules.mjs pins the shape).
- `tools/`: repository guardrails, release tooling, and benchmark support.

The marketing site and connected-service workers live in the private
SiteCMD-Web repository. This repository does not import them.

`product-facts.json` is the generated cross-repository facts channel. Regenerate
it with `pnpm facts:generate`. Do not add prices or local feature limits to it.
Every surface asserting what is free, paid, or transmitted must appear in the
maintained-surface matrix. Business strategy stays in the private repository;
public documents must not link to private records.

Generated plans, review transcripts, design exports, browser captures, and
session artifacts are not committed. Promote durable conclusions into a
maintained document.

## Commands

Run commands from the repository root.

```bash
pnpm install
pnpm tauri:dev
pnpm tauri:build:contributor

pnpm test
pnpm test:desktop
pnpm test:mcp
pnpm guardrails:repo:test
pnpm e2e
cargo test --workspace --manifest-path apps/desktop/src-tauri/Cargo.toml

pnpm typecheck
pnpm lint
pnpm format
pnpm guardrails:repo
pnpm knip
```

`pnpm verify:push` is the primary local pre-push gate. It includes the declared
Rust MSRV and dependency-policy checks, while GitHub adds platform builds,
CodeQL, and scheduled jobs that cannot be reproduced by one local command. Run
it after committing, not as a pre-commit check. `pnpm verify:push:all` reports
every failing tier in one run.

Hooks are load-bearing. Pre-commit runs fast type, lint, format, Rust format,
and secret checks. Commit-msg enforces the plain-English message contract and
budget ratchet. Pre-push runs the full gate. Never bypass a hook or guardrail
without explicit permission.

## Architecture boundaries

### Tauri IPC

Every custom command requires all three registrations:

1. the `#[tauri::command]` function;
2. the `invoke_handler!` entry in `lib.rs`; and
3. the command name in `build.rs` `APP_COMMANDS`.

Grant the generated permission in the narrowest capability. Destructive data,
filesystem, external-connector, and project-execution commands stay behind the
privileged-command bridge and feature-scoped capabilities. Hidden analyzer
webviews receive no command capability.

All third-party API calls go through Rust. The renderer never holds service
credentials or calls external APIs directly. CSP and Tauri capabilities remain
least-privilege.

Backend events are registered in the typed event taxonomy. React subscriptions
use `useTauriEvent`; do not add raw listeners outside the documented imperative
exceptions.

### Data and scoring

- SQLite runs on its dedicated worker thread. Database closures are `move`, and
  no mutex is held across `.await`.
- SQL values use `rusqlite::params!` or named parameters, never interpolation.
- Session queries must not filter `session_id IS NULL`.
- Scan cancellation uses `ScanControlState`, never thread termination.
- Issue state lives in `project_issue_states`. Use the typed ignore, block,
  snooze, reopen, and verify transitions; there is no `dismiss_issue` command.
- Rust `compute_current_score` is the only SiteCMD Score authority. The
  TypeScript score module is presentation and ranking only.
- Correlation is computed in Rust and persisted. The MCP server reads the stored
  result and generated causal assets; the frontend must not build a parallel
  correlation cache.

### Shared sources

Use the existing authority instead of copying logic:

- time formatting: `apps/desktop/src/lib/format.ts`;
- severity ordering and tones: `apps/desktop/src/lib/severity.ts`;
- score bands and labels: `apps/desktop/src/lib/score.ts`;
- navigation state: `apps/desktop/src/app/useNavigationState.ts`;
- command error redaction: `commands::sanitize_error`;
- HTTP clients: `http_client::for_url`;
- outbound URL policy: `network_policy::validate_url`;
- sensitive-operation logging: `audit_log::record`;
- webhook signing: `webhooks::compute_webhook_signature`;
- Code Scan path validation: `core::code_scan::validate_project_path`;
- frontend progress bars: `components/ui/progress-bar.tsx`;
- backend timeouts and tuning: `constants.rs`.

Guardrails reject common copies, including inline time arithmetic, severity
maps, score thresholds, ad-hoc HTTP clients, broker bypasses, and inline
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

## Frontend requirements

Read the desktop guide and component guide before writing markup.

- Component classes live in `src/styles/*.css` partials. `index.css` imports
  them and is not the component source of truth.
- Use the shared `Button`; do not hand-roll clickable buttons or reintroduce
  CVA.
- No inline `style` attributes except the allowlisted `progress-bar`,
  `score-ring`, and `ReportPDFSections` components (see the desktop guide).
- No hardcoded hex colors. Use tokens.
- Extract a pattern when it appears twice.
- Spell out Accessibility. Never use the abbreviation `a11y`.

## Process

1. Restart `pnpm tauri:dev` after Rust changes. Frontend changes hot-reload.
2. Branch names use `<type>/<short-kebab-case-description>` with one of
   `feature`, `bugfix`, `hotfix`, `release`, or `docs`. Add a ticket after the
   prefix when applicable.
3. Commit subjects use a capitalized imperative verb and specific object. Keep
   them to 10 words and 60 characters. Do not use Conventional Commit, scope,
   ticket, or colon prefixes. Keep any body short and limited to non-obvious
   reasoning.
4. Never push, change visibility, create or close issues or pull requests, or
   post externally without explicit permission.
5. Dependency overrides are a last resort. Prefer updating the parent
   dependency. Every override needs an advisory or `non-security:` rationale and
   a `# reviewed: YYYY-MM-DD` line. Avoid exact pins unless explicitly marked
   `pinned-exact:` and justified.

## Build constraints

- Test production changes to Vite chunking with `pnpm tauri:build:contributor`.
  It skips updater artifacts, so it finishes without the updater signing key;
  `pnpm tauri:build:release` needs `TAURI_SIGNING_PRIVATE_KEY` and is for
  official release operators only.
- `whoami` v2 returns `Result<String, Error>`.
- RustCrypto `hmac` and `sha2` version changes require an explicit decision and
  re-verification of the OpenSSL webhook reference vectors.
- Window close hides the app to the tray. Only the tray Quit action exits.
