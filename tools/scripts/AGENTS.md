# Repository tooling

Node scripts that keep this public repository honest: the static guardrails, the publication and
public-tree checks, engine module tooling, local verification, release preparation, and their
vitest suites. Maintainers and CI run them; nothing here ships in the CLI.

## Code map

- `check-repo-guardrails.mjs`: the guardrail runner behind `pnpm guardrails:repo`. It collects
  every failure from the rule modules and exits non-zero.
- `lib/guardrail-*.mjs`: the rule modules, one family each. `lib/guardrail-script-budgets.mjs`
  holds line budgets for these scripts; `lib/guardrail-text-utils.mjs` and
  `lib/guardrail-workflow-yaml.mjs` hold shared parsers.
- `*.test.mjs`: vitest suites. `repo-guardrail-*.test.mjs` plant regressions to prove each rule
  fails; `guardrail-test-support.mjs` holds their shared fixture helpers.
- `audit/`: standalone checks CI runs directly, such as `audit/check-agents-md.mjs`,
  `audit/forbid-adhoc-rust-patterns.sh`, `audit/check-rust-toolchain.mjs`, and
  `audit/check-rust-dependency-policy.mjs`.
- `check-publication-hygiene.mjs` with `lib/publication-hygiene-rules.mjs` and
  `lib/publication-root-files.mjs`: what the public snapshot may contain.
- `check-publication-history.mjs` with `lib/publication-history-rules.mjs`: before a push to a
  public remote (`--pre-push`) and on pull requests (`--pull-request`), refuses engine paths and
  engine crate names in the outgoing commits. In its other modes (`--all`, the default;
  `--candidate-main`; or one ref), it checks the paths in history and scans the reachable commits
  with Gitleaks. `run-public-tree-check.mjs`
  runs the base commit's copy of it in CI. `published-engine-moves.json` lists files approved to
  match a blob that once lived in the engine.
- `prepare-public-history.mjs`: the backup-first helper for the public history rewrite.
- `fetch-engine.mjs`, `verify-engine-pin.mjs`, `build-standin.mjs`, `lib/build-wasm-artifact.mjs`,
  `lib/wasm-build-settings.mjs`: fetch and pin the engine module, verify a binary's embedded pin,
  and build the stand-in module.
- `verify-push.mjs` and `verify-push-lib.mjs`: optional local verification in tiers.
- `sitecmd.mjs`: the checkout wrapper behind `pnpm sitecmd`. `cli-smoke.mjs`: the CLI smoke test.
- `release.mjs`, `tag-release.mjs`, `check-release-bump.mjs`, `check-changelog-notes.mjs`,
  `lib/version-files.mjs`: release preparation, signed tags, and changelog notes.
- `check-commit-message.mjs`, `check-budget-ratchet.mjs`, `pr-title.mjs`: commit message, budget
  ratchet, and pull request title checks.
- `check-workflows.mjs`, `check-repository-labels.mjs`, `check-repository-protection.mjs`: workflow
  syntax and the repository settings contracts in `/.github/`.
- `generate-third-party-artifacts.mjs`, `audit-regex.mjs`, `audit-rust-deps.mjs`,
  `check-knip-export-budget.mjs`: legal artifacts, regex safety, Rust advisories, and the knip
  export budget.
- `testdata/`: fixtures, including the `testdata/deny-wasi/` crates the WASI ban must reject.

## Entry points

The root `/package.json` scripts: `guardrails:repo`, `guardrails:repo:test`,
`guardrails:publication`, `guardrails:publication:history`, `engine:fetch`, `verify:push`,
`release`, `release:tag`, `sitecmd`, `legal:check`, `audit:regex`, `audit:deps`, `workflows:check`,
`labels:check`, `protection:check`, and `publication:prepare`. Lefthook (`/lefthook.yml`) runs
`check-commit-message.mjs`, `check-budget-ratchet.mjs`, and, before a push, the history check.

## How it works

Each rule module exports `<name>Failures(...)` that returns failure strings, and the runner
concatenates them. Rules read the tree through an I/O view, so tests can run them against an
overlaid fixture tree. The public tree check reads the guard from the pull request's base commit,
so a pull request cannot weaken the guard that judges it.

## Invariants

- A rule lands with a test that fails on a planted regression, in a `repo-guardrail-*.test.mjs`
  or `guardrail-*.test.mjs` suite, which `pnpm guardrails:repo:test` runs (convention, not
  checked).
- These scripts stay within their line budgets: `lib/guardrail-script-budgets.mjs`. Budgets only
  go down; a raise needs a `[budget-raised: <reason> (#123)]` line in the commit message, naming
  a tracked issue or pull request (`check-budget-ratchet.mjs`).
- ESLint covers every `.mjs` script here with js.configs.recommended and Node globals:
  `check-repo-guardrails.mjs` checks `/eslint.config.js`.
- The public tree guard's files must exist together in the base and head commits:
  `run-public-tree-check.mjs`.
- `AGENTS.md` files cite only existing paths and pnpm scripts: `audit/check-agents-md.mjs`.

## Testing

From the repository root on the Node version in `/.nvmrc`:

```bash
pnpm guardrails:repo:test
pnpm exec vitest run tools/scripts/<name>.test.mjs
pnpm guardrails:repo
pnpm guardrails:publication
```

Some suites need `cargo`, `git` history, or `minisign`; CI installs the pinned minisign with
`/.github/scripts/install-minisign.sh`. `pnpm guardrails:publication:history` needs the Gitleaks
CLI.

## Boundaries

- These checks read the whole tree: the Rust workspace, `/docs/`, `/.github/`, `/packaging/npm/`,
  and the root files.
- `fetch-engine.mjs` downloads the module that `/engine.lock` pins from releases.sitecmd.com, with
  a GitHub release fallback, and verifies its SHA-256; `--bump` also verifies its signature.
- CI runs these scripts from `/.github/workflows/ci.yml`; `/.github/ci-inventory.json` records which
  job runs each check.

## Guide triggers

- `check-repo-guardrails.mjs`
- `lib/guardrail-script-budgets.mjs`
- `check-publication-hygiene.mjs`
- `check-publication-history.mjs`
- `run-public-tree-check.mjs`
- `lib/publication-*.mjs`
- `verify-push.mjs`
- `fetch-engine.mjs`
- `build-standin.mjs`
- `audit/check-agents-md.mjs`
- `lib/guardrail-agent-guidance-rules.mjs`
- `../../package.json`
- `../../lefthook.yml`
