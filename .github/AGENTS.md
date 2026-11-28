# CI, Actions, and release scripts

GitHub configuration for this repository: the required `CI` workflow, the public composite
Actions that install the CLI and run the merge gate, the Bash steps of the release workflow, and
the settings contracts that tooling checks against the live repository.

## Code map

- `workflows/ci.yml`: the `CI` workflow. Its final `CI` job is the one required check; it passes
  only when every other job passed or was allowed to skip.
- `workflows/cache.yml`: warms the Rust and pnpm caches, including those used by the engine pin
  check, on `main` when dependency lockfiles or toolchains change.
- `workflows/module-pin.yml`: builds the CLI with the public engine module, verifies its embedded
  pin, and reports the module load time on all four runner platforms.
- `workflows/manual.yml`: an on-demand Rust coverage report.
- `workflows/weekly-advisories.yml`: the weekly dependency advisory audit.
- `workflows/release.yml`: verifies signed release tags, builds and signs the CLI, checks the
  embedded engine pin, and publishes the verified payload.
- `actions/setup-sitecmd/`: installs an exact CLI release after verifying its updater-key
  signature (`actions/setup-sitecmd/install.sh`, `actions/setup-sitecmd/updater-public-key.pub`).
- `actions/sitecmd-gate/`: fails a pull request on code findings that are new against the
  connected baseline, by running `sitecmd gate`.
- `scripts/release/`: the build, signing, and verification steps the release workflow calls.
- `scripts/install-minisign.sh`, `scripts/report-advisory-failure.sh`: CI helpers.
- `updater-signer/` and `updater-verifier/`: the pinned updater signer package and the secretless
  verifier crate used in releases.
- `ci-inventory.json`: which job and stage runs each check.
- `repository-protection.json` and `repository-labels.json`: the branch protection and label
  contracts.
- `allowed-signers`: the public mirror of the release tag signer list.
- `CODEOWNERS`, `dependabot.yml`, `actionlint.yaml`, `ISSUE_TEMPLATE/`,
  `pull_request_template.md`, `security-contact-key.asc`: ownership, Action updates, lint
  settings, issue forms, the pull request template, and the security contact key.

## Entry points

- `workflows/ci.yml` runs on `pull_request`, `merge_group`, and `workflow_dispatch`. The static,
  workflow lint, dependency path, and CodeQL jobs run on every event, and the dependency advisory
  job runs when dependencies change or on manual dispatch. The PR title and public tree jobs
  run only on pull requests. The CLI builds and smoke tests, guardrail tests, Rust tests and
  Clippy, doctests, and the 1.95 MSRV check run only in the merge queue and on manual dispatch.
- `workflows/module-pin.yml` runs on same-repository pull requests and pushes to `main` that
  change `/engine.lock`. It is a non-required check.
- `workflows/release.yml` runs on pushes of signed version tags from the protected default branch.
  See `/docs/operations/releasing.md` for environment setup, approval, and recovery.
- Users call the Actions from their own workflows with
  `uses: brambleworks/SiteCMD-Local/.github/actions/<name>@<full-release-commit-sha>`.
  Each Action's README shows the usage.

## How it works

Rust jobs build the stand-in with `node tools/scripts/build-standin.mjs` and set
`SITECMD_ENGINE_WASM` and `SITECMD_ENGINE_UNPINNED`, so CI never needs the engine module. The
public tree job runs only for pull requests in brambleworks/SiteCMD-Local; it runs the base
commit's copy of the history guard over the pull request's commits. The gate Action installs the
CLI with `actions/setup-sitecmd/install.sh`, writes the connection export to an owner-only
runner file, and runs `sitecmd gate` with the inputs as environment variables.

Release preflight and platform builds fetch the module pinned by `/engine.lock` with
`pnpm engine:fetch`. Each platform verifier checks the signed archive and embedded pin before
the checkout-free publisher uploads to R2, advances the release manifest with GitHub OIDC,
and creates the GitHub Release. The `publish-npm` job uses npm trusted publishing.

## Invariants

- Every third-party action is pinned to a commit SHA with an exact version comment (vX.Y.Z), and Rust is
  installed with rustup: `/tools/scripts/lib/ci-step-pins.mjs`.
- Runner labels are literal and versioned, never `-latest`: `/tools/scripts/lib/guardrail-workflow-pins.mjs`.
- Every CI check in `ci-inventory.json` names a real job, once:
  `/tools/scripts/lib/ci-inventory-rules.mjs`.
- Workflow permissions, triggers, and step rules: `/tools/scripts/lib/guardrail-workflow-rules.mjs`
  and `/tools/scripts/lib/guardrail-ci-workflow-rules.mjs`; syntax: `pnpm workflows:check`;
  security audit: the zizmor step in the workflow lint job.
- The gate Action's `ci-token` description names everything the token can do:
  `/tools/scripts/lib/guardrail-ci-credential-disclosure-rules.mjs`.
- No stored npm token or static release publishing key appears anywhere here; publishing uses
  OIDC: `/tools/scripts/lib/guardrail-release-rules.mjs`.
- `CODEOWNERS` covers every release, dependency, network, and privacy boundary:
  `/tools/scripts/lib/guardrail-codeowners-rules.mjs`.
- The installers stay valid shell and pass their tests: `pnpm installer:check`.
- The live protection and labels match the contracts: `pnpm protection:check:live` and
  `pnpm labels:check:live`, which a maintainer runs by hand; CI runs only the offline
  `pnpm protection:check` and `pnpm labels:check`.

## Testing

From the repository root:

```bash
pnpm workflows:check
pnpm guardrails:repo
pnpm installer:check
pnpm exec vitest run tools/scripts/actions-inputs.test.mjs tools/scripts/release-payload-scripts.test.mjs
```

`pnpm workflows:check` needs actionlint; see `/README.md` for the pinned version.

## Boundaries

- The Actions install releases from releases.sitecmd.com, signed with the updater key in
  `actions/setup-sitecmd/updater-public-key.pub`, the same key `/install.sh` uses.
- The gate Action calls the connected service through `sitecmd gate`, using the connection
  export and CI token that `sitecmd connect` writes to the user's repository secrets.
- The release workflow calls `scripts/release/` and publishes
  `/packaging/npm/` through npm trusted publishing.
- `/tools/scripts/` holds every script these workflows run.

## Guide triggers

- `workflows/*.yml`
- `actions/*/action.yml`
- `actions/setup-sitecmd/install.sh`
- `scripts/release/*.sh`
- `ci-inventory.json`
- `repository-protection.json`
- `CODEOWNERS`
- `repository-labels.json`
- `allowed-signers`
- `dependabot.yml`
