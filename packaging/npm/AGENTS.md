# npm distribution

The checked-in skeleton of the @sitecmd/cli npm distribution: one launcher package and one
platform package per release target. The binaries and the real version arrive only when the
release workflow publishes; in Git every package stays on the `0.0.0-dev` placeholder.

## Code map

- `cli/package.json`: the @sitecmd/cli manifest. Its `bin` entry for `sitecmd` points at
  `cli/bin/sitecmd.js`, and its `optionalDependencies` are the four platform packages.
- `cli/bin/sitecmd.js`: the launcher. It maps process.platform and process.arch to a platform
  package, resolves its binary, and runs it with the same arguments, exit status, and signal.
- `cli-darwin-universal/`, `cli-linux-x64/`, `cli-linux-arm64/`, `cli-win32-x64/`: the platform
  packages. Each manifest sets `os` and `cpu`, and an empty bin folder holds the binary's place.
- `*/README.md`: the npm page text for each package.

## Entry points

- `npx @sitecmd/cli <command>` or an installed `sitecmd` runs `cli/bin/sitecmd.js`.
- `/.github/scripts/release/publish-npm-packages.sh`, called by the release workflow, stages and
  publishes the packages.

## How it works

At publish time the script verifies each release archive against its `SHA256SUMS`, extracts the
binary and license files into the platform package, stamps the release version into every
package and into the launcher's `optionalDependencies`, and publishes with provenance. A version
npm already has is skipped, so a rerun repairs a partial publication. npm installs only the
platform package whose `os` and `cpu` match, and the launcher has no install scripts and
downloads nothing.

## Invariants

- The launcher package is @sitecmd/cli at `0.0.0-dev`, exposes `bin.sitecmd = bin/sitecmd.js`,
  lists exactly the platform packages at `0.0.0-dev`, and the launcher maps every one of them:
  `/tools/scripts/lib/guardrail-npm-cli-rules.mjs`.
- Every package's `license` is `SEE LICENSE IN LICENSE`:
  `/tools/scripts/lib/guardrail-npm-cli-rules.mjs`, tested by
  `/tools/scripts/guardrail-npm-cli-rules.test.mjs`.
- Only the release workflow's npm job may publish, through npm trusted publishing with no stored
  token: `/tools/scripts/lib/guardrail-release-rules.mjs`.

## Testing

From the repository root:

```bash
pnpm guardrails:repo
pnpm exec vitest run tools/scripts/guardrail-npm-cli-rules.test.mjs
```

## Boundaries

- The binaries are the signed CLI release archives built from
  `/apps/desktop/src-tauri/crates/cli/`; nothing is rebuilt for npm.
- `/README.md` documents `npx @sitecmd/cli`; `/install.sh` and `/.github/actions/setup-sitecmd/`
  are the other install paths.
- These directories are not pnpm workspace packages; `/pnpm-workspace.yaml` lists none.

## Guide triggers

- `cli/package.json`
- `cli/bin/sitecmd.js`
- `*/package.json`
- `../../.github/scripts/release/publish-npm-packages.sh`
