# SiteCMD

[![Code Scan](https://github.com/brambleworks/SiteCMD/actions/workflows/app-guardrails.yml/badge.svg?branch=main)](https://github.com/brambleworks/SiteCMD/actions/workflows/app-guardrails.yml)
[![CodeQL](https://github.com/brambleworks/SiteCMD/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/brambleworks/SiteCMD/actions/workflows/codeql.yml)
[![Latest release](https://img.shields.io/github/v/release/brambleworks/SiteCMD)](https://github.com/brambleworks/SiteCMD/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Desktop website health scanner and command center. SiteCMD scans websites and
linked codebases for security, performance, SEO, accessibility, compliance, and
configuration issues, ranks them by real risk, and hands the fix to the editor
or coding agent you already work in.

![SiteCMD desktop dashboard showing issues, updates, score, alerts, traffic, search, and deploy signals](https://sitecmd.com/images/features-hero-poster.png)

## What ships

| Surface           | Purpose                                                                                                  | Account required   |
| ----------------- | -------------------------------------------------------------------------------------------------------- | ------------------ |
| Desktop app       | Local website and source scanning, project history, correlations, reports, and fix guidance              | No                 |
| `sitecmd` CLI     | Local Web Scan and Code Scan, machine-readable reports, git hooks, and connected CI gates                | No for local scans |
| MCP server        | Gives supported AI coding tools local findings and fix briefs, then hands attempts back for verification | No                 |
| Connected service | Hosted scheduled scans, deploy verification, alerts, shared reports, and baseline-aware CI decisions     | Yes                |

The desktop app, CLI, and MCP server in this repository are the complete local
product. The connected service is a separate hosted product; local scan detail
is not withheld to create the paid tier.

## What it checks

One scan runs the engines below and merges everything they find into a single
ranked list, whether a finding came from the live site or the checkout behind
it.

| Engine        | Checks | Covers                                                                                                        |
| ------------- | -----: | ------------------------------------------------------------------------------------------------------------- |
| Web Scan      |    157 | Security headers and TLS, SEO, performance, accessibility, compliance, and configuration, against a live URL  |
| Code Scan     |    170 | Security, operations, architecture, supply chain, AI safety, and data handling, across a source checkout      |
| Accessibility |     55 | axe-core WCAG 2 Level A and AA rules, run against the rendered page                                           |
| Polish        |     30 | CSS architecture, HTML quality, copy, visual defaults, and framework leftovers that mark a page as unfinished |

Dependency findings resolve across 8 package ecosystems. Every count above is
derived from the registries themselves by `pnpm facts:generate`, published in
[product-facts.json](product-facts.json), and held to that file by a repository
guardrail.

## Install and try it

### The desktop app

Download it from [sitecmd.com/download](https://sitecmd.com/download). Release
builds support macOS 11 or later with Safari/WebKit 16.2 or later (Apple
silicon and Intel through one universal app), Windows 10 or later on x86_64
with WebView2 111 or later, and Ubuntu 22.04 or a compatible x86_64 Linux
distribution with WebKitGTK 2.40 or later as an AppImage.

[Get value in five minutes](docs/product/get-value-in-5-minutes.md) is the
shortest walkthrough, and [the MCP server README](apps/mcp-server/README.md)
puts the same findings inside an AI coding tool.

### The CLI

`sitecmd` runs a Web Scan against a live URL and the complete Code Scan against
a source checkout. Neither needs an account. npm is the quickest way to try
one, and carries the platform binary for macOS, Linux, or Windows:

```bash
npx @sitecmd/cli audit .
npx @sitecmd/cli scan --url https://example.com
```

Pin it as a dev dependency so CI and git hooks run the exact version your
lockfile names:

```bash
npm install --save-dev @sitecmd/cli
npx sitecmd audit . --format github --fail-on high
```

For a standalone binary on macOS or Linux, the installer is
[maintained in this repository](install.sh), authenticates the archive with the
public updater key, and verifies its SHA-256 checksum and reported version:

```bash
curl -fsSL https://sitecmd.com/install.sh | sh
```

To inspect it before running it:

```bash
curl -fsSLo sitecmd-install.sh https://sitecmd.com/install.sh
less sitecmd-install.sh
sh sitecmd-install.sh
```

The installer requires [Minisign](https://jedisct1.github.io/minisign/) and
accepts `SITECMD_VERSION` for a pinned release. It prints where it placed the
binary; if that directory is not on your `PATH`, run the `export` command it
prints. A signed Windows zip is linked from the
[CLI documentation](https://sitecmd.com/docs/cli).

`sitecmd --help` lists the rest: `init`, `audit`, `scan`, `fix`, `watch`,
`check`, `connected`, `deploy`, and `gate`.

## Verify your download

Every release attaches `SHA256SUMS` and its detached signature
`SHA256SUMS.minisig`, made with the SiteCMD updater key. It is the same key
[install.sh](install.sh) uses to authenticate what it installs:

```txt
RWTtzNh0gmMU/8O1AJBbQbUEy9oD5lpqL/dV0qRqlpsCldfWNWgxr5kE
```

Verify the manifest signature first, on macOS, Windows, or Linux:

```bash
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P RWTtzNh0gmMU/8O1AJBbQbUEy9oD5lpqL/dV0qRqlpsCldfWNWgxr5kE
```

Then check the file you downloaded against the manifest you just trusted.

On macOS:

```bash
shasum -a 256 -c --ignore-missing SHA256SUMS
```

On Linux:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

The macOS DMG is Apple-signed as well, and its checksum is listed in the same
manifest.

Releases published by the release workflow carry a Sigstore build-provenance
attestation; verify one with
`gh attestation verify <file> --repo brambleworks/SiteCMD`. Releases
back-filled by hand before the workflow change carry none.

## Where your data lives

Source-processing code in this repository runs on the execution host: your
machine for the desktop app and CLI, or the CI runner executing an action.
SiteCMD does not upload source code or raw file paths from that host to its
connected service. Report output that you configure a CI workflow to publish is
handled by that CI provider. Desktop integration credentials are stored locally
by the desktop app and sent only to the provider they authenticate, never to
SiteCMD. SiteCMD does not transmit scan findings to its connected service unless
you explicitly connect a site, which is off until you set it up.

That claim is checkable rather than asserted, which is the reason this
repository is public:

- The filesystem and network boundaries are in this source. What the scanner
  requests, what the code audit reads, and where either can send anything are
  all here to be read, and [sitecmd.com/trust](https://sitecmd.com/trust)
  names each fixed host and describes dynamic destinations by class.
- The sync payload builder is in this source too. The app's inspection view and
  `sitecmd connected --dry-run` render a concrete snapshot with the same public
  wire schema and serializer used for transmission, without sending it. The
  displayed bytes are the exact serialization of that inspected snapshot. A
  later sync rebuilds the payload from current local and connected state, so its
  values may have changed.
- Site operators reading SiteCMD's identity out of an access log get the same
  treatment at [sitecmd.com/scanner](https://sitecmd.com/scanner): every kind
  of request, why some look hostile, and how to block them.

## What is sold, and what is not

The paid product is the connected service: hosted scans between deploys,
deploy-anchored verification, baseline-aware regression alerting, and the CI
merge gate's server side. The line is not how much of the local product you
get; it is whether SiteCMD's servers have to exist for the capability to exist
at all. Code that runs on your machine is here under Apache-2.0. Code that runs
on SiteCMD infrastructure is not part of this repository.

## Repo map

This repository is a pnpm monorepo. The root contains orchestration, CI, shared
tooling, and repository documentation; deployable code lives under `apps/`.

```txt
apps/
  desktop/            Tauri v2 desktop app: React frontend + Rust backend
  mcp-server/         MCP server package
.github/actions/
  setup-sitecmd/      GitHub Action: verify and install an exact CLI release
  sitecmd-gate/       GitHub Action: fail a PR on findings new against the
                      connected baseline
docs/                 Current engineering, product, QA, and operations docs
packaging/npm/        The @sitecmd/cli npm package and its per-platform binaries
tools/                Repository tooling and maintained benchmarks
install.sh            The installer sitecmd.com/install.sh serves
```

The marketing site, the public scanner page, and the Cloudflare Workers live in
the separate SiteCMD-Web repository. `product-facts.json` publishes the values
that side has to restate accurately: check counts, the commercial boundary and
surface status, the Sentry ingest host, and the license-activation deep-link
scheme. Regenerate it with `pnpm facts:generate` after changing any of their
sources.

## Prerequisites

Toolchain versions are pinned in files rather than repeated here. External
utilities link to their installation instructions:

- Rust, on the toolchain `apps/desktop/src-tauri/rust-toolchain.toml` pins.
  rustup applies it automatically to any cargo work under that directory;
  local dev, `verify:push`, and the release build all read the same pin.
- Rust 1.89.0, installed with `rustup toolchain install 1.89.0`, for the MSRV
  checks mirrored by `verify:push` and CI.
- Node.js, on the version `.nvmrc` pins. CI workflows read the same file via
  `node-version-file`.
- pnpm, on the version the `packageManager` field in `package.json` pins
  (`corepack enable` makes that automatic).
- [Tauri's system dependencies for your OS](https://v2.tauri.app/start/prerequisites/),
  including the platform webview and native build tools.
- The [Gitleaks CLI](https://github.com/gitleaks/gitleaks#installing), required
  by the pre-push and publication-history secret scans.
- [cargo-audit](https://github.com/rustsec/rustsec/tree/master/cargo-audit),
  [cargo-deny](https://embarkstudios.github.io/cargo-deny/cli/index.html), and
  [cargo-nextest](https://nexte.st/docs/installation/pre-built-binaries/),
  required by the dependency and Rust test tiers in `verify:push`.
- [actionlint](https://github.com/rhysd/actionlint), installed with
  `go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`, for the
  workflow syntax tier in `verify:push`.

## Development

```bash
pnpm install
pnpm tauri:dev
```

Common root commands delegate into the right workspace:

```bash
pnpm dev
pnpm build
pnpm test
pnpm test:desktop
pnpm test:mcp
pnpm e2e
pnpm quality:mcp
pnpm sitecmd -- audit .
```

The checkout wrapper forwards CLI commands, including `scan`, `--help`, and
`--version`, to the Rust binary. To navigate an installed desktop app, use the
explicit checkout shortcut `pnpm sitecmd -- open dashboard`.

For a focused introduction to the scanner, follow
[Adding a detector](docs/engineering/adding-a-detector.md).

`pnpm build` builds the desktop web frontend and validates and bundles the MCP
server. It does not create a native desktop package. Contributors can build the
native app without an updater signing key with:

```bash
pnpm tauri:build:contributor
```

Tauri prints the generated artifact locations. `pnpm tauri:build:release` is
reserved for release operators with the required signing credentials.

Direct workspace examples:

```bash
pnpm --filter @sitecmd/desktop run tauri:dev
pnpm --filter sitecmd-mcp run test
```

The desktop app and the MCP server each document themselves through their own
`AGENTS.md`. Start there before changing either.

## Desktop app workspace

The desktop app lives in `apps/desktop/`.

```txt
apps/desktop/src/          React frontend
apps/desktop/src-tauri/    Rust backend, Tauri config, capabilities, CLI
apps/desktop/e2e/          Playwright smoke tests
```

Run the complete Rust workspace from its directory so rustup applies the pinned
toolchain:

```bash
cd apps/desktop/src-tauri
cargo test --workspace
```

## Code Scan audit

```bash
pnpm sitecmd -- audit .
pnpm sitecmd -- audit . --format review --output guardrails-review.md
pnpm sitecmd -- audit . --format github --fail-on high
pnpm sitecmd -- audit . --inspect-local-databases
```

- Local Code Scan is free and needs no account, license, desktop database, or
  connected-service credential.
- The installed release runs as `sitecmd audit`; `pnpm sitecmd -- audit` is the
  source-checkout wrapper for contributors.
- Ordinary audits do not read local dotenv values or open database files or
  connections. `--inspect-local-databases` opts that run into local dotenv
  target discovery and read-only inspection of schema and migration metadata,
  never application table rows. SQLite targets must be inside the audited
  project; every PostgreSQL host must resolve to loopback or a local Unix
  socket. Remote targets are rejected.
- CI guardrails live in `.github/workflows/app-guardrails.yml`.

### Acknowledging Code Scan findings

Commit reviewed suppressions in `.sitecmd/config.json`. A suppression may match
an exact canonical rule, a gitignore-style project-relative path, an occurrence
fingerprint from JSON output, or a combination of those fields. Every entry
requires a reason; `expires` is optional and uses `YYYY-MM-DD`.

```json
{
  "version": 1,
  "url": "https://example.com",
  "name": "Example",
  "code_scan": {
    "suppressions": [
      {
        "match": {
          "path": "examples/**",
          "rule": "code_scan.tls-verification-disabled"
        },
        "reason": "The insecure client is an instructional fixture."
      }
    ]
  }
}
```

Suppression counts remain visible in every report, and ignored findings do not
count toward `--fail-on`. JSON output includes active-finding fingerprints,
full `ignoredFindings` records, and the state of every configured suppression.
Unmatched and expired entries are reported as stale policy so obsolete
acknowledgements can be removed. The same policy is applied before `sitecmd
gate` or a connected CI submission builds its code snapshot.

## The CI gate

`sitecmd gate` audits the checkout in front of it and asks the connected
service which findings are new against the site's baseline, and only those: a
repository that has carried a finding for a year does not start failing because
someone touched an unrelated file. The
[GitHub Action](.github/actions/sitecmd-gate/README.md) wraps it for pull
requests. Both need a site connected to the connected service.

## Documentation

- [Documentation index](docs/README.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)

Repository documentation describes current behavior and accepted decisions.
Generated plans, review transcripts, design-tool exports, browser captures, and
other session artifacts are not committed. How AI coding agents are
directed here, and what automated review does and does not stand in for, is
documented in
[AI-assisted development](docs/engineering/ai-assisted-development.md).

## Contributing

Issues and discussion are open. Unsolicited code contributions are not accepted
yet, and pull requests are limited to invited collaborators while the public
maintenance process is established; [CONTRIBUTING](CONTRIBUTING.md) has the
current policy and the local quality gates.

## License

Brambleworks-authored source is licensed under the
[Apache License 2.0](LICENSE). Bundled third-party material retains its own
license; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

SiteCMD names and logos are trademarks of Brambleworks LLC. The software
license does not grant trademark rights.
