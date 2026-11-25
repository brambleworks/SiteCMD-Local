# SiteCMD

[![Latest release](https://img.shields.io/github/v/release/brambleworks/SiteCMD-Local)](https://github.com/brambleworks/SiteCMD-Local/releases)
[![Source license](https://img.shields.io/badge/source%20license-Apache--2.0-blue)](LICENSE)

SiteCMD scans websites and source code for security, performance, SEO,
accessibility, compliance, and configuration issues.

## What ships

| Surface           | Purpose                                                                                                                                      | Account required                                         |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `sitecmd` CLI     | Code Scan and checks of a site on your own computer, hosted scans of your sites, machine-readable reports, git hooks, and connected CI gates | No for code audits and local sites; yes for public sites |
| Connected service | Hosted scheduled scans, deploy verification, alerts, shared reports, and baseline-aware CI decisions                                         | Yes                                                      |

The CLI in this repository audits code and checks a site on your own computer with no account.
Scans of public sites run on SiteCMD's hosted scanner, which the CLI calls when you're signed in.

## Install and try it

### The CLI

`sitecmd` scans local websites and source checkouts without an account.
Public sites use SiteCMD's hosted scanner. Run `sitecmd login` or set
`SITECMD_TOKEN` in CI, then scan a site in your account. Add `--latest` to
read the last finished hosted scan. npm carries the platform binary for macOS,
Linux (x86_64 and arm64), and Windows:

```bash
npx @sitecmd/cli audit .
npx @sitecmd/cli login
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

Additional command options are available with `sitecmd init --help`,
`sitecmd autofix --help`, `sitecmd fix --help`, `sitecmd watch --help`,
`sitecmd check --help`, and `sitecmd deploy --help`.

`sitecmd --help` lists the rest: `init`, `audit`, `rules`, `engine info`,
`autofix`, `scan`, `fix`, `watch`, `check`, `connected`, `deploy`, and `gate`.

`sitecmd login` signs in to SiteCMD on this computer, and `sitecmd logout`
signs out and revokes this computer's token. `sitecmd connect <url>` connects
a site's GitHub repository to SiteCMD.

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
`gh attestation verify <file> --repo brambleworks/SiteCMD-Local`. Releases
back-filled by hand before the workflow change carry none.

## Where your data lives

Source-processing code in this repository runs on the execution host: your
machine for the CLI, or the CI runner executing an action.
SiteCMD does not upload source code or raw file paths from that host to its
connected service. CLI reports, autofix artifacts, and published fix briefs
contain file and line metadata without source text or source-derived digests.
Human CLI summaries also omit excerpts. Code findings return the rule, file,
and line with SiteCMD's guidance. Report output published by a CI workflow is
handled by that CI provider. SiteCMD does not transmit scan findings to its connected service unless
you explicitly connect a site, which is off until you set it up.

That claim is checkable rather than asserted, which is the reason this
repository is public:

- The filesystem and network boundaries are in this source. Every file the
  code audit reads, every request the CLI makes and every byte it can send are
  decided by code here. SiteCMD's checks run in a compiled engine module with
  no imports, so it can't reach the network, your files or anything else on
  your machine; it sees only what this code hands it.
  [docs/engineering/engine-boundary.md](docs/engineering/engine-boundary.md)
  shows how to check that yourself.
- The sync payload builder is in this source too. `sitecmd connected --dry-run` renders a concrete snapshot with the same public
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
at all. The code that reads your files and makes network requests is here
under Apache-2.0. SiteCMD's checks aren't: on your machine they run inside a
sandboxed engine module compiled from SiteCMD's private source, and site scans
run on SiteCMD's infrastructure.

## Repo map

The root contains CI, shared tooling, and repository documentation.

```txt
apps/
  desktop/src-tauri/ Rust workspace for the CLI
.github/actions/
  setup-sitecmd/      GitHub Action: verify and install an exact CLI release
  sitecmd-gate/       GitHub Action: fail a PR on findings new against the
                      connected baseline
docs/                 Current engineering, product, QA, and operations docs
packaging/npm/        The @sitecmd/cli npm package and its per-platform binaries
tools/                Repository tooling and guardrail scripts
install.sh            The installer sitecmd.com/install.sh serves
```

The SiteCMD website and hosted services live outside this repository.

## Prerequisites

Toolchain versions are pinned in files rather than repeated here. External
utilities link to their installation instructions:

- Rust, on the toolchain `apps/desktop/src-tauri/rust-toolchain.toml` pins.
  rustup applies it automatically to any cargo work under that directory;
  local dev, `verify:push`, and the release build all read the same pin.
- Rust 1.95.0, installed with `rustup toolchain install 1.95.0`, for the MSRV
  checks mirrored by `verify:push` and CI.
- Node.js, on the version `.nvmrc` pins. CI workflows read the same file via
  `node-version-file`.
- pnpm, on the version the `packageManager` field in `package.json` pins
  (`corepack enable` makes that automatic).
- The [Gitleaks CLI](https://github.com/gitleaks/gitleaks#installing), required
  for local verification and publication-history secret scans.
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
pnpm test
pnpm sitecmd -- audit .
```

The checkout wrapper forwards CLI commands, including `scan`, `--help`, and
`--version`, to the Rust binary.

## Rust workspace

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

- Local Code Scan is free and needs no account, license, local database, or
  connected-service credential.
- The installed release runs as `sitecmd audit`; `pnpm sitecmd -- audit` is the
  source-checkout wrapper for contributors.
- Ordinary audits do not read local dotenv values or open database files or
  connections. `--inspect-local-databases` opts that run into local dotenv
  target discovery and read-only inspection of schema and migration metadata,
  never application table rows. SQLite targets must be inside the audited
  project; every PostgreSQL host must resolve to loopback or a local Unix
  socket. Remote targets are rejected.
- The public repository runs Code Scan on pull requests.

Live provider-format secrets are graded Critical in code only when the file is
in git's index. Untracked and ignored files retain their existing grade. When
tracking cannot be established, including missing git, a timeout, or a
foreign-owned checkout rejected by git, the audit keeps the existing grade
without reporting a tracking error. The hardened runner ignores global and
system git configuration, including their `safe.directory` entries.

### Listing Code Scan rules

`sitecmd rules [--format text|json]` lists every Code Scan rule from the same
registry the audit uses, sorted by `producerRuleId`. It reads no project and
requires no account or connection.

```bash
sitecmd rules
sitecmd rules --format text
sitecmd rules --format json
```

Use `sitecmd rules --help` or `sitecmd rules -h` for usage.

The default text output is a plain table. JSON output is exactly one object
with `version` (the CLI version) and a `rules` array. Every rule contains:

| Field             | Meaning                                                                                                                                |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `producerRuleId`  | The producer slug carried by audit findings.                                                                                           |
| `checkId`         | `code_scan.<producerRuleId>`, matching audit findings for every current registry rule.                                                 |
| `category`        | The category key carried by audit findings, one of the ten category keys.                                                              |
| `defaultSeverity` | The effective severity after the audit's built-in policy, or `null` when the registry leaves severity to the emitter.                  |
| `severitySource`  | `"fixed"` when the registry pins the grade; `"per_finding"` when the detector chooses the grade from evidence or at its emission site. |

No titles are emitted because the registry has no title field. Published audit
titles identify the rule without including source-derived wording. Rules without
a fixed registry grade are
shown as `null` with `severitySource: "per_finding"`; use each audit finding's
`severity` for its actual grade. Fixed rules have `severitySource: "fixed"`
and a non-null `defaultSeverity` matching the normalized audit grade. The text
table includes both fields as columns.
Allowed `category` values, in canonical order, are `security`, `domain_https`,
`email`, `seo`, `ai_visibility`, `performance`, `accessibility`, `privacy`,
`polish`, and `reliability`. Their labels are Security, Domain and HTTPS, Email,
SEO, AI visibility, Performance, Accessibility, Privacy and policies, Polish,
and Reliability. Web Scan uses the same keys with `sitecmd scan --categories
security,email` and `sitecmd fix --category email`. Non-null `defaultSeverity`
values are `critical`, `high`,
`medium`, and `low`. Text output prints null literally, for example:

```text
producerRuleId	checkId	category	defaultSeverity	severitySource
agent-instructions-stub	code_scan.agent-instructions-stub	reliability	null	per_finding
```

Successful listings exit 0. Invalid formats or arguments exit 2.

### Embedded engine

`sitecmd engine info [--json] [--save <path>]` prints the embedded engine's version,
SHA-256, ABI, import count, and exports. Use `--save` to write the embedded module
to a file.

### Acknowledging Code Scan findings

Commit reviewed suppressions in `.sitecmd/config.json`. A suppression may match
an exact canonical rule, a gitignore-style project-relative path, an occurrence
fingerprint from JSON output, or a combination of those fields. Published
fingerprints use rule, normalized path, and the finding's ordinal within that
rule and file, ordered by line. They use the `sitecmd/v3:sha256:` prefix and the
SARIF key `sitecmd/v3`; earlier baselines and suppressions must be regenerated.
Unrelated line shifts preserve fingerprints. Baselines and suppressions compare
per-rule, per-file counts, including line-less findings: growth reports extra
findings and shrinkage reports stale entries. A suppression's `count` defaults
to 1 per matching rule and file; fingerprint entries always have count 1.
Every entry requires a reason; `expires` is optional and uses `YYYY-MM-DD`.

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
current policy and quality checks.

Open a pull request against `main` in `brambleworks/SiteCMD-Local`. GitHub runs
the required checks on the pull request. Use `pnpm verify:push` for optional
local verification.

## License

Brambleworks-authored source in this repository is licensed under the
[Apache License 2.0](LICENSE). Release builds embed SiteCMD's engine module,
which isn't in this repository and is licensed under the SiteCMD Engine
Module License; see LICENSE. Bundled third-party material retains its own
license; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

SiteCMD names and logos are trademarks of Brambleworks LLC. The software
license does not grant trademark rights.
