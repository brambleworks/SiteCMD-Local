# SiteCMD public repository and release security

**Status:** The checked-in tag-to-publication workflow is implemented. GitHub
rulesets, protected environments, secrets, and app settings are external state
that must be configured and rehearsed before publication. Reproducible builds,
SBOM generation, and isolated platform signing are future hardening work.

**Audience:** Maintainers configuring the public repository and release path.

The [release procedure](../operations/releasing.md) owns the exact commands. The
[publication checklist](../operations/publication-checklist.md) owns the history
replacement and GitHub-side cutover. This document explains the trust boundaries
those procedures establish.

## Implemented release model

Official releases start from a signed `v*` tag on protected `main`. The release
workflow binds artifact-producing and publication jobs to the tag's source
commit and candidate-manifest hash. Separate jobs build the CLI, handle
platform signing, sign updater artifacts, verify, and publish.

The current model provides:

- A release commit reviewed through the normal pull-request path
- A signed annotated tag verified against an externally configured signer list
- A release-specific hosted preflight before platform builds
- Updater-key and publication OIDC probe approvals before platform builds
- Platform signing approval after the builds, with signing credentials scoped
  to the separate signing jobs
- The production updater key isolated in its probe and minimal signer job
- Secretless verification of hashes, platform signatures, updater signatures,
  CLI version output, and packaged legal files
- Publication credentials isolated from build and signing jobs
- Immutable versioned objects followed by an atomic updater-manifest advance

Tag verification runs automatically before the builds. Human approval of
platform signing comes after the build artifacts exist and covers the protected
source commit and candidate manifest. The signing jobs can sign malicious bytes
from a compromised build. Artifact signatures attest to integrity under the
signing key. Independent reproducible builds are a separate milestone.

## Repository controls

Configure these controls before making the repository public:

- Require pull requests for `main`, including maintainer changes.
- Require resolved conversations, signed commits, linear history, and the
  repository's required checks.
- Apply the ruleset to administrators and block branch deletion and force pushes.
- Use squash merges and delete merged branches.
- Enable the merge queue. Every required workflow must subscribe to
  `merge_group` with `checks_requested`.
- Enable secret scanning, push protection, private vulnerability reporting,
  dependency review, CodeQL, and security advisories.
- Keep default `GITHUB_TOKEN` permissions read-only. Grant write permissions only
  to the job that needs them.

`.github/repository-protection.json` is the contract for the first three
bullets and the two rulesets; `pnpm protection:check` proves every required
check comes from a workflow that runs on every pull request, and
`pnpm protection:check:live` reads the repository through `gh api` and fails
on any drift. Run the live check after every settings change and quarterly.

There is no routine bypass. A break-glass action is limited to an active security
or release incident, must be recorded, and must restore the normal controls
before unrelated work continues.

`CODEOWNERS` covers repository automation, dependency policy, installers,
release tooling, signing configuration, Tauri capabilities, network policy,
credential handling, and privacy-sensitive code. With one maintainer, ownership
records responsibility but cannot provide independent approval. Once a second
qualified maintainer exists, require non-author code-owner approval for those
paths.

## Required checks

Pull requests and merge-queue candidates run deterministic checks for:

- Formatting, linting, TypeScript, and repository guardrails
- GitHub Actions syntax and expression validation
- Unit, integration, browser, Rust, MSRV, and build tests
- CodeQL, secret scanning, dependency advisories, licenses, and source policy
- Tauri command registration, capabilities, bundle size, and release invariants

`pnpm verify:push` is the local mirror and the primary gate every pushed commit
must pass. It is not a
substitute for protected repository settings. The release workflow repeats its
own critical checks so an explicitly pushed tag cannot publish unverified code.

Automated code review may supplement these checks, but the repository does not
currently require or claim a review bot.

## Dependency automation

Renovate owns JavaScript and Rust version updates. Dependabot owns GitHub Actions
pins. Both create pull requests; neither may update a protected branch directly.

Current Renovate policy permits auto-merge only for selected development-tool
groups and only for minor, patch, pin, or digest updates. Pre-1.0 packages,
major updates, the desktop runtime, TypeScript, Tauri, networking, serialization,
security-sensitive dependencies, vulnerability-alert pull requests, and workflow
updates require manual review.

Before enabling auto-merge publicly, test one real Renovate pull request against
signed-commit requirements, required checks, CODEOWNERS, and the merge queue.
GitHub's platform auto-merge must enqueue the pull request rather than bypass the
queue.

Security updates do not automatically cut a release. A maintainer evaluates the
advisory, merges the reviewed dependency pull request, and prepares an ordinary
patch release when shipped code is affected. The repository does not implement a
pending security-release set, debounce bot, or generated security-release pull
request.

## Release transaction

### 1. Prepare a release pull request

From a clean `release/*` branch, run `pnpm release`. The helper:

- Refuses `main` and a dirty worktree
- Updates every maintained version carrier
- Moves reviewed `Unreleased` notes into the versioned changelog section
- Leaves an unstaged, reviewable diff
- Never commits, tags, pushes, or publishes

Commit the result and merge it through the protected pull-request path.

### 2. Create the signed release tag

Update local `main`, then run `pnpm release:tag`. The helper requires local
`main` to equal the known `origin/main`, verifies version and changelog parity,
and creates a signed annotated tag. The maintainer verifies the tag and pushes
that exact tag explicitly.

Only strict semver `v*` tags trigger `.github/workflows/release.yml`.

### 3. Authenticate and preflight the source

The workflow verifies that the tag:

- Is strict semver and annotated
- Resolves to a commit on the default branch
- Is signed by an entry in the protected `RELEASE_ALLOWED_SIGNERS` value
- Matches the reviewed `.github/allowed-signers` file
- Names the same version as every release version carrier

The preflight then runs repository, dependency, Rust, JavaScript, CLI, test, and
build gates without publication credentials.

### 4. Create the immutable candidate

The secretless candidate job records:

- Repository, workflow run, tag, version, and protected source commit
- Default branch and workflow reference
- SHA-256 digests of the release workflow and JavaScript and Rust lockfiles
- Preflight status, tag date, and changelog release notes

The workflow hashes this JSON manifest. Every downstream job receives and
verifies the same candidate hash, source commit, and version.

The candidate does not contain an SBOM, SBOM diff, advisory summary, or included
pull-request manifest. SiteCMD does not claim that it does.

### 5. Build and sign on separate runners

The build jobs check out only the candidate commit, compile the CLI, and run
its version check without signing credentials. The `release-signing`
environment requires a human approval for the platform signing jobs.

Fresh runners verify the downloaded artifact digest and package the CLI
without executing it. The macOS runner signs and notarizes the binary, and
the Windows runner signs it with Azure Artifact Signing.

### 6. Sign updater artifacts in isolation

The platform signing jobs produce CLI archives before the isolated updater
signing job starts. That job pauses for approval in `release-updater-signing`
after the earlier probe and then proceeds as follows.

- Uses a sparse checkout containing only the release helpers and pinned signer
- Installs the signer with scripts disabled
- Verifies the candidate and every input hash before exposing the key
- Signs each exact CLI archive
- Signs one release-wide `SHA256SUMS` covering the archives
- Records candidate, source, and artifact hashes in the signed payload

This isolates the hardest-to-rotate credential from product build code. It does
not prove that the build produced safe bytes.

### 7. Verify without secrets

Separate macOS, Linux, and Windows jobs verify:

- Candidate and artifact hashes
- Updater signatures against the public key embedded in the app
- Native macOS and Windows signatures where applicable
- CLI archive structure, legal files, and `sitecmd --version`

The verifier has no signing or publication credentials.

### 8. Publish without executing artifacts

The `release-publish` job downloads only the candidate and verified signed
payload. It checks the tuple again, uploads immutable versioned objects to R2,
and advances the production updater manifest through the release administration
endpoint. It does not check out or execute product source.
It also creates the GitHub Release for the tag, carrying the changelog notes
and the signed `SHA256SUMS` and `SHA256SUMS.minisig`; the binaries stay on R2.
Finally it records a build provenance attestation for every published
artifact and the checksum manifest with `actions/attest-build-provenance`;
`gh attestation verify <file> --repo brambleworks/SiteCMD-Local` reads it. The
attestation names the workflow run that published the bytes. It is not a
reproducible-build proof.

Publication stops if a platform is missing, an existing immutable object has
different bytes, or any expected hash or signature differs.

## External configuration

The checked-in workflow is not operational until these protected environments
and values are configured and rehearsed. All five disable admin bypass and allow
only `v*` tags. The signing and publication environments require approval.

- `release-tag-trust`: the reviewed `RELEASE_ALLOWED_SIGNERS` variable, with no
  required reviewers
- `release-signing`: required human reviewer and platform signing credentials
- `release-updater-signing`: production updater key
- `release-publish`: R2 credentials; its jobs' OIDC tokens publish the updater
  manifest
- `npm-publish`: no secrets; each npm package's trusted publisher names it

Repository-level copies of release secrets must be removed. Use short-lived
provider identity where supported. Review environment access, rulesets, installed
apps, bypass lists, and signing keys quarterly and after each incident.

## Future hardening

The following are not part of the implemented baseline:

- Generating and publishing an SBOM and dependency diff
- Reproducible unsigned inputs from independent builders
- Human approval of exact unsigned artifact hashes
- Platform signing isolated from product build code
- External rebuild verification
- Automated release pull requests or debounced security-release scheduling

Implementing any item requires its own reviewed design, failure tests, operational
runbook, and accurate update to this document. Do not describe a future control
as active until the repository and external configuration can prove it.

## Publication acceptance

Before announcing the public repository, prove with test pull requests and a
disposable prerelease tag that:

- Direct pushes and failed required checks cannot land on `main`.
- Every required check reports on a merge-queue candidate.
- Sensitive and ineligible dependency updates cannot auto-merge.
- Pull-request and candidate jobs cannot read release credentials.
- Production signing waits for the configured human approval.
- Build jobs cannot publish or advance the updater manifest.
- A missing or invalid platform artifact prevents publication.
- The signed CLI installs and reports the expected version on supported systems.

The exact rehearsal and public-history replacement steps live in the
[publication checklist](../operations/publication-checklist.md).

## Related operations

- [Desktop release procedure](../operations/releasing.md)
- [Updater signing-key rotation](release-signing-key-rotation.md)
- [macOS code signing](macos-code-signing.md)
- [Windows code signing](windows-code-signing.md)
- [Security review cadence](security-review-cadence.md)
- [Launch smoke test](../operations/launch-smoke.md)
