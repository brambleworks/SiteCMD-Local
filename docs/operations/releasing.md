# Releasing the CLI

How to prepare a CLI release through a protected pull request, create the
signed tag on the merged commit, and read download / install numbers afterward.
The push that actually ships is deliberately manual.

> **First-publication boundary.** The existing repository will be rewritten in
> place before its visibility changes. Follow the
> [public repository cutover](publication-checklist.md). The local helper is
> backup-first and never pushes, deletes refs, or changes visibility. A root
> commit alone is insufficient while an old remote branch, tag, release,
> artifact, or GitHub-side record still exposes private history.

## One-time release trust setup

The workflow fails closed until tag trust and four GitHub environments are
configured. For the full tag-signing setup, the local proof steps, and
troubleshooting, follow
[release-tag-signing.md](../engineering/release-tag-signing.md); the summary
below is the short version.

Create a release-only SSH signing key outside the repository and commit only its
public key. Append, never overwrite: `>` silently drops whichever key is already
trusted, and every tag that key signed stops verifying.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/sitecmd_release_signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/sitecmd_release_signing.pub
printf '%s %s\n' "$(git config user.email)" \
  "$(cat ~/.ssh/sitecmd_release_signing.pub)" >> .github/allowed-signers
```

The principal in `.github/allowed-signers` must match the tagger email. Protect
and back up the private key separately. A release tag signed by any other key is
rejected.

### Publishing the trust list to CI

CI does not use `.github/allowed-signers` as its trust authority. The file is
the public review mirror; the tag gate normalizes it, requires it to match the
protected environment variable, and verifies the tag with the protected copy.

The reason is that the tag gate authenticates a commit, and it used to read the
signer list out of that commit's own checkout. Anyone able to land a commit on
`main` could append a key, sign a tag with it, and pass verification, which
made the gate prove only that a tag agreed with itself. A variable scoped to a
deployment environment is not editable by a commit, and a workflow edited to
drop the `environment:` line loses the value and fails closed.

One-time setup, and again after any key rotation:

1. Create a `release-tag-trust` environment on the repository. It holds this one
   variable and no secrets, so it grants nothing beyond the signer list.
2. Publish the file's contents into it:

```bash
gh variable set RELEASE_ALLOWED_SIGNERS \
  --env release-tag-trust -R brambleworks/SiteCMD-Local \
  --body "$(cat .github/allowed-signers)"
```

Skipping this fails the tag gate with `RELEASE_ALLOWED_SIGNERS is not set` or a
trust-list mismatch before any billable build work starts.

### Rotating the signing key

Replacing the key is the same append, plus one edit: bound the outgoing key with
`valid-before` instead of deleting its line.

```txt
admin@brambleworks.com valid-before="YYYYMMDD" ssh-ed25519 AAAA...outgoing...
admin@brambleworks.com ssh-ed25519 AAAA...current...
```

Git checks `valid-before` against the signature's own timestamp, not the clock,
so the retired key keeps verifying the tags it already signed and can authorize
nothing dated later. Use the rotation date; tags predate it, the new key does
not.

If the outgoing public key is no longer on disk, recover it from a tag it
signed. The SSHSIG blob carries the signer's public key:

```bash
git cat-file tag vX.Y.Z | awk '/BEGIN SSH SIGNATURE/,/END SSH SIGNATURE/' |
  grep -v -- '-----' | base64 -d |
  python3 -c 'import sys,struct,base64
b=sys.stdin.buffer.read(); o=10
n=struct.unpack(">I",b[o:o+4])[0]; k=b[o+4:o+4+n]
t=struct.unpack(">I",k[0:4])[0]
print(k[4:4+t].decode(), base64.b64encode(k).decode())'
```

Confirm the result before trusting it: every signed tag must verify, and a
signature made now must still verify.

```bash
for t in $(git tag --list 'v*'); do
  git cat-file tag "$t" 2>/dev/null | grep -q 'BEGIN SSH SIGNATURE' &&
    { git verify-tag "$t" >/dev/null 2>&1 && echo "$t OK" || echo "$t FAIL"; }
done
```

Configure these GitHub environments:

| Environment               | Protection                                                                           | Values                                                                                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `release-tag-trust`       | Deployment tags limited to `v*`; protected from workflow-authenticated writes        | `RELEASE_ALLOWED_SIGNERS`, matching `.github/allowed-signers`                                                                             |
| `release-signing`         | One required reviewer, admin bypass disabled, deployment tags limited to `v*`        | Apple credentials and Azure secrets                                                                                                       |
| `release-updater-signing` | Deployment tags limited to `v*`; holds the signing key probe and the isolated signer | `TAURI_SIGNING_PRIVATE_KEY` and its optional password                                                                                     |
| `release-publish`         | Deployment tags limited to `v*`; no reviewer or timer                                | `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, and `R2_SECRET_ACCESS_KEY`; no releases-worker key, because publishing presents the job's OIDC token |
| `npm-publish`             | Deployment tags limited to `v*`; no reviewer or timer                                | None; npm trusted publishing accepts the `publish-npm` job's OIDC token ([npm credential](#npm-credential))                               |

Put `AZURE_SIGN_ENDPOINT`, `AZURE_SIGN_ACCOUNT`, and `AZURE_SIGN_PROFILE` in the
`release-signing` environment as variables. Move the listed secrets out of
repository scope after the environments work. Duplicate repository secrets
defeat the intended boundary.

Configure `SITECMD_ENGINE_TOKEN` as a repository Actions secret with read
access only to `brambleworks/SiteCMD-Engine-Releases`. The token is scoped to
each fetch step. Without it, the fetch starts with the public module URL.

While there is one maintainer, leave "prevent self-review" disabled on
`release-signing`; otherwise the person who starts the release cannot approve
it. Add a second reviewer and enable non-author review when a second qualified
maintainer exists.

On GitHub Free, Pro, and Team plans, required reviewers are available for
public repositories only (the API answers 422 for a private repository; only
Enterprise lifts this). Deployment branch and tag policies do work on private
repositories with Pro or Team, so the `v*` restrictions and the tag-protection
ruleset are the enforceable subset until the repository is public, where every
protection rule above is free.

Before the first real release, run a disposable prerelease tag through the
workflow, confirm every environment gate and failure path, and withdraw the
prerelease without advancing stable clients.

## Verify release readiness

Run `pnpm verify:push` on the release commit. The protected `main` commit must
also have a green Code Scan workflow at the High severity threshold. Confirm an
automatic or scheduled Code Scan Postgres Integration run covers the latest
database-inspection changes; manually dispatch it when no qualifying run does.

## Cut a release

```bash
git switch -c release/vX-y-z
pnpm release <patch|minor|major|X.Y.Z>
git diff --check
git add CHANGELOG.md apps/desktop/src-tauri/crates/cli/Cargo.toml \
  apps/desktop/src-tauri/crates/runtime/Cargo.toml \
  apps/desktop/src-tauri/Cargo.lock
git commit -S -m "Prepare vX.Y.Z"
# Push the branch and merge it through the protected pull-request path.
git switch main
git pull --ff-only origin main
pnpm release:tag
git tag --verify vX.Y.Z
# This explicit tag push starts the production release workflow.
git push origin vX.Y.Z
```

`pnpm release` (`tools/scripts/release.mjs`):

- Requires a clean working tree on a `release/*` branch and refuses `main`.
- Bumps every release version carrier: the runtime and CLI Cargo manifests
  and the Cargo lockfile.
- Freezes the `Unreleased` changelog entries into `## [X.Y.Z] - YYYY-MM-DD`
  and leaves a new empty `Unreleased` section for the next release.
- Stops with an unstaged, reviewable version-and-changelog diff. It never
  commits, tags, or pushes. Commit that diff on the release branch and merge it
  through the protected pull-request path.

Flags: `--dry-run` (preview, writes nothing) and `--force-patch "<reason>"`
(override the patch veto below). There is no main-branch or direct-commit
override. `patch`/`minor`/`major` bump the current version; or pass an exact
`X.Y.Z` (prerelease suffixes like `1.2.0-rc.1` are allowed).

`pnpm release:tag` (`tools/scripts/tag-release.mjs`) is the separate post-merge
step. It requires a clean local `main` whose `HEAD` exactly equals the locally
known `origin/main`, verifies that all version files agree and the versioned
changelog section exists, then creates a signed annotated `vX.Y.Z` tag carrying
those notes. It never commits, fetches, pulls, or pushes. This separation makes
it impossible for the preparation helper to tag the pre-review branch commit.

## Choosing patch vs minor

Ask one question: **would you write a release note about it?**

- **patch** - the app looks and behaves the same, it just works correctly. Bug
  fixes, perf, dependency patches, internal refactors. Every changelog line
  reads "fixed X."
- **minor** - the user sees something new or different, but nothing they relied
  on broke. Any line reads "now does Z" or "Z changed."
- **major** - something they depended on is gone or works incompatibly.

Two tiebreakers override the judgment call: **new database migrations** (the app
persists something it did not before) and **a user-facing number changing** (they
will notice and will not know why).

`pnpm release patch` enforces the floor automatically via
`tools/scripts/check-release-bump.mjs`. It diffs the range since the last `v*`
tag and refuses a patch when any of these fire:

| Tripwire           | Detects                                                       |
| ------------------ | ------------------------------------------------------------- |
| new persisted data | an **added** `apps/desktop/src-tauri/src/db/migrations/*.sql` |

Private release checks also cover changes to the module's scoring and product contracts.

The check is deliberately one-directional. These diffs prove a release is _at
least_ a minor; nothing can prove the inverse, since a one-line change inside an
analyzer can alter every user's results while touching none of these paths. So
it is a veto on `patch`, never an automatic bump picker: it removes the
unrecoverable mistake (shipping a behavior change as a patch, which the
never-retag rule means you cannot walk back) and leaves "is this really only
fixes?" to you.

The emphasised words above are load-bearing. Matching every edit under `pages/`
or any touch of an existing page would fire on nearly every release,
and a guardrail that always fires is one you learn to ignore.

If the veto is genuinely wrong, override it on the record:

```bash
pnpm release patch --force-patch "why this is genuinely only fixes"
```

The reason is validated (placeholders and one-word answers are rejected),
printed with the prepared diff, and must be copied into the release pull
request so the reviewed record explains the classification.

The command requires local SSH signing configuration that matches
`.github/allowed-signers`. The release commit is signed through the ordinary
review workflow, and `pnpm release:tag` stops before pushing if signed-tag
creation fails. Inspect `git status` and the tag list, then verify the tag with
`git tag --verify vX.Y.Z` before the explicit tag push.

## Prepare the in-place public root

This is a one-time cutover operation, not part of an ordinary release. Follow
the complete [public repository cutover](publication-checklist.md). The first
command is a read-only dry run:

```bash
pnpm publication:prepare -- \
  --backup /absolute/private/path/sitecmd-before-publication.bundle
```

Apply mode requires both `--apply` and `--confirm-rewrite-main`. It verifies an
external all-ref bundle before moving local `main` to a signed root commit with
the exact approved tree. The checklist owns remote cleanup, clean-clone proof,
the visibility change, and restoration of GitHub rulesets.

## Bump the pinned engine

Set `ENGINE_MINISIGN_PUBLIC_KEY` in `tools/scripts/fetch-engine.mjs` to the
engine release public key before the first bump. With `minisign` installed,
run these commands from the repository root.

```bash
pnpm engine:fetch -- --bump <version>
pnpm legal:generate
```

The bump verifies signatures for the module and its licenses, updates
`engine.lock` and `engine/local-engine.wasm.LICENSES.txt`, and stages the
module locally. Include the lock, license sidecar, and regenerated legal
artifacts in the pin change. The engine pin workflow builds and checks the CLI
on macOS, Linux x86_64, Linux arm64, and Windows and reports the module load
time on each runner.

## What the signed tag triggers

Pushing a `v*` tag runs `.github/workflows/release.yml`.

1. **Tag verification** checks the version format, annotated tag signature,
   trusted signer, and ancestry from the repository default branch.
2. **Preflight** fetches the module pinned in `engine.lock` and checks its
   digest. It runs dependency audits, repository guardrails, legal artifact
   checks, Rust tests, clippy, and formatting. It runs workspace tests with
   the pinned module and replays them with the stand-in.
3. **Candidate preparation** verifies the source version and binds the source
   commit, workflow hash, lockfile hashes, engine version and digest, changelog
   notes, and publication date into an immutable manifest.
4. **Human approval** pauses the `release-signing` environment. Check the
   candidate manifest hash, source commit, and engine pin before approval.
5. **Platform builds** fetch the pinned module and build CLI archives for
   macOS universal, Linux x86_64, Linux arm64, and Windows x86_64. Apple
   signing and notarization and Azure Authenticode signing apply to the CLI.
6. **Archive signing** validates and stages the allowlisted payload before
   passing the production key to the isolated signer. It signs each CLI archive
   and one release-wide `SHA256SUMS`. The decoded `SHA256SUMS.minisig` is
   the detached signature read by `minisign -V`.
7. **Secretless verification** checks payload hashes, provenance, archive
   signatures, CLI versions, platform signatures, and the embedded engine pin
   in every archive, including both macOS architectures.
8. **Publication** begins after every verifier passes. A checkout-free job
   hash-compares existing objects before uploading to R2, advances the
   release manifest with an OIDC token, and creates the GitHub Release with
   changelog notes, the engine version and digest, and the signed checksum
   manifest. It attests build provenance and checks every public object and
   the advertised latest version. The npm job publishes the verified binaries.

The candidate check now forces the tag, source files, and protected commit to
agree. The version-sync guardrail separately prevents any release version
carrier from drifting.

Human approval in this interim model covers the candidate manifest and source
commit. The platform artifacts are built afterward, so their hashes are
post-build provenance, not bytes the reviewer inspected. Isolating the
permanent updater key limits key theft; it does not prove a compromised build
produced safe bytes. The post-publication reproducible-build milestone in the
[repository and release security specification](../engineering/repository-release-security-spec.md)
addresses that remaining source-to-bytes gap.

Cost: the repository is public, and every release job runs on a standard
GitHub-hosted runner, so a release bills no Actions minutes and a failed job is
recovered by re-running it. Signing runbooks live in
[macos-code-signing.md](../engineering/macos-code-signing.md) and
[windows-code-signing.md](../engineering/windows-code-signing.md); key rotation
in [release-signing-key-rotation.md](../engineering/release-signing-key-rotation.md).

### Public CLI installer

The repository-root `install.sh` is the canonical source for
`https://sitecmd.com/install.sh`. It embeds the public release verification key from
`.github/actions/setup-sitecmd/updater-public-key.pub` and verifies the archive signature, checksum, and CLI
version before installation. The repository guardrails hold those checks and
the public key in sync.

Before publication or after changing the installer, deploy that exact file and
verify endpoint parity without executing it:

```bash
curl -fsSL https://sitecmd.com/install.sh | diff -u install.sh -
```

Any diff blocks the release. The convenience one-liner in the README is only as
trustworthy as the script served at that endpoint.

### Publish credential

Two jobs call the releases worker's admin endpoint,
`https://releases.sitecmd.com/api/releases-admin`: the `validate-publish-key`
probe before any build, and the manifest advance in `publish-release`. Neither
holds a stored key. Each has `permissions: id-token: write`, asks GitHub for an
Actions OIDC token with the audience `https://releases.sitecmd.com`, and sends
it as the bearer. The worker verifies the token against GitHub's published keys
and accepts it only when the repository is `brambleworks/SiteCMD-Local`, the
workflow is `.github/workflows/release.yml`, the environment is
`release-publish`, and the ref is a `v*` tag. Membership of
`release-publish` is therefore the publish credential, and a repository
guardrail scans every workflow in `.github/workflows`, since any of them could be
dispatched against a tag, and allows only the probe and `publish-release` in
`release.yml` to use that environment.

The releases worker must accept CLI release manifests with an empty
`platforms` map before shipping a CLI-only tag. The publisher requires a
successful manifest advance before creating the GitHub Release.

The probe posts an empty manifest and expects `400`: the worker accepted the
token and refused the body, so nothing was published. Any other status fails
the run before the platform builds, and the step prints the worker's answer. A
`401` means the worker refused the token: either the job no longer runs in
`release-publish` on a `v*` tag, or the deployed worker expects another audience
or claim. Fix whichever side moved, then use **Re-run failed jobs**.

There is no manual publish path. When the manifest advance fails, fix the cause
and re-run the failed `publish-release` job the same way. It rebuilds nothing,
skips R2 objects that already hold the verified bytes, and must run within the
24-hour retention of the `signed-release-payload` artifact, as
[Verify the release](#verify-the-release) describes.

Nothing reads `RELEASE_ADMIN_KEY` any more. Once the releases worker that
verifies OIDC tokens is deployed, delete the `RELEASE_ADMIN_KEY` secret from the
`release-publish` environment. A repository guardrail refuses the name anywhere
under `.github/`.

### npm credential

`publish-npm` runs in its own `npm-publish` environment and holds no npm token.
It publishes through npm trusted publishing: with `permissions: id-token: write`,
npm exchanges the job's GitHub Actions OIDC token for a short-lived publish
token and attests provenance. npm accepts the token only when each package's
trusted publisher matches: GitHub Actions, organization `brambleworks`,
repository `SiteCMD-Local`, workflow `release.yml`, environment `npm-publish`.
Trusted publishing needs npm 11.5.1 or later, which the Node in `.nvmrc` ships.
A repository guardrail allows only `publish-npm` in `npm-publish`, keeps it out
of `release-publish`, and refuses `NPM_TOKEN` and `NODE_AUTH_TOKEN` anywhere
under `.github/`.

Set up once, before the first tag that carries this workflow:

1. Create the `npm-publish` environment with deployment tags limited to `v*`.
2. Add the trusted publisher above to each of `@sitecmd/cli`,
   `@sitecmd/cli-darwin-universal`, `@sitecmd/cli-linux-arm64`,
   `@sitecmd/cli-linux-x64` and `@sitecmd/cli-win32-x64`, either on npmjs.com
   under each package's **Settings > Trusted Publisher**, or with npm 11.15.0
   or later from an account with two-factor authentication:

   ```bash
   for pkg in cli cli-darwin-universal cli-linux-arm64 cli-linux-x64 cli-win32-x64; do
     npm trust github "@sitecmd/$pkg" --file release.yml \
       --repo brambleworks/SiteCMD-Local --env npm-publish --allow-publish
   done
   ```

3. On npmjs.com, set each package's **Publishing access** to **Require
   two-factor authentication and disallow tokens**.
4. Revoke the granular npm token and delete `NPM_TOKEN` from the
   `release-publish` environment.

npm cannot create a package through trusted publishing, so a platform package
added later is published by hand once, then given the same trusted publisher.
If a tag runs before step 2, only `publish-npm` fails: the release is already
live, and **Re-run failed jobs** publishes to npm once the trusted publishers
exist, within the 24-hour retention of the `signed-release-payload` artifact.

## Verify the release

Once the workflow is green, work through [launch-smoke.md](launch-smoke.md)
with the exact signed artifacts. The public distribution service and download
page have their own production pass maintained privately beside that service.

Confirm the two public verification surfaces exist for the version:
`https://releases.sitecmd.com/v<version>/SHA256SUMS` and
`https://releases.sitecmd.com/v<version>/SHA256SUMS.minisig` return 200, and
`gh release view v<version> --repo brambleworks/SiteCMD-Local` lists both as assets.

If the attestation step fails, R2, the release manifest, and the Release are
already live and correct; only the attestation is missing. Re-running
`publish-release` recovers it as long as the `signed-release-payload` artifact
is still within its 24-hour retention window; once that artifact has expired,
`sign-updaters` must run again to produce a new one.

A failed or asset-less Release recovers the same way, and is more urgent. The
release manifest advances before the Release is created, so from that step on
the new version is already offered to every client while the Release they are
pointed at may not exist or may carry no checksums. Re-run `publish-release`
within the same 24-hour window: it creates the Release when there is none, and
attaches a missing `SHA256SUMS` or `SHA256SUMS.minisig` to one that already
exists. A Release left in draft fails the step instead of passing silently,
because clients cannot read it; publish or delete it, then re-run.

Download and active-install analytics are operated with the release service and
documented privately beside that service. This repository's release procedure
ends at signed artifact publication and the public smoke pass; it carries no
Cloudflare account query or operator credential.
