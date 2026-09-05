# Releasing the desktop app

How to prepare a desktop release through a protected pull request, create the
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
  --env release-tag-trust -R brambleworks/SiteCMD \
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

| Environment               | Protection                                                                                 | Values                                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| `release-tag-trust`       | Deployment tags limited to `v*`; protected from workflow-authenticated writes              | `RELEASE_ALLOWED_SIGNERS`, matching `.github/allowed-signers`                                  |
| `release-signing`         | One required reviewer, admin bypass disabled, deployment tags limited to `v*`              | License configuration, desktop OAuth credentials, Sentry DSN, Apple credentials, Azure secrets |
| `release-updater-signing` | Deployment tags limited to `v*`; reachable only after the approved platform builds succeed | `TAURI_SIGNING_PRIVATE_KEY` and its optional password                                          |
| `release-publish`         | Deployment tags limited to `v*`; no reviewer or timer                                      | R2 credentials and `RELEASE_ADMIN_KEY` only                                                    |

Put `AZURE_SIGN_ENDPOINT`, `AZURE_SIGN_ACCOUNT`, and `AZURE_SIGN_PROFILE` in the
`release-signing` environment as variables. Move the listed secrets out of
repository scope after the environments work. Duplicate repository secrets
defeat the intended boundary.

Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as `release-signing` environment
secrets from the same Google **Desktop app** OAuth client. The build preflight
rejects missing values. Both are embedded in the desktop binary, as Google's
installed-app flow requires; the client secret is not a confidentiality boundary.
PKCE and callback-state validation remain required. After OAuth changes, test a
new connection and an expired-token refresh in a release candidate.

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
git add CHANGELOG.md apps/desktop/package.json apps/desktop/src-tauri/tauri.conf.json \
  apps/desktop/src-tauri/Cargo.toml apps/desktop/src-tauri/crates/cli/Cargo.toml \
  apps/desktop/src-tauri/crates/runtime/Cargo.toml \
  apps/desktop/src-tauri/Cargo.lock apps/mcp-server/package.json \
  apps/mcp-server/src/version.ts
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
- Bumps every release version carrier: the desktop package and Tauri config,
  the desktop, runtime, and CLI Cargo manifests, the Cargo lockfile, and the MCP package
  and protocol version constant.
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

| Tripwire              | Detects                                             |
| --------------------- | --------------------------------------------------- |
| new persisted data    | an **added** `src-tauri/src/db/migrations/*.sql`    |
| score movement        | non-test changes under `src-tauri/src/scoring/`     |
| monetization boundary | `licensing/config.rs` or generated commercial facts |
| new capability        | a **growing** count of `#[tauri::command]`          |
| check coverage        | `checkCounts.total` in `product-facts.json`         |
| new surface           | an **added** file under `apps/desktop/src/pages/`   |

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

## What the signed tag triggers

Pushing a `v*` tag runs `.github/workflows/release.yml`:

1. **Tag verification** rejects a non-semver, lightweight, untrusted, or
   incorrectly signed tag. It also rejects a tag whose commit is not in the
   repository default branch.
2. **Preflight** runs repository guardrails, tests, dependency audits, Rust
   tests, clippy, and formatting before any release credential is available.
3. **Capability manifest publication** sends
   `crates/engine/manifest/capability_manifest.json` to the connect manifest
   registry with a GitHub Actions OIDC token. `build` depends on it, so no
   artifact is produced unless it succeeded. See
   [Capability manifest publication](#capability-manifest-publication) below.
4. **Candidate preparation** requires the tag version to match the protected
   source version and binds the source commit, workflow hash, dependency
   lockfile hashes, release notes, and publication date into an immutable
   manifest.
5. **Human approval** pauses the `release-signing` environment. Review the
   candidate manifest artifact and job summary, then approve the exact manifest
   hash and protected source commit.
6. **Platform builds** run after approval on macOS universal, Linux x86_64, and
   Windows x86_64. Apple and Azure platform signing remain inline. Tauri receives
   a job-generated throwaway updater key, never the permanent updater key.
7. **Updater and CLI signing** validates and stages an allowlisted payload,
   then exposes `TAURI_SIGNING_PRIVATE_KEY` only to the minimal standalone
   signer step. It signs the updater bundle, the standalone CLI archive (whose
   `.sig` sidecar feeds CI installers), and one release-wide `SHA256SUMS`
   listing every installer and archive; the manifest's decoded `.minisig` is
   what `minisign -V` reads.
8. **Secretless verification** checks payload hashes, candidate provenance,
   updater and CLI archive signatures, CLI versions, and available platform
   signatures on all three platforms.
9. **Publication** runs only after every verifier passes. A checkout-free job
   hash-compares any existing R2 object before upload (including `SHA256SUMS`,
   `SHA256SUMS.sig`, and `SHA256SUMS.minisig`), advances the updater manifest,
   and then creates the GitHub Release for the tag with the changelog section
   as notes and the two checksum files attached. Binaries stay on R2. Once the
   Release exists, a SHA-pinned `actions/attest-build-provenance` step attests
   build provenance over every published artifact glob and `SHA256SUMS`,
   scoped to this job alone. It never executes source, dependencies, or
   artifacts.

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

Cost: a clean release is roughly 300-600 billed GitHub Actions minutes (macOS
bills at 10x). Signing runbooks live in
[macos-code-signing.md](../engineering/macos-code-signing.md) and
[windows-code-signing.md](../engineering/windows-code-signing.md); key rotation
in [release-signing-key-rotation.md](../engineering/release-signing-key-rotation.md).

### Public CLI installer

The repository-root `install.sh` is the canonical source for
`https://sitecmd.com/install.sh`. It embeds the same public updater key as the
desktop configuration and verifies the archive signature, checksum, and CLI
version before installation. The repository guardrails hold those checks and
the public key in sync.

Before publication or after changing the installer, deploy that exact file and
verify endpoint parity without executing it:

```bash
curl -fsSL https://sitecmd.com/install.sh | diff -u install.sh -
```

Any diff blocks the release. The convenience one-liner in the README is only as
trustworthy as the script served at that endpoint.

### Capability manifest publication

Every observation the desktop sends carries a `manifest_digest`. Connect
resolves that digest against an immutable, content-addressed registry, and an
observation whose digest the registry does not know is quarantined as
incomparable: the finding is still recorded, but nothing can ever be verified
fixed under it. Publication is therefore a release precondition, not a release
step, and the rule is that the manifest reaches the registry **before** any
build ships under its digest.

Two things run `tools/scripts/publish-capability-manifest.mjs`:

- `.github/workflows/publish-capability-manifest.yml`, on every push to main
  that touches the manifest artifact or the publisher, so the registry stays
  ahead of main.
- the `publish-capability-manifest` job in `release.yml`, which `build` depends
  on, so a release cannot produce an artifact without it.

The digest tracks the check registry, not the app version, so most releases
republish bytes the registry already holds and are told `already_registered`
(HTTP 200). That is a success. A release that moved a check contract registers
a new digest instead (HTTP 201).

**A 409 means the digest is already registered with different bytes.** Do not
retry it and do not look for a way to overwrite the entry: the registry is
immutable by design, because a registered manifest is the meaning of every
observation ever recorded under its digest, and rewriting one would silently
retro-define findings the service has already accepted. A 409 says one of two
things happened, and you need to know which before anything ships:

- the artifact moved without its digest moving, which is a generation bug (the
  committed JSON is not what `sitecmd_engine::manifest` produces; regenerate it
  with
  `cargo test -p sitecmd-engine --test capability_manifest -- --ignored regenerate`
  and commit the result, noting that the unignored test only asserts the file
  is current), or
- two builds computed one identity for two meanings, which is a collision in
  the manifest hash itself.

Rollback is re-pointing a build at an already-registered digest. Nothing is
ever unregistered.

A 404 is also a hard failure, not a no-op: it means the connect Worker is
deployed without its manifest bucket or publisher allowlist, or this repository
is not the allowed publisher. Passing on a 404 would let the release ship under
a digest the registry never learned, which is the exact state the ingest gate
quarantines.

## Verify the release

Once the workflow is green, work through [launch-smoke.md](launch-smoke.md)
with the exact signed artifacts. The public distribution service and download
page have their own production pass maintained privately beside that service.

Confirm the two public verification surfaces exist for the version:
`https://releases.sitecmd.com/v<version>/SHA256SUMS` and
`https://releases.sitecmd.com/v<version>/SHA256SUMS.minisig` return 200, and
`gh release view v<version> --repo brambleworks/SiteCMD` lists both as assets.

If the attestation step fails, R2, the updater manifest, and the Release are
already live and correct; only the attestation is missing. Re-running
`publish-release` recovers it as long as the `signed-release-payload` artifact
is still within its 24-hour retention window; once that artifact has expired,
`sign-updaters` must run again to produce a new one.

A failed or asset-less Release recovers the same way, and is more urgent. The
updater manifest advances before the Release is created, so from that step on
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
