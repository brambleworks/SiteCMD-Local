# Release Tag Signing Runbook

Release tags are the only trigger for shipped desktop builds. Before any
billable work starts, `.github/workflows/release.yml` rejects a tag unless it
is annotated, points to the protected default branch, and has an SSH signature
accepted by the protected release-tag trust list.

This key signs the Git tag. It is separate from the updater key and the Apple
and Windows platform-signing identities.

## Trust model

The signer list has two synchronized copies with different jobs:

- `.github/allowed-signers` is the public, reviewable mirror used for local
  verification.
- `RELEASE_ALLOWED_SIGNERS` in the `release-tag-trust` environment is the
  authority used by CI.

The tag gate normalizes the signer entries, rejects any difference between the
two copies, and then points Git at the protected copy. A commit therefore cannot
authorize its own signing key, while an environment-only key change cannot ship
without a matching public review.

## Set up a signing identity

The principal in each signer entry must equal the email Git records as the tagger:

```bash
git config user.email
```

Create a release-only SSH key outside the repository and configure Git to use it:

```bash
ssh-keygen -t ed25519 -C sitecmd-release-signing -f ~/.ssh/sitecmd_release_signing
git config gpg.format ssh
git config user.signingkey ~/.ssh/sitecmd_release_signing.pub
```

Back up the private key in encrypted, access-controlled storage separate from
the updater and platform-signing credentials.

## Maintain the reviewed signer list

Add one line per current signer. The first field must match that maintainer's
tagger email:

```bash
printf '%s %s\n' "$(git config user.email)" \
  "$(cat ~/.ssh/sitecmd_release_signing.pub)" >> .github/allowed-signers
```

The resulting entry has this form:

```txt
admin@brambleworks.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... sitecmd-release-signing
```

Commit signer changes through the protected pull-request path. The file contains
public keys, not private key material.

## Publish the protected copy

After the reviewed file lands on `main`, publish its exact contents to the
protected environment:

```bash
gh variable set RELEASE_ALLOWED_SIGNERS \
  --env release-tag-trust -R brambleworks/SiteCMD-Local \
  --body "$(cat .github/allowed-signers)"
```

Do this once during repository setup and after every signer rotation. A missing,
empty, or mismatched environment value fails the tag gate before a build starts.

## Prove the chain before a release

Create a throwaway signed tag, verify it with the reviewed mirror, and remove it:

```bash
git tag -s zzz-verify-throwaway -m "Prove release signing"
git -c gpg.ssh.allowedSignersFile=.github/allowed-signers \
  verify-tag zzz-verify-throwaway
git tag -d zzz-verify-throwaway
```

The verification must name the expected tagger principal. Then run the repository
guardrails so the workflow and trust-mirror invariants are checked together:

```bash
pnpm guardrails:repo
```

## Release flow

1. On a clean `release/*` branch, run `pnpm release <bump>`. Commit the resulting
   version and changelog changes and merge them through the protected path.
2. Update local `main` from `origin/main` and run `pnpm release:tag`. The command
   refuses another branch or a commit that differs from `origin/main`.
3. Verify the created tag with `git tag --verify vX.Y.Z`.
4. Explicitly push only that tag with `git push origin vX.Y.Z`.
5. The tag gate fetches the annotated tag object, compares the reviewed and
   protected signer lists, and verifies the signature using the protected list.

The full release transaction and environment configuration are in
[the release procedure](../operations/releasing.md).

## Add or rotate a signer

For an overlap rotation:

1. Add the new key to `.github/allowed-signers`.
2. Bound the outgoing entry with `valid-before` rather than leaving it able to
   authorize future tags.
3. Merge the reviewed file change.
4. Republish the complete file to `RELEASE_ALLOWED_SIGNERS`.
5. Repeat the throwaway-tag proof with the new key before cutting a release.

Git checks `valid-before` against the signature timestamp, so a bounded key can
still verify the historical tags it signed without authorizing newer ones. Once
those tags are no longer part of the public history, remove the retired entry
from both synchronized copies.

## Troubleshooting

| Symptom                                                          | Cause                                     | Fix                                                                    |
| ---------------------------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------- |
| `RELEASE_ALLOWED_SIGNERS is not set`                             | The protected environment is unconfigured | Publish the reviewed file to `release-tag-trust`.                      |
| `RELEASE_ALLOWED_SIGNERS does not match .github/allowed-signers` | The two copies drifted                    | Review the file, then republish its exact contents to the environment. |
| `Tag '...' is not signed by an allowed signer`                   | Wrong key or principal                    | Confirm the tagger email, signing key, and signer entry.               |
| `cannot verify a non-tag object of type commit`                  | Lightweight or checkout-materialized ref  | Create an annotated signed tag or fetch the annotated tag first.       |
| `pnpm release:tag` stops before creating the tag                 | Local branch or signing state is invalid  | Synchronize `main` and confirm `gpg.format` and `user.signingkey`.     |
