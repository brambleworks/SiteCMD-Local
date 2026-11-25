# Public repository cutover

Use this checklist once, when the existing private SiteCMD repository becomes
public. The repository is rewritten in place. Do not create a replacement
repository, and do not copy these checkboxes into Git as a completed audit.
Keep the dated execution record privately.

The cutover has five independent boundaries:

1. the approved source tree;
2. reachable Git history;
3. GitHub records and artifacts outside ordinary Git refs; and
4. repository security settings after the visibility change; and
5. official download, installer, and updater endpoints.

Passing one boundary does not prove the others.

## Before the maintenance window

- [ ] Commit the exact tree that will become the public root and pass GitHub CI
      for that tree.
- [ ] Complete the maintained-surface review and record founder acceptance
      privately. Automation cannot supply this decision.
- [ ] Run the current-tree publication and legal checks.
- [ ] Run the all-ref publication-history check. Classify every Gitleaks
      finding. Remove false positives from the public root and rotate every
      credential that may have been real. Rewriting Git does not revoke a
      secret.
- [ ] Configure the documented SSH signing identity and confirm its principal
      is present in the repository's allowed-signers file.
- [ ] Choose a new absolute `.bundle` path outside the checkout on encrypted,
      access-controlled storage.
- [ ] Record the current `main` SHA and inventory every remote branch, tag,
      GitHub Release, open pull request, workflow run, artifact, ruleset,
      environment, deploy key, webhook, GitHub App, and collaborator.
- [ ] Inventory every linked worktree. Preserve or explicitly abandon its
      uncommitted changes, then leave every worktree clean. The publication
      helper refuses to continue while a linked worktree is dirty.
- [ ] Inventory the live download page, installer script, updater manifest, R2
      objects, signatures, and source commit for every artifact still offered.
- [ ] Pause release automation and put downloads, the installer, and the updater
      manifest into an explicit maintenance state. No merge, tag, download, or
      update publication may race the rewrite.

Useful read-only inventory commands:

```bash
git rev-parse main
git worktree list --porcelain
git ls-remote --heads origin
git ls-remote --tags origin
pnpm guardrails:publication
pnpm guardrails:publication:history
pnpm labels:check:live
```

## Prepare local `main`

First run the helper without `--apply`. It validates the checkout, signing
identity, public tree, secret scan, and backup destination without writing a
bundle or moving a ref.

```bash
pnpm publication:prepare -- \
  --backup /absolute/private/path/sitecmd-before-publication.bundle
```

Review the printed SHA, tree, ref count, tag count, and backup path. Then run the
explicit apply mode with the same unused backup path:

```bash
pnpm publication:prepare -- \
  --backup /absolute/private/path/sitecmd-before-publication.bundle \
  --apply \
  --confirm-rewrite-main
```

The helper creates and verifies an all-ref private bundle, proves that every
inventoried local ref and SHA is present, creates an SSH-signed root commit with
the exact approved tree, verifies the candidate history, and moves local `main`
with an expected-old SHA check. It does not push, delete a branch or tag, edit a
remote, or change repository visibility.

Verify the local candidate before touching GitHub:

```bash
git bundle verify /absolute/private/path/sitecmd-before-publication.bundle
git rev-list --count main
git rev-list --parents --max-count=1 main
git -c gpg.ssh.allowedSignersFile=.github/allowed-signers verify-commit main
pnpm guardrails:publication
pnpm guardrails:publication:history -- --candidate-main
```

The two `rev-list` commands must show one commit and no parent. The working tree
must remain clean.

## Clean the existing GitHub repository

Keep the repository private during this phase.

- [ ] Close or merge every open pull request before rewriting `main`.
- [ ] Review old pull requests and issues for private implementation details.
      Archive or remove material that must not become public.
- [ ] Delete obsolete workflow runs and artifacts that expose private source,
      logs, environment names, or release credentials.
- [ ] Delete old GitHub Releases and their assets.
- [ ] Force-update only `main` with the exact lease command printed by the
      helper. Do not use an unqualified `--force`.
- [ ] Delete every old remote branch. The public repository starts with only
      `main`.
- [ ] Delete every old remote tag. The first public release creates the first
      public tag after the cutover is verified.
- [ ] Withdraw pre-public R2 downloads and updater metadata from public service.
      Preserve any required private archive beside the verified Git bundle, not
      at an endpoint the public README or installer can still serve.
- [ ] Retire the rewritten checkout and its linked worktrees, or remove every
      linked worktree, old local branch, and tag by exact name after the
      clean-clone proof. Confirm each worktree is clean before removal. Do not
      resume public work from a checkout that can accidentally push a private
      ref.
- [ ] Remove obsolete deploy keys, webhooks, app installations, collaborators,
      environments, variables, and secrets.

Delete branches and tags by exact ref name after comparing them with the saved
inventory. Do not use a wildcard deletion command.

Force-pushing does not erase every GitHub-side reference or cached view. If a
real secret or regulated data was committed, rotate it first and follow
[GitHub's sensitive-data removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository),
including GitHub Support when hidden pull-request refs or cached views must be
purged.

## Verify the remote from a clean clone

Do not use the rewritten working copy as final evidence. Clone the still-private
remote into a new directory on another trusted path, then run:

```bash
git ls-remote --heads origin
git ls-remote --tags origin
git rev-list --all --count
git log --all --show-signature --oneline --decorate
node tools/scripts/check-publication-hygiene.mjs
node tools/scripts/check-publication-history.mjs --all
```

The remote must advertise only `main`, advertise no tags, and expose one signed
root commit. The publication history and hygiene checks must pass. Independently
confirm that old releases, workflow artifacts, private pull-request material,
and unwanted GitHub integrations are gone.

## Change visibility and restore protections

- [ ] Change the existing repository from private to public.
- [ ] Confirm the repository description, `https://sitecmd.com` homepage, and
      maintained topics are present.
- [ ] Enable Issues and Discussions. Disable Wiki and Projects unless someone
      is actively maintaining them.
- [ ] Allow squash merges only, require linear history, and automatically
      delete merged branches.
- [ ] Run `pnpm labels:check:live` and confirm every contracted automation label exists.
- [ ] Immediately re-enable and verify every ruleset. GitHub documents that a
      private-to-public change disables push rulesets.
- [ ] Confirm branch protection, required reviews, required checks, signed
      commits, merge queue behavior, environment reviewers, and default
      workflow-token permissions.
- [ ] Enable secret scanning, push protection, dependency review, code
      scanning, security advisories, and private vulnerability reporting.
- [ ] Recheck collaborator, team, app, webhook, deploy-key, environment, and
      Actions-secret access after visibility conversion.
- [ ] Open a representative pull request and prove that direct pushes, failing
      checks, and bypass attempts are rejected.
- [ ] Run Code Scan against the rewritten `main` and confirm it passes at the
      High severity threshold.
- [ ] Run the localhost Postgres integration workflow against the rewritten
      `main` and confirm every ignored `postgres_live` test passes.
- [ ] Cut the first signed public tag from the rewritten, protected `main` and
      complete the release workflow.
- [ ] Verify that every published artifact records that public source commit and
      that its signatures, checksums, release notes, and GitHub source tag agree.
- [ ] Install the artifacts on every supported platform and exercise the updater
      path against a separately signed rehearsal manifest.
- [ ] Publish the download page, installer metadata, updater manifest, and first
      public release as one coordinated switch. Do not announce the repository
      while any official endpoint still serves an untagged pre-public binary.
- [ ] Confirm `https://sitecmd.com/install.sh` serves the reviewed public source
      byte-for-byte: `curl -fsSL https://sitecmd.com/install.sh | diff -u install.sh -`.

GitHub's current visibility side effects are documented in
[Setting repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).
Recheck that page during the maintenance window because platform behavior can
change.

## Abort and recovery

Before the visibility change, an abort means leaving GitHub private, stopping
automation, and restoring local work from the verified bundle in a separate
clone. Do not move `main` back or force-push private history during a rushed
rollback. Diagnose first, compare the saved ref inventory, and require the same
review used for the forward rewrite.

After the visibility change, assume anything exposed was copied. Making the
repository private again limits new access but does not undo disclosure. Rotate
affected credentials and follow the incident process.
