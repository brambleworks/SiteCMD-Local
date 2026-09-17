# SiteCMD gate action

Fails a pull request on code findings that are **new against the connected
baseline**, and only those. A repository that has carried a finding for a year
does not start failing because someone touched an unrelated file; a branch that
introduces one does.

```yaml
name: SiteCMD
on: pull_request

jobs:
  gate:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-actions-checkout-commit-sha>
      - uses: brambleworks/SiteCMD-Local/.github/actions/sitecmd-gate@<full-release-commit-sha>
        with:
          version: <version>
          connection-export: ${{ secrets.SITECMD_CONNECTION_EXPORT }}
          passphrase: ${{ secrets.SITECMD_CONNECTION_PASSPHRASE }}
          ci-token: ${{ secrets.SITECMD_CI_TOKEN }}
          fail-on: high
```

Use the full commit behind the signed SiteCMD release tag, not `main` or a
moving major tag. The action installs that exact CLI version and verifies the
archive with SiteCMD's updater signing key before it runs any product code.

## The three secrets, and why they are three

| Secret              | Where it comes from                        | What it is                                             |
| ------------------- | ------------------------------------------ | ------------------------------------------------------ |
| `connection-export` | Desktop app: Settings, Transfer Connection | The site id and the project fingerprint key, encrypted |
| `passphrase`        | You chose it when creating the export      | What decrypts the above                                |
| `ci-token`          | Desktop app: Settings, CI Gate Credential  | The bearer that may ask for a verdict on this site     |

They are separate because they fail separately. The export carries the
fingerprint key, which is what makes a code location's identity mean anything
to the service without the service ever learning a path; it is encrypted at
rest and useless without the passphrase. The CI token carries no key and can
read nothing, so a leak of it costs you a revoke and a remint rather than a
re-identification of every finding you have.

## One command, not a pipeline

The action installs the CLI and runs `sitecmd gate`. There is no separate scan
step, because the connection export already names the environment being graded
and a second step would be a second chance to grade the wrong one. The gate
audits the checkout in front of it, every time.

## What the gate can and cannot do

It asks one question and gets one answer: which of this checkout's findings are
new against the baseline. It cannot list the site's existing findings, read its
history, change its lifecycle, or establish a baseline of its own. That is not
a convention, it is the credential: a CI secret is readable by anyone who can
edit a workflow file, so the token is bound to one site and to this one
operation.

Because nothing is persisted, running the gate on every branch of every pull
request is safe. A branch full of new findings is a build failure, never a
change to what the site is known to be.

## Thresholds and the two warnings

`fail-on` names the least severe NEW finding that fails the build, and
defaults to `high`. Findings below it are still reported, just not fatal.
`threshold` still works as a deprecated alias.

Two conditions warn instead of failing, and both are deliberate:

- **`instrument_changed`** - the candidate was scanned by a different engine
  build than the one that established the baseline, so a finding that looks new
  may be a check that did not exist before. Pass `strict: true` to fail on
  these anyway.
- **`coverage_incomplete`** - the candidate scan did not finish everything it
  claimed. The repository decides whether that is acceptable to merge on; the
  service does not decide it for you.

## Exit codes

`0` passes, `1` blocks the merge, and anything else means the gate could not
run at all. The third case is not reported as a pass, because a gate that
cannot reach the service is not evidence that a branch is clean.
