# Security review cadence

Use this runbook for security decisions that require a maintainer to inspect
upstream state or repository settings. Automated checks catch code regressions;
they cannot decide whether an advisory exception, signing identity, credential,
or access grant is still justified.

Connected-service infrastructure is reviewed privately beside the service.
This public runbook covers the CLI, release pipeline, and GitHub repository.

## Quarterly

### Dependency exceptions

1. Run `pnpm audit:deps` and review every allowed Rust advisory warning.
2. Open the upstream advisory and dependency release history for each warning.
3. Remove an exception as soon as a compatible, non-yanked fix is available.
4. When an exception is still required, update its review date and retain a
   concise explanation of the blocked upgrade path.
5. Review dependency overrides in the workspace configuration. Remove any
   override that no longer changes the installed graph.

The audit warns when an advisory review is older than its allowed window. A
maintenance commit should use a subject such as `Refresh Rust advisory reviews`.

### Repository access and automation

1. Review collaborators, teams, GitHub Apps, deploy keys, webhooks, and Actions
   permissions. Remove access without a current owner and purpose.
2. Confirm dependency bots still use pull requests and produce titles accepted
   by the repository title guard.
3. Confirm GitHub Actions updates have exactly one owner and that workflow
   dependencies remain pinned to full commit hashes.
4. Review branch protection, required checks, signed-commit policy, and release
   environment approvers against the release security specification.

## Yearly

### Updater and release signing identities

1. Review the current updater key, release tag signer, and platform signing
   identities for unexpected access or approaching expiry.
2. Confirm private keys exist only in their documented protected environments.
3. Exercise recovery from the previous supported release before rotating any
   updater key.
4. Use the [updater signing-key rotation](release-signing-key-rotation.md) and
   [release tag signing](release-tag-signing.md) procedures for an approved
   rotation. Rotate immediately on suspected compromise.

### Release credentials

1. Inventory every Actions secret and variable used by the release workflow.
2. Map each credential to the one step that needs it and remove obsolete values.
3. Confirm credentials are environment-scoped where possible and have the
   minimum provider permissions required by that step.
4. Confirm the checkout-free publisher and isolated signer still receive only
   their documented inputs.

Provider-specific service credentials are reviewed in the private repository
that owns the corresponding service and deployment workflow.

## Every release

The release pipeline must prove:

- strict version agreement, protected-branch ancestry, and trusted signed-tag
  verification
- human approval bound to the candidate manifest and source commit
- isolated updater signing with no production private key in product builds
- secretless verification before publication
- dependency, secret, source-policy, and CLI quality gates
- post-build scanning that rejects leaked key material

After the workflow is green, execute the maintained release smoke test with the
exact signed artifacts. Automation is evidence for approval, not a substitute
for approval.

## Suspected secret leak

1. Revoke the suspected credential in its issuing system before investigating.
2. Search reachable Git history, workflow logs, release artifacts, and caches
   for exposure.
3. Replace the credential only in the narrow environment or service that needs
   it. Do not recreate a release credential at repository scope.
4. Follow the signing-key rotation procedure for updater or release-signing
   material.
5. Record the incident timeline, impact, rotation evidence, and control gap in
   the private security record. Publish a durable postmortem when coordinated
   disclosure and user safety permit it.
