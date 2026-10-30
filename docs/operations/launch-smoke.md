# Release smoke test

Use this checklist to verify the signed desktop, CLI, and MCP artifacts that
users receive. Run it after the release workflow produces artifacts and again
after publication. Keep the completed record, machine details, screenshots,
and failures in the private release workspace. Do not add point-in-time status
to this maintained procedure.

The hosted connected service has a separate production pass maintained with
the service. This checklist verifies the open-source client and its public
distribution boundary. It deliberately contains no service secrets, database
queries, deployment ordering, or provider administration.

## Preconditions

- The release workflow is green for the exact commit and tag under review.
- Candidate hashes, updater signatures, CLI signatures, and platform
  signatures have passed the release verification jobs.
- Testers have the exact signed artifacts produced by that workflow. A local
  development build is not a substitute.
- A disposable public test URL and an authorized source repository are
  available. Neither contains customer data or credentials.
- Each desktop test starts from a clean OS account or clean virtual machine.
- One separate machine still has the previous supported release installed for
  the updater test.
- A supported Node.js runtime is available for the bundled MCP server.

Use the [manual testing runbook](../qa/manual-testing-runbook.md) for deeper
product review. This pass is the final artifact-level sanity check.

## 1. Artifact identity and installation

Run the following on every supported desktop platform:

1. Download the candidate from the release workflow or the published release.
2. Confirm the filename, checksum, and signature belong to the intended tag.
3. Install without bypassing Gatekeeper, SmartScreen, package signatures, or
   other operating-system trust checks.
4. Launch SiteCMD and confirm the displayed version matches the release tag.
5. Confirm the app opens to a usable window without a blank screen, crash, or
   permission prompt unrelated to an action the user requested.
6. Quit from the tray or application menu and confirm the process exits.

Record the artifact hash and result privately for each platform.

## 2. Desktop core flow

Use a fresh local workspace:

1. Add the disposable site and confirm its environment is classified correctly.
2. Run a Web Scan and confirm progress completes with a SiteCMD Score and
   actionable findings.
3. Link the authorized source repository and run Code Scan.
4. Run a Full Scan and confirm the dashboard combines evidence without showing
   separate user-facing Web and Code scores.
5. Open the highest-priority item from Dashboard, then inspect it in Issues.
6. Confirm evidence, severity, affected locations, fix guidance, and the agent
   handoff are present without a subscription lock.
7. Ignore or snooze one disposable finding, restart the app, and confirm the
   lifecycle state and project history persist.
8. Run verification or a follow-up scan and confirm the result is reflected in
   Dashboard, Issues, Events, and Reports.

Repeat the first-run and restart checks against an existing local database on a
separate test account so upgrade compatibility is covered without reusing the
clean-install workspace.

## 3. CLI distribution

Install the signed CLI through the public installer or the signed Windows
archive. Do not use a locally compiled binary.

```bash
sitecmd --version
sitecmd scan --url https://example.com --output text
sitecmd audit . --format summary
```

Confirm:

- the reported version matches the release tag
- the web scan returns findings and a score without requiring the desktop app
- the code audit walks only the selected repository
- text, JSON, and GitHub output formats remain machine-readable where selected
- `--fail-on` returns the documented nonzero status against a controlled
  failing fixture and exits zero after the fixture is fixed or suppressed
- an invalid URL, missing directory, and invalid option fail with concise help
  and no panic or stack trace
- the public installer refuses a modified archive or signature

## 4. Bundled MCP server

After the desktop has stored at least one scan:

1. Open Integrations and connect one supported coding tool.
2. Review the proposed configuration change before applying it.
3. Confirm SiteCMD reports the connection as healthy only after its command,
   arguments, Node runtime, database path, and bounded health probe succeed.
4. Restart the coding tool and call `get_projects`, `get_issues`, and
   `get_fix_prompts`.
5. Confirm the returned project, finding, evidence, and fix data match the
   desktop state and contain no tier-based redaction.
6. Start a disposable fix attempt and call `request_verification`. Confirm it
   updates that existing attempt and cannot create unrelated records.
7. Break the configured command, run the connection check, and confirm the UI
   offers Repair rather than claiming the stale configuration is connected.

Repeat one read with SiteCMD closed. The bundled server should continue reading
the local database without requiring the desktop process.

## 5. Privacy and entitlement boundary

Run the desktop and local CLI while signed out and disconnected:

1. Confirm Web Scan, Code Scan, Full Scan, issue details, fix guidance, reports,
   CLI output, and MCP reads remain complete.
2. Confirm no local feature asks for a paid plan to reveal more detail.
3. Enable the local database-inspection option once and review its disclosure.
   Confirm the next scan resets the option to off.
4. Inspect the connected payload preview without submitting it. Confirm source
   text, raw file paths, credentials, and application table rows are absent.
5. Cancel the connection flow and confirm nothing is submitted.

Production entitlement, hosted scanning, alert delivery,
reports, retention, and erasure are verified by the private connected-service
runbook because those systems do not ship from this repository.

## 6. Update loop

On the machine holding the previous supported release:

1. Launch the older signed build and check for updates.
2. Confirm it offers the intended release and displays the correct version and
   release notes.
3. Download, install, and relaunch through the in-app updater.
4. Confirm the new version starts without another platform trust prompt.
5. Confirm projects, history, issue lifecycle, integration settings, and MCP
   configuration survive the update.
6. Run one Web Scan and one Code Scan after migration.

Test updater-key transitions only from releases documented as trusting the
current key. Older builds that require a fresh installer are covered by the
[updater signing-key rotation](../engineering/release-signing-key-rotation.md)
procedure.

## Exit criteria

The release passes only when:

- every published artifact identifies the same version and passes its trust
  checks
- desktop install, first run, restart, scan, lifecycle, and update flows pass
  on every supported platform
- the signed CLI passes its web scan, code audit, output, exit-code, and
  tamper-rejection checks
- the bundled MCP server passes connection, read parity, verification, repair,
  and desktop-closed checks
- the complete local product remains available without a connected entitlement
- every failure has an owner and is fixed or explicitly accepted before the
  release proceeds

Do not weaken a failed step by editing this procedure after the run. Fix the
artifact or record a deliberate release decision in the private release record.
