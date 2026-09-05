# SiteCMD Manual Testing Runbook

Use this runbook for release-candidate and product-quality reviews.

The goal is not to click every page. The goal is to exercise representative projects and workflows consistently enough that trust, usability, packaging, and entitlement regressions are visible.

## What This Runbook Should Prove

For each project and flow, we want to know:

1. Can someone get into the product without confusion?
2. Does SiteCMD surface the right next action?
3. Is the issue detail trustworthy and specific?
4. Does the fix and verify loop feel faster or clearer than the manual stack?
5. Does anything in the free/paid boundary, stability, or packaging story still feel broken?

## Test Set

Choose projects that collectively cover:

- a small static or content-focused site
- a framework application with a linked source tree
- a dependency-heavy application
- a mature or intentionally messy codebase
- SiteCMD itself as a dogfood case

Use only repositories and URLs the reviewer is authorized to inspect. Keep project names, local paths, findings, credentials, and screenshots in the private test record.

## Testing Order

1. Representative-project workflow review
2. Free-tier and catalog-boundary smoke pass
3. Packaged-app install and update pass
4. SiteCMD dogfood pass

## Core Flow Script

Run this script for each representative project.

1. Add or import the project using the real product flow.
2. Confirm the environment is classified correctly.
3. Run the first Full Scan.
4. Confirm the app lands on `Dashboard` with a useful next step.
5. Open the highest-priority Dashboard action, whether it routes to `Issues`
   or `Updates`.
6. Review the top 10 recommended issues or launch blockers.
7. Open the top 3 meaningful items in detail.
8. Try to follow the fix guidance for at least 1 to 3 items.
9. Run verification or a follow-up scan.
10. Record whether the result was clearly better than the manual stack.

## What To Capture For Each Project

Every review should capture:

- top 10 issue audit
- false positives
- false negatives
- weak priority calls
- weak copy calls
- verification gaps
- fix-loop notes
- worth-paying-for judgment

Use the [acceptance review template](acceptance-review-template.md), but store completed records privately when they contain project-specific information.

If you find a scanner trust issue that could affect other projects too, also log it in:

- [Scanner Accuracy Log](../product/scanner-accuracy-log.md)

## Pass And Fail Heuristics

Treat these as practical rules, not philosophical ones.

### Pass

- The first Full Scan lands on Dashboard with a useful next step.
- The top issues are mostly correct.
- The first recommended action feels reasonable.
- At least one fix feels faster or clearer than doing it manually.
- Verification clearly shows what changed.

### Follow-Up Needed

- The issue is technically correct but weakly prioritized.
- The copy is understandable but vague.
- Verification works but does not make the outcome obvious.
- The user can eventually recover, but the route is clumsy.

### Fail

- The issue is a clear false positive.
- The issue is missing something obviously important.
- The workflow sends the user to the wrong place.
- The free/paid boundary leaks.
- The app looks unstable, blank, or misleading.

## Free Local Workbench Smoke

Run one short free-tier pass before or between project reviews.

Check these surfaces:

1. `Dashboard`
2. `Issues`
3. `Updates`
4. CLI scan output and fix path
5. MCP finding and fix-prompt paths

Confirm:

- every issue retains full evidence and fix guidance
- exports, prompts, and MCP reads contain the complete local payload
- no local scan or detail surface renders a subscription lock
- connected-service prompts describe hosted automation, not local detail depth

## Packaged App Smoke

Use the packaged app for a small sanity pass, not a full project wave.

Check:

1. app opens without a blank window
2. existing local DB is picked up
3. first navigation works
4. first Full Scan can be started
5. `Dashboard`, `Issues`, and `Updates` open
6. logs appear in the expected release log location

Use the exact signed package produced by the release workflow. A development
bundle or locally rebuilt package does not verify the artifact users receive.

## Local Database Inspection Smoke

Run Code Scan once with **Inspect local database schemas** off. Confirm the run
does not derive findings from values in `.env`, `.env.local`, or other
non-example dotenv files and does not open a project database. Run it again with
the option on and confirm the disclosure says that SiteCMD reads local dotenv
values only to discover a target, reads schema and migration metadata only, and
never reads application table rows. Confirm the option resets to off for the
next run and is always off for scheduled scans.

For the CLI, confirm ordinary `sitecmd audit .` behaves the same way and that
only `sitecmd audit . --inspect-local-databases` enables the inspection. Reject
an SQLite path outside the audited project and a PostgreSQL URL containing any
non-loopback host or hostaddr. A valid PostgreSQL inspection starts a read-only
transaction.

`SITECMD_POSTGRES_TEST_URL` is maintainer-only input for the ignored Rust
integration tests. It is not app configuration and is never set on a user's
machine. When exercising those tests, point it at a disposable local Postgres
maintenance database whose role may create and drop throwaway test databases,
then run:

```bash
SITECMD_POSTGRES_TEST_URL=postgresql://sitecmd_test:test-fixture-sitecmd-postgres@127.0.0.1:55432/postgres \
  cargo test -p sitecmd-runtime --manifest-path apps/desktop/src-tauri/Cargo.toml postgres_live -- --ignored --nocapture
```

## Time Savings Check

For at least 5 real issues across the test wave, write down:

- what the manual workflow would have been
- what SiteCMD let you skip
- whether SiteCMD was actually faster, or just clearer

This is the minimum evidence needed for the `Real Time Savings` checklist section.

## Logging Bugs And Friction

Use the triage template:

- [Manual Bug Triage Template](./manual-testing-triage-template.md)

When logging issues:

- one issue per template copy
- include repro steps
- include project and environment
- tie it to the checklist section when possible

## Session Rhythm

Use this rhythm to avoid fatigue:

1. one project setup
2. top 10 audit
3. one to three real issue loops
4. write notes immediately
5. stop before the session turns into random clicking

If a session starts feeling noisy, switch from product interaction to note capture. Good notes are more valuable than one more half-focused click-through.

## Suggested Session Plan

### Session 1

- `sitecmd.com`
- `ProjectCostCalc`

### Session 2

- `VisitYourTeam`
- `example-site`

### Session 3

- free-tier smoke pass
- packaged app smoke pass

### Session 4+

- remaining acceptance projects
- `SiteCMD` dogfood pass

## Exit Criteria For The Manual Wave

The manual wave is useful enough to stop and switch back to fixes when:

- the first wave is reviewed
- at least one free-tier smoke pass is done
- at least one packaged-app smoke pass is done
- the main recurring scanner trust issues are known
- the biggest workflow slowdowns are written down clearly
