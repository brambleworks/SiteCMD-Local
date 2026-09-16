# Performance Budgets

SiteCMD enforces renderer performance budgets in automated tests and records the same metrics during
normal app use. This document defines the durable budgets and validation process. Release-specific
measurements belong in the release QA record, not in this file.

## Runtime Metrics

The desktop app records these metrics locally:

- `app.cold_start_ms`
- `app.first_project_load_ms`
- `scan.duration_ms`
- `issues.initial_ready_ms`
- `events.initial_ready_ms`

## Budgets

| Metric              |    Budget | Notes                                              |
| ------------------- | --------: | -------------------------------------------------- |
| Cold app start      |  `2500ms` | From bootstrap start to mounted shell              |
| First project load  |  `1500ms` | From initial project fetch to usable context       |
| First scan duration | `20000ms` | End-to-end scan timing recorded by the desktop app |
| Issues page render  |  `1200ms` | From page entry to rendered issue content          |
| Activity page load  |  `1500ms` | From range load to rendered activity feed          |

The source of truth is `apps/desktop/src/lib/performance-metrics.ts`. Update the code and this table
together when a budget changes.

## Automated Regression Gate

Run:

```sh
pnpm perf:baseline
```

The command exercises renderer bootstrap, project loading, Issues, and Activity with representative
fixtures. It fails when a measured average exceeds its budget and runs as part of `pnpm verify:push`
and the frontend quality workflow.

The harness is a regression signal, not a native startup benchmark. It does not include Tauri
process launch, operating-system integration, real IPC latency, network latency, or production
hardware variance.

## Release Validation

Validate each release candidate with a release build on every supported platform:

1. Install the signed release candidate from the release workflow. For a local optimized build, use `pnpm tauri:build:contributor`; `pnpm tauri:build:release` is reserved for release operators with the updater signing key.
2. Cold launch the installed artifact.
3. Open a project that already has data.
4. Run one scan and confirm Dashboard is usable afterward.
5. Open Issues and Activity.
6. Copy `Settings -> Privacy & Diagnostics -> Diagnostic logs -> Copy Logs`.

The copied diagnostics include a `SiteCMD Performance Snapshot` with local samples and budget status.
Attach that snapshot to the private release QA record. Investigate any repeatable budget breach before
publishing. Document an accepted exception with the affected platform, measurement, and rationale.
