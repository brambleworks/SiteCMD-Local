# Unified Scan Architecture

**Status:** Implemented

**Audience:** Engineers changing scan execution, persistence, findings, issue lifecycle, scoring, history, or downstream consumers.

**After reading:** A reader should be able to add or modify a collector without creating another parallel history, identity, lifecycle, or scoring model.

## Purpose

SiteCMD has two collection engines with different runtime needs:

- Web Scan analyzes a live URL through HTML checks, HTTP probes, and optional browser analysis.
- Code Scan walks a linked source tree and emits source-level findings.

Those engines remain separate. Their output converges before persistence so every downstream feature can use one execution, finding, lifecycle, history, and scoring model.

The architectural boundary is:

```text
user or scheduler intent
  -> validated execution plan
  -> one admitted scan execution
  -> one or more collector runs
  -> immutable findings
  -> active work-item projection
  -> lifecycle, score, history, reports, and MCP
```

Collector source is evidence metadata. It must not create a second product model.

## Canonical domain model

### Scan execution

A scan execution records one user or system intent. It owns:

- project and environment scope
- requested mode
- trigger
- validated capability plan
- idempotency key
- admission and concurrency decision
- start, completion, cancellation, and failure state

Full, Web, Code, scheduled, tray, and verification requests all enter through the same admission boundary.

A Full scan is one execution with Web and Code child runs when a source folder is linked. It appears once in history. Local scans have no plan-based quota.

### Scan run

A scan run records one collector unit inside an execution. Web and Code are sibling run kinds. Multi-page Web scans may add child page runs without creating more top-level executions.

Run state may succeed, fail, or be unavailable independently. One unavailable capability does not erase evidence produced by another run.

### Scan finding

A scan finding is immutable evidence emitted by a run. It records:

- canonical check identity
- severity and confidence
- title, description, and evidence
- source and occurrence location
- observation time
- collector-specific metadata needed for later explanation

Historical findings are not edited to represent current state. A later observation creates later evidence.

### Work item

A work item is the current projection of related finding occurrences. It supports active Issues, grouping, recurrence, and score inputs.

The projection may point to the latest evidence, but it is not the historical record. History reads executions, runs, and immutable findings.

### Issue state

Issue state stores the user's decision for one canonical issue group, including ignore, block, snooze, reopen, and verify transitions.

All producers and consumers use the same lifecycle store. A collector must not introduce a source-specific dismissal or status table.

### Fix-attempt target

A fix attempt keeps rule identity separate from occurrence target:

- the canonical check ID identifies the detector
- the group target identifies the affected issue group
- the occurrence target identifies a file, route, or other concrete location

Paths and line snapshots are occurrence data, not part of the canonical check ID. This keeps lifecycle, grouping, navigation, and recurrence stable when a file moves or line numbers change.

## Identity invariants

1. A canonical check ID names one detector or rule and contains no project path.
2. Group identity is stable across repeated observations of the same issue.
3. Occurrence identity may include a concrete location, but location parsing never reconstructs rule identity.
4. Display title, severity, and copy are not identity fields.
5. Web and Code findings use the same grouping and lifecycle contracts.
6. New collectors map into these identities instead of inventing a parallel namespace for downstream features.

## Execution semantics

### Admission

The backend validates the complete execution plan before starting a collector. Admission decides:

- requested collectors and capabilities
- project and environment scope
- bounded verification status
- concurrent execution ownership
- idempotency ownership
- cancellation identity

No frontend label or trigger name is trusted as proof that work is safely bounded.

### Idempotency

One idempotency key belongs to one validated plan. Reusing it returns existing work or rejects an incompatible request. It never starts an unrelated scan.

A deliberate new action receives a new key.

### Local access and hosted entitlement

The complete local workbench is free. Admission does not reserve or consume daily scan units, and local Full, Web, Code, scheduled, tray, and verification runs are not tier-gated.

Concurrency, idempotency, path validation, and network policy still apply. Connected-service entitlement is enforced by that service and is separate from admission of a local scan. A verification request must accurately describe its scope even though neither bounded nor full local scans consume a quota.

### Cancellation and progress

Cancellation belongs to the execution request and is checked between collector phases. Child progress rolls up to the execution without losing source-specific detail.

Cancellation must leave a coherent terminal execution record and release active execution ownership. Partial evidence must not appear complete.

## Persistence and history

The persistence service writes execution state, run state, findings, work-item projection changes, and related events through one bounded database worker.

History is execution-first:

- one row represents one user or system intent
- detail expands into child runs and findings
- Full does not appear as unrelated Web and Code entries
- multi-page Web work remains grouped under its execution

Current Issues are projection-first:

- immutable findings provide evidence
- work items provide current grouped state
- issue state applies the user's workflow decisions
- recurring evidence updates the projection without rewriting history

Reports, exports, events, regressions, and MCP read the same canonical data rather than reconstructing a second combined model.

## SiteCMD Score

SiteCMD exposes one user-facing score.

The Rust scoring authority computes it over deduplicated, status-filtered issue groups. Web Scan, Code Scan, and future collectors are evidence sources only. Source-specific scores may remain in raw historical diagnostics but must not become competing product scores.

Changing a collector adapter or occurrence location must not change the score unless the active evidence, severity, confidence, or lifecycle state changes.

## Consumer responsibilities

### Frontend

The frontend starts canonical executions, renders execution history, and consumes grouped issues and score snapshots. It does not merge separate Web and Code histories or calculate a second score.

### MCP server

MCP reads the same execution, finding, correlation, lifecycle, and score model. It does not infer canonical IDs from display copy or file paths.

### CLI

The standalone `sitecmd-cli` package and desktop both depend on `sitecmd-runtime`. The CLI runs Web Scan and the full Code Scan audit without Tauri or a GUI. Default binaries omit browser analysis; source builds can enable the optional `browser` feature. Its output uses canonical check identities and the same finding semantics. See [the native runtime boundary](native-runtime-boundary.md) for ownership.

### Background scheduler

Scheduled work enters the same admission and persistence boundaries as manual work. It cannot bypass concurrency, cancellation, network, or lifecycle rules by calling collectors directly.

## Adding a collector

A new collector is complete only when it:

1. declares its capabilities and validation requirements
2. runs as a child of a canonical execution
3. maps evidence into canonical check, group, and occurrence identities
4. persists through the shared service
5. updates the active work-item projection
6. participates in cancellation, progress, and terminal-state handling
7. feeds the existing score and lifecycle model
8. appears through existing history, report, export, and MCP contracts
9. has migration, identity, admission, redaction, and failure tests

Adding a collector must not add a new top-level history table, issue-state store, score, or frontend merge path.

## Failure and recovery

Execution state must distinguish complete, partial, cancelled, and failed work. Missing browser support, an unavailable linked source tree, or one failed child run is visible coverage state, not a clean result.

Database migrations fail closed and preserve a recoverable backup when compatibility cannot be guaranteed. Pre-launch development data may be reset only where the release policy explicitly permits it.

The event and query layers invalidate downstream views after durable state changes. In-memory UI state is not the authority for completed scans or issue lifecycle.

## Structural verification

Repository tests protect the architecture by checking:

- one admission path for manual, scheduled, and verification work
- one canonical execution and admission decision for Full
- path-free canonical check IDs
- no legacy source-specific scan tables or command families
- one issue lifecycle store
- one Rust score authority
- history and MCP parity
- migration integrity and orphan prevention
- bounded persistence and cancellation behavior
- score neutrality for identity-only changes

These are architectural invariants, not migration-era compatibility promises.
