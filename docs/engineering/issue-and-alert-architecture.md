# Issue And Alert Architecture

This is the current operating model for issues, alerts, action items, and their
state inside SiteCMD. The goal is to keep the product model explicit so future
changes stay legible for humans and AI agents.

## Core Concepts

`work_items`
: Raw detected issue signals from scans and integrations.
: These are observations, not user workflow state.
: Examples: `web_scan` failure, PSI regression, package vulnerability signal.

`IssueGroup`
: The grouped read model built on top of raw `work_items`.
: Groups multiple raw signals under one canonical `check_id`.
: This is what the Issues page and issue-score logic read.

`project_issue_states`
: Env-scoped workflow state for canonical issues.
: Stores user decisions like `ignored`, `blocked`, `snoozed`, and `verified`.
: Keyed by `project_id + env_url + check_id`.

`project_work_items`
: Operator-facing action items and maintenance workflow rows.
: These are not the same thing as grouped issues.
: Examples: stale scan reminders, launch blockers, dependency update work, action-item queue rows.

`alerts`
: Informational signals that matter, but are not directly actionable enough to
be treated as issues or action items.
: Example: a traffic drop or trend change that should inform operator judgment.

## Separation Of Responsibility

### Raw issue storage

Module: `apps/desktop/src-tauri/src` work item storage.

Owns:

- raw work-item row shape
- diff upsert behavior
- active row reads

Does not own:

- grouped issue projection
- user workflow state

### Grouped issue projection

Module: `apps/desktop/src-tauri/src` grouped issue projection.

Owns:

- grouping by canonical `check_id`
- severity rollup
- impact score
- likely causes
- integration suggestions
- page-scoped filtered issue views

Reads:

- raw `work_items`
- env-scoped `project_issue_states`

### Issue state overlay

Module: `apps/desktop/src-tauri/src` issue state storage.

Owns:

- env-scoped state transitions for grouped issues
- canonical `check_id` overlay state

Important rule:

- project-wide issue reads must not apply env-scoped state overlays, because
  multiple environments can legitimately share the same `check_id`

### Action-item assembly

Module: `apps/desktop/src-tauri/src` project action item commands.

Owns:

- action-item queue building
- action-item summary building
- workflow cue generation
- complete local action detail without subscription-tier filtering

These functions operate on `project_work_items`, not raw issues.

### Maintenance item assembly

Module: `apps/desktop/src-tauri/src` project maintenance item commands.

Owns:

- stale scan reminders
- deploy-follow-up maintenance items
- watched-file follow-up maintenance items
- integration freshness maintenance items

This module exists so maintenance policy does not drift back into the main
project IPC orchestration module.

### Project signal snapshot orchestration

Module: `apps/desktop/src-tauri/src` project signal snapshot commands.

Owns:

- project signal snapshot assembly
- lightweight snapshot assembly
- dashboard scan state loading
- dashboard integration/reference-signal loading
- nav badge source inputs

This module exists so the main project command module can stay focused on IPC
command handlers instead of also holding the full dashboard/snapshot
orchestration layer.

### Issue verification capability routing

Module: `apps/desktop/src-tauri/src` issue source capability routing.

Owns:

- mapping source names to verification capability
- dispatching verification behavior per source type

This avoids letting the issue command module grow a large hardcoded source
switch.

## Frontend Model

Module: `apps/desktop/src` issue API boundary.

This is the frontend API boundary for grouped issues and issue-state actions.

Prefer this naming:

- `getIssues`
- `getIssueScore`
- `getIssuePages`
- `getPageIssues`

Avoid reintroducing `work-items` naming in the frontend for grouped issues,
because in Rust that name refers to raw issue signals, not the grouped read
model.

Shared issue-state fetch/event logic lives in the issue resource hook. That
hook is the common layer for the Issues list and score reads.

## Rules To Preserve

1. A grouped issue is identified by canonical `check_id`, not by source-specific signal IDs.
2. User issue state must always be env-scoped.
3. Project-wide issue reads must stay state-agnostic unless we add a real
   project-wide state model.
4. Raw issue storage and operator action items are different layers and should
   not be merged again.
5. Alerts are not issues and should not silently become action items without a
   product-level decision.
6. Frontend naming should follow the grouped-issue model, not the raw storage table names.

## Good Future Extensions

- Add a source capability registry entry instead of extending `issues.rs`
- Add a grouped-issue projection helper instead of expanding raw storage code
- Add a new action-item builder in `project_action_items.rs` instead of pushing
  more queue logic into `project.rs`
- Add new maintenance follow-up policy in `project_maintenance_items.rs` instead
  of re-expanding `project.rs`
- Add snapshot/read-model helpers in `project_signal_snapshots.rs` instead of
  re-expanding command handlers
