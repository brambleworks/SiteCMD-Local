# SiteCMD Observability

SiteCMD keeps a privacy-safe local observability snapshot for the core workflow and supports
explicit opt-in hosted telemetry for launch diagnostics.

## What It Captures

- Crash and startup failures from:
  - global `window.error`
  - `unhandledrejection`
  - React error boundaries
  - startup watchdog timeouts
  - bootstrap failures before the app shell mounts
- Workflow health events for:
  - `add_site`
  - `run_scan`
  - `open_issues`
  - `copy_guidance`
  - `verify_issue`

## Privacy Guardrails

The local snapshot strips common sensitive patterns before storing them:

- URLs
- localhost addresses
- filesystem paths
- email addresses
- obvious API key prefixes

It is designed to tell us which workflow broke, not what site content or prompt text the user had open.

Hosted telemetry is off until the user opts in. Usage analytics and crash/error reports are separate
choices. Renderer telemetry enters through `apps/desktop/src/lib/telemetry.ts`.
Its typed requests cross the Tauri bridge to the native backend, which owns
consent enforcement, validation, and transport to the fixed telemetry and Sentry hosts.

Hosted telemetry must never include:

- scan URLs or website content
- project names or local filesystem paths
- source code, source excerpts, prompts, or request/response bodies
- license keys, API keys, OAuth tokens, webhook URLs, or provider errors
- raw logs

## How To Retrieve It

From the desktop app:

1. Open `Settings`
2. Go to `Privacy & Diagnostics`
3. In `Diagnostic logs`, click `Copy Logs`

The copied diagnostics still include:

- recent backend/frontend logs
- the local performance snapshot
- the local observability snapshot

## What To Look For

The observability snapshot surfaces four health signals first:

- `onboarding`
  - derived from failed `add_site` events
- `scans`
  - derived from failed `run_scan` events
- `issues`
  - derived from failed `open_issues` events
- `crashes`
  - derived from fatal startup / runtime error events

If any of those flip to `needs attention`, we should treat it as launch-triage material.

## Launch Intent

This is meant to answer a simple question quickly:

- Is onboarding breaking?
- Are scans failing?
- Is the Issues surface failing to load?
- Are people hitting startup or runtime crashes?

## Hosted Telemetry

The hosted pipeline is split by purpose:

- Usage analytics go to a SiteCMD-controlled Cloudflare Worker. The worker validates an allowlisted
  schema and writes accepted events to hosted storage for aggregate product analysis. The desktop
  first registers its random anonymous subject and receives a short-lived, subject-bound ingest
  token; ingestion is rate-limited globally, by IP, and by anonymous subject.
- Crash and error reports go to Sentry only after the separate diagnostics opt-in. Session replay,
  broad tracing, autocapture, and default PII collection are disabled. A small bounded breadcrumb
  tail is retained for debugging only after each message and metadata field is sanitized.

Raw Cloudflare D1 telemetry rows are deleted after 90 days by a daily scheduled retention job.
Aggregate Analytics Engine data is used for product metrics. The desktop drops locally queued
events after seven days so offline data cannot remain stuck retrying after the server acceptance
window closes.

The first-run prompt and Settings > Privacy & Diagnostics let users enable, disable, preview, reset,
and delete telemetry data. Turning usage analytics off clears queued local telemetry immediately.
The native backend persists both consent controls and defaults them to off. Enabling either control
requires native confirmation. Renderer code sends a closed, typed request enum to that backend; it
cannot supply a destination URL, arbitrary body, or arbitrary diagnostic event. The backend checks
consent again, validates an allowlisted schema, constructs the final envelope, and chooses the fixed
SiteCMD telemetry or baked Sentry host. Disabling consent therefore closes the transport boundary,
not just the visible switch.

The telemetry deletion-proof secret is stored in the OS keychain. The renderer
receives its hash for registration and queues deletion through the native
backend; it never receives the secret itself. Deleting uploaded telemetry and
resetting the anonymous identity are explicit operations, separate from turning
off future collection.

Desktop builds opt into hosted endpoints with explicit public env values:

- `VITE_SITECMD_TELEMETRY_ENDPOINT` points at the Cloudflare Worker `/v1/events` endpoint.
- `VITE_SITECMD_SENTRY_DSN` enables the Sentry diagnostics wrapper after crash-report consent.
- `VITE_APP_VERSION` is copied into telemetry envelopes so aggregate reports can group by release.

Leaving these unset keeps hosted telemetry disabled even if a local test toggles consent on.
