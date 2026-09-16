# Product

## Platform

desktop

## Users

Primary: solo and small-team developers shipping AI-assisted ("vibe-coded")
sites and apps. Indie hackers, solo founders, and small startups who build fast,
often with AI coding tools, and need to verify a site is secure, accessible,
performant, and free of AI-generated footguns before and after they ship. They
are technical enough to link a source folder and read findings, but want
reproducible answers rather than one more dashboard to babysit.

Their situation and job: "I just shipped, or am about to ship, something I built
quickly. Is it actually sound, and if not, exactly what do I fix?"

Secondary (a later target, not the launch focus): agencies and freelancers
managing many client sites, where the ongoing multi-site command-center use case
leads over one-off scanning. In-house engineers bolting SiteCMD onto an existing
quality/CI stack are a possible tertiary audience. Center PRODUCT decisions on
the primary user unless the user says otherwise.

## Product Purpose

SiteCMD is a local-first desktop app that scans both a live site (Web Scan) and
its linked source code (Code Scan), unifies every finding into one SiteCMD Score
and one prioritized issue list, and tells the developer exactly what to fix.

It exists because people now ship production sites built fast with AI assistance
and have no trustworthy, private way to check whether those sites are secure,
accessible, and sound. The existing options are either cloud services that
ingest your code, or single-purpose linters that each see one narrow slice.
Success is a developer opening the app, running a scan, and walking away with a
ranked, actionable fix list they trust, repeatedly, treating SiteCMD as an
ongoing health command center rather than a one-off audit.

## Positioning

The mechanism a neighboring product could not truthfully copy: SiteCMD's
detection basis is 390+ deterministic, reproducible checks run entirely on the
user's machine, not an AI model guessing at problems. AI is confined to a
fix-assist layer (fix prompts and guides) and never decides whether a finding
exists. "Run your site on facts, not vibes" is the public expression of this.

Two supporting pillars reinforce the lead, but do not replace it:

- Local-first and publicly auditable. SiteCMD does not upload source content
  to its services. Connected finding submissions require explicit setup.
  Configured AI editors and user-published reports handle the evidence shared
  with them under their own data controls. The Apache-2.0 client makes the
  SiteCMD boundary inspectable.
- One unified score and issue list spanning live-site checks, source-code audit,
  and connected services, so issues get fixed wherever they live instead of
  scattered across single-purpose tools.

The desktop client, CLI, MCP server, and scan engine are published under
Apache-2.0. Durable commercial value lives in the connected service and its
maintained intelligence delivery, enforced on SiteCMD infrastructure. The
private strategy and service implementation records live in the separate
SiteCMD-Web repository.

## Operating Context

- This is a desktop application (Tauri v2: Rust backend, React 19 + TypeScript +
  authored CSS frontend), not a website. Its design language is web, rendered
  in a native window. It lives in the system tray, runs background scheduled
  scans, and raises OS notifications on score drops or critical issues; closing
  the window hides to tray rather than quitting.
- The unit of work is a Project, which has environments (local, development,
  staging, production), each with a URL. Scans produce scored findings stored in
  a local SQLite database. The Activity timeline unifies scans, deploys, uptime
  incidents, and analytics anomalies.
- Two evidence engines feed one model: Web Scan (categorized checks against a
  live URL) and Code Scan (audit of a linked local source folder). The user
  points Code Scan at a real source directory on their machine.
- It fits into a developer's existing workflow rather than replacing it: an MCP
  server lets AI coding tools (Cursor, Claude Code, Windsurf) read scan results
  and help fix issues; a standalone CLI (`sitecmd`) runs Web Scan and the full
  Code Scan audit in CI/CD without Tauri or a GUI;
  connectors pull in analytics, search, uptime, and deploy data; findings can be
  mirrored to GitHub or Jira.
- Primary in-app surfaces (workflows): Dashboard (primary triage), Issues (the
  unified findings list), Traffic, Alerts, Deploys, Activity, Search & SEO,
  Updates (dependency updates), Reports, Integrations, Overview, Settings.

## Capabilities and Constraints

Capabilities:

- Web Scan: categorized deterministic checks (security, accessibility,
  compliance, SEO, performance, config, predeploy, plus polish signals) against
  a live URL, including axe-core WCAG A/AA auditing and Core Web Vitals measured
  in a hidden webview.
- Code Scan: a static source-code auditor for security, database analysis, AI
  safety, architecture, operations, dependencies, and AI setup. The separate
  Updates workflow queries registries and advisories for eight ecosystems:
  npm, pip/Python, Composer, Cargo, Go, Ruby, Drupal, and WordPress.
- One SiteCMD Score, computed once in Rust over deduplicated, status-filtered
  issue groups. One unified, ranked Issues list merging web and code findings;
  scan source never changes an issue's priority.
- Framework-aware fix guides, AI-ready fix prompts, reports and dossiers, and a
  cross-finding correlation engine (likely causes, downstream effects,
  deploy-risk preview).
- Eight user-configurable integrations: Plausible, Cloudflare, UptimeRobot, GA4,
  Search Console, Bing, GitHub, Jira.
- Background scheduled scans with OS notifications and a system tray; an issue
  lifecycle of ignore, snooze, block, reopen, and verify.

Constraints and durable product facts:

- Deterministic-first: AI never originates a finding; it only helps fix one that
  the checks already produced.
- Local-first privacy is a hard boundary: source content and raw file paths are
  never sent to a Brambleworks service. Connecting a site is explicit and sends
  the documented, inspectable finding envelopes needed for shared baselines,
  hosted verification, and alerts. The maintained catalog is delivered to the
  client and receives no source content.
- One score, never split by source. Unified scans, never fragmented into
  separate web/code navigation. These are core product theses, not preferences.
- `product-facts.json` carries the derived check counts for this repository
  (currently 420 total). The public "390+" floor is maintained and
  guardrail-enforced in the separate SiteCMD-Web product package.
- Honest scoring: diminishing deductions from 100, reduced effective counts
  for needs-review findings, and explicit coverage state. Severity alone does
  not cap the score. A narrow audited class of critical findings with explicit
  High or Confirmed confidence caps it at 49 while active.
- Licensing: subscriptions use LemonSqueezy and retain the internal
  free/core/pro tier vocabulary. The local workbench is complete and free on
  every tier: every scan, full issue detail, fix guides, AI prompts, reports,
  and dossiers, with no meters, caps, or redaction anywhere in the client. A
  subscription buys the connected service and maintained intelligence stream,
  enforced server-side where no fork reaches. Connected-service access is
  free during the beta and public pricing is not set.

Terminology: "SiteCMD Score" (never Web Score or Code Score); "Issues" for the
unified list (security is a category filter inside it, not its own page); "list,"
not "queue," in user-facing copy; Web Scan and Code Scan for the two engines;
"SiteCMD Connect" for the hosted service (lowercase "connected service" only as
a descriptor in running prose);
"Accessibility" always spelled out in full, never "A11y."

## Brand Commitments

- Name: SiteCMD. Vendor: Brambleworks. Marketing at sitecmd.com; checkout at
  shop.sitecmd.com; support at support@sitecmd.com.
- Voice: "facts, not vibes." Plain, deterministic, honest. No fabricated claims:
  never invent policies, guarantees, statistics, testimonials, or customers.
  The published [SiteCMD terms](https://sitecmd.com/terms) are the source of
  truth for commercial terms; all sales are final (there is no refund policy).
- One SiteCMD Score, never split by source. Unified scans, never fragmented.
  Non-negotiable product theses that also govern how the product is described.
- "Accessibility" is always written in full; never "A11y."
- Binding visual-identity constraints, enforced by repository guardrails and
  detailed in the design system rather than expanded here: theme tokens only (no
  hardcoded hex or `text-zinc-*`), no inline `style=` attributes, no pill/badge
  styling for severity or status metadata, flat list rows (not rounded cards),
  and no colored accent bars at the top of cards. The full visual world belongs
  in DESIGN.md, not this file.

## Evidence on Hand

- A fully built, shipping product. `product-facts.json` marks the desktop app,
  MCP server, CLI, CI quality gates, and ticket mirroring as available.
- Real, generated check counts live in `product-facts.json`; the current total
  is 420 and the public marketing floor is 390+.
- A marketing and documentation site plus a public top-of-funnel scanner exist
  in the separate SiteCMD-Web repository.
- Accessibility is shipped as a product feature (axe-core WCAG A/AA), a standard
  the organization also holds its own surfaces to.
- Absences future work must not paper over: there are no customer testimonials,
  case studies, named customers, third-party benchmarks, or refund policy to
  cite. Do not invent any. Social proof must be genuinely sourced or omitted.

## Product Principles

1. Deterministic facts over vibes. Findings come from reproducible checks, never
   an AI guess; AI is confined to helping fix what the checks already found. This
   is the trust contract and the reason to believe the score.
2. Local-first and auditable by design. SiteCMD does not send source content to
   its services; connected-site envelopes leave only after explicit setup and
   remain inspectable in the open client. Editors and exported reports have
   their own sharing boundaries.
3. One score, one list, wherever issues live. Web, code, and integration
   findings unify into a single SiteCMD Score and a single ranked issue list;
   scan source never changes priority, and the product never fragments by origin.
4. Honest by construction. No fabricated claims, diminishing severity
   deductions with a narrow evidence-gated security cap, and coverage stated
   plainly. Uncertain static matches do not establish exploitability.
5. Meet developers where they already work. MCP for AI editors, a CLI for CI, and
   connectors for the existing stack. SiteCMD is an ongoing command center that
   plugs into the workflow, not another silo to babysit.

## Accessibility & Inclusion

Accessibility is both a product feature and a self-imposed standard. SiteCMD
ships WCAG A/AA auditing (axe-core) as a core capability, so its own surfaces
must meet the bar it sells: every interactive element carries a visible,
non-color hover and active state; active/selected states are clearly
distinguishable; text contrast avoids low-contrast greys; and a minimum readable
text size is enforced. Shipping an inaccessible surface is the one regression the
product cannot afford. "Accessibility" is always written in full.
