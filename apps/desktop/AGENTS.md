# AGENTS.md

Frontend guidance for the SiteCMD desktop app. Read the root guide for product
and repository rules, the Rust guide before backend changes, and
`src/styles/COMPONENT_GUIDE.md` before writing markup.

## Commands

Run from the repository root.

```bash
pnpm tauri:dev
pnpm dev
pnpm test:desktop
pnpm test:watch
pnpm e2e
pnpm --filter @sitecmd/desktop exec tsc -b
pnpm size
```

`pnpm dev` starts Vite without the Tauri shell, so IPC calls fail. Rust changes
require a Tauri dev restart; frontend changes hot-reload.

## App shell and navigation

SiteCMD has no router library.

- `App.tsx` is the provider shell.
- `app/AppContent.tsx` owns orchestration.
- `app/AppRoutes.tsx` renders one lazy page per `NavPage`.
- `app/useNavigationState.ts` is the only page, overlay, settings-tab, and
  command-palette state. Extend its reducer instead of adding navigation state
  to `AppContent`.
- `components/layout/nav-page.ts` owns the navigation vocabulary and validates
  untrusted targets.
- `app/ShellHeader.tsx` owns page headings. Pages do not render duplicate title
  headings.

Dashboard is the primary triage surface. Issues is the unified active-finding
list. Security is an Issues category filter, not a separate page.

`app/useAppScanActions.ts` owns scan dispatch. `code` runs Code Scan, `web` runs
a health Web Scan, and `full` runs Web Scan followed by Code Scan when a source
folder is linked.

## Data and events

- Re-fetchable IPC data uses the TanStack Query layer in `lib/query/`. Register
  keys centrally and add refresh events to the invalidation registry.
- Data that would be lost on eviction remains in its explicit Tauri Store-backed
  domain store.
- Register every backend event and payload in `lib/app-events.ts`. Subscribe
  through `useTauriEvent` and emit through `emitAppEvent`.
- Raw event listeners are limited to the documented per-scan and updater
  progress paths.
- Background jobs use the `useSyncExternalStore` store in `lib/jobs.ts`.
- Memoize every context-provider value.
- Toast only for manual actions, never automatic loads or background refreshes.
- Correlation is computed in Rust. Do not create a frontend correlation cache.

## Issues and fix guides

- Issue transitions use the typed wrappers in `lib/commands/issues.ts` and key
  on project, environment URL, and canonical check id. There is no generic
  dismiss command.
- Unified ranking combines Web and Code findings. Severity and confidence drive
  priority; scan source does not.
- The complete local workbench is free. Do not add `FeatureGate`, `hasFeature`,
  tier-conditional local data, or local upsell locks.
- `useTier` is for subscription display and connected-service state only.
- Local fix guides contain at most two bounded baseline steps with a quick,
  moderate, or involved effort. Deep stack-aware content comes from the private
  catalog.
- Adding a check requires its local baseline guide and public regression fixtures.
  Follow `../../docs/engineering/adding-a-detector.md`. Maintainers coordinate
  private catalog content separately before an official release.
- Baseline acceptance and dismissal are separate controls. Acceptance sends the
  displayed revision and value digest; `stale_revision` is shown, not retried.
- Deploy-regression copy must keep detector-change findings separate from
  findings attributed to the deploy.
- Extract page handlers into a focused `use<Page>Actions` hook before a page
  approaches its line budget.

## Styling

`src/styles/COMPONENT_GUIDE.md` is authoritative. Component classes live in
`src/styles/*.css` partials; `index.css` only imports them.

Use the established source map:

- `tokens.css`: variables and themes;
- `typography.css`: text roles;
- `layout.css`: layout primitives;
- `chrome.css`: application chrome and navigation;
- `cards.css`: cards, tiles, and panels;
- `data.css`: rows, statistics, and metadata;
- `interactive.css`: icon buttons, tabs, toggles, and segmented controls;
- `buttons.css`: shared Button variants and sizes;
- `pages/`: page-specific layouts.

Hard rules:

1. Use `components/ui/button.tsx` for every clickable action. CVA is banned.
2. Extract a named class when a `className` exceeds 100 characters or composes
   six or more classes.
3. No inline `style` attributes. The only exceptions, allowlisted in
   `tools/scripts/lib/guardrail-style-rules.mjs`, are `progress-bar` (runtime
   width), `score-ring` (geometry derived from its numeric `size` prop), and
   `ReportPDFSections` (react-pdf has no stylesheet).
4. No hardcoded hex colors or `text-zinc-*`. Use design tokens.
5. Extract any repeated visual pattern with a role-based name.
6. Empty states include a direct action button.

Do not add pill-shaped metadata badges, top accent strips, list-row radii,
hover effects on noninteractive elements, text below 10px, bracketed eyebrow
labels, U+2014 em dashes, or the abbreviation `a11y`.

## Accessibility

- Every interactive element needs a visible background-changing hover state.
- Selected states need more than a subtle text-color shift.
- Buttons, links, selects, and clickable custom elements use a pointer cursor.
- Disabled controls expose a clear disabled appearance and cursor.
- Readable content must meet contrast requirements in every theme.
- Prefer native controls. Custom interactions require keyboard behavior, focus
  treatment, and an accessible name.

## Conventions

- `@/` maps to `apps/desktop/src/`.
- `lib/types.ts` mirrors Rust serde output.
- Use the root guide's shared time, severity, and score helpers.
- Third-party API calls belong in Rust, never the renderer.
- Use shared UI primitives in `components/ui/` before introducing a new one.
