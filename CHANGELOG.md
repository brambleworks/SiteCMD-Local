# Changelog

Notable user-facing changes to SiteCMD will be recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
releases use [Semantic Versioning](https://semver.org/).

This changelog begins with SiteCMD's first public release. Private development
tags and their generated artifacts are intentionally not carried into the
public repository history.

## [Unreleased]

## [1.4.0] - 2026-09-16

### Added

- The `sitecmd` CLI ships for Linux arm64. `@sitecmd/cli` installs
  `@sitecmd/cli-linux-arm64` on arm64 machines, the standalone installer and
  the GitHub Actions setup action pick the `linux-aarch64` archive, and each
  release publishes it beside the other signed archives.
- Coding agents can aim `start_fix` at one Code Scan finding. The MCP tool
  accepts the `relative_path` and `line` that `get_issue` reports, and when
  that location is missing, ambiguous, resolved, or suppressed it returns an
  error instead of choosing a different occurrence. Leaving both out keeps
  the old behavior, where SiteCMD picks the occurrence.
- Code Scan recognizes FastAPI's `CORSMiddleware` allowing every origin while
  also allowing credentials, including when the wildcard or the credential
  flag comes from a configuration default or a helper that returns `["*"]`.
  A setting guarded so the two can never combine stays quiet.
- Code Scan reports Python code that turns off certificate verification for
  the whole process by replacing `ssl._create_default_https_context` with the
  unverified context.

### Changed

- A fix handed to a coding agent from one Code Scan finding is now about that
  finding alone. The brief names its file and line and says only that
  occurrence has to clear, and verifying it no longer marks every other open
  occurrence of the same check as verified. Each location keeps its own
  attempt, so two findings from one check in the same file can be in progress
  at once, and a finding's "Fix with" button shows the attempt for that
  finding rather than the latest one anywhere under its check.
- Raw-HTML findings are reported per sink, each at its own line. A sanitizer
  now clears only the sink whose value it cleans, where one sanitizer anywhere
  in a file used to excuse every sink in it, and an `innerHTML` assignment of
  any computed value is reported while a complete string literal is not.
  Files with several sinks will show more findings, each pointing at one line.
- An open redirect in a JavaScript or TypeScript route counts as guarded only
  when the guard applies to that redirect's destination: a literal path, an
  allowlist helper, a URL built against a trusted base, or an origin check
  before the redirect. Any `.origin`, `.host`, or `startsWith("/")` elsewhere
  in the file used to silence the finding, so some redirects that were
  excused before are now reported.
- `spawn` and `execFile` calls are reported as shell injection only when they
  pass `shell: true`. Without a shell, arguments reach the program as separate
  values and are never read as shell syntax.

### Fixed

- Code Scan findings that shared a check, a file, and a line, such as two
  unused dependencies reported on the same `package.json` line, were saved as
  a single issue. Each now has its own.
- A database export could leave out recent changes. The export copied the
  database file after asking SQLite to fold in its write-ahead log, which
  cannot finish while another part of the app is reading, so changes still in
  the log were missing from the backup. Exports now use SQLite's backup
  interface, which includes every committed change.
- A `robots.txt` line whose first eight bytes split a multi-byte character
  crashed the sitemap check.
- A coding agent could start a fix through MCP for an issue you had dismissed
  or snoozed. The desktop app now refuses the request and tells the agent to
  read the current issue list.
- `get_fix_prompts` could return an unbounded response: asking for one check
  ignored `limit`, and long prompts had no overall size cap. Responses now stop
  at a fixed size and say when they were shortened.
- Long sessions did more background work than they needed to. The events feed
  kept every event it polled for as long as the page stayed open and now keeps
  one page, and the check that watches project folders for changes could start
  a new pass while the previous one was still reading a large project.

### Security

- Updated rustls, the TLS library behind every HTTPS request the app and the
  CLI make, past RUSTSEC-2026-0285, under which it accepted TLS 1.3 handshake
  messages sent at the wrong encryption level.
- A scan of `localhost` skipped certificate verification for every host it
  contacted, including public sites a local page redirected to or loaded
  assets from. The exception for self-signed certificates now covers loopback
  addresses only.
- The secret that authorizes deleting your uploaded telemetry now lives in the
  OS keychain beside the license key and never enters the app's webview, and
  the short-lived upload token stays in memory. Both used to sit in the
  webview's local storage.
- The MCP server marks project URLs, framework names, and fix prompt metadata
  as untrusted scan data, as it already did for project names and paths, so
  text a scanned site controls cannot pass for instructions to a coding agent.
  A `.sitecmd/config.json` whose site URL is not plain `http` or `https` is
  ignored.

## [1.3.0] - 2026-09-04

### Added

- Scans can target a development server on your own network, such as
  `http://192.168.1.40:8080/`, a container by its service name in CI, or a
  machine on a tailnet. SiteCMD runs as you, on your machine, with your
  network, so a target you name reaches what you can already reach. Only the
  target you name gains that reach: a redirect, a stylesheet, a sitemap entry,
  or any other URL a fetched page chooses still reaches no further than the
  origin you asked for, and link-local addresses stay refused everywhere
  because cloud metadata answers there. The hidden browser keeps the narrower
  loopback boundary, so a private-network scan reports its browser measurements
  as unavailable.

### Changed

- The scan category labeled "Legal" is now "Privacy & Policies". Its checks
  observe what a page shows: whether a privacy notice, terms, accessibility
  statement, consent banner, or tracker is present, and how long a cookie
  lives. They do not determine whether a site meets a legal obligation, and
  every one of those findings already said so in its own words. The label now
  agrees with them, and the scales-of-justice icon that made the same claim
  without words is now a fingerprint. The category id is unchanged, so saved
  scans and issue history carry over untouched.
- Confirmation dialogs for protected actions now name the action in the title
  bar, and the warning icon is reserved for actions that destroy data, revoke
  access, or disclose a secret. Saving an integration used to raise a warning
  triangle headed "Allow Protected Action"; it now reads "Save Integration"
  and asks the same question in the same words. The confirmation itself is
  unchanged, so storing a credential, configuring a webhook, or syncing a
  connected site still needs a native dialog that nothing inside the app can
  answer on your behalf.

### Fixed

- Web links, including Bing setup, open without an extra confirmation dialog.
- Google integration setup stays on the selected service and no longer defaults
  to an unrelated Analytics property or Search Console site.
- Google Analytics and Search Console connections include Google's required
  desktop client credential during sign-in and token refresh.
- A Web Scan's score charged one defect more than once. Open Graph tags, form
  labels, the document language, heading structure, and page-level SEO markers
  are each graded by a Web Scan check and again by a polish signal, and both
  deductions landed even though the issue list already showed them as a single
  finding. A check that reports one row per occurrence, such as one per
  malformed `Set-Cookie` header, also deducted once per row while the dashboard
  score deducted once for the group. Both now charge a defect once, under the
  identity the issue list files it under, so a scan's score and the dashboard's
  agree. Category bars still report what each category observed, and scores on
  affected pages will read a little higher.
- The app and the CLI disagreed about what could be scanned. The app refused a
  private address outright, while the CLI never checked a bare address at all
  and would scan one, yet refused the same machine named by hostname. Both now
  answer the same way, because the scanner validates its target itself rather
  than trusting each entry point to have done it.
- A development server reached by its address on the local network was graded
  as a public production site. It earned a High "served over HTTP" finding
  measured against whatever answered port 443 at that address, and the custom
  404 page and CORS reflection checks had the same gap. Private network
  addresses now count as local, the way a `localhost` or `.test` hostname
  already did.
- Web scans of pages that embed third-party iframes graded the wrong
  document. The hidden browser followed the iframe and measured that page
  instead, producing an accessibility failure, a load time, and a JavaScript
  error that belonged to somebody else's page. It now verifies which document
  it measured and reports the browser layer as unavailable rather than
  reporting a verdict about a different page. Every scan also reported one
  JavaScript error that was SiteCMD's own permission request, not the site's.
- Half the open-redirect probes went unanswered on some sites, taking the
  redirect walk and the www check down with them, because the scan opened all
  of them at once and tripped its own HTTP/2 client's protection. Probes to a
  single origin are now bounded.
- Time to first byte was measured while the scanner's own requests were in
  flight, so a server that accepts connections slowly was blamed for the
  scanner's retries.
- A check that cannot reach a verdict now reports as skipped with the reason
  instead of guessing a warning. A rate-limited 404 probe, an unresolved www
  host, and a partial sitemap read all say what happened.
- A site served only over HTTP now fails the HTTPS check instead of skipping
  it, so an unencrypted site no longer scores well on security.
- Cross-page checks compared pages the scan never really reached: an error
  page could be reported as a duplicate title, and one page reached through
  two URLs was reported as a duplicate of itself.
- Checks matched words inside comments and scripts. A commented-out heading
  counted as a heading, and the words "skip to" in a sentence passed for a
  skip link.
- Sitemap dates written in the shorter standard form were all reported
  invalid, one site had all 1385 flagged. Cloudflare's email-protection link
  was counted as a broken link, and mail signing was reported missing on
  domains that sign through a provider the check never probed.
- A published contact address in structured data was read as a leaked
  password, a form posting to the site's own subdomain was graded by neither
  of the two checks that cover it, and a site whose only analytics is
  cookieless was told it needs a cookie banner.
- Code Scan reported findings for code that was not there: one rule matched
  the words "import" and "export" anywhere in a file, dependencies installed
  from GitHub were called registry mismatches, files a framework installs
  itself were graded as the project's own, and a structured-data block
  excused every raw-HTML sink in its file.
- Coding agents reading SiteCMD through its MCP server could not see
  dependency findings that the score counts, and asking about one was refused
  even though the app itself accepts it.

### Changed

- Cancelling a scan now stops it. The code scan checks for cancellation
  before every file and between stages, the browser analysis abandons its
  wait and releases the hidden browser window, and a cancelled run saves
  nothing and reports nothing. Cancelling and starting again no longer leaves
  the old scan running underneath the new one.
- Ordinary requests ask servers for compressed responses and cap the
  decompressed size, so registry metadata and other large downloads move less
  data. The measurement probes behind the performance checks still fetch raw
  bytes, so transfer sizes and compression headers stay true. Time to first
  byte is now measured the way a browser would see it, with compression
  negotiated, so that number can shift once for origins that compress on the
  fly.
- The "Fix with" handoff to a coding agent no longer shows the system's Allow
  Protected Action dialog. It only opens the agent's app with the prompt
  staged in its composer; nothing runs until you send it there.
- Web scans on Linux no longer run the browser layer, so Core Web Vitals and
  accessibility analysis report as unavailable there. The Linux webview gives
  SiteCMD no private-network subresource filter, and the app now refuses to
  load a page in it rather than expose the local network. Every other check
  still runs.

### Fixed

- Long scans no longer reload every open finding for the whole site after
  each page. The projection asks only for the routes the page covered.
- Sitemap imports run in one transaction. A refused row keeps the previous
  list instead of leaving a partial or empty one, and the refresh reports the
  error instead of claiming success.
- The code scan compiled its request-variable matchers once per evaluation
  instead of once per file, which took a 40 KB route file tens of seconds. It
  now takes milliseconds.
- Multi-page scans download each shared stylesheet once per scan instead of
  once per page. A stylesheet that timed out is still retried on the next
  page; only a definite refusal is remembered for the rest of the scan.
- Opening one scan's details fetches only that run's findings instead of
  every run in the execution.
- The MCP server matched suppression patterns with a regex that a short
  pattern could stall for seconds. Matching now takes time linear in the
  pattern and path, and scan comparison loads history once instead of three
  times.
- The dashboard kept one full code scan report per project in memory for the
  life of the app, including deleted projects. The cache is bounded and
  clears on deletion and when a newer scan lands.
- The scan-scope picker, sitemap settings, and issue Locations lists page
  their rows the way the Issues list does, so a site with thousands of pages
  no longer mounts every row at once.
- The startup bundle gate missed part of the eager graph and reported a false
  pass. It now walks every static import, including the boot stylesheet, and
  the page guide panel, command palette, scan summary, add-project, and
  telemetry consent overlays, and the scan completion handlers load on
  demand to keep startup under budget.
- The scan progress percent no longer sprints, freezes, and leaps. It was
  mapped straight onto check counts, so ninety in-memory checks filled half
  the ring in the first second, the network-bound origin checks then held it
  flat for anything from one to thirteen seconds, then leapt to the end. One
  time-aware model now owns the number for the overlay ring, the jobs tray,
  and the system tray: every event sets a floor, the estimate drifts toward
  the end of the current phase between events, each step of a full scan fills
  its own ring, and the number never moves backward within a step.
- The scan form offers accessibility analysis again. The axe-core pass is on
  by default for web scans, with a switch to skip it for a quicker run, and
  the first baseline scan of a new project includes it so later runs compare
  like for like. The option had been wired to a paid gate that no longer
  existed, so no desktop scan could run it.
- Browser analysis now delivers Core Web Vitals, the browser build, and axe
  results again. The analyzer read every result back through the window
  title, which Tauri only updates from the page when asked, so each read
  silently timed out and every scan recorded the browser layer as having run
  with nothing to show for it.
- Accessibility results and Core Web Vitals now cross from the scanned page in
  chunks. The platform truncates a document title to 1000 characters, so a
  full axe report written into one title never parsed and the pass timed out
  after 20 seconds; a Web Vitals payload carrying several JavaScript errors
  was lost the same way.
- Accessibility analysis no longer takes fifteen seconds a page. The hidden
  analyzer window was timer-throttled as a background tab, on macOS by WebKit
  and on Windows by Chromium, and axe-core schedules its rule batches through
  timers. The analyzer now switches the throttle off before the page loads,
  so axe finishes in well under a second and the page under measurement runs
  at its normal speed.

### Security

- The hidden analyzer webview removes the WebRTC and WebTransport interfaces
  from every frame before a scanned page's scripts run, closing the one path a
  page had around the private-network subresource rules on macOS and Windows.
- The PageSpeed API key is no longer captured as a tracing span field. No
  shipped build wrote it to a log file, because span fields are only forwarded
  at trace level and the app never logs at that level.

## [1.2.0] - 2026-09-01

### Added

- The web scan now flags meta refresh redirects and timed reloads, and asks
  for review when a single page carries more than a thousand links.
- Code Scan reports a test suite that exists but never runs automatically, when
  CI or a commit hook runs other quality commands and skips the tests.
- Code Scan reports a checked-in git hook that was never installed in the
  scanned clone, so the hook config promises a guardrail it does not provide.

### Changed

- Project hygiene checks (tests, linter, CI workflow, commit hooks, and
  .gitignore) now cover static sites, single-page apps, and Composer-based PHP
  projects that have no server routes, instead of only apps with API routes.
  A static site with no tests is reported as Low rather than Medium.
- A missing or decorative commit hook is now Medium when no CI workflow runs
  the project's build, lint, or tests, since the hook would be the only
  automated gate. It stays Low when CI already enforces those checks.
- npm's default `echo "Error: no test specified"` script, and any script that
  only echoes or exits, no longer counts as a test, lint, or build command.
- CI and hook commands for PHP (Pint, PHPStan, PHPUnit, Pest, `composer test`),
  Python (tox, nox, pyright), and task runners are recognized as quality gates.
- A page with several H1 headings, or none, is now reported as an SEO issue,
  matching how search consoles classify it. The accessibility check keeps
  reviewing heading order.
- The Issues list drops the web/code scan filter. One category filter now covers
  findings from both scanners, a search box narrows the list by title, and the
  list pages twenty issues at a time.
- The Issues list and Code Scan results share one pager with numbered page links.
  Previous and Next sit beside the numbers and are hidden at the ends rather than
  shown as dead controls.

### Fixed

- Adding a project folder that runs on DDEV, Lando, Docksal, or a `.test`
  hostname now labels the detected URL as Local instead of listing it as
  another production site.
- Code findings in the Issues list now name their category, such as Database or
  Architecture, instead of every row reading "Code".
- Issue history no longer claims an issue regressed after a deploy when the
  issue had never passed. A regression now requires an earlier verified pass.

## [1.1.1] - 2026-08-31

### Changed

- Fix guides and MCP scan comparisons now use plain words instead of
  emoji, so status and severity read the same everywhere they are quoted.
- The hosted service is now named SiteCMD Connect, replacing the retired
  "Founder Beta" branding in the app and documentation.
- New and resolved counts in scan summaries now come from exact issue
  lifecycle tracking across the whole run, instead of per-check estimates.

### Fixed

- A scan that cannot finish everything it was asked to run now reports as
  partially complete and names what fell short, instead of presenting a partial
  run as a clean one. New, resolved, and regression counts are withheld from a
  partial run rather than compared against full history.
- Scheduled scan notifications no longer report a regression when the two runs
  did not cover the same ground. A run whose in-app browser or accessibility
  layer did not execute is compared only against runs with the same coverage.
- The scan history limit set in Settings now applies to scans started from the
  app, which previously kept the built-in default instead.
- Automatic dependency refreshes no longer record an update as applied when
  verification did not observe it, and previously recorded inferred entries
  are removed.
- The MCP server now reports a clear health error when the desktop database
  schema is newer than it supports, instead of failing unpredictably.

## [1.1.0] - 2026-08-25

### Added

- The MCP server can now drive the whole fix loop: `start_fix` opens a fix
  attempt, `run_scan` triggers a scan, and a desktop heartbeat tells the agent
  whether the app is running. `request_scan` is now `how_to_rescan` (the old
  name still works).
- The CLI gained unified gate flags across `audit`, `scan`, `check`, and
  `gate`, SARIF output for code-scanning integrations, and audit baselines.
- A false-positive report form and accuracy labels, so a wrong finding can be
  reported from the issue itself.
- Every release now publishes signed checksums and build provenance: a
  minisign-signed `SHA256SUMS` beside the artifacts and on the GitHub
  Release, with verification steps in the README.
- The first run walks through connecting an AI editor, with manual MCP setup
  instructions for every supported editor.
- The Issues page explains how each issue affects the SiteCMD Score.

### Changed

- Backend errors shown in the app are now plain-language messages with a next
  step, instead of raw error text.
- Fix guides and first screens open with plain-English leads.
- Dialogs, toasts, and navigation follow accessibility expectations: correct
  focus handling, screen-reader announcements, visible focus rings, and
  reduced-motion support across the app.

### Fixed

- The installer script refuses truncated downloads and version downgrades,
  and compares release versions strictly.
- Scan traffic is harder to abuse: the analyzer blocks private-network
  subresources, API responses are size-bounded, git metadata is read with
  hostile repository configuration neutralized, and credentials that never
  migrated to the OS keychain are refused instead of silently used.

## [1.0.0] - 2026-08-21

### Added

- Initial public release of SiteCMD. The desktop app scans websites and linked
  codebases for security, performance, SEO, accessibility, compliance, and
  configuration issues, ranks them by real risk, and hands the fix to the
  editor or coding agent you already work in.
- The complete local workbench is free: scanning, scan history, issue
  correlation, reports, and fix guidance all run on this machine, and nothing
  leaves it unless a site is explicitly connected.
- The connected service enters founder beta: hosted scheduled scans, alert
  email and webhooks, and shareable reports for connected sites, comped for
  the beta cohort.
- An MCP server so AI editors can read scan results and fix briefs directly.
- A CLI (`sitecmd`) for scanning and CI quality gates.
