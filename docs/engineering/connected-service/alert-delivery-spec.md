# Connected service: alert and report delivery

**Status:** Accepted, 2026-08-05.

This specification owns connected-service delivery behavior. The
[protocol and state spec](connected-protocol-spec.md) owns alertability,
alert-stream storage, and pagination. The
[hosted scanner spec](hosted-scanner-spec.md) owns cause classification.
This document owns wake-up policy, aggregation, notification content,
destination verification, redemption, outbound webhooks, reports, CI gate
delivery, privacy, and abuse handling. Pricing and allowances are outside
this document.

Revision history is maintained in Git. Only the current normative text in
this document is part of the implementation contract.

**Audience:** Engineers building delivery in SiteCMD-Web and the
desktop's notification surfaces.

**After reading:** A reader should be able to say, for any alertable
event, which channel carries it and why; for any email, exactly what it
contains under each mode; and for any link in any email, what it can
and cannot unlock.

## Ground truth: the precedents this spec extends

Delivery is the spec that gets to reuse the most shipped code:

- **Resend** is the established email provider (plain `fetch`, no SDK):
  the contact form's bounded retry (3 attempts, 250 ms exponential
  backoff, retryable statuses `{429, 500, 502, 503, 504}`, error
  bodies truncated and redacted) and the newsletter's **double-opt-in
  confirmation flow** (32 random bytes as a 43-character base64url
  token, 24-hour TTL, pending-key storage) are established SiteCMD service
  patterns. Existing automated mail is **plain text** and built from string
  arrays; this service introduces no HTML email templating. Sender identities
  are already split: `hello@` for automated mail, `support@` for humans.
- **The signed-token pattern** (base64url claims plus HMAC, signature
  verified before parse, expiry inside the claims) is in production in
  the telemetry worker's ingest auth.
- **Outbound webhooks already exist in the desktop**
  (`apps/desktop/src-tauri/src/webhooks.rs`): HMAC-SHA256 signatures as
  `sha256=` plus lowercase hex over the raw body, the strict
  ExternalCallback egress policy with connect-time resolved-IP
  validation, and URL redaction in logs and errors. The hosted channel
  keeps that egress policy and redaction but signs in the
  [Standard Webhooks](https://www.standardwebhooks.com/) format
  instead, because a body-only HMAC carries no timestamp and a
  captured delivery would verify forever; receivers verify with any
  Standard Webhooks library.
- **The desktop deep-link scheme is live**: `sitecmd://` with
  registered `activate`, `import`, and `connected` hosts
  (`desktop_deep_links.rs`), so "Open in SiteCMD" is a route addition,
  not a platform integration project.
- From the protocol spec: the account-level `alert_sequence` and
  `GET /v1/alerts`, alert retention of 90 days, opaque alert ids, and
  the rule that `active`, `dismissed`, and `claimed_fixed` states as
  such never wake anyone.

## The alert object and aggregation

An alert is a stored record: opaque `alert_id`, account sequence
number, site, event classes and causes it aggregates, top severity,
per-class counts, the deployment reference when attribution supports
one, creation time, **per-target current-generation delivery
outcomes**
(`queued | sent | suppressed | not_sent | failed | bounced | indeterminate`,
one per destination or webhook endpoint the alert addresses - a
single scalar could represent neither two endpoints disagreeing
nor an attempt superseded and reissued; `indeterminate` is the
honest terminal for an unknowable provider outcome, and a
`superseded` attempt reduces to `suppressed` when the current
state blocks the class, to `not_sent` when nothing is owed, and
otherwise to its replacement generation's outcome), and the mode
the site had when it was minted. The reduction has a **contract,
not a habit**: each cell is
`{target_kind, target_id, attempt_id, delivery_generation, outcome}`,
and an outcome event - a provider response, a bounce, a webhook
result - updates the cell **only when its
`(attempt_id, delivery_generation)` equals the cell's current pair
or carries a newer `delivery_generation`**; a late response or
bounce from an old attempt lands
in the delivery logs and never overwrites the replacement
generation's cell. **Within the same generation the outcome moves
along a declared transition table, never by arrival order**,
because provider events are not ordered: `queued` may move to any
outcome; `sent` may move only to `bounced` (a bounce is later
knowledge about the same send); `indeterminate` may move only to
`bounced` too - an authenticated bounce arriving after a lost
response is newer knowledge about the same send, exactly the
`sent` case, and freezing the less accurate answer would serve
nobody; `bounced`, `suppressed`,
`not_sent`, and `failed` are **absorbing** - in
particular, a delayed provider acceptance arriving after a
recorded bounce or suppression lands in the logs and regresses
nothing. Authenticated **complaints** act on destination
suppression only and never touch delivery cells: suppression is
the actionable fact, and rewriting a cell's history from a
complaint adds no protective value. The table is the fixture,
both directions: every allowed
transition and every forbidden one. The axis matters: cells order on
**`delivery_generation`, the replacement axis** - never
`dispatch_generation`, which counts Queue republications of the
same attempt and belongs to pointer CAS matching alone, or an old
attempt redispatched five times would outrank its replacement at
delivery generation two. Cells materialize at outcome-recording time
onto the alert record itself, which is durable - the reduced
outcome must survive the attempt row's 7-day expiry, because the
alert is what export and the desktop read. Rendered content is produced per channel
**at attempt creation and frozen into the `delivery_attempt` row**
(the protocol spec's contract: idempotent replay needs identical
bytes, so nothing renders at send time from a record that may have
changed); evidence is never part of the record or the frozen body,
so there is nothing to redact later.

**Aggregation happens before delivery, always.** One applied
observation yields at most **one** alert, however much it found: a
deploy that breaks twelve things is one email saying twelve things
broke, with counts by severity and class, not twelve emails. The dedup
basis is `(site, observation)` for immediate alerts; digests aggregate
everything in their window.

**Storm control is a budget, not a hope.** Each site has a wake-up
budget (default: 3 immediate alerts per rolling 24 hours). Overflow
folds into the next digest and the hosted view with an explicit "N
further alerts were folded into this digest" line, and the fold itself
is visible in site state. Nothing is silently dropped; the guardian
says when it is summarizing. Two classes are never allowed to wait for
a weekly digest behind an exhausted budget: further `critical`-severity
events and protection-degradation events instead fold into a **storm
summary** - one additional immediate email per rolling 6 hours that
says "the storm is continuing, N events since the last message, worst
severity X" - so an incident's fourth critical is late by hours, never
by a week, and the summary itself is bounded so a flapping site cannot
turn the storm control back into a storm. Non-observation events
(protection degradation, suppression, webhook auto-disable) carry an
event-based idempotency key on the alert record, since they have no
`(site, observation)` pair to dedup on; redelivery of the same
underlying condition updates the existing alert rather than minting
siblings.

## The wake-up policy

The state layer records event classes; this table decides who gets
woken. Three channels read the same alert stream: **immediate** (email
now, webhook now), **digest** (batched), and **in-app** (the desktop
timeline shows everything, always, immediately).

Immediate, by default:

- A **new group** at severity `critical` or `high` (deterministic and
  clock-dependent classes).
- A **regression of a verified fix** at `critical` or `high`. This is
  the core promise; `medium` and `low` regressions go to the digest.
- **Certificate horizon** crossing its warning bands: clock-driven and
  genuinely time-critical.
- **Protection degradation**: `scope_over_plan` entering its grace
  window, allowance exhaustion, a failing webhook endpoint or stale CI
  key version, and the first `bot_challenge` on a route (the site is
  blocking its own guardian; that is actionable today). The RFC's rule
  that protection never quits quietly makes these wake-ups, not
  footnotes.

Digest-only, by default: new `medium` and `low` findings; new
occurrences inside already-active groups; anything caused by a
detector or corpus update (we never wake a human for our own release);
newly available coverage; snooze expiries; `claim_not_confirmed`
outcomes; measurement threshold crossings under this contract:
thresholds are user-set, opt-in, and default to none
(measurements were pulled out of the lifecycle model precisely to
stop noise, and an undefined threshold notion would smuggle it
back), stored as protocol notification-settings rows
`{series_id, bound: upper | lower, value, hysteresis}` (hysteresis
defaulting to 10% of the threshold value), revision-guarded like
every settings mutation; a **crossing** is the transition from
inside to outside the bound as measured at the digest snapshot, it
re-arms only after the series re-enters the hysteresis band, and
digest lines deduplicate per `(series, bound)` per window - an
oscillating value produces at most one line per digest, not one
per wobble; and verification successes,
because good news belongs in the morning paper, not a midnight call:
verified fixes appear in-app immediately and in the digest with
celebration, but they never page.

User controls, v1, deliberately small: per-site mute (immediate class
demoted to digest), a per-site severity floor for wake-ups, and digest
cadence. Defaults are stated in-product; there is no configuration
matrix to misconfigure. These controls, the content mode, and the
outbound webhook lifecycle are the protocol spec's
notification-settings, destination, and alert-webhook resources -
revision-guarded, evented, exported, erased - not delivery-side
prose.

## The digest

Weekly by default, daily opt-in, off only by explicit choice. The
aggregation key is
**(account, verified destination, content mode, cadence)**,
never the bare account: sites sharing a destination, mode, and
cadence fold into
one digest grouped under their aliases, sites with different
destinations get different digests, a minimal-mode digest carries
only minimal-mode sites (so one client's digest can never leak
another client's site names through a shared account), and sites on
different cadences at the same destination get separate digests
rather than a merged compromise. Destinations are the protocol's
account-level resource precisely so this key is representable: one
address, one verification, one policy, many subscribed sites. Contents,
in order: regressions and new findings that did not wake anyone,
folded-overflow from storm control, verification wins, drift notes,
coverage health (exceptions by reason, `pending_reentry` routes,
key-version warnings), and measurement trends worth a sentence. An
empty digest is not sent; an optional "all quiet" heartbeat exists,
off by default, for users who want the guardian to say "nothing
happened" out loud. Delivery at a fixed hour, 14:00 UTC in v1.

## Notification modes and exact content

The two modes from the RFC, made field-precise. Both are plain text.

**Private (default):**

- Subject: `SiteCMD: {severity} alert for {alias}` (or the digest
  equivalent). The alias is user-chosen text and is sanitized for
  header context: CR and LF stripped, length-capped; the
  alias-injection fixture asserts a hostile alias cannot smuggle
  headers or reflow the subject.
- Body: site alias, severity, cause, event-class counts, detection
  time, deployment reference label when attribution supports one, and
  the link. **Never**: URLs or routes of the site, selectors, code
  locations, evidence, check output, or scores.

**Minimal:**

- Subject: `SiteCMD alert`. Body: "An alert is waiting for one of your
  connected sites." plus the link. No alias, no severity, no cause, no
  count. The alert id in the link is opaque and unguessable, so even
  the URL carries no project metadata.

Both modes: sender is `alerts@sitecmd.com` (a third identity beside
`hello@` and `support@`, disclosed on the trust pages with Resend as
subprocessor), `List-Unsubscribe` and its token in **every alert and
digest message** - and only those: the transactional classes
(confirmation, courtesy, security) carry no unsubscribe headers,
because no unsubscribe transition is defined for them and a header
promising one would be a lie a mail client acts on - plus a
notification-settings link in
every message of every class (the settings link is the desktop deep
link - no hosted
settings page exists, per the protocol's public-surface table; the
only email-actionable hosted capability is the cadence-demoting
unsubscribe token), **no HTML, no images, and no tracking of any kind**: no
open pixels, no click redirectors, no per-recipient beacons. A privacy
product does not surveil its own alarm bell.

**The webhook channel ignores modes by design.** Webhooks are
deliberately configured infrastructure, authenticated by signature, so
their payload is the machine-readable superset: alert id and sequence,
site id, event classes, causes, severities, canonical check ids, web
routes (public by construction), and the deployment reference. Still
never: code locations, evidence, source excerpts. The payload shape is
versioned and documented with the OpenAPI artifacts.

## Destination verification

An alert destination that was never confirmed is a spam cannon aimed
by whoever typed the address, so **no alert flows to an unconfirmed
destination, ever**:

- Destinations are the protocol spec's **account-level** destination
  resource (create, resend, policy `PATCH`, delete, list with
  verification, suppression, and policy
  state) and are confirmed through the double-opt-in flow the
  newsletter already uses: 43-character base64url token, 24-hour TTL,
  bounded resends - once per address per account, however many sites
  deliver to it. Until a site's referenced destination is confirmed,
  site state and the desktop show
  "alerts unconfigured" as a protection-health warning.
- Addresses are immutable, so "changing where alerts go" is a
  notification-settings **association switch** to a different
  (possibly new, then verified) destination; the switch transaction
  writes the courtesy "this address will no longer
  receive alerts for {alias}" note into the protocol's outbox
  (keyed by site and notification revision, so a crash cannot lose
  it; sends carry a deterministic provider idempotency key that
  deduplicates retries inside Resend's 24-hour window, and beyond
  that window delivery is honestly at-least-once - the protocol's
  wording, mirrored here) addressed to the previously
  subscribed address, so alerts cannot be silently rerouted.
- Bounces and complaints arrive on a Resend webhook endpoint; either
  suppresses the destination, surfaces in site state and the desktop
  as a protection-health warning, and requires re-verification to
  resume. Suppression is visible; a guardian whose pager number is
  disconnected says so.
- **A forged complaint must not be able to silence a pager**, so the
  Resend endpoint authenticates before it believes: Svix signature
  verification over the **raw body** using the `svix-id`,
  `svix-timestamp`, and `svix-signature` headers, a bounded timestamp
  tolerance (5 minutes) against replay, deduplication by `svix-id`
  (Resend delivers at least once and out of order, so a suppression
  event that arrives twice or late applies once, and a
  later-timestamped re-verification is not undone by a stale
  redelivery), and webhook-secret rotation with a dual-validity
  overlap mirroring the outbound contract. An unverifiable event is
  dropped and counted on the ops lane, never applied.
- Per-destination and per-account daily send caps backstop every
  class **except the security lane** (admin-recovery notices bypass
  the caps by design - a takeover alarm must not queue behind a
  noisy day); the caps are operational configuration with disclosed
  defaults.
- **Every delivery class initiates through the protocol spec's
  attempt-and-claim machinery** - immediate alerts, digests, storm
  summaries, confirmation and re-verification mail, courtesy notes,
  security notices, the fallback page's fresh-link resend, and
  outbound webhooks with their retries. No route calls a provider
  inline: browser and public routes enqueue a guarded attempt and
  return, and provider calls run only in the bounded queue-consumer
  worker, so erasure's `admission_fenced_at` fence and drain
  barrier cover this spec's entire egress - a send path outside the
  machinery would race erasure into a post-quiescence initiation,
  and the erasure fixtures include an erase-race case per class
  listed here.

## The mail eligibility matrix

The delivery classes are a **closed enum**, used identically by the
`delivery_attempt` rows (protocol spec), this matrix, the cost
model's email metering, and the erase-race fixtures - one name set,
so eligibility, attempts, billing, and tests cannot drift apart:
`immediate_alert`, `digest`, `storm_summary`, `confirmation`,
`courtesy`, `security_notice`, `fresh_link_resend`, and `webhook`
(the one non-mail member; it has no row below because destination
eligibility is a mail concept - its gate is the endpoint's own
enabled state).

The matrix is the single authority on which message class may reach
which destination, superseding any looser sentence elsewhere in this
spec or the protocol:

| Message class                      | Verification required               | Suppressed destination              | Policy bits                                             | Caps                                |
| ---------------------------------- | ----------------------------------- | ----------------------------------- | ------------------------------------------------------- | ----------------------------------- |
| Immediate alert                    | Verified                            | Never                               | Blocked by `immediate_disabled`                         | Capped                              |
| Storm summary                      | Verified                            | Never                               | Blocked by `immediate_disabled`                         | Own rolling 6-hour rule             |
| Digest                             | Verified                            | Never                               | Blocked by `digest_disabled`                            | Capped                              |
| Confirmation / re-verification     | Unverified by nature                | Only via the explicit resend action | Ignored                                                 | Rate-limited per destination        |
| Security notice (admin recovery)   | Verified                            | Never                               | Ignored - unsubscribe must not blind takeover detection | Exempt                              |
| Courtesy note (association switch) | Old address must have been verified | Never; skipped silently             | Ignored                                                 | Capped                              |
| Fresh-link resend                  | Verified (current destination only) | Never                               | Blocked by `immediate_disabled`                         | Rate-limited per alert, destination |

The storm summary row states what "inherits immediate-alert
eligibility" means exactly: same verification, suppression, and
policy-bit gates as an immediate alert, differing only in its cap
(it exists because the wake-up budget is exhausted, so its bound is
its own rolling 6-hour rule). The fresh-link resend is
human-initiated but re-delivers alert content, so it honors the
alert gates: a suppressed destination gets nothing (the address is
bouncing - the remedy is re-verification, not retrying it), and
`immediate_disabled` blocks it, because the nonce holder clicking
the button is not necessarily the destination owner who set the
bit.

Reading rules: suppression blocks every **automatic** send without
exception - the explicit re-verification resend is the one
deliberate, human-initiated path out, rate-limited; an address that
was never verified receives nothing except the verification mail
whose job is to verify it; and "both policy bits set" silences
**alert** mail only - the transactional classes above have their own
rows, which is why the guardian can still warn a fully-unsubscribed
account that someone is trying to take it over.

## The redemption flow and the hosted alert view

**There are no web accounts in v1, and this spec does not invent
them.** Identity lives in the desktop (installation tokens) and in CI
(scoped tokens); the hosted alert view is therefore nonce-gated and
deliberately narrow:

- The email link carries a single-use redemption nonce: 32 random
  bytes, stored server-side only as a hash, bound to exactly one alert
  and its destination, TTL 72 hours (a closed laptop deserves a
  weekend). **One activation rule for every emailed capability** -
  alert nonce, confirmation token, unsubscribe token alike, since
  tokens are minted when the attempt is created and frozen, not
  when the mail leaves: the TTL clock starts at the attempt's
  **first provider-call initiation, recorded before the external
  I/O and never moved later**. Provider acceptance is not the clock
  anchor: a lost response followed by a same-key replay returns
  the **original** acceptance at a later recorded time, silently
  extending a capability that may have escaped into the world on
  the first call - first-initiation is the earliest moment the
  link could exist anywhere, so the window only ever errs shorter,
  and the indeterminate path needs no special case (initiation is
  always recorded, whatever the outcome). Terminal never-sent
  outcomes (refused, `superseded`) **delete their capability
  records atomically with the outcome** - a capability whose mail
  never left has no clock to start and no business staying
  redeemable - and when reconciliation consumes enough of the
  window that a late-delivered link arrives near-dead, the remedy
  is the rate-limited fresh-link resend, never a longer clock. The
  TTL numbers themselves (24 hours, 72 hours, 30
  days; the public-surface table's rows) are unchanged - this rule
  defines when their clocks start. **Redemption is two steps, because the first request is
  not the human**: enterprise mail security (Safe Links and its
  cousins) fetches and rewrites URLs during delivery and at click
  time, so the `GET` landing page is non-consuming - it renders a
  single "view this alert" button and burns nothing - and only the
  explicit `POST` redeems, exchanging the nonce for a short-lived
  view session (30 minutes, a secure, `HttpOnly`, `SameSite=Strict`
  cookie scoped to that one alert) and marking the nonce used; a
  second redemption answers the expired page. The nonce grants the
  alert view and nothing else: no state mutations, no other alerts,
  no reports, no tokens. One-click unsubscribe is deliberately **not**
  this nonce: `List-Unsubscribe-Post` carries its own single-purpose
  token, so a mail
  system exercising RFC 8058 on the user's behalf cannot consume an
  alert link, and an alert link cannot change settings. The token's
  exact semantics, because "demotes the cadence" is not a state
  transition: it is minted per message, encodes the message's class,
  and acts on the **destination** (the level a digest actually
  aggregates at, since one digest spans sites): the protocol models
  policy as **two independent suppression bits**,
  `{ immediate_disabled, digest_disabled }` - "digest only" and
  "digest off" suppress different channels and no single ordering
  can rank them without re-enabling one. An immediate-class token
  sets `immediate_disabled`; a digest token sets `digest_disabled`;
  **tokens only ever set bits** (monotonic OR - no token, however
  old, replayed, or redeemed out of order, can re-enable any mail),
  and both bits set means no **alert** email while the in-app
  timeline carries everything as always (the transactional classes
  follow the mail eligibility matrix above, not the bits). Both transitions are the protocol's
  destination **policy**
  overlay: recorded as events, visible everywhere delivery health
  appears, revision-advanced on every mutation source (tokens,
  bounces, confirmations, re-verification) so a stale desktop write
  fails its guard, and cleared from the desktop through the
  revision-guarded
  destination `PATCH`. Lifecycle, one rule (the public-surface table
  states the same): hash-stored,
  TTL **30 days from the message's activation point** (the
  capability-activation rule above: first provider-call
  initiation, recorded before the I/O; the record
  deletes at expiry),
  single-use with idempotent replay - the same token again answers
  `2xx` as a no-op, because mail infrastructure retries and RFC 8058
  callers must always get success semantics. An **expired** token
  answers `410` honestly, because claiming success for an action not
  performed would strand the user subscribed; a message older than 30
  days therefore simply cannot one-click unsubscribe (the caller is
  a mail system, the response is a bare status, and RFC 8058 forbids
  redirecting the POST - there is no page to land on), and the
  message's separate settings deep link remains the recovery path -
  the accepted trade for not
  keeping token records forever. Per RFC 8058 section 3.2 the
  endpoint accepts **both** permitted encodings,
  `application/x-www-form-urlencoded` and `multipart/form-data`,
  carrying `List-Unsubscribe=One-Click`. Fixtures cover both
  encodings, expiry, replay, and the concurrent-reversal race: a
  redemption landing after the desktop re-enabled the destination
  applies the demotion again (the mail user's later gesture wins,
  visibly, and the desktop can reverse it once more), while
  single-use means one token can never flap the state twice. And per
  RFC 8058 the
  outbound message's **DKIM signature must cover the
  `List-Unsubscribe` and `List-Unsubscribe-Post` headers
  themselves** - a DKIM-enabled domain is not the requirement, header
  coverage is - so the delivery prerequisites include verifying a
  real delivered message's raw DKIM `h=` list contains both headers
  under Resend's signing.
- The landing and view pages carry `Referrer-Policy: no-referrer`, a
  strict CSP, and no third-party assets; nonces never appear in
  server logs (the path is redacted to the alert id), and the session
  cookie is never sent cross-site.
- The **view** renders the alert's private-mode content plus cause
  detail, verification status, and next-step guidance. It never
  renders evidence, code locations, or site content; the deep detail
  lives in the desktop, which is the point of the product. Minimal
  mode renders the same view (the nonce proves receipt of the email;
  the mode governs what the _email_ said in transit, not what the
  recipient may see after redeeming).
- **Open in SiteCMD** is `sitecmd://connected/alerts/{alert_id}`; the
  desktop resolves it through its installation token
  (`GET /v1/alerts` and the event stream) and lands on the local
  dossier with full detail.
- **An expired or used link is never a dead end**: the fallback page
  offers exactly two things: "resend a fresh link" (rate-limited,
  sent only to the currently verified destination) and "open in the
  SiteCMD desktop app". No login wall, because no logins exist; that
  honest sentence is on the page.
- Nonce hygiene: lookup by hash, constant-time comparison, no
  metadata in the URL beyond the opaque alert id, `Cache-Control:
no-store` on every view, and the link-lifecycle fixtures cover
  reuse, expiry, cross-alert attempts, and the forwarded-email
  scenario (a forwarded unused link works once, exactly like a
  forwarded house key opens a door once, and the view's content
  ceiling is what bounds the damage).

## Hosted reports

The report answers a client's "is it fine?" without opening an app:

- Rendered once at creation, from connect state only, and stored as
  the frozen projection the link serves thereafter (protocol spec's
  report registry - a shared link never changes under the client it
  was shared with): the score summary,
  severity and category counts, verification wins, protection status,
  and measurement trends. Route-level detail is an explicit toggle at
  generation time (routes are public by construction, but the report
  owner chooses); evidence and code never appear at any setting. The
  score is computed by the **same extracted scorer artifact** the
  desktop and the hosted scanner's tier-one core use, from the score
  inputs the protocol carries (occurrence severity and confidence,
  group state for the active-set predicate, manifest category); a
  second score implementation in worker TypeScript is forbidden, so a
  report can never disagree with the app about the number.
- Generated **only from the desktop's Reports surface**, through the
  protocol spec's report registry (installation token). The hosted
  alert view cannot generate reports because its nonce authorizes the
  alert view and nothing else. The registry row records provenance:
  who generated it, when, and with which content toggles.
- The link is a signed token per the telemetry pattern: claims name
  one `report_id` and an expiry (default TTL 30 days) plus the `kid`
  of the signing key (rotation is additive; old links age out),
  signature checked before parse, and the render path requires the
  registry row to exist and be unrevoked - so revocation through the
  protocol's revoke endpoint is immediate and wins over TTL.
- Report pages carry `noindex` and `no-store`, and report views are
  logged as counts, not identities: the report exists to be shared,
  and shared things are not tracked per reader.

## The CI gate channel

Policy-breaking findings fail the merge. The CI credential permits
**exactly one read-shaped operation**, shaped as a verdict rather than
a general read:

- `POST /v1/sites/{site}/gate` (CI token): the request carries the
  candidate branch's code fingerprints and coverage (same schema as a
  CI snapshot, computed in the checkout, never persisted as
  baseline); the response is the verdict: pass or fail, the counts,
  and the identities (canonical ids, severities) of findings that are
  **new against the hosted baseline**, with no evidence. The
  submission is evaluated and discarded: gate calls never mutate
  baselines, never create deployments, and never touch lifecycle.
- Gate policy, configured in the repository, not the server: fail on
  new findings at or above a severity threshold (default `high`);
  never fail on measurements; never fail on findings whose only cause
  is a detector or corpus update unless the repository opts into
  strictness; surface `pending_fresh_evidence` and `bot_challenge`
  conditions as warnings, not failures. A stale fingerprint key
  version fails visibly (the protocol's `stale_key_version` already
  guarantees it).
- Gate output is CI-native: exit code, a plain-text summary naming
  counts and thresholds, and the same identities the response
  carried. The gate is packaging over the same baseline, exactly as
  the RFC framed it.

## Delivery-side privacy and abuse

- **Content rules are fixtures, not intentions**: mode-content
  fixtures assert each mode's exact field set, the alias-injection
  fixture asserts header safety, the hostile-alias digest fixture
  asserts a malicious alias cannot break the digest's structure, the
  hostile-alias **report-rendering** fixture asserts a malicious
  alias in a stored report projection renders as inert text, and
  the link-lifecycle fixtures cover the nonce state machine. The
  report renderer's escaping contract is **context-aware HTML
  escaping, not JSON escaping** (JSON escaping neither escapes HTML
  metacharacters nor survives script-context breakouts like a
  literal `</script>`): projection strings reach the page only as
  DOM text nodes or through a context-aware autoescaping template,
  raw-HTML interpolation and JSON-in-`<script>` embedding are
  forbidden outright (the strict CSP already bans inline script, and
  the page needs none), and the hostile-alias report fixture
  **executes in a real browser** and asserts no script ran and the
  payload rendered as text - a string-comparison fixture cannot
  prove a rendering contract.
- **Outbound webhook egress at server strength**: public HTTPS only,
  default ports, the address-filtering rule set, resolved-address
  validation at connect time (this channel controls its connections),
  no redirects followed, response bodies read only to a bounded
  length and never persisted. Signatures follow Standard Webhooks
  (`webhook-id`, `webhook-timestamp`, and `webhook-signature`
  headers) under a shown-once per-endpoint `whsec_` secret, so a
  receiver's library refuses a stale timestamp; delivery is
  **best-effort with bounded retries, documented as such** - retries with
  persistent-failure auto-disable can produce zero, one, or
  several receiver effects, which is neither "exactly once" nor a
  true at-least-once guarantee, and the endpoint documentation says
  so; every payload carries a **stable delivery id** (attempt id
  and generation) for cooperative receiver deduplication, which
  supports dedup and guarantees nothing; retries follow the
  Resend-precedent
  bounded backoff honoring `Retry-After`; an endpoint failing
  persistently is auto-disabled **visibly** (site state, desktop,
  digest note), never silently.
- **Logging**: alert ids and hashed nonces only; destination
  addresses appear in operational storage because delivery needs
  them, but logs carry them masked, and the privacy projection's
  no-content rule applies to every delivery log line.
- **Ops alerts are a separate lane**: admission exhaustion, delivery
  backlog, suppression spikes, and webhook auto-disables page the
  operator through internal channels and never ride the tenant alert
  stream.

## Retention, export, and erasure

Additions to the protocol's retention table, same authority rules:
content-bearing `delivery_attempt` rows follow the protocol's rule
exactly (encrypted body purged at terminal outcome, row deleted 7
days later - never 90); content-free operational **delivery logs**
90 days, with the retained fields enumerated and closed: attempt
id, class, site and account references, destination id (never the
address), outcome with its timestamps, and the provider message
id - no subject, no body, no capability, no address;
redemption nonces 7 days past expiry, hashes only; destinations and
their verification, suppression, and policy state for the life of
the **account** (they are account-level resources and survive
individual sites; the protocol's retention table has the split
rows); report registry
rows and their stored projections for the life of the site with links
bounded by their TTL (the protocol's retention table is the
authority), revocations logged as events.
All of it rides export where tenant-readable (destinations, report
registry) and every row falls in the erase cascade. The erasure
receipt's account binding already covers post-erase retries; nothing
readable **through any ordinary path** outlives the tenant except
the receipt the
protocol already defines - stated in the protocol's five-clause
staged contract, which this paragraph copies rather than tidies:
the protocol's
per-account delivery stream retains encrypted projections for
erased sites until its lock expires and the pruner runs (at most 90
days); the stream key is destroyed before the receipt is issued,
which ends every ordinary read immediately; until the wrapping
KEK version's hard retirement (60 days after the receipt at
worst, by deadlines stamped at the version's activation), a
privileged restore path plus the live
KEK could still recover those projections - a disclosed window,
not a caveat hidden behind an absolute; after retirement, no
SiteCMD-operated path can; and at the 90-day confirmed
deletion - the pruner's verified, irreversible direct delete,
never a lifecycle rule - the ciphertext itself is gone, which is
where the public guarantee anchors. Key destruction now, KEK
retirement as the SiteCMD-side end, confirmed provider deletion
as the completion, and the protocol's retention table and
trust-page
language carry the same staged clauses.

## Prerequisites

1. **Desktop**: the alert timeline consuming `GET /v1/alerts` (the
   AlertDossier surfaces exist and gain the connected source), a
   notification-settings surface (destination, mode, cadence, mute,
   severity floor), the `sitecmd://connected/alerts/{id}` deep-link
   route, and gate configuration documentation in the CLI.
2. **SiteCMD-Web**: delivery lives inside connect (alerts are its
   state): Resend sending with the established retry constants, the
   bounce and complaint webhook endpoint, the digest scheduler (an
   hourly cron selecting due accounts, the repository's existing
   pattern), the nonce and view routes, the report renderer and
   registry, and the outbound webhook dispatcher with its egress
   module.
3. **Sending domain**: `alerts@sitecmd.com` provisioned in Resend
   with SPF, DKIM, and DMARC that pass SiteCMD's own DNS checks: the
   guardian's pager must survive its own scan.
4. **Fixtures**: mode content, alias injection, nonce lifecycle,
   webhook hostile endpoints, storm control and folding, and the
   digest's minimal-mode site rendering.

## Decisions taken in this spec

1. **One observation, one alert.** Aggregation precedes delivery
   unconditionally, and storm control is a stated budget with visible
   folding, because twelve emails about one deploy is how alarm
   fatigue is manufactured.
2. **Good news never pages.** Verification successes and everything
   caused by our own detector updates are digest material; the
   immediate channel is reserved for new critical or high evidence,
   regressions of verified fixes, certificate horizons, and
   protection degradation, the last because a guardian that quits
   quietly is worse than none.
3. **No web accounts are invented for the alert view.** The nonce
   gates one alert's mode-bounded view; expiry falls back to resend
   or the desktop, honestly labeled; identity keeps living where it
   already lives.
4. **Minimal mode bounds the email, not the redeemed view**: the
   nonce proves receipt at the verified destination, and what
   traveled unauthenticated is what the mode was protecting.
5. **Webhooks are mode-exempt machine delivery** with the desktop's
   exact signature format, so one receiver serves both, and they
   carry routes but never evidence or code locations.
6. **Destinations are double-opt-in, always**, with visible
   suppression and courtesy notice on change, because an alert system
   that sends to unconfirmed addresses is a spam engine with a
   security product's letterhead.
7. **No tracking in alert email, ever**: no pixels, no click
   redirectors. The product's privacy posture applies to its own
   mail first.
8. **The gate is a verdict endpoint, not a read grant**: the CI
   token's "reads nothing" survives as "learns nothing but the
   delta", candidate submissions are evaluated and discarded, and
   gate policy lives in the repository.
9. **Reports are shareable and therefore untracked**, revocable
   ahead of TTL, and content-bounded at generation with routes as
   the owner's explicit choice.
10. **Plain text everywhere**, extending the repository's only
    existing email idiom; deliverability is dogfooded through
    SiteCMD's own DNS checks.
