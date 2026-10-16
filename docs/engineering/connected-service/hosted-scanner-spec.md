# Connected service: hosted scanner

**Status:** Accepted, 2026-08-05.

Revision history is maintained in Git. Only the current normative text in
this document is part of the implementation contract.

This specification defines hosted-scan execution. The
[protocol and state spec](connected-protocol-spec.md) owns the wire
contract this scanner feeds: identity, coverage encoding, evidence
precedence, deployment currency, the scan-scope resource, the
current-basis predicate, and the comparability envelope. This document
owns how hosted scans execute, how parity with the desktop engine is
achieved and proven, what the `crawl_profile` and `execution_profile`
pin, how pair-precise coverage is produced, the network-security
boundary, scheduling and supersession behavior, and the verified-good
drift checks. It does not own alert content or wake-up policy (alert
and report delivery spec) or allowances and pricing, which are set
outside this specification.

**Audience:** Engineers building the hosted runner and
maintaining the desktop engine it must match.

**After reading:** A reader should be able to say, for any of the
desktop's checks, how the hosted runner executes it or why it does not,
which artifact proves the two agree, and why a hosted observation's
coverage claims can be trusted by the verification semantics.

## Shared engine ground truth

Hosted parity is based on the engine SiteCMD ships, not a separately maintained
reimplementation:

- **Portable verdict core.** `sitecmd_engine` owns deterministic check
  evaluation, scoring, identity, coverage, release stamps, scope, profiles, and
  connected payload vocabulary. Evaluation time is injected; the portable crate
  has no ambient clock, filesystem, network, environment, or desktop runtime
  dependency.
- **Native and wasm entry points.** Desktop and CLI link the native crate. The
  hosted runner consumes the wasm wrapper. The push gate compiles both the core
  and check surface for `wasm32-unknown-unknown`.
- **Adapted probes, shared verdicts.** Network, DNS, TLS, and browser runtimes
  gather typed facts through platform adapters. Pure verdict functions consume
  those facts. Golden probe fixtures pin classification and verdict behavior
  across runtimes.
- **Shared browser assets.** Axe and Core Web Vitals payloads live with the
  engine and return typed facts, including executed axe rule identities. Static
  and browser findings supersede one another per rule.
- **Explicit crawl scope.** SiteCMD scans the selected route set, with sitemap
  discovery as input rather than an unbounded link-following crawler.
  Origin-scoped checks run on the entry route.
- **Separate integration metrics.** PageSpeed Insights remains an on-demand
  integration and is not part of hosted scan parity.

The capability manifest is the authoritative inventory. Avoid hardcoded trait or
check counts in this specification; generated product facts own public totals,
and registry tests keep the manifest aligned with the source registrations.

## Parity tiers

The RFC demands "the same versioned engine artifact or a conformance
corpus." The engine's structure makes that a four-tier design, and each
tier names the artifact that proves agreement:

1. **Artifact tier: the wasm engine.** The pure core is extracted into
   an engine crate compiled twice from one source: natively into the
   desktop, and to `wasm32` as the hosted runner's check module. The
   hosted runner executes the identical compiled logic, so this tier's
   parity is by construction. The crate boundary is the portable surface
   described in the implemented parity foundation below.
2. **Probe tier: shared verdicts, adapted transports.** Each async
   check splits into a **probe plan** (what to fetch or resolve: paths,
   methods, headers, record types) and a **pure verdict** (probe
   results in, `CheckResult` out). Verdicts move into the wasm
   artifact. Probe plans are executed by a runtime transport adapter:
   `reqwest` on the desktop, Workers `fetch` hosted. The adapters are
   where divergence can hide (redirect handling, timeout
   classification, size-limit behavior, header casing), so the
   conformance corpus pins them: shared fixtures assert that both
   adapters classify the same transport situations identically
   (final-URL recording, the 10-redirect limit, timeout as `Skipped`,
   HEAD-then-GET link probing); past its page cap, the hosted lane excepts
   the route while the desktop fails that page's read.
   Special transports: the seven DNS checks resolve over DNS-over-HTTPS
   hosted (Cloudflare's resolver) while the desktop keeps its
   system-resolver-only posture; record projection and verdicts
   (`analyze_spf`, DKIM selector sweep, `DnsOutcome` three-state) are
   shared verdict code. OSV and RDAP calls move to the worker with
   their flows disclosed (privacy section below).

   **TLS facts need dual sources.** The desktop's `security.ssl` opens
   a raw TCP connection; Workers block outbound TCP to
   Cloudflare-fronted destinations, which describes a large fraction
   of real targets, so porting the raw probe alone would turn the
   flagship certificate check into `Skipped` exactly where users live.
   The check is therefore refactored onto a **TlsFacts schema**,
   defined here rather than deferred:

   - `not_before`, `not_after`: timestamps. rustls parses them from the
     leaf certificate. Hosted supplies them when its pinned `node:tls`
     metadata probe can reach the validated public address.
   - `issuer`: string. Hosted supplies it from the same pinned probe
     when available.
   - `subject_names`: the subject plus SAN list. rustls and `node:tls`
     parse the served certificate.
   - `protocol`: negotiated TLS version. Hosted supplies it from the
     pinned probe when available.
   - `validation`: `{ "authority": "webpki" | "chromium" | "cloudflare_workers", "result": "valid" | "invalid" | "unavailable" }`.
     rustls reports its webpki result directly. The hosted browser
     proxy uses Workers global `fetch` with the platform trust store;
     a successful HTTPS response records `cloudflare_workers/valid`
     even when the platform will not expose the leaf certificate.
     `chromium` remains a schema authority for observations produced by
     an adapter that actually uses Chromium's validator. Authorities
     are different trust programs, which is exactly why the
     chain-validity sub-verdict's `compare_on` includes the authority,
     expiry and hostname compare across adapters, and protocol compares
     within the TLS client profile.
   - `facts_observed_at`: when the facts were captured, with a
     **freshness rule**: the certificate-horizon drift check and any
     re-evaluation may grade facts no older than 7 days; staler facts
     make the TLS pairs inconclusive and schedule a **targeted
     refresh** (a single-page `full`-profile fetch of the entry URL),
     because warning about a certificate that already rotated would be
     the guardian crying wolf with old news.

   Adapters fill the schema from the desktop's `rustls` handshake or,
   hosted, from two pieces of one public-egress path during `full` page
   loads. Workers global `fetch` supplies the chain verdict. After
   navigation settles, the hosted runner starts exactly one best-effort
   `node:tls` connection for the final main-document HTTPS response,
   pinned to its already validated public IP and carrying the original
   hostname as SNI. Redirect intermediates, iframe documents, and
   subresources never start metadata probes. Cloudflare blocks direct
   sockets to some destinations, including its own ranges, so a fetch
   that succeeds while the metadata probe cannot connect records only
   the chain field. It never invents dates, names, issuer, or protocol.
   Fields an adapter cannot supply are absent and produce the same
   `Skipped` sub-verdicts on both sides. Same verdict code, same schema;
   adapter equivalence is pinned by TlsFacts fixtures in the corpus.

   **The sub-verdicts are separate checks**, because one check id
   cannot carry two comparison rules: the manifest has one class and
   one `compare_on` per id, and occurrence identity has no sub-verdict
   discriminator, so "expiry compares across adapters but chain
   validity compares within a trust authority" is only expressible by
   splitting the identity. `security.ssl` becomes
   `security.ssl.expiry` (clock-dependent, cross-adapter: dates are
   dates), `security.ssl.hostname` (deterministic, cross-adapter:
   name matching is data), `security.ssl.chain` (deterministic,
   `compare_on` the trust authority), and `security.ssl.protocol`
   (deterministic, `compare_on` the TLS client profile: the negotiated
   version is a function of the client hello, so Chromium and rustls
   can negotiate differently against an unchanged server, and treating
   it as cross-adapter would let a finding vanish without the site
   changing; each adapter versions its client profile, and that
   version is the comparison dimension). The split ships as a corpus
   release with an explicit migration in the canonical-id resolution
   table, and the lifecycle rules are stated, not waved at:
   **dismissals copy** to every successor (`blocked`, `snoozed`,
   `ignored` express intent about certificates generally, and policy
   objects carry over verbatim); **claims and verifications do not**
   (`claimed_fixed` and `verified_fixed` on the composite cannot be
   attributed to one sub-verdict, so successors seed from fresh
   observation with a migration event recording the provenance);
   `regressed` maps to `active`. Nothing is silently dropped: the
   migration event names the predecessor and every successor.

3. **Browser tier: same payloads, profiled engines.** The hosted
   browser layer runs Browser Run (formerly Browser Rendering;
   Chromium) and injects the **same three payload assets** the desktop
   webview uses, moved to a shared location consumed by desktop, CLI
   headless-Chrome, and the hosted runner. Instrumentation parity is
   therefore by construction; engine differences are real and already
   exist across desktop platforms (WebKit on macOS, WebView2 on
   Windows, `longtask` being Chromium-only), so the browser engine and
   build are **profile facts**, and the comparability gate applies the
   per-class rules below. Hosted axe runs with the identical `runOnly`
   tag set and the identical node-evidence caps; the hosted runner then
   drops each violation's node sample in the page, keeping its node count,
   since no hosted verdict, record or page reads it. SiteCMD's scripts in
   a rendered page run in an isolated world the page's own scripts cannot
   reach, and the browser Worker bounds what the page returns before
   reading it, refusing a payload past its bound. The browser Worker
   counts every message the browser sends it before reading it, and ends
   the pass when one message exceeds 2 MiB or the session's total exceeds
   12 MiB, counting text at two bytes per UTF-16 code unit. One message at Cloudflare's 32 MiB WebSocket limit is whole in
   the Worker's memory before the Worker can refuse it, so it can lift its
   own pass past half the isolate for a moment; at the 3 MiB per-response
   cap and 12 MiB session message cap, that pass measured 67,982,303 bytes.
   Cloudflare lets in-flight requests complete when an isolate passes
   128 MB, and starts a new isolate for later ones. A page near the request
   cap (400) and the session's 25 MiB of response data can lift its pass
   past half the isolate too, almost all of it garbage the isolate has not
   collected yet. A page of 399 images of 16 KiB measured 86,759,684 bytes,
   100 images of 128 KiB 68,975,409, and a heap snapshot of a pass with 99
   such images fulfilled found 34,735,673 bytes live. A shared user agent
   does not guarantee equivalent content, so browser (and transport)
   coverage passes through the challenge gate defined under coverage.
4. **Measurement tier: honest non-parity.** Timing values (TTFB, LCP,
   CLS, long-task blocking) are measurements, not derivations; they
   vary by vantage even between two desktop runs. Measurement vantage
   is the same structured identity as everything else: hosted
   transport measurements carry the attested colo, hosted browser
   measurements the `unattested` lane (the session API exposes no
   location), desktop measurements their credential-keyed producer. These checks are
   marked `class: measurement` and follow the measurement rules below,
   including their exclusion from automatic lifecycle transitions.

## The capability manifest and the comparability rules

A versioned document generated at engine build time, shipped with
`engine_release` and identified by `manifest_digest` (which every
observation's envelope carries, per the protocol spec). One entry per
check id:

```json
{
  "check": "security.dns.spf",
  "contract": "e57c98162a303632",
  "hosted": "probe_adapter",
  "class": "deterministic",
  "scope": "origin",
  "requires": ["resolver"],
  "compare_on": []
}
```

Built in the desktop repository: `sitecmd_engine::manifest::registry`
is the authored table, `capability_manifest()` resolves it into the
document, and `crates/engine/manifest/capability_manifest.json` is the
published artifact a test regenerates and compares. The manifest is
keyed by the id an OBSERVATION carries, which is not the same set as
the ids the check trees declare: five ids (`security.headers`,
`security.server_info`, `seo.headings`, `security.ssl`,
`security.exposed_files`) name a check runner that emits only
sub-verdict rows, so they are declared as runner ids with their reason
rather than given a contract no observation could ever reference.

The current publication is manifest schema version 2. A
measurement-class entry must carry `measurement_unit` (`ms` or
`ratio`), and a non-measurement entry must not. The unit participates
in the entry contract hash. Connect accepts schema version 1 only for
the one-version compatibility window and publishes version 2 for every
new engine build.

- `contract` is the check's **semantic compatibility hash**: a digest
  over the check id, a declared meaning `revision`, and any external
  facts the check's meaning depends on (the axe family folds in the
  pinned axe-core version, so an upgrade re-contracts every rule at
  once). This is what makes cross-release comparability decidable per
  check: two observations under different `engine_release`s are
  comparable for a check when both manifests give it the same
  `contract`.

  It is deliberately NOT a digest over the check's source or over its
  corpus rows. Source hashing re-contracts on a comment edit and
  severs comparability for a rename; corpus hashing re-contracts every
  time a case is ADDED, which would make growing the corpus a
  comparability event and punish the thing the parity harness exists
  to encourage. What is left is a declared revision, and what keeps
  the declaration honest is that the golden corpora are committed: a
  verdict change cannot land without a corpus diff in the same commit,
  beside the revision that should have moved with it.

- `hosted`: `artifact`, `probe_adapter`, `browser`, or `unsupported`.
  Unsupported checks are never comparable, exactly as the RFC
  requires.
- `class`, with its compatibility and cause rules:
  - `deterministic`: comparable when contracts match **and the entry's
    comparison dimensions match**. Recording profiles while ignoring
    them would let WebKit verify Chromium and a webpki result verify a
    Workers trust result after this spec spent pages saying those
    environments differ, so every
    manifest entry carries `compare_on`: the profile dimensions that
    must additionally match for comparability, derived at generation
    from what the check consumes. A pure HTML check compares on
    contract alone; an axe-family check on axe version, browser
    engine, and the **browser compatibility epoch**; the
    `security.ssl.chain` check on the trust authority and
    `.protocol` on the TLS client profile, while `.expiry` and
    `.hostname` compare across adapters. The compatibility epoch is
    how builds participate without severing baselines weekly: exact
    builds are recorded for forensics but never compared directly.
    The epoch lives in the **certification registry** at connect, not
    on the wire: producers report `(engine, build, axe_version)`
    facts, connect resolves the epoch at apply time from immutable
    registry entries, and historical observations stay stable because
    entries never change once written. Hosted Chromium builds are
    certified by CI against the corpus's browser fixtures;
    behavior-equivalent builds share an epoch and a behavior-changing
    build advances it. A build the registry does not know (desktop
    webviews churn with OS updates and cannot be pre-certified)
    resolves to a **singleton epoch equal to its own identity**:
    comparable with itself, never falsely merged with anything, and
    upgradeable in place when certification lands. Nothing is
    blocked, and an unnoticed Chromium update can never silently
    verify a finding fixed under changed behavior.
  - `measurement`: **outside the lifecycle model entirely**, per the
    protocol contract: no groups, no occurrence records, no
    `verified_fixed`, no `regressed`, no wake-up alerts. Measurement
    checks produce samples (`check`, `route`, `value`, `unit`) stored as
    bounded series under event retention, surfacing as current values
    and trends; threshold crossings are digest material (delivery
    spec). One noisy sample leaving a group active forever and one
    noisy sample verifying it fixed were both wrong, and the way out
    was to stop pretending measurements are findings.
  - `clock_dependent` (certificate expiry, `security.txt` expiry,
    domain expiry): comparable when contracts match;
    `evaluation_time` rides the observation; changes caused by time
    passing classify as **ambient drift** (a certificate crossing its
    warning band is the site's world changing, not the detector's).
  - `external_corpus` (OSV-backed findings): comparable when
    contracts match. OSV exposes no corpus revision in its query
    response, so the classification fact is constructed instead of
    wished for: each external-corpus check records an **input digest**
    (the detected library set queried) and a **result digest** (the
    verdict-relevant projection of the response). Producers send the
    transient canonical projections; connect mints the keyed MACs at
    ingest per the privacy projection (library sets are low-entropy
    and dictionary-reversible bare, and desktop producers cannot hold
    connect's key). Identical input digest with a changed
    result digest is the corpus moving, and classifies as **detector
    or corpus update** even though neither `engine_release` nor the
    contract changed; a changed input digest means the site changed,
    and ordinary attribution applies.
  - Availability failures (RDAP down, OSV unreachable, resolver
    failure) are not a class: they are coverage exceptions for their
    pairs, in every class.
- `scope`: `page`, `origin`, or `session`. `origin` checks are covered
  as entry-page pairs; `session` checks are covered only when their
  complete required route set ran, so a partial scan cannot claim
  session-level absence.
- `requires` names the runtime facts the check needs (browser, sockets,
  resolver), which is how the gate knows a `standard` observation
  cannot speak to browser-family pairs. It declares runtime needs,
  **not** input completeness, and is therefore never the basis for
  input equivalence.
- `equivalence_inputs`, per check and usually absent, names the exact
  projection fields that constitute the check's **complete** inputs.
  **No current manifest entry declares it.** A registry test asserts the set
  remains empty. An absent declaration is the conservative state: the check
  never crosses vantages, which costs a resolution opportunity and cannot
  invent one. Any future declaration must land with the property fixtures that
  prove the named projection is complete.
  Only a check with a non-empty `equivalence_inputs` participates in
  cross-vantage input equivalence, and the field is populated only
  when the check reads nothing outside the named projection fields -
  which excludes every body-reading check by construction, **and only
  a check whose manifest class is `deterministic` may declare it at
  all** - a clock-dependent check's verdict is a function of its
  inputs _and_ `evaluation_time`, so matching projections do not
  imply matching verdicts: `security.ssl.expiry` on identical
  certificate projections verdicts clean before the warning threshold
  and failing after it, and a delayed pre-threshold clean observation
  must never clear a post-threshold failure. Clock-dependent and
  external-corpus checks therefore never cross vantages, full stop.
  The instructive body example is CSP: `security.csp` and the
  Referrer-Policy
  check honor `<meta http-equiv>` policies in the document body
  (`checks/security/headers.rs`), so despite being "header checks"
  their inputs are not contained in the header projection and they
  carry no `equivalence_inputs`. Certificate-**identity** and
  DNS-posture
  checks, deterministic functions of exactly the certificate and DNS
  projections, do; certificate expiry does not. A **property test
  enforces the contract**: for
  every check declaring `equivalence_inputs`, corpus fixtures assert
  that equal projections of those fields imply equal verdicts,
  including mutation cases (a fixture pair differing only outside the
  declared fields must verdict identically; one differing inside them
  must not compare equal) - so an unsound declaration is a failing
  test, not a false verification in production. The fixture set
  includes the **delayed-pre-threshold-clean case**: a clean
  observation with an earlier `evaluation_time` arriving after a
  failing one must resolve nothing, proven against the expiry checks
  specifically. It also includes the **A-then-B-then-clean-A case**:
  a vantage establishes presence under context A, reports the
  still-standing finding under context B (a new evidence generation
  replaces the entry's establishing context - protocol spec), and a
  clean observation whose inputs MAC to A must resolve nothing,
  because the entry's current generation was established under B. Equivalence comparison always runs against the
  **establishing entry's stored MAC and versions** (protocol spec's
  evidence record), never against the latest route-profile MAC, so a
  profile refreshed since establishment cannot stand in for the
  content that was actually seen failing.

**The manifest registry.** A digest is only as useful as the registry
that resolves it. Connect maintains an immutable manifest registry:
every engine build publishes its manifest to the registry (R2,
content-addressed by digest) **before** the scanner or a desktop
release ships it; observations are accepted only under registered
digests, and an unknown digest quarantines the observation as
incomparable with an operational alert, never a guess. Registered
manifests are retained for the life of the service (they are small and
they are the meaning of history); rollback is re-pointing deployment to
an already-registered digest, never unregistering one.

**The execution profile**, carried in the observation envelope
(protocol spec): browser engine **and build** (the Chromium version
Browser Run reports; automatic platform updates change it, and
pretending otherwise would make unequal environments compare equal),
axe version, resolver identity, transport adapter identity and
version, scan profile (`full` or `standard`), and `layers_run` - the
layers the observation actually ran, the only vantage fact a
producer states. `producer_instance` and locality are
**server-derived, never wire values**: the instance from the
authenticated credential or internal path, locality from what the
platform **documents** at execution time - today that is the colo on
an inbound `Request.cf`, which exists for request-driven work and
does **not** exist for Durable Object alarms or RPC-driven steps, so
any scan step without a documented platform source records
`unattested` rather than an inferred colo (unattested is itself a
locality value: unattested-to-unattested matches, one lane,
conservative). Whether a documented colo fact exists for
worker-originated fetch contexts is a recorded provider verification
item, and attestation widens only when the platform's documentation
does. Nothing for Browser Run, whose
session API exposes no location; `local` for desktop;
per-result layer comes from each check's manifest entry, and each
result's vantage is assembled server-side from
`(derived producer_instance, its check's
layer, that layer's attested locality or its constant)`. Desktop
snapshots carry the applicable subset for their source.

The manifest is generated from the registry, never hand-written; a
check added to the engine without a registry row fails the build.
Dynamic ids (`accessibility.axe.{rule}`, `security.exposed_files.{path}`)
are covered by family entries keyed by exactly the `CHECK_ID_PREFIX`
constant those ids carry, with a shared contract that folds in the
pinned axe version for the axe family. Lookup resolves an exact id
first and the longest matching family second.

Three things a generator cannot check about itself are enforced
against the source instead (`guardrail-capability-manifest-rules.mjs`):
a row may claim a hosted lane other than `unsupported` only when the
check's verdict code is in the engine crate, so the lane is checked
against where the code lives rather than against intent; the entry's
`scope` must agree with the desktop's own `AsyncCheck::origin_scoped`,
because two answers to one coverage question is how coverage claims go
wrong; and a check whose verdict reads `evaluation_time` must be
classed `clock_dependent`, because classing one as deterministic
blames an operator for the calendar.

## Execution architecture

Three workers provide hosted execution, with fail-closed rate limits,
`nodejs_compat`, and observability:

- **`apps/sitecmd-connect`** (protocol spec) owns triggers, durable
  tenant state, the event log, and the manifest registry. It never
  fetches user sites.
- **`apps/sitecmd-scan`** owns scan execution: the wasm engine module,
  the transport adapters, and the network-policy
  module. Connect invokes it over a service binding, and it commits
  observations back through the named `commitHostedObservation`
  operation (protocol spec), idempotent by scan id. It holds no
  durable tenant findings; what it does hold is the bounded, sanitized
  execution state defined next.
- **`apps/sitecmd-browser`** owns the browser pass: the Browser Run binding
  and the egress and isolation policy every rendered page runs under. The
  scan Worker invokes it over a service binding, sending each call's
  session id and deadline and receiving the pass's evidence as plain data;
  it holds nothing between calls.

### The scan state machine and its fence

Scan orchestration lives in a Durable Object per connected site. The
DO gives per-site serialization of _decisions_, but it is not a
correctness crutch: Cloudflare explicitly permits request interleaving
around external I/O, objects can be evicted or migrated during
deployments, and alarms are at-least-once. Correctness comes from a
**persisted, fenced, idempotent scan record**:

- The scan record holds: `scan_id` and `generation`, the
  **captured basis** (deployment head identity or the explicit
  no-deployment state, `scope_revision`, and `event_sequence`, per the
  protocol's currency predicate), `engine_release`, `manifest_digest`,
  `crawl_profile`, the execution profile, the current page step,
  sanitized partial outputs (occurrence identities, their authored
  `scope_route` provenance, per-pair outcomes, coverage facts only), a retry
  count, and a terminal status. Redirected findings retain final-URL identity
  while coverage also names the authored route, so a later redirect-target
  change can clear the old occurrence without moving its identity.
- **The fence is transactional, not advisory.** Every commit that
  follows external I/O (a page fetch, a browser session, an admission
  wait) is a conditional write comparing
  `(scan_id, generation, status, erasure_epoch)` against storage in
  the same transaction. `erasure_epoch` is a site-level counter bumped
  by disconnect and erase; a step that was mid-fetch while an erase
  interleaved finds the epoch advanced (or the state absent) and its
  write is rejected. **Missing or deleted state always rejects the
  write**: a stale step can never recreate storage after an erase,
  which is a privacy guarantee, not just a consistency one.
- **The fence is end-to-end, not local.** The DO fence protects the
  scanner's own storage, but a service-binding call is not a
  transaction, and tenant truth lives at connect: a scan could pass
  its local fence and still race a disconnect, erase, deployment, or
  scope mutation before connect applies it. `commitHostedObservation`
  therefore carries the captured `erasure_epoch` alongside the basis,
  and connect applies the observation inside one per-site database
  transaction whose conditional predicates compare the site row's
  `{phase, erasure_epoch, head, scope_revision}` (protocol spec);
  disconnect, erase, deployment recording, and scope mutation update
  that same row, so the race has a deterministic loser. The
  interleaving fixtures (erase-during-commit, disconnect-, deploy-,
  and scope-change-during-commit) prove it.
- Page-step commits are idempotent on `(scan_id, route)` under the
  fence: an alarm that fires twice or a step retried after eviction
  re-commits the same result, not a duplicate.
- Recovery is resumption from the record, **and connect linearizes
  it**: a restarted DO reads the scan record and calls
  `advanceScanGeneration(scan_id, current, current + 1)` at connect
  **before** touching local state, because bump-locally-then-register
  would leave the exact window it exists to close (a zombie's commit
  landing between the bump and the registration). On `advanced` the
  coordinator adopts the new generation and resumes; on
  `already_committed` the scan finished under the old generation and
  recovery stops; on `stale` it adopts the returned generation. The
  call is idempotent by target generation, so a crash between the
  connect CAS and local adoption re-runs and converges. Steps that
  exceed the retry budget except their pairs; a scan that cannot
  proceed terminates with honest partial coverage.
- Disconnect and erase cancel outstanding alarms, bump the
  `erasure_epoch`, and delete the DO storage for the site; erase
  includes this storage in its cascade.

### The page-step loop

A hosted scan mirrors the desktop's sequential page loop as a chain of
steps driven by the coordinator: each step scans one route (transport
fetch, wasm checks, browser work when the scan profile includes it),
commits its sanitized partial result under the fence, and yields.
Between steps the coordinator checks for supersession and cancellation,
the hosted equivalent of the desktop's 50 ms cancel polling, at page
granularity. Browser work follows platform guidance: **one Browser Run
session per scan**, acquired through admission below, with a fresh
isolated browser context per page and never any cross-site or
cross-scan reuse; the session closes at scan end or on budget breach.
Launching a browser per page would multiply acquisition latency and
session-creation load for no isolation gain that per-page contexts do
not already provide. After the final step the coordinator assembles
coverage, submits the observation through `commitHostedObservation`,
and acts on the response: `applied`, or `history_only` with a
replacement scan scheduled.

### Global browser admission

Per-site serialization does not bound account-wide Browser Run
concurrency, and scheduled alarms cluster. Admission is **leased and
sharded**, not a single global object (a lone global DO is exactly the
singleton hotspot Cloudflare warns against):

- Admission state is sharded: per-account admission objects enforce
  per-account fairness and bounds, over a small fixed set of capacity
  shards that together enforce the account-wide session ceiling.
- **Independent shards cannot enforce one exact global ceiling, so
  the ceiling is statically partitioned**: the provider account's
  session budget (Browser Run's billed-free concurrency allowance
  rather than its higher platform limit, minus a held-back reserve) is
  divided into fixed per-shard quotas that sum under it,
  each shard admits strictly within its quota, and account-to-shard
  routing is stable (hash of account id). **Quotas are immutable at
  runtime for the beta**: Durable Objects share no storage, so moving
  quota between live shards safely requires a donor-drain protocol
  (revoke, wait for the donor's leases to fall below its new quota,
  then grant) that is real machinery with real failure states -
  machinery the beta's fleet size cannot justify. Rebalancing is
  therefore a configuration version bump rolled out by deploy, the
  quotas are pinned in the beta operating configuration below
  (ceiling, reserve, shard count, per-shard quota - the configuration
  is not complete without them), and the dynamic donor-drain
  rebalancer is explicitly deferred until observed demand proves
  static partitioning wastes real capacity. Uneven demand under
  static quotas surfaces as the delay-first behavior below - degraded
  fairness, never an exceeded ceiling.
- A browser slot is an **expiring, idempotent lease** keyed by
  `(scan_id, page batch)`. A crashed step never strands capacity: its
  lease expires and the slot returns. Lease renewal accompanies
  page-step commits; a fenced-off zombie cannot renew.
- A reconciliation sweep compares outstanding leases against actual
  Browser Run sessions and closes orphans in both directions.
- Platform pushback (429, capacity) follows one rule everywhere:
  **capacity failures delay protection, they do not falsify
  coverage.** Steps retry with backoff honoring `Retry-After`; only
  when the scan-level retry budget is exhausted does the scan complete
  with browser-family pairs excepted, and that exhaustion is an
  operational alert about the service, not a quiet coverage note about
  the site.

### Scan profiles

Two, mirroring the desktop's own split (its scheduler always passes
`axe_enabled: false`):

- `full`: transport plus browser layer. Default for deploy-triggered
  scans, because the deploy-verification promise includes the browser
  checks, and the source of hosted TLS facts.
- `standard`: transport only. Default for scheduled between-deploy
  scans, where the drift checks below carry the watch and browser cost
  is not justified per tick. Cadence and the periodic full pass are
  operating values in the beta operating configuration below; what a
  paid plan eventually includes is decided outside this specification.

## Beta operating configuration

No plan numbers are set before cost data exists, but a comped beta
still has to run, and "decided later" is not an executable cadence. The beta's operational
values are therefore a **versioned configuration artifact** in the
connect worker - engineering capacity decisions, explicitly not
prices, replaced by the pricing pass's decided values at graduation:

- The keys, all required: scheduled standard-scan cadence, periodic
  full-pass cadence, deploy debounce window, fair-use deploy-scan
  ceiling and coalescing floor, per-destination and per-account daily
  send caps, per-credential rate limits, per-scan and per-site budget
  bounds (pages, sessions, session seconds), the allowance-slot
  cooldown window, and the retained `dunning_grace_days` setting.
  Entitlement does not read that setting: payment grace is the Stripe
  `past_due` status, which permits watching but not adding sites or
  dispatching fix jobs.
- The **beta-1 values**, the initial committed artifact ("set
  conservatively" is not a value an implementer can ship). These are
  capacity engineering, not prices; every revision is a version bump
  with a changelog line, so "what were the limits when this scan ran"
  is answerable:

  | Key                              | Beta-1 value                                                                                                                                                                                                                                                                                                                         |
  | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
  | Scheduled standard scan          | 1 per site per day                                                                                                                                                                                                                                                                                                                   |
  | Periodic full pass               | 1 per site per week                                                                                                                                                                                                                                                                                                                  |
  | Deploy debounce window           | 120 seconds                                                                                                                                                                                                                                                                                                                          |
  | Deploy-scan fair-use ceiling     | 30 deploy-triggered scans per site per day                                                                                                                                                                                                                                                                                           |
  | Coalescing floor                 | Full profile for the first 10 deploy scans per day, `standard` after                                                                                                                                                                                                                                                                 |
  | Per-destination send cap         | 50 messages per day                                                                                                                                                                                                                                                                                                                  |
  | Per-account send cap             | 200 messages per day                                                                                                                                                                                                                                                                                                                 |
  | Account-credential rate limit    | 120 requests per minute                                                                                                                                                                                                                                                                                                              |
  | Live personal tokens per account | 50                                                                                                                                                                                                                                                                                                                                   |
  | CI-token rate limit              | 60 requests per minute                                                                                                                                                                                                                                                                                                               |
  | Hook-door rate limit             | 60 events per minute per site                                                                                                                                                                                                                                                                                                        |
  | Resend-intake rate limit         | 300 events per minute, global                                                                                                                                                                                                                                                                                                        |
  | Browser-form public-route limit  | 30 requests per minute per source address per resource                                                                                                                                                                                                                                                                               |
  | Per-site daily budget            | 60 scans, 15 sessions, 13,500 session seconds, 6,000 pages                                                                                                                                                                                                                                                                           |
  | Per-scan budget                  | 100 routes, 1 browser session, 900 session seconds, 400 outbound probe requests per route                                                                                                                                                                                                                                            |
  | Allowance-slot cooldown          | 7 days                                                                                                                                                                                                                                                                                                                               |
  | Retained dunning setting         | 7 days, unused by entitlement                                                                                                                                                                                                                                                                                                        |
  | Browser admission partition      | Ceiling = the billed-free concurrency allowance (10), deliberately not the platform limit (120) recorded beside it: the provider refuses above one and bills above the other, so they are different numbers on purpose; reserve 2; 4 shards; per-shard quota = floor((ceiling - reserve) / 4), literals stamped at config generation |
  | Scheduled reservation, daily     | Up to 3 attempts: 300 pages, 0 sessions, per site                                                                                                                                                                                                                                                                                    |
  | Scheduled reservation, weekly    | Up to 3 attempts: 300 pages, 3 sessions, 2,700 session seconds, per site                                                                                                                                                                                                                                                             |

  The account-credential rate uses `account_token_requests_per_minute`:
  120 requests per minute per dashboard session bearer or personal token,
  including the dashboard entrypoint. `personal_tokens_per_account` limits
  live personal tokens to 50; revocation frees a place. Configuration
  version 13 introduces that limit. `dunning_grace_days` remains declared
  as 7 but is unused; entitlement reads subscription status.

- **The trigger algorithm, deterministic end to end.** "Day" means
  the UTC calendar day, everywhere a daily quantity appears (rolling
  windows apply only where a key says "rolling", as the alert storm
  budget does). A qualifying deploy event opens or extends the
  debounce window; when the window closes, let N be the number of
  deploy-triggered scans already started this UTC day for the site:
  N < 10 runs a `full` scan; 10 <= N < 30 runs `standard`; N >= 30
  enters **coalesced mode**: no scan starts, a pending-deploys marker
  aggregates everything that lands, and while the marker is set one
  `standard` scan runs at the top of each hour against the
  then-current deployment, clearing the marker it consumed.
  Marker-consuming scans are always `standard` and **never count in
  N**, which settles the midnight edge: a marker pending at 00:00 UTC
  is consumed by the 00:00 marker scan as usual (standard,
  N-neutral), the day's counter resets independently, and the next
  actual deploy event starts the new day at N = 0 with a `full` scan
  through the ordinary debounce. Two determinism rules close the
  remaining edges. First, a scan belongs to the UTC day in which its
  **start decision** is made (a 23:59 deploy whose debounce closes at
  00:01 is the new day's N = 1, full). Second, the marker is a stored
  object with a generation, and consumption is a **generation CAS**,
  because Cloudflare alarms are at-least-once and a bare
  compare-and-delete would let a consumer that read stale state
  delete a deploy it never scanned: the marker is
  `{ generation, latest_deployment_id, set_at }`, every deploy that
  lands sets or updates it with `generation + 1`, and the consumer
  reads `(G, D)`, starts the scan against `D`, then deletes with the
  predicate `generation == G` - a deploy that bumped the generation
  in between fails the delete and the marker survives to the next
  hour with its newer deployment intact. `generation` is drawn from a
  **durable site-level `coalescing_generation` high-watermark** that
  increments atomically on every marker create or update and **never
  resets** - it outlives the marker it stamped, because if the
  counter lived in the marker, deleting a consumed marker would let
  the next coalesced deploy mint a reused G, collide with the
  completed scan's idempotency key, silently join it, and never be
  scanned. Duplicated alarms converge
  because scan start is idempotent by `(site, erasure_epoch, G)` -
  the erasure epoch is in the key, and the watermark itself is stated
  in the protocol's retention table to **survive disconnect** but
  reset with erasure, so a reconnected-after-disconnect site
  continues its G sequence while an erased-and-recreated site cannot
  collide with a ghost of its former self: the second alarm
  either finds no marker or finds the same `(G, D)` and joins the
  already-started scan, and G values are unique for the site's life,
  so "joins" can only ever mean the scan for exactly that marker. Scheduled **retries** are new scan records
  with fresh scan ids and fences (a retry never resumes a fenced-off
  execution), keyed to the same reservation attempt counter
  `(site, UTC day, class, attempt <= 3)`; resources consumed by
  failed attempts are recorded against the reservation's accounting
  but do not reduce the remaining attempt allowance - the
  reservation's promise is "up to three tries, each within the
  per-scan budget", not "three tries minus whatever the crash
  burned". Scheduled
  scans continue regardless. Supersession is unchanged (a newer
  current deployment mid-scan finishes the page step, marks the scan
  superseded, submits partial coverage honestly), the marker state
  and the mode are visible in site state, and the UTC day boundary
  resets N, so the worst case is bounded and computable from this
  paragraph alone.
- **Per-site daily budgets** (beta-1), backstopping the per-scan
  bounds against pathological days: 60 scans, 15 browser sessions,
  13,500 session seconds, 6,000 pages per site per UTC day. The
  budgets bind the **demand-driven classes** - deploy-triggered,
  coalesced, and manual-refresh scans; the scheduled classes (the
  daily standard scan and the weekly full pass) run from their own
  **reserved allocation outside these budgets**, with the arithmetic
  in the reservation rows above, so "scheduled protection continues"
  is arithmetic, not a contradiction: exhausting the demand budget
  stops demand scans and cannot touch the reservation. Reservation
  mechanics: on the weekly full pass's day, the full pass **replaces**
  the daily standard scan (they never stack); a failed scheduled scan
  retries at most twice within its own reservation, and a day that
  ends with the reservation unfulfilled records a protection-health
  note rather than rolling capacity forward. Exhaustion behaves like
  every other ceiling: visible degradation
  (scheduled protection continues, further deploy scans coalesce to
  the next UTC day),
  never a silent stop.
- A **test fixture pins the schema and the values**: every key
  present, typed, within declared sanity bounds, and equal to the
  committed beta-1 artifact, so a missing, nonsensical, or silently
  drifted value is a failing test, not a runtime surprise. The
  fixture also replays the trigger algorithm against a scripted deploy
  day and asserts the exact scan sequence, covering scans 1 through
  10, 11 through 30, coalesced mode, a 23:59 debounce spanning
  midnight, a deploy landing at exactly 00:00, a duplicated marker
  alarm, demand-budget exhaustion with the reservation intact, and
  the daily-scan-replaced-by-weekly-full collision. Site state
  and error surfaces quote the running configuration's values (the
  `422`s already name their limits), so the beta cohort always sees
  the numbers that are actually in force.

## Crawl profile, version 3

`crawl_profile: 3`, the envelope field the protocol spec reserved,
pins:

- **Route set: the scan-scope resource, entirely.** The scan record
  pins the `scope_revision` it ran against, and a hosted scan covers
  the **whole effective scope**: there is no silent per-scan
  truncation, because a route that can never be scanned is a promise
  that can never be kept. The reconciliation is at the resource
  boundary instead: the protocol rejects a scope `PUT` exceeding the
  single 100-route cap for every account with `422 scope_exceeds_plan`,
  so scope and scan capacity are the same number by
  construction, session checks can always reach complete coverage,
  and nothing rots uncovered. The environment entry URL counts as a
  route (deduplicated if also listed). The wire-format bound of 5,000
  routes is just the schema limit, not a scanning promise.
- **Discovery is informational:** each scan refreshes the sitemap through the
  shared sitemap-document parser and candidate policy, then reports route-set
  deltas as drift facts without scanning unselected routes.
- **Sequential route and transport execution, entry page first**,
  origin-scoped checks on the entry page only, per the manifest's
  `scope` entries. A rendered page's Chromium subresources retain
  browser-like concurrency inside that route; every request still
  passes through interception, public-address validation, and the
  browser session ledger before it is fulfilled.
- **Identity rules** by reference to the protocol spec's canonicalizer:
  final URL after redirects, preserved trailing slashes, stripped query
  with `query_dependent` flagging.
- **Transport constants**, identical to the desktop's except for the
  page body and sitemap caps:
  10-redirect limit with per-hop validation, 30 s page fetch timeout,
  15 s per-check timeout with timeout-as-`Skipped`, 1 MiB page body
  cap (overrun excepts only that route as `page_too_large` while the scan
  continues), 512 KiB probe cap, 2 MiB
  sitemap cap, 2 MiB stylesheet cap with at most 8 stylesheets,
  30-asset sample with `Range: bytes=0-0`, link-probe samples of
  100 internal and 30 external. One route at every bound must stay under
  half the Workers isolate's 128 MB, which every Durable Object it hosts
  shares with the Worker's code, so a second route fits beside it; the
  scan Worker measures that in workerd (`measure-route-memory.mjs`), and
  these caps are the largest 1 MiB steps toward the desktop's that held
  it. Version 2 held every intercepted browser response at once; version 1
  read pages to 10 MiB, with overrun scan-fatal as on desktop, and sitemaps
  to 5 MiB. Neither ran for a customer.
- **Browser interception constants and timing semantics:** at most 400
  requests, 64 distinct hosts, 3 MiB of decoded body data for any one
  response, at most 3 MiB of response bodies held at once, each from its
  fetch to its fulfillment, and 25 MiB across the session. The per-response cap is
  enforced while reading, before the body is concatenated or handed to
  Playwright; the session ledger charges the same decoded bytes before
  fulfillment. Playwright fulfillment cannot stream the main document,
  so the proxy records the main-document body-wait interval and removes
  that artificial delay from TTFB, FCP, and LCP. CLS and long-task
  blocking are not shifted. These values are explicitly hosted,
  proxy-adjusted lab samples, not field measurements. Repeated
  `Set-Cookie` field lines are preserved in order and installed one at a
  time in the isolated browser context, while remaining structurally
  absent from every persisted projection.
- **Outbound probe bound, per route: 400 requests.** Every constant
  above caps one request; this one caps their sum, which nothing did
  before. Measured rather than chosen: driving `engine_route_plan` to
  its fixpoint against a page carrying 200 internal and 80 external
  links costs 380 requests for one route when every probe fails (four
  rounds: 245, 132, 2, 1) and 254 when every probe answers along a live
  redirect chain (ten rounds: 245, then one per hop). The sitemap walk's
  longest request set, twenty failing declared sitemaps beside failing
  probes and the og:image, asks for 401 and makes 400, the twentieth
  declaration refused and read as unread. Requests and
  rounds are maximised by opposite situations: failures cost requests,
  because the link check's `GET` confirmations are planned only where a
  `HEAD` failed, while answers cost rounds, because the redirect walk is
  planned one hop at a time and each `3xx` names the next position. The
  cap therefore admits the crawl profile's own
  arithmetic with headroom rather than trimming it: a bound below the
  profile would make coverage exceptions the normal case and would make
  the limits published on `/scanner` false. The per-scan worst case
  follows as routes times the cap, and with origin-scoped checks
  narrowed to the entry route the realistic ceiling is about 27,000
  requests to one origin per full scan. The bound is per route rather
  than per scan so that it needs no durable spend counter across alarm
  ticks and so that one pathological route cannot starve the rest of
  the scan. A probe the budget refuses is reported as a failed probe
  with its own reason, never as a silent absence, because a hole is
  graded as evidence nobody gathered.
- **User agent:** one shared, versioned identity across desktop and
  hosted: `SiteCMD/{version} (+https://sitecmd.com/scanner)`. The
  desktop and CLI derive the version from their package build, and the
  scanner page documents the bot,
  its source, and how operators can allowlist and verify its traffic.
  Browser Run additionally injects identifying headers that cannot be
  removed, which is disclosed on the same page; a shared UA is
  necessary for parity but not sufficient for equivalent content,
  which is what the challenge gate below is for.

Any change to these rules is a new `crawl_profile` version through the
comparability gate.

## Coverage production

The protocol spec's pair-precise coverage (claim plus exceptions) is
produced from per-check outcomes, and where the engine does not emit
enough outcome to prove execution, the engine is extended rather than
the proof weakened. The derivation itself is shared code
(`sitecmd_engine::coverage`, protocol implementation contract item 2): the
hosted runner assembles outcomes and calls the same `derive`, so the two
producers cannot disagree about what a claim means. What this section
adds is the hosted lane's own exception reasons and the gate that
produces them.

- A `(route, check)` pair is covered when the route's step completed,
  **the main document passed the challenge gate**, and the check
  executed to a verdict (`Pass`, `Fail`, `Warn`). Two extensions the
  desktop half already landed for exactly this rule: the axe integration
  reports every rule it executed rather than only its violations (a fix
  deletes the id its own proof would need), and the cross-page analyzer
  reports an outcome for every check it considers rather than only the
  ones that found something.
- **The challenge gate.** The RFC's verification semantics already
  name "the deployment answered with a bot challenge" as a reason a
  finding can vanish without being fixed; the gate makes that
  operational. Before any of a route's results count as coverage, the
  main document is validated as plausibly the intended page and not an
  interstitial: challenge-page signatures (managed-challenge and
  CAPTCHA markers, challenge status codes and headers), and a
  document-validity heuristic against the route's last known **page
  signature**. The signature is a defined, bounded object in a
  **server-owned route-profile resource** (per route, beside the
  occurrence state; site lifetime, exported, erased with the site,
  explicitly on the persistence allowlist), never inside the
  scope resource changed by a signed-in person through the dashboard,
  because scans refresh signatures and
  a scan must not churn `scope_revision` or race a scope replacement.
  Two signatures per route, transport and browser:
  `{ status_class, content_length_bucket, title_mac, script_origin_set_mac }`
  from the transport document, plus `{ landmark_count }` from the
  rendered DOM when a browser ran. Every content-derived field is a
  count or a **keyed MAC**: bare hashes of low-entropy titles and
  script sets are dictionary-reversible, the exact argument this
  architecture makes about code locations. The MACs are **minted at
  connect ingest** (protocol spec): every producer, hosted scanner
  and desktop alike, sends the transient canonical projection (the
  source fields, the detected library set), connect computes the MAC
  under its per-site content key and domain strings, and the
  projection is never persisted, logged, or traced. This is the only
  model that works for all producers: the desktop cannot hold
  connect's key, the project fingerprint key is one connect must
  never hold, and inventing a third distributed secret would be a
  custody problem nobody needs. The key is server-held deliberately,
  unlike the fingerprint key: here the threat is exposure of persisted
  data to a third party, not the server reading what it transiently
  processes anyway; it rotates by `key_version` (digests compare only
  within a version) and is deleted in the erase cascade. The
  hostile-content fixture asserts a secret-bearing page's signatures
  contain nothing recoverable and that no projection survives
  ingest.

  The gate algorithm is asymmetric, so a redesign cannot lock a site
  out: **challenge markers except; signature mismatch flags and
  narrows.** Deterministic challenge signatures (managed-challenge and
  CAPTCHA markers, challenge status codes and headers) except all of
  the route's pairs with the `bot_challenge` reason, browser and
  transport alike, because axe finding zero violations on a challenge
  page must never verify the real page's violations fixed. A signature
  mismatch without challenge markers records a `document_changed` flag
  on the route profile and **narrows what the observation may prove**:
  presence evidence stays valid (a finding observed on whatever
  document was served is real on that document), but the route's pairs
  are **excluded from absence resolution** - no verification, no
  `verified_absent`, no verified-good promotion - until the new
  signature is stable or explicitly accepted, because a site serving
  scanner-specific content can otherwise falsely verify a fix that
  ordinary visitors still see broken. The exclusion is a named
  coverage exception (`document_changed`), visible like every other.
  **Self-heal**: three consecutive consistent observations of the new
  signature adopt it and lift the exclusion. The route-profile contract
  describes an immediate reset for deliberate redesigns, but Connect
  does not implement that endpoint. A first scan
  has no signature and gates on challenge markers alone - **unless
  standing evidence exists for that vantage**, in which case the
  missing signature is `profile_cold`, not first-scan innocence: a
  vantage returning after cell retirement with a standing entry to
  clear must first rebuild its signature through the same
  three-observation stability window before its observations may
  resolve absence (presence counts immediately, as always). Without
  this, cell eviction would quietly re-open the door the signature
  gate exists to close, for exactly the entries where it matters.

  Signatures carry a **vantage dimension**, and vantage identity is
  one structured object everywhere it appears - signatures, evidence
  entries, execution profiles, measurements. **`layer` is the
  check's manifest layer, never a scan
  label**: a `full` scan produces transport and browser results in
  one observation, so the observation declares only `layers_run`
  (instance and locality are server-derived, per the execution
  profile) and every
  result's vantage
  layer comes from the check that produced it - the scan profile can
  narrow `layers_run`, it cannot mislabel a result.

  Vantage identity is
  `{ producer_instance, layer, locality }`, with each part earning
  its place:

  - **`producer_instance`** identifies the authenticated producer. For a
    desktop submission it is `user:<subject>` for a dashboard session or
    `token:<token_id>` for a personal token. Clients sharing that actor
    share a vantage; separate personal tokens create separate vantages.
    For the hosted scanner it is `hosted`; for CI it is the CI token's
    stable identity. The client cannot supply this key.
  - **`layer`** is the check's manifest layer, as before.
  - **`locality` is recorded only from a documented platform fact at
    the scan step's own execution** - one derivation function, no
    inference: today's only documented source is the colo on an
    inbound `Request.cf`, which alarm-driven and RPC-driven steps do
    not have (service-binding RPC is a method call, not an inbound
    request), and trigger-request colos and inferred DO locations
    **never propagate** to steps they did not execute. Since this
    architecture drives page steps from the coordinator, hosted
    transport locality is therefore **effectively `unattested` in
    v1** - stated plainly rather than promised away - and widens
    only if the platform documents a colo fact for worker execution
    contexts (a recorded provider verification item). The Browser
    Run session API
    exposes no location at all, so the hosted browser lane's
    locality is the constant `unattested` - one lane, honestly
    unlocalized, with the residual geo-variance risk stated rather
    than a fabricated colo pretending precision. Desktop locality is
    the constant `local`; the credential-keyed producer supplies identity,
    so changing location does not change its vantage. There are no
    epochs and no lane transitions: an attested locality **is** the
    identity - if attestation ever exists, a moved execution point
    simply produces a
    different vantage key, and a return to the old locality is the
    old
    vantage again, no bookkeeping required.

  The clearing rule collapses to one sentence: **full key equality
  clears with same-vantage authority; everything else clears only
  through per-check input-MAC equivalence.** Signature equality never
  merges continuity across vantage keys: route signatures omit most
  check inputs (CSP headers, accessibility state), so two localities
  can serve signature-identical pages that differ in exactly what a
  check reads, and moving occurrence evidence on signature equality would
  make an incomplete signature an absence authority - the same error
  this document already rejected once for cross-vantage clearing.
  Signatures heal signatures; they never move evidence. Entries from
  a vantage that never recurs resolve through input equivalence
  where their checks qualify and otherwise stand with the named
  locality-variant condition - visible, explained, and deliberately
  unresolvable by machine, because differing content across
  localities is exactly when clearing would be a guess. The human
  paths for a genuinely stuck entry are the lifecycle's own -
  dismissal, or a claim verified by a lane that can see the route -
  **not** the route-profile reset or baseline acceptance, which
  govern signatures and drift baselines respectively and resolve no
  occurrence evidence. Route signatures and check-input MACs key by
  the same `(producer_instance, layer, locality)` identity, and
  vantage cardinality is bounded by compaction: resolved entries
  compact first, standing entries are never silently dropped, and
  the per-record entry count has its explicit bound in the protocol
  spec (32 entries, with the aggregate-overflow rule).
  Profiles store and compare signatures per the same full
  `(producer_instance, layer, locality)` identity - a narrower
  signature key would collapse credential-keyed producers and localities right
  back together. The browser layer executes page code and uses a
  browser request profile even though its target traffic is fetched by
  the Worker, so a site may legitimately produce different content than
  it serves the desktop or ordinary visitors. A stable per-vantage
  variant is honest state, not drift:
  each vantage heals against its own history, and absence
  verification requires stability in the observing vantage.

  Stability within a vantage is not sufficient across them: a CDN
  consistently serving the identifiable hosted browser a clean page
  would otherwise build a stable hosted profile and then "verify"
  fixes ordinary visitors never received. The protocol's evidence
  rule is therefore **per-vantage presence with same-vantage
  clearing**: every vantage that observed an occurrence holds its own
  standing evidence, a clean observation resolves only its own
  vantage's entry, and `verified_absent` requires every entry
  resolved. Route signatures are the **drift detector** that flags
  variants and blocks a vantage's own absence resolution while
  unstable; they are deliberately **not** a cross-vantage absence
  authority, because their fields (status class, title, script
  origins, landmarks) do not include most checks' actual inputs - two
  pages can match signatures while differing in exactly the CSP
  header or accessibility state a check reads.

  The one sound crossing is **check-input equivalence**: for checks
  whose complete canonical inputs ride the transient projection, an
  observing vantage whose projection of those inputs MACs equal to
  **the establishing entry's stored
  `establishing_context.input_mac`, exclusively** (same
  `transient_projection` version, same MAC key version; never the
  route profile's copy, which later observations refresh and would
  create the mutable-reference bug the stored MAC prevents) may
  resolve that vantage's entry,
  because identical inputs give identical verdicts by construction.
  The qualifying set is the manifest's per-check
  `equivalence_inputs` declaration - an explicit completeness claim
  enforced by property test, **not** an inference from `requires`,
  which declares runtime needs and says nothing about inputs. The
  worked counterexample is why: CSP and Referrer-Policy read
  `<meta http-equiv>` fallbacks from the document body, so their
  header-projection values can compare equal while the verdicts
  differ; they carry no `equivalence_inputs` and never cross.
  Certificate-identity and DNS-posture checks do; certificate expiry
  is clock-dependent and never crosses. A projection whose
  declared input fields include any truncated scalar or overflowed
  collection is **never equivalence-comparable** for that check
  (the `projection_overflow` exception rule); scalar truncation
  counts, not just collection overflow. Persistently disagreeing
  vantages keep
  their entries unresolved indefinitely, as a named content-variant
  condition in site state - visible, explained, never silently
  accepted and never silently flagged forever.
  The protocol spec describes route-profile reads and a revision-guarded
  reset, with export, site erasure, and compaction requirements. Connect
  implements neither route, so a deliberate redesign has no API reset
  that bypasses the healing window. The `bot_challenge` exception is
  user-visible and actionable: the site is challenging its own
  guardian, and the scanner page documents how to allowlist it.

- **The origin gate.** A planned route's document fetch must end on
  the origin the route names: the transport walk may follow a
  same-origin redirect chain, but a final URL on any other origin
  excepts every one of the route's pairs with the
  `cross_origin_redirect` reason before anything reads the response.
  Nothing the foreign document says is filed - no occurrences, no
  measurements, no route profile advance - and no probe fires at the
  landing origin, because the verified site vouches only for its own
  origin, and a route that 301s to a parked domain or an acquirer's
  page answers with a document that is not the tenant's. For the same
  reason a start whose planned routes span more than one origin is
  refused whole as `mixed_origin_routes`: one scan speaks for one
  verified origin.

- **Axe coverage is rule-level.** The current bridge returns violation
  identities and only a count of passes, so a vanished
  `accessibility.axe.image-alt` finding has no rule-level pass proving
  the rule executed. The shared browser payload is extended to return
  rule id arrays for all four axe buckets: `passes`, `violations`,
  `incomplete`, and `inapplicable`. A rule listed in any bucket
  executed; `passes` and `inapplicable` prove absence for that rule on
  that route; `incomplete` is a coverage exception for the rule's
  pair. This payload change ships to desktop and hosted together.
- Timeout-as-`Skipped`, probe failures classified as `Skipped` (the
  `DnsOutcome::Failed` path, OSV or RDAP unreachability), and the
  polish CSS-incompleteness rule all become coverage exceptions for
  their pairs, never silent gaps.
- Browser-layer failures except only the browser-family pairs for that
  route; the transport checks on the same route remain covered.
  Browser-slot exhaustion follows the admission rule: delay first,
  except only at the retry budget's end.
- `origin`-scoped checks are covered as entry-page pairs only;
  `session`-scoped checks are covered only when the complete route set
  ran.
- A step that fails entirely excepts every pair on that route; a scan
  superseded mid-flight submits what it completed with the remaining
  routes excepted, and its observation's fate is the basis rule below.

## Triggers, supersession, and the captured basis

Trigger contracts are the protocol spec's. This spec owns what
execution does with them:

- **Every hosted scan captures its basis at start**: the current
  deployment head (or the explicit no-deployment state, which is
  ordinary for sites that connect before their first recorded deploy),
  the `scope_revision`, and the site `event_sequence`. The protocol's
  currency predicate is exact: the observation is applied only when
  the captured head still equals the current head **and** the captured
  scope revision is still current at submission; a deploy or a scope
  change mid-flight makes it history-only with a replacement scan
  scheduled; event-sequence movement alone never invalidates it.
- A qualifying deploy event schedules a scan against the deployment
  after the **debounce window from the beta operating configuration**
  (beta-1: 120 seconds - the configuration is the single source, so
  this prose can never disagree with it again), reset by further
  deploys for the same environment. Every deployment is still
  recorded individually; debounce coalesces work, not history. The
  full trigger algorithm, including the ceiling and coalescing
  behavior, is the deterministic procedure in the beta operating
  configuration section.
- When a newer deployment becomes current mid-scan, the coordinator
  finishes the current page step, marks the scan superseded, submits
  its partial observation with honest coverage, and lets the basis
  rule classify it; the replacement scan is scheduled in the same
  breath, so history-only never means unwatched.
- **Cause classification happens at the connect layer, from facts, not
  from the trigger alone.** A scheduled scan is not automatically
  ambient drift: if a deployment occurred since the last observation
  and provenance supports it, attribution names the deployment; if
  `engine_release` or a check's `contract` changed, or an
  external-corpus revision moved, the cause is `detector or corpus
update`; coverage that newly succeeded is `newly available
coverage`; clock-dependent changes are `ambient drift` (time passing
  is the site's world changing); only with those ruled out does a
  non-deploy change classify as `ambient drift` generally. The
  trigger contributes one fact; it does not decide the story.
- Per-site and global trigger rate limits sit in front of everything,
  fail closed, and are separate from the scan allowance: rate limits
  protect the service, allowances price the product.

## Transient projection schema, version 1

The protocol's `transient` envelope and `commitHostedObservation` both
carry `transient_projection: 1` objects; this section is the schema,
because "certificate identity and header set" is not something two
producers on two runtimes can independently build identically. Every
collection is sorted lexicographically, deduplicated, and lowercased
where case-insensitive; deterministic bounding rules below are part of
canonicalization (both producers apply them identically by rule, which
is what makes them canonical form rather than silent truncation). Per
route:

- `document`: `{ status_class, content_length_bucket, title,
script_origins, landmark_count }`. `title` is canonicalized to the
  first 256 bytes at a UTF-8 boundary after whitespace collapse;
  `script_origins` is the sorted, deduplicated origin set
  (scheme, host, port), bounded at 64 entries with an overflow count
  included in the MAC input beyond that.
- `security_headers`: an **explicit allowlist projection, never the
  raw response header set** - `content-security-policy`,
  `strict-transport-security`, `x-frame-options`,
  `x-content-type-options`, `referrer-policy`, `permissions-policy`,
  `cross-origin-opener-policy`, `cross-origin-embedder-policy`,
  `cross-origin-resource-policy`, `cache-control`. The allowlist is a
  shared code constant and part of the projection version.
  `Set-Cookie` and every unlisted header are structurally incapable
  of riding the wire, not merely filtered. Representation is pinned
  and **preserves field-line structure**: each present header maps to
  an **array of field-line values in received order** - never joined,
  because joining is lossy exactly where it matters (multiple CSP
  field lines are enforced independently by browsers; a joined string
  can compare equal across a semantic difference). Per field line:
  internal whitespace runs collapsed to one space,
  leading and trailing whitespace trimmed, value bounded at 2,048
  bytes at a UTF-8 boundary with a per-line truncation marker when
  the bound bites; an absent header is an absent key,
  never an empty array.
- `certificate`: `{ leaf_sha256, subject_cn, san_dns_names (sorted,
bounded 100 with overflow count), not_before, not_after, issuer_cn,
issuer_org }`. Name strings bounded at 256 bytes each. No
  chains, no keys.
- `dns`: record sets the DNS checks read - `a`, `aaaa` (sorted
  addresses, bounded 32 each with overflow count), `cname_target`,
  `mx_hosts` (sorted, bounded 32), `caa_present`, and
  from TXT **only** policy strings matched by allowlisted prefixes
  (`v=spf1`, `v=DMARC1`), each bounded 512 bytes; arbitrary TXT
  content never rides, because
  TXT records routinely hold third-party verification secrets.
- `origins`: the third-party origin set observed on the route,
  sorted, bounded 128 with overflow count. Origin normalization is
  pinned: lowercase scheme and host, IDN hosts in punycode form,
  default ports omitted, non-default ports kept.
- `libraries`: the detected library set `{ name, version }` from the
  existing stack detection, bounded 64 with overflow count.

**One overflow rule everywhere, scalars included**: every bounded
collection that
overflows carries its explicit overflow count, every bounded scalar
that truncates carries its truncation marker (both included in MAC
input so nothing hides behind a bound), and any check whose declared
inputs include a truncated scalar or an overflowed collection
receives a `projection_overflow` coverage
exception for its pair and is excluded from input-equivalence
comparison on that observation - overflow narrows what an
observation can
prove, never silently weakens it. The schema itself is not prose: a
**shared DTO with a published JSON Schema** lives in the engine crate
and ships with the OpenAPI artifacts, and both producers serialize
through it.

Cross-runtime golden fixtures assert byte-identical projections from
both producers for the same artifacts; hostile fixtures assert
`Set-Cookie` and unlisted headers cannot cross, arbitrary TXT cannot
cross, duplicate and whitespace-mangled headers canonicalize
identically, oversize collections canonicalize identically with their
overflow counts, and no error
path echoes projection content. Any field addition or bound change is
a new `transient_projection` version through the comparability gate.

## The verified-good profile lifecycle

The verified-good profile is server-derived (protocol spec); this spec
owns its lifecycle, because "derived from accepted observations"
without promotion rules would let the first bad observation become the
new good:

- **Fields**: certificate facts, security-relevant header profile,
  third-party origin set, DNS posture records, route set. All
  deterministic or clock-dependent; no measurement field exists in the
  profile, by construction.
- **Seeding**: a field seeds from the first observation after
  bootstrap that is applied (current-basis), complete for that field's
  pairs, and clean for that field.
- **Promotion**: a field's good value advances only from an applied,
  unexcepted, clean observation. Each field retains its source
  observation id, deployment reference, and the engine and profile
  versions it was recorded under.
- **Drift never overwrites good.** A drifting observation freezes the
  field: the drifted value is the finding, the good value is what it
  drifted from. The baseline advances again through exactly two roads:
  the resulting issue is resolved (verified fixed) and a subsequent
  clean observation re-establishes the field, **or the user explicitly
  accepts the new value as the baseline**
  (`POST /v1/sites/{site}/verified-good/accept`, protocol spec): a
  distinct, confirmed action with recorded provenance (who, when,
  which value), deliberately separate from dismissing the drift
  finding, because dismissing a finding means "stop telling me" while
  accepting a baseline means "this is now correct", and conflating
  them would leave intentional changes frozen forever or make
  dismissal quietly rewrite what good means.
- **Detector changes do not launder baselines**: when a field's
  underlying check contract changes, the field re-seeds under the new
  contract with cause `detector or corpus update`.

The drift checks reading the profile: certificate horizon
(clock-dependent, ambient drift), header profile delta, third-party
origin set growth, DNS posture delta, route-set delta. The alert and
report delivery spec decides which of these wake anyone.

## The privacy projection

The RFC's transient-content promise is enforced at a named boundary:
**the sanitize-before-persist projection**. Everything downstream of a
page step's in-memory evaluation passes through it before touching any
storage, log, trace, cache, error report, or the connect submission:

- Never persisted anywhere: response bodies, rendered DOM, extracted
  selectors, node HTML, JS error strings, query strings, `raw_data`,
  `detail_json`, and failure summaries. These exist only inside the
  executing step's memory.
- Persisted (scan record and observation): occurrence identities in
  the protocol's canonical form, per-pair outcomes, coverage facts,
  profiles and versions, timing counters, and operational counters.
- Error reports and logs carry the error taxonomy and `request_id`s,
  never page content; the projection is a function with a test, and
  the conformance corpus includes a hostile-page fixture (secrets in
  body, DOM, and error strings) asserting the scan record contains
  none of them.
- The scan record's transient execution state has a TTL of 24 hours
  after terminal status; erase deletes the site's DO storage
  immediately, and the fence guarantees no stale step recreates it.
- Browser Run sessions run with **session recording disabled and no
  cross-site session or context reuse**: ordinary rendering content is
  ephemeral, but opt-in session recordings retain DOM activity, which
  would violate the transient-content promise outright. Disabling them
  is a contract term of this spec, and the trust pages' subprocessor
  disclosure states it.
- **Hosted third-party flows are enumerated, because moving a call
  from the user's machine to the service changes who is sending.** The
  hosted scanner's complete external egress beyond the target site:
  the DoH resolver (`cloudflare-dns.com`; queried names are the
  hostname of every URL the transport or isolated Browser Run context
  is about to fetch, including page-named subresources, plus the target's
  mail-record and DNS-policy names. Resolution runs per hop, and the crawl
  profile samples external links, so a redirect
  target, a sampled asset host, or an external link's host is resolved
  too. Public disclosures state this complete set), OSV
  (`api.osv.dev`; sends detected client-library names and versions
  observed on the public page, nothing else), and RDAP (`rdap.org`
  and the registry endpoints its bootstrap redirects to; sends the
  registrable domain). Fixed allowlist, no other third-party endpoint,
  failures classify as coverage exceptions, and third-party retention
  is theirs, which is why only derived verdicts persist on our side.
  The trust pages and the connected-service `network-facts.ts` entry
  disclose all three flows; the disclosure guardrail covers them.

## Network-security boundary

The desktop's `network_policy.rs` posture applies at server strength, with the
Workers runtime's properties stated honestly. Each runtime must enforce the
outcome at the strongest point it offers:

- **Targets:** scans run only against a connected, verified site's
  environment URL and its scope routes. No URL from any request body
  is ever fetched.
- **Scheme and ports:** HTTPS-only for production targets, default
  ports only.
- **Address filtering:** the desktop's exact rule set carries over
  (RFC 1918, loopback, link-local, unspecified, broadcast, 0.0.0.0/8,
  CGNAT 100.64/10, IPv6 unique-local and link-local, IPv4-mapped
  recursion, metadata hostname), plus the cloud metadata IP ranges.
  Applied to the initial URL, every redirect hop, and every
  sitemap-derived and subresource URL.
- **Rebinding posture, per-runtime:** Workers `fetch` does not expose
  connection control, so the compensating layers are: manual redirects
  (`redirect: "manual"`) giving strictly per-hop validation, an
  advisory DoH resolution check rejecting names that resolve into
  blocked ranges before fetching, and the structural backstop that
  Workers egress has no route into private networks. Browser Run does
  not open target sockets: every intercepted HTTP request is fetched by
  the Worker under that same policy and fulfilled into Chromium. The
  TLS metadata probe, which does control its connection, pins the
  connection to a pre-validated public address and sends the original
  hostname as SNI.
- **Browser egress is a behavior policy, not only an address policy.**
  A verified tenant is authenticated, not trusted. Browser Run
  sessions enforce, via request interception and launch configuration:
  schemes `http`/`https` on default ports only; resource types limited
  to what scanning renders (document, script, stylesheet, image, font,
  xhr/fetch); **safe methods only (GET, HEAD, OPTIONS) for every
  origin, the target's own included**: a compromised page holding a
  scanner-issued cookie could otherwise fire same-origin POSTs that
  trigger jobs, emails, purchases, or deletions, and "it was their own
  site" is no comfort to the tenant whose site was the compromised
  one. Scanning renders pages; it never submits them. When a blocked
  unsafe request fired before evaluation settled (a scripted
  same-origin mutation the page needed for its rendered state), the
  route's browser-derived pairs are excepted rather than grading a
  partial DOM; blocked fire-and-forget beacons after settle are
  recorded without excepting anything. WebSockets, WebRTC, and service
  workers disabled; downloads and popups denied (the desktop webview
  already denies both); and per-session budgets on request count,
  distinct hosts, and total bytes, with a policy or budget breach
  terminating the session and excepting the route's browser pairs. An
  ordinary upstream network failure aborts only that browser request;
  it neither marks a policy breach nor retires the reusable session, so
  later requests and routes can continue. Repeated policy breaches
  surface to the entitlement layer as tenant abuse with suspension
  consequences.
- **Every egress control is proven, not declared.** The conformance
  suite includes hostile-page fixtures exercising each control:
  WebSocket and WebRTC connection attempts, service-worker
  registration, beacons, cross-origin POSTs and form submissions,
  **same-origin POST, PUT, PATCH, and DELETE attempts**,
  popups and downloads, redirect rebinding into blocked ranges, and
  request, host, and byte budget breaches, each asserting the
  attempt was blocked, the session tore down where required, and the
  coverage and abuse records show what happened. A control without a
  failing test is a wish.
- **Per-scan budgets:** the crawl profile's caps, plus wall-clock,
  browser-session, response, and page-count budgets per scan. Values
  are operational configuration with the v1 numbers as defaults;
  changes are disclosed operational facts.
- **Provider events** are signature-verified, idempotent, and
  replay-protected at the connect layer, per the protocol spec.

## Cost model and provider verification items

Browser Run is metered with account-wide concurrency limits; the
sockets API and DoH calls are ordinary worker work. Browser cost now
scales with `full` scans (one session each) plus per-page contexts;
transport cost with routes times probes. Instrumentation records, per
scan: pages scanned, sessions opened, contexts created, session
seconds, bytes fetched, and admission wait time.

Per-scan counters alone cannot produce the cost report the pricing
pass depends on, because Cloudflare does not bill in scans. The
instrumentation therefore also records the dimensions the bill is
actually computed from:

- **Peak browser concurrency at the level Cloudflare actually bills**:
  the provider account's **global daily peak** (Browser Run bills
  browser-hours plus the monthly average of the global daily peak),
  recorded alongside a per-site concurrent-session time series.
  Summing per-tenant peaks would overstate cost whenever tenants peak
  at different times, so the concurrency component is allocated to
  sites by a **disclosed proportional rule** - each site's share of
  session-seconds during that day - and the cost report reconciles
  the modeled total back to the actual invoice line, so the
  allocation model is checked against the bill every month rather
  than trusted.
- **Workers requests and CPU time, Postgres queries and storage, Hyperdrive,
  Durable Object duration and storage, Queue operations, and R2
  operations**, attributed to site and activity (scan, ingest,
  delivery, render) by the worker doing the work.
- **Email deliveries** by class, keyed by the delivery spec's
  closed class enum so metering cannot drift from delivery
  (immediate alert, storm summary, digest, confirmation,
  courtesy, security notice, and fresh-link resend - the cap-exempt
  security lane especially, since exemption from caps is not
  exemption from the bill, and the human-initiated resend
  especially, since a rate limit is not a zero),
  because Resend is a per-send line item. Site-scoped
  classes attribute to their site; account-level security notices
  are account overhead, allocated **equally across the account's
  connected site-days in the billing month** - deliberately not the
  session-seconds rule, because an account can send leaked-token notices
  on a day with zero browser activity, and a zero-denominator
  allocation is undefined. An account can also hold personal tokens,
  destinations, and security notices with **zero** connected site-days
  (every site disconnected, none erased), so the rule has an
  explicit floor: with no site-days in the period, the cost lands in
  a named **account overhead bucket** in the cost report - its own
  line against the subscription, allocated to nothing - so the
  margin math sees every send without ever inventing a denominator.
- A **versioned price book**: current unit prices for every metered
  dimension plus the fixed-plan allocation, checked in and dated, so
  the cost report is `usage x price book` at a named version and a
  provider price change is a price-book commit, not a silent drift in
  the margin math.

The roll-up to cost per connected site per month, as a distribution
split by scan profile, is the measurement program this instrumentation
exists to make computable.

Provider items recorded for build-time verification rather than
asserted: whether reaching Vercel Hobby deployments requires a Vercel
Integration; Netlify's signed notification format; Browser Run's
current session, creation, and concurrency limits and pricing, read
from the documented limits and pricing pages, which are the only place
those numbers are published - the provider dashboard shows runs and
usage and never the limits, so "check the dashboard" is not a
verification anyone can perform - with the monthly invoice
reconciliation above as the check that catches drift after launch,
since a concurrency line that appears on the bill is the provider
telling us an allowance moved; the session-recording default-off
confirmation; Workers global-fetch public-egress and trust-store flags;
`node:tls` certificate metadata behavior; and the current Workers TCP
restriction boundaries.

## Parity harness and release discipline

- **The conformance corpus** is a shared fixture set living with the
  engine crate: page artifacts paired with expected findings under a
  frozen `evaluation_time`, transport fixtures for the probe adapters,
  TlsFacts fixtures for both adapters, the canonicalizer fixtures the
  protocol spec obligates, the privacy hostile-page fixture, the
  egress-control fixtures, and challenge-gate fixtures (a challenge
  page must produce `bot_challenge` exceptions, never coverage).
  Desktop CI runs the corpus natively; the hosted runner's CI runs it
  through the wasm artifact and the Workers adapters. A fixture
  disagreement fails whichever build introduced it.
- **Release discipline:** the hosted runner deploys pinned to an
  `engine_release`; the capability manifest, its contracts, and its
  digest regenerate with every engine build and publish to the
  registry before anything ships under them; the hosted runner refuses
  to scan under a digest its artifact does not match.
- **Panic semantics:** a trap in wasm check evaluation, or the engine's
  refusal of a request, excepts that route's pairs `route_unscannable`
  and keeps the browser time the route spent, and the scan goes on: the
  engine has no clock and no I/O, so a retry of the same document would
  fail the same way. An I/O failure still fails the step, for the step's
  retry. Step timeouts classify as `Skipped` coverage exceptions.

## Implemented parity foundation

The public client repository supplies the shared artifacts the hosted runner
must consume:

1. **Portable engine and scorer.** `sitecmd_engine` contains the check
   verdicts, scoring model, input schema, identity rules, coverage, profiles,
   and release metadata. Its `chrono` configuration has no ambient clock.
2. **Wasm surface.** The dedicated wasm wrapper exposes the scorer and check
   evaluation surface. The push gate compiles the base and full-check variants
   for `wasm32-unknown-unknown`.
3. **Typed probe seams.** HTTP, DNS, TLS, and browser adapters produce shared
   fact schemas. TLS is split into expiry, hostname, chain, and protocol
   verdicts so each comparison rule has its own identity.
4. **Golden conformance corpus.** Score, HTML-check, probe, and browser fixtures
   run natively and through the wasm entry points. Evaluation time and runtime
   profiles are pinned in the fixtures.
5. **Shared browser payloads.** The desktop webview, CLI headless browser, and
   hosted runner use the same axe and Core Web Vitals assets and fact shapes.
6. **Scan scope and verified-good profiles.** Canonical route scope, revisioned
   profile state, stale-decision rejection, and baseline acceptance semantics
   live in shared engine types and persisted desktop state.
7. **Sitemap and scanner identity.** Discovery and the sitemap check share one
   parser and candidate policy. Every transport uses the generated SiteCMD user
   agent, and product facts bind the public scanner disclosure to the engine.
8. **Capability manifest and release stamps.** The generated manifest records
   every observable check contract and dynamic family. Release workflows
   publish its digest before product artifacts are built. Persisted runs and
   connected envelopes carry the matching release and profile facts.

The hosted service owns transport adapters, scheduling, tenant isolation, and
deployment. A hosted implementation is conformant only when it consumes these
artifacts, passes the same corpus, and refuses an unknown or mismatched manifest
digest. Copying verdict logic into TypeScript is not a supported fallback.

## Decisions taken in this spec

1. **Parity is tiered, not monolithic**: wasm artifact, corpus-pinned
   probe adapters, shared browser payloads with profiled engines, and
   declared measurements.
2. **Comparability is per check, not per release**, via contract
   hashes, per-entry `compare_on` dimensions, the execution profile
   (exact build and colo recorded for forensics, the corpus-certified
   browser compatibility epoch compared), and a registered manifest
   digest resolved against an immutable registry that quarantines
   unknowns. Where one id would need two comparison rules, the id
   splits: the TLS sub-verdicts became their own checks.
3. **The four evidence classes are deterministic, measurement,
   clock-dependent, and external-corpus**, because one "environmental"
   bucket forced wrong causes: time passing is ambient drift, corpus
   movement is a detector update, and availability failure is neither,
   it is a coverage exception.
4. **Measurement checks live outside the lifecycle model entirely.**
   Samples and trend series, yes; groups, occurrence records,
   verified-fixed, regressed, or wake-ups from one noisy sample,
   never.
5. **The fence is end-to-end**: conditional writes on
   `(scan_id, generation, status, erasure_epoch)` after every external
   await at the scanner, and a per-site transactional authority at
   connect comparing `{phase, erasure_epoch, head, scope_revision}` in
   the applying transaction itself, because a service binding is not a
   transaction and tenant truth lives at connect.
6. **The currency predicate is exact**: current head (including the
   no-deployment state) and current scope revision; bare
   event-sequence movement never invalidates an observation.
7. **Scope membership follows the selected routes**: an occurrence becomes
   `out_of_scope` only when none of its authored `scope_routes` remains
   selected. Absence requires every currently in-scope provenance route
   to be covered, and groups with no in-scope records go dormant.
8. **Scope and scan capacity use the same cap**: scope `PUT` refuses an
   excessive route count explicitly. Connect scans the accepted scope
   without allowance-driven truncation. Connect's site state omits
   `scope_over_plan`, `site_allowance_over_plan`, their grace-expiry fields,
   and `scope_overflow_count`. The desktop reads the absent flags as
   `false`, expiry fields as `null`, and overflow count as `0` through
   deserialization defaults; it never sends those fields. Incomplete
   execution still produces coverage exceptions and cannot prove absence.
9. **TLS facts come from a schema with runtime adapters**, because
   Workers cannot open direct TCP to every Cloudflare-fronted target.
   The hosted adapter therefore keeps the Workers-fetch chain verdict
   when its pinned metadata socket is unavailable instead of turning
   the entire certificate family into parity theater.
10. **Coverage passes a challenge gate that cannot lock a site out**:
    deterministic challenge markers except the whole route with a
    named reason; signature mismatch flags, blocks absence resolution
    until the variant is stable or accepted (presence evidence still
    counts), and self-heals per vantage; page signatures live in a
    server-owned route profile as keyed MACs (bare hashes of
    low-entropy content are dictionary-reversible, our own argument
    applied to ourselves), with a vantage dimension because Browser
    Run is honestly identifiable; and a visible reset exists for
    deliberate redesigns.
11. **Browser sessions are per scan with per-page contexts**, and
    admission is leased, sharded, and reconciled: expiring leases
    return crashed capacity, per-account shards avoid the global
    singleton, and platform capacity failures delay protection rather
    than falsifying coverage.
12. **The verified-good baseline distinguishes dismissal from
    acceptance**: dismissing drift silences it, accepting drift
    rebaselines it, with provenance, and only the second changes what
    good means.
13. **Hosted third-party flows are enumerated and disclosed** (DoH,
    OSV, RDAP, with exact transmitted fields), because moving a query
    from the user's machine to the service changes who sends it.
14. **Every egress control ships with a hostile fixture that proves
    it**, with the outcome enforced at each runtime's strongest point
    rather than tied to one runtime's mechanism.
15. **The privacy projection is a named, tested boundary**, Browser
    Run session recording is contractually disabled, and the fence
    makes post-erase resurrection impossible.
16. **One shared user agent, honestly framed**: necessary for parity,
    insufficient for content equivalence, which is the challenge
    gate's job; rendered-page target traffic is disclosed as unsigned
    Worker egress fulfilled into Browser Run.
17. **Provider facts are verification tasks, not assertions.**
