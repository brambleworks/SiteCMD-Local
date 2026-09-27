# Connected service: protocol and state

**Status:** Accepted, 2026-08-05.

Revision history is maintained in Git. Only the current normative text in
this document is part of the implementation contract.

This implementation specification fulfills the protocol portion of the
connected service architecture record in the private SiteCMD-Web repository,
which owns the product direction and privacy semantics. This document owns the
wire contract: issue identity, the sync payload, credentials, the
lifecycle-state protocol, the concurrency invariants, and custody of the
project fingerprint key. It does not own hosted-scan execution, parity, or
the network-security boundary (hosted scanner spec), notification content or
redemption (alert and report delivery spec), or quantities and pricing,
which are set outside this specification.

**Audience:** Engineers implementing the sync client in the desktop and CLI,
and the connected-service workers in SiteCMD-Web.

**After reading:** A reader should be able to implement either side of the
protocol from this document, the referenced source, and the OpenAPI
document this spec obligates, and should be able to answer, for any field
on the wire, why it is there and why it is safe.

## Scope

In scope: the versioned issue-identity contract, canonicalization rules, the
project fingerprint key (owner, storage, distribution, rotation, loss,
concurrency), the wire lifecycle model and its transition authority, the
resource model and full sync payload schema, evidence ordering and
precedence, the credential and capability-token inventory with its
lifecycles, the API surface
and its HTTP conventions, idempotency and revision semantics,
deployment-record ordering, retention, recovery, and deletion.

Out of scope, with owners: how the hosted scanner executes and proves
comparability (hosted scanner spec); what alert emails contain and how the
redemption nonce works (alert and report delivery spec); allowances, caps,
and overage (set outside this specification); the rewrite of the governing documents
(maintained-surface matrix).

Normative artifacts: this document is the semantics authority. The exact
wire shapes live in an OpenAPI document checked into SiteCMD-Web beside the
worker implementation and kept in agreement by contract tests; prose and
schema disagreeing is a build failure, not a judgment call.

## Resource model

The protocol has three distinct resources, and the distinction is
load-bearing: collapsing them is what makes verification tripwires
impossible to express.

1. **Lifecycle groups** are the canonical units the user manages: one per
   canonical check id, carrying lifecycle state. A group survives with
   zero present occurrences; that is not an edge case but the whole point,
   because a `verified_fixed` group is precisely a group whose occurrences
   are gone. Group existence and state are **server-owned**: hosted
   observations create and transition groups too, so no client's picture
   of the group set is complete, and no client may replace it. Clients
   bootstrap groups once at connection and mutate them thereafter;
   omission never means deletion.
2. **Occurrence records** are durable per-occurrence state: where a
   group's findings live or last lived. Each record carries identity,
   severity, provenance, and first and last observation facts, and is
   one of two wire kinds: `established`, carrying a server-derived
   status, or `candidate`, a status-less identity awaiting fresh
   evidence (defined under occurrence status). Records survive absence: a `verified_absent`
   record is exactly the tombstone that says where to look to confirm a
   fix stays fixed, so "the finding is gone" removes an occurrence's
   presence, never its record. Records are maintained by coverage-scoped
   application of snapshots and observations; clients never author their
   status.
3. **Observations** are the append-only record of what was seen: hosted
   scans, synced local and CI snapshots, deployments, verification
   outcomes, and lifecycle transitions. They are server-owned history,
   never client-replaceable.

Site and environment: in v1 a connected site binds exactly one
environment, `production`, with one canonical production URL. The
`environment` discriminator appears on the wire for forward compatibility;
environment resources, preview scanning, and per-environment lifecycle
arrive with a later preview opt-in and are out of scope for v1. The
billable unit is the connected production site.

## Issue identity contract, version 1

Verification requires an identity finer than a strict local baseline. Local
baselines and lifecycle policy intentionally key on canonical check identity,
while persisted scan findings also carry occurrence identity and route
provenance. The wire contract composes these into the two identity levels the
resource model needs.

### Two identity levels

**Canonical identity** is the `canonical_check_id` produced by the shared
resolver and validated to reject path-bearing code ids. Lifecycle groups key on
it. Web and code findings that normalize to the same canonical id form one
cross-source group.

**Occurrence identity** is canonical identity plus a location:

- Web occurrence: `(source: web, check, route)` where `route` is the
  canonical path on the connected environment (see canonicalization).
- Code occurrence: `(source: code, check, location_hash)` where
  `location_hash` is a keyed hash of the producer rule and the relative
  file path (see fingerprints below). Line numbers are excluded from
  identity: they churn under ordinary editing, and an identity that dies
  every time a neighbor line changes cannot support verification. Multiple
  instances of one rule in one file collapse to one occurrence with an
  `instance_count`.

Lifecycle policy attaches at group level; observability is tracked at
occurrence level (see occurrence status below). Both granularities feed
alerting: a group nobody has seen before is a new finding, a new
occurrence inside a known-active group is a newly affected location that
must be recorded rather than silenced by its neighbors, and a
reappearance after verified absence is a regression whether it is the
whole group or one route.

### Canonicalization, version 1

Web route canonicalization, applied identically by the sync client and the
hosted scanner. Identity must never merge resources that can serve
different content, because a successful observation of one would falsely
verify findings belonging to the other.

- The environment pins scheme and host; a route is a path, never a full
  URL.
- Identity uses the final URL after redirects, as observed by the scanner
  that produced the finding.
- Every Web occurrence, desktop and hosted, also carries `scope_route`, the
  canonical authored route whose execution reached that final URL. It is
  provenance, not part of occurrence identity. More than one authored route
  can converge on the same final occurrence; the wire may therefore repeat
  that occurrence with a different `scope_route`, and the service preserves
  the complete set as `scope_routes`. The occurrence is in scope while any
  provenance route is selected, and absence requires coverage of every
  currently in-scope provenance route. A configured `/checkout` that redirects
  to `/checkout/` therefore remains watched without allowing a clean scan of
  one alias to clear a finding another selected alias can still reach. Records
  created before this marker fall back to `route`.
- Repeated snapshot rows with the same `(check, identity)` are normalized
  before lifecycle decisions, persistence, or alerting. Authored routes and
  evidence layers union; severity keeps the worst observed value, confidence
  keeps the strongest, and code `instance_count` keeps the maximum. One
  logical occurrence therefore creates one state write and one alert member,
  independent of wire order.
- Bootstrap tombstones use the same final-route identity but carry their
  authored provenance as a `scope_routes` array on each Web member of
  `last_known_occurrences`. This compact form lets the first server-side
  absence decision use the routes the desktop actually scanned. Older
  tombstones without the array fall back to their identity `route`.
- Trailing slashes are preserved. `/checkout` and `/checkout/` are
  distinct routes unless an observed redirect between them makes the
  final-URL rule collapse them naturally. No unobserved equivalence is
  assumed.
- Dot segments are resolved per RFC 3986. Repeated slashes are preserved.
  A percent-encoded slash (`%2F`) is never decoded. Percent-encoding is
  otherwise normalized: uppercase hex digits, unreserved ASCII characters
  decoded. Bytes outside unreserved ASCII are preserved as sent; no
  Unicode normalization is applied. Path case is preserved.
- Query strings and fragments are stripped from the stored route (a
  privacy-spec obligation), and any occurrence observed on a URL that
  carried a query string is marked `query_dependent: true`.
  Query-dependent occurrences are never comparable for verification: the
  stripped route cannot distinguish `/product?id=1` from `/product?id=2`,
  so observations of such routes record `verification inconclusive`
  rather than pretending one variant proves anything about another. The
  merge is explicit and flagged, never silent.

Code location canonicalization: the repository-relative path with forward
slashes and no leading `./`, exactly as `CodeIssue.relative_path` already
stores it; the producer rule id exactly as `code_producer_rule_id` extracts
it.

The canonicalizer carries its own version (`canonicalizer: 1` in the
payload), and its exact behavior is pinned by shared golden fixtures in
the scanner-parity conformance corpus, so the desktop, the CLI, and the
hosted scanner cannot drift apart silently. Any change to these rules is a
new canonicalizer version and goes through the compatibility gate below.

### Fingerprints on the wire

The privacy rule is precise: **keyed hashing protects private location
material; public location material syncs in the clear.** Verification requires
this distinction for the reasons below.

- **Check ids sync in the clear.** The check corpus is public source, the
  hosted scanner must know which check a baseline entry refers to in order
  to prove "the relevant check executed", and severity and category
  handling need it.
- **Web routes sync as canonical path strings.** The hosted scanner
  observes the same routes on the public site and must compute matching
  identity for every live finding; a hash the server cannot compute would
  make baseline matching impossible, and a hash the server can compute
  protects nothing. Routes of a connected production site are public by
  construction, and the payload already carries them in scan scope. There
  is no privacy gained by hashing them and real capability lost.
- **Code locations sync only as keyed hashes.** File paths and rule
  placements are exactly the low-entropy private material the
  dictionary-reversal warning is about. The hash is
  `HMAC-SHA256(project_fingerprint_key, "sitecmd-fp-v1|code|" + producer_rule + "|" + relative_path)`,
  lowercase hex. The server performs equality matching on these values and
  nothing else; only an install holding the project key can resolve one
  back to a file.

`raw_data`, `detail_json`, evidence, source excerpts, and titles or
descriptions beyond the check's public metadata never appear in identity
and never sync.

### Versioning, compatibility, and identity epochs

Every snapshot and every hosted observation pins:

- `engine_release`: the engine and check-corpus release identifier, stamped on
  every persisted scan run with the capability-manifest digest and execution
  profile.
- `fingerprint_schema`: integer, starts at 1.
- `fingerprint_key_version`: integer per project, starts at 1 (code
  snapshots only).
- `canonicalizer`: integer, starts at 1.
- `crawl_profile`: integer; its contents are owned by the hosted scanner
  spec but the field is part of this envelope.
- `execution_profile`: the observation-level runtime facts comparability
  needs beyond version integers: browser engine (or none), axe version,
  resolver identity, transport adapter, TLS adapter, trust authority,
  scan profile, and
  `layers_run` - which layers the observation executed. That is the
  **only** vantage fact a client may state, because vantage identity
  is clearing authority and clearing authority is never
  client-asserted: `producer_instance` is derived server-side from
  the authenticated credential (the bearer's installation identity,
  the CI token's identity, or the internal hosted path - a submission
  cannot stamp itself as another installation), and locality is
  derived from what the server itself can attest (its own execution
  for hosted transport, the constants otherwise). Wire values for
  either field do not exist; a payload carrying them is rejected as
  an unknown field like any other. Layer
  belongs to each check (its manifest layer), and each result's
  vantage is assembled server-side from the derived instance, the
  check's layer, and the layer's attested locality or constant (the
  hosted scanner spec owns the identity). The profile's
  field set is owned by the hosted scanner spec's capability-manifest
  section; the envelope carries it.
- `manifest_digest`: the digest of the capability manifest the producer
  ran under, so the comparability gate evaluates checks against the
  exact manifest that governed the observation, including each check's
  semantic contract hash (which is what makes cross-release
  comparability decidable per check rather than per release). The
  server accepts only digests present in its manifest registry (hosted
  scanner spec); an unknown digest quarantines the observation as
  incomparable rather than guessing. Browser comparability resolves
  server-side against the **certification registry** (hosted scanner
  spec): producers report `(engine, build, axe_version)` facts, connect
  resolves the compatibility epoch at apply time from immutable
  registry entries (an unknown build resolves to a singleton epoch
  equal to its own identity: comparable with itself, never falsely
  merged, upgradeable when certification lands), and historical
  observations resolve against entries as they existed at production
  time, which immutability makes stable. **Persisted content digests
  are minted at connect ingest**: producers send transient canonical
  projections (the detected library set, the signature source fields),
  connect computes the keyed MACs under its per-site content-MAC key
  and domain strings (`sitecmd-cmac-v1|<site>|<field>`), and the
  projections are never persisted, logged, or traced, which the
  hostile-page fixture asserts. The MAC key never leaves connect, is
  deleted in the erase cascade, and rotates by `key_version`: digests
  compare only within one key version, and rotation retires old
  digests at each series' next refresh rather than pretending
  re-MACing without plaintext were possible. Each snapshot carries the
  execution-profile subset applicable to its source (a code snapshot
  has no browser or resolver profile); exact shapes live in the
  OpenAPI document.

Versions ride on each snapshot, not on the request envelope, because a
desktop's web scan and code scan can run at different times under
different releases. Each snapshot also carries `evaluation_time`: the
clock the engine context evaluated under (the injected time the
clock-dependent checks graded against), skew-validated like
`observed_at` but semantically load-bearing, because cause
classification needs to know what "now" meant to the evidence.

**Measurement-class checks are outside the lifecycle model entirely.**
Checks the capability manifest marks `measurement` (timing values that
vary by vantage) never create groups or occurrence records: they ride
snapshots as measurement samples (`check`, `route`, `value`), the
server stores them as bounded series under event retention, and they
surface as current values and trends, never as tripwires. Bootstrap
group entries naming a measurement-class canonical id are rejected
(`422`), and the payload builder maps the desktop's local
measurement-class findings into samples rather than groups. One noisy
sample must never arm, disarm, or fire the states that matter.

The measurement contract is wire-level, not prose. Snapshots and the
internal hosted commit carry `measurement_samples`
(`{ check, route, value, unit }`, at most 1,000 per snapshot, numeric
values validated against per-unit sanity bounds, oversize batches
`422`); each sample inherits its snapshot's `observed_at` and
execution profile, and the **unit authority is the capability
manifest**: a measurement check's manifest entry declares its unit,
and a sample whose unit disagrees is `422`. The server stores that entry's
semantic `contract` beside the sample; a trend or threshold never compares
rows across contracts or units. Measurement checks create
no lifecycle pair. The version-1 sanity bounds are inclusive
`0..86,400,000` for `ms` and `0..100` for `ratio`; changing either is a
protocol change, not an adapter preference. A present sample is the execution record for that
route; an unavailable metric produces no sample and cannot resolve,
regress, or create any issue state. The read is
`GET /v1/sites/{site}/measurements?check=&route=&vantage=&from=&to=&cursor=&limit=`:
`from`/`to` are epoch milliseconds bounded by retention, `vantage` is
an explicit filter and series are **always grouped per
`(check, route, contract, unit, vantage)`**, never blended across semantic
revisions, units, or vantages, and items
are raw samples
`{ check, contract, route, vantage, observed_at, value, unit }` in the standard
paginated envelope. Current value is the latest sample of a series;
trend windows are 7-day and 30-day medians computed at read time,
returned alongside the series, never stored. Measurement series have
their own retention row (90 days), ride export, and are erased with
the site. Each item also returns an opaque `vantage_id` for the query
filter and a canonical `series_id` for threshold settings; the series id
encodes the manifest contract, unit, and full server-derived vantage, so an
old threshold row that named only a check and route remains pinned to the
explicit legacy contract and lane rather than starting to consume newly
attributed samples.

Two observations are comparable only when the scanner-parity contract in
the RFC says so for their pinned versions. The server never guesses across
versions: a baseline synced under `fingerprint_schema: 1` is never matched
against an observation computed under a different schema, and an
incompatible pair records `verification inconclusive`, never
`verified fixed`.

**Identity epochs.** Because occurrence records are durable, a
`fingerprint_schema` or `canonicalizer` bump must not leave incompatible
tombstones alive forever. The pair `(fingerprint_schema, canonicalizer)`
is the record's identity epoch, and epoch migration mirrors key rotation:

- Records from an older epoch are never matched against new-epoch
  observations (comparability already forbids it); while they remain,
  verification against them records `verification inconclusive`, never a
  false match.
- A complete-coverage snapshot under the new epoch re-establishes present
  occurrences with new-epoch identity and retires the covered scope's
  old-epoch records, tombstones included.
- Groups carry across epochs untouched, because canonical check ids are
  epoch-stable. A `verified_fixed` group whose tombstones were retired
  keeps its state; its tripwire operates at group level (any new-epoch
  occurrence under its canonical id is a regression) until new-epoch
  occurrence identity accrues. Migration therefore never permanently
  blocks verification and never manufactures false new-occurrence alerts:
  a new-epoch occurrence in an active group is ordinary evidence, and in
  a verified group it is a real regression, because the finding is
  actually present.

## The project fingerprint key

- **Owner:** the project. The key is generated by the desktop when the site
  is first connected: 32 random bytes, never derived from anything.
- **Storage:** the OS keychain, through the existing app-secrets layer
  (`apps/desktop/src-tauri/src/keyring/app_secrets.rs`), alongside the
  license key and catalog token. Never in SQLite, never in config files
  inside the repository, never in the payload.
- **The server never holds it.** Nothing in the protocol transmits the key
  or anything derived from it except the HMAC outputs and a one-way key
  commitment (below). This is what makes the keyed-hash privacy claim
  structural rather than procedural: SiteCMD cannot dictionary-reverse
  code locations because it does not have the key, not because it
  promises not to try.
- **Key commitment.** Each key version has a commitment
  `SHA-256("sitecmd-fpk-commit|" + key)`, registered with the server when
  the version is claimed. The key is 32 random bytes, so the commitment
  reveals nothing, but it lets the server detect a client hashing under
  the wrong key for a claimed version (`409 key_commitment_mismatch`)
  instead of silently corrupting identity matching. Code snapshots carry
  the commitment of the key they used. **Version 1 is claimed at site
  creation**: the desktop generates the key when it connects the site,
  and `POST /v1/sites` carries the version-1 commitment, so the
  commitment exists before any snapshot and independently of whether the
  bootstrap contains code. There is no unclaimed window in which a
  web-only bootstrap would let the first later CI or desktop submission
  establish a conflicting key; a version-1 submission with a different
  commitment is `409 key_commitment_mismatch` like any other version.
- **Distribution to CI:** the CI door needs the key to compute matching
  code fingerprints inside the checkout. It travels as one secret
  alongside the CI token, pasted into the repository's secret store once.
- **Distribution to a second desktop:** an explicit local export and
  import of the site connection. The export file is encrypted and
  authenticated under a user-supplied passphrase, contains the site
  connection metadata and the fingerprint key, and **never contains any
  credential**: installation tokens are per-install and issued by the
  service, so the export authorizes nothing by itself. There is no cloud
  channel for the key, by construction, because any cloud channel would
  put it on SiteCMD infrastructure.
- **Installation assignment is separate from key transfer.** A second
  installation authenticates with its own installation token (issued
  through the activation exchange) and must then be assigned to the site
  by an already-assigned installation
  (`POST /v1/sites/{site}/installations`). Importing the key file grants
  the ability to compute and resolve fingerprints; it grants no server
  authorization, and assignment grants no key. Both are required, and the
  two travel by different roads on purpose.
- **Rotation, including concurrent rotation.** Rotation is a
  server-coordinated epoch so two installations cannot mint different
  keys under the same version number:
  1. The initiating desktop generates a candidate key locally and claims
     the next version:
     `POST /v1/sites/{site}/key-rotations { "commitment": "…" }`. The
     server assigns `fingerprint_key_version + 1` to exactly one claim
     (atomic insert). While a claim is pending, another claim answers
     `409 rotation_in_progress` with the pending version and commitment.
  2. A pending claim ends one of three ways: **completion**, **abort**
     (`POST /v1/sites/{site}/key-rotations/abort`, any assigned
     installation, for the machine-lost case), or **expiry** after 72
     hours. After abort or expiry a new claim may be made; the aborted
     version number is burned, never reused. This replaces any looser
     "supersede the winner" notion: exactly one pending claim exists at a
     time, and only abort or expiry clears it.
  3. **Completion requires a code snapshot with complete project
     coverage** (`kind: "project"`, `complete: true`, no exceptions)
     under the new version and commitment. A partial snapshot
     (`rule_set` coverage, or any exceptions) advances nothing and can
     never complete a rotation: completion atomically switches the
     current version and retires every old-version occurrence record and
     correlation pair, and retiring state that a partial snapshot did not
     re-establish would erase it. Until completion, the previous version
     remains current for enforcement.
  4. The rotation response and `GET /v1/sites/{site}/state` report the
     migration status: current version, pending claim if any, the key
     version and commitment of the most recent CI submission, and which
     assigned installations have submitted under the current version. A
     stale CI secret or an unmigrated second desktop is visible, not
     silent.
  5. After completion, submissions carrying a `fingerprint_key_version`
     below current are rejected with `409 stale_key_version`, so a
     not-yet-updated CI secret fails visibly in the user's own pipeline.
- **Loss:** the key exists only in user custody, so losing every copy
  (every keychain entry, every export, the CI secret) is unrecoverable by
  design. Recovery is rotation: claim a new epoch, resync with complete
  coverage, reprovision CI. Code occurrence records and correlation pairs
  recorded under the lost version become unresolvable history and are
  retired at completion. Web identity, group lifecycle, deployments, and
  alert history are unkeyed and survive intact.

## Lifecycle on the wire

### Group state classes

Lifecycle lives on groups, never on occurrences. The desktop's six-state
vocabulary (`new`, `snoozed`, `ignored`, `blocked`, `verified`,
`regressed` in `project_issue_states`) maps onto five wire states:

| Wire state       | Local states                    | Server semantics                                   |
| ---------------- | ------------------------------- | -------------------------------------------------- |
| `active`         | `new`                           | Known issue; stays silent                          |
| `dismissed`      | `snoozed`, `ignored`, `blocked` | Stays silent; stored policy governs re-observation |
| `claimed_fixed`  | `verified` (user claim)         | User says fixed; awaiting verification             |
| `verified_fixed` | `verified` (scan-verified)      | Regression tripwire armed                          |
| `regressed`      | `regressed`                     | Active again; carries `regression_of` facts        |

`dismissed` groups carry an explicit policy object, because guardian
behavior must not depend on whether a laptop is awake:

- `{ "kind": "snoozed", "until": <ms> }` - the server evaluates expiry at
  read time, mirroring the desktop's `IssueStatus::effective`: once
  `until` passes, the group is effectively `active`. No stored transition
  and no laptop is required. Expiry does not alert (the issue is known);
  it re-enters active views and digests.
- `{ "kind": "ignored", "reopen_on_reobservation": true }` - the
  desktop's local rule that ignore is temporary
  (`reconcile_reobserved_lifecycle` in `db/scan_run_projection.rs`),
  encoded as user policy. Either a synced local scan or a hosted
  observation may execute it: re-observation transitions the group to
  `active`, and the recorded event attributes the transition to the
  stored policy, not to the scanner. Reopening this way does not alert.
- `{ "kind": "blocked", "reason"? }` - durable. Nothing but an explicit
  user mutation changes it. This is the dismissal that means "stop".

`verified_fixed` groups carry
`verified_by: "local_scan" | "hosted_scan" | "ci_scan"`,
`verified_at` (a display timestamp), and **`verified_at_sequence`**
(the event sequence of the verification - the ordering authority;
every `_at_sequence` field in this spec is an event sequence and
every bare `_at` is display metadata, stated once here). `ci_scan`
exists because exact CI evidence governs code
absence while its deployment is current, and the source of a
verification is a fact the timeline states. **A user claim can never produce `verified_fixed`, and
neither can a bootstrap assertion.** The desktop's `mark_issue_fixed`
writes local `verified` on the user's word; on the wire that is
`claimed_fixed`. Only server-side derivation from comparable observation
evidence (the rules below) produces `verified_fixed`, and only
`verified_fixed` receives the product's verified language. The desktop
records which of its own paths wrote `verified` (implementation contract item
3 below), so
the payload builder reads the distinction rather than guessing it.

### Occurrence status

Policy is group-level; observability is occurrence-level, because a group
that stays `active` on one route must not silence what happens on
another. Occurrence records are durable, and each established record
carries a server-derived status (candidates, defined below, carry
none):

- `known` - at least one standing evidence entry (below).
  Its first appearance is recorded as a `new_occurrence` event: a newly
  affected route or location inside an existing group is recordable
  evidence, not noise to be swallowed by the group already being active.
- `verified_absent` - every evidence entry resolved. The record
  persists as the
  tombstone that verification and regression detection read; absence
  deletes presence, never the record.
- `regressed` - previously `verified_absent` (or part of a
  `verified_fixed` group) and now present again.

**The evidence record, exact.** Status is derived from per-vantage
evidence entries, stored on the occurrence record and served in reads,
bootstrap responses, export, and recovery:

```json
"last_verified_absent_at_sequence": 5388,
"regressed_basis": null,
"evidence": [
  {
    "kind": "entry",
    "vantage": { "producer_instance": "hosted", "layer": "browser", "locality": "unattested" },
    "standing": false,
    "established_at_sequence": 4120,
    "establishing_context": {
      "evaluation_time": 1754780390000,
      "input_mac": "7c19…",
      "mac_key_version": 1,
      "projection_version": 1
    },
    "resolved_at_sequence": 5388,
    "resolved_by": "same_vantage"
  },
  {
    "kind": "entry",
    "vantage": { "producer_instance": "ins_2b41…", "layer": "transport", "locality": "local" },
    "standing": true,
    "established_at_sequence": 5901,
    "establishing_context": {
      "evaluation_time": 1754781000000,
      "input_mac": "9d02…",
      "mac_key_version": 1,
      "projection_version": 1
    }
  }
]
```

`vantage` is the hosted scanner spec's structured identity
`{ producer_instance, layer, locality }`, where `layer` is **the
check's
manifest layer, never an observation label** - a full scan carries
both transport and browser results, so the observation declares
only `layers_run` and each
occurrence's entry
takes its layer from the check that produced it; nothing is
mislabeled by the scan profile. `producer_instance` is a **stable
instance identity, derived server-side from the authenticated
credential and never read from the wire** - clearing authority
cannot be a client claim, or installation B would stamp a clean
snapshot as installation A and clear A's evidence: the installation
id for desktop (each
installation is its own vantage - one installation's clean scan
must never clear evidence another installation established from
somewhere else on earth), `hosted` for the internal hosted path,
the CI
token's stable identity for CI. `locality` exists only where a
documented platform fact attests it at the step's own execution
(the hosted scanner spec's derivation; in practice hosted lanes are
`unattested` in v1, since alarm- and RPC-driven steps have no
inbound request fact and the Browser Run session API exposes no
location; the constant
`local` for desktop - honest
unlocalized lanes rather than a fabricated colo). The clearing rule
is one sentence: **full key equality clears with same-vantage
authority; everything else clears only through per-check input-MAC
equivalence** - there are no epochs, no lane transitions, and no
signature-based adoption of evidence, because route signatures omit
most check inputs and moving evidence on their equality would make
an incomplete signature an absence authority. An entry whose vantage
never recurs stands
with the locality-variant condition named, visibly, unless its
check's inputs prove equivalence, because check code is
locality-independent but the artifacts it evaluates are not (one
locality can be served a missing CSP
while another is served a present one, and the route signatures,
which omit headers, would never notice). `resolved_by` is
`same_vantage | input_equivalence`; sequences
reference the append-only event stream. The **establishing context**
pins what was actually seen, including the **composite `input_mac`
itself** - stored on the entry, immutable, because the route
profile's copy is refreshed by later observations and a comparison
"against the establishing value" that resolves through a mutable
record is a comparison against whatever was seen last, which is
exactly the bug - plus the observation's `evaluation_time` and the
MAC key and projection versions,
because clock-dependent checks need the
establishment time to reject temporally unsound clears (the hosted
scanner spec restricts equivalence to deterministic checks for
exactly that reason). `input_mac` is present only for checks
declaring `equivalence_inputs`; entries for other checks carry the
context without it and can never clear by equivalence. Presence
evidence from any
comparable producer adds or refreshes its vantage's entry, and
**every accepted sighting replaces the context, standing repeats
included**: re-establishment of a resolved entry sets `standing`
back to true with a fresh `established_at_sequence` and context,
clearing the `resolved_*` fields - and a repeat sighting on an
entry that already stands is a **new evidence generation in place**,
atomically replacing `established_at_sequence` and
`establishing_context` with the new observation's, the prior
generation surviving in the append-only observation history. A
repeat that merely refreshed a timestamp would re-open for entries
exactly the hole the aggregate rule closes for folds: vantage V
establishes under context A, the page changes and V reports the
still-present finding under context B, and a clean observation
whose inputs MAC to A cross-resolves V's entry while V's newest
sighting - made under B - still stands; equivalence must always
compare against what the vantage saw **last**, which is why the
current generation's context is what the entry stores (immutable
within the generation - replaced only by an accepted sighting,
never refreshed from any other source). The scanner spec's
conformance fixtures pin the sequence
(**A-then-B-then-clean-A resolves nothing**). The record-level
`last_verified_absent_at_sequence` (set whenever all entries stand
resolved) is the durable history that survives re-establishment. Resolution
follows the per-entry governance above. Status derivation, in
precedence order: `regressed` when either **regression basis**
holds - the record's own tombstone
(`last_verified_absent_at_sequence` set and an entry standing with a
greater `established_at_sequence`) or the **enclosing group**
(the group stood `verified_fixed` and this record's first
establishment is after the group's `verified_at_sequence` - which is
how a brand-new route under a verified group derives `regressed`
despite having no prior record of its own). The regression is
pinned, not just labeled: the record stores
`regressed_basis: "occurrence_tombstone" | "group_verification"`,
`regressed_at_sequence` (the establishing event that constituted the
regression), and `regression_of_sequence` (the exact verification
event it regressed from - the record's
`last_verified_absent_at_sequence` or the group's
`verified_at_sequence` per the basis), so "regressed from the fix
verified at X" is a stored fact, not a reconstruction. Within one
observation's apply, every occurrence is evaluated against the
**same pre-apply group state** (the transaction reads the group
once), so an observation that both regresses one route and
establishes another cannot see two different group histories.
Otherwise `known` while
any entry stands; otherwise `verified_absent` when at least one entry
exists and none stands; the in-between is served as
`verification_state: "partial"` with the standing vantages named, so
"absent at hosted, unresolved locally" is wire state, not prose. Code
occurrences have a single-lane evidence list under the same schema
(the fixed logical vantage
`{ producer_instance: "repository", layer: "code", locality: "repository" }`,
**one lane per site, not per machine**: fingerprint-key possession
and the identity contract prove **project and path identity** -
every code producer speaks about the same logical location space -
which is what justifies a single shared lane, and per-instance code
lanes would model a distinction without a difference and strand
evidence forever when the establishing machine is lost. Key
possession proves nothing about checkout state, so whether any
submission's evidence **governs** inside the lane is decided by
`code_basis` or attested CI provenance under the clearing rules
below, never by lane membership; the submitting producer is
recorded on the entry as metadata);
bootstrap seeds desktop-vantage entries from the
local scan history - **with `provenance: "seeded"`, a distinct
wire fact with a weaker standing than an observed entry**, because
the alternative is a product that cannot deliver its own loop:
every connected site starts with a seeded desktop entry on every
imported occurrence, and if only a fresh local scan could resolve
those, the RFC's flagship moment - fix, deploy, hosted rescan
marks it verified fixed - could never fire, every verification
would land `inconclusive (content variant)` with "run a local
scan" as the next step, and the laptop would be back in the loop
the service exists to remove; worse, `verified_fixed` is what arms
the regression tripwire, so the core regression-alert class would
never fire either. A **governing hosted observation covering the
pair may therefore resolve a seeded entry**
(`resolved_by: "seeded_provenance"`), and the per-vantage
unclearable standing is reserved for entries established by a
**post-connection desktop observation** (`provenance:
"observed"`) - which is where the CDN-variant threat actually
lives: a seeded entry is a historical pre-connection sighting, and
a fresh deploy-anchored production observation is exactly the
evidence the import lacked, while a post-connection desktop
sighting is a current claim about what this vantage sees that no
other vantage can honestly clear. Presence re-established at the
desktop vantage after connection converts the entry to
`observed` with full standing. The residual is stated: a CDN
serving scanner-specific content from day one, never locally
re-scanned after connection, could have its seeded entry cleared
by a clean hosted run - bounded by the fact that any later local
scan re-establishes an observed entry and re-arms the tripwire,
and accepted because a loop that never verifies protects nobody. Entries compact with their record, ride export
inside it, and are erased with it. **The entry list has its own
bound**, because the record cap counts records, not nested entries,
and device churn would otherwise grow one standing list without
limit: at most **32 tracked entries** per record. Admission when
full: resolved entries retire oldest-first to make room; when all 32
stand, presence from a further new vantage still counts as presence
(status stays `known` - presence is never dropped) but folds into
the record's single **aggregate entry** - a discriminated wire
variant, not prose: every item in `evidence` is
`kind: "entry"` (the shape above) or `kind: "aggregate"`, at most
one aggregate per record, occupying its own slot **outside** the 32
(the list is at most 32 entries plus the aggregate), identical in
reads, export, and recovery. The aggregate is a **complete union of
exactly two variants**, and every serialization is one of them -
standing:
`{ kind: "aggregate", standing: true, generation, vantage_count,
first_folded_at_sequence, last_folded_at_sequence,
shared_context | null, saturated }`, or resolved:
`{ kind: "aggregate", standing: false, generation, vantage_count,
first_folded_at_sequence, last_folded_at_sequence,
shared_context, saturated, resolved_at_sequence,
resolved_by: "input_equivalence" }` (the resolved variant keeps the
shared MAC it resolved against; a shape that hardcodes
`standing: true` while the text promises a persisted
`standing: false` is two implementations waiting to disagree, so
both variants are declared here). `vantage_count` counts
**distinct vantages**, deduplicated against a stored set of folded
vantage-key hashes (bounded at 96): a folded vantage reporting again
never increments the count, but its context is **still compared** -
the repeat refreshes `last_folded_at_sequence`, and a
`(input_mac, key version, projection version)` differing from the
stored `shared_context` clears it (null), permanently, exactly as a
differing new member would. "Refreshes the timestamp and nothing
else" would be a hole: a vantage folded under context A and
reporting again under context B leaves an aggregate a clean
A-observation can resolve wholesale while B's sighting stands
inside it. Past 96 distinct keys the set
saturates, `saturated: true`, the count freezes, and the aggregate
is permanently standing regardless of context. `shared_context`
exists only while every folded member carried the identical
`(input_mac, key version, projection
version)` - the moment a folded member differs, it is cleared
(null), permanently, because keeping "the latest"
MAC would let a clean observation matching vantage Y's inputs clear
an aggregate that still contains vantage X's unverified different
ones. Liveness: a homogeneous aggregate resolves **wholesale** by
input equivalence against
its shared MAC (identical inputs everywhere folded means one
comparison answers for all), and resolution moves it to the resolved
variant above - persisted in reads, export, and recovery alike
(never an atomic delete, which
would erase the history the tombstone model keeps everywhere else),
compacting with its record like any resolved evidence; a
heterogeneous or saturated one never
clears by machine, only by the group-level human paths -
conservative in exactly one direction: an overflowing
record can fail to verify, it can never falsely verify. **Re-entry
is defined, not assumed**: when overflow presence arrives while the
record's aggregate sits resolved (the 32 entry slots still full),
the single aggregate slot **starts a fresh generation in place** -
`generation` increments, `standing` returns to true, the resolution
fields clear, the folded-vantage hash set and `vantage_count` reset,
`first_folded_at_sequence` restarts at the arriving observation, and
`shared_context` is computed from the fresh members alone (never
inherited from the resolved generation, whose members the new
presence may not share). The retiring generation's resolution is
recorded as an `aggregate_generation_reset` event in the append-only
stream before the reset, so the history the single slot cannot hold
survives where history lives; the monotonic `generation` number is
the wire fact that tells a reader "resolved and refilled" from
"never resolved". A resolved aggregate is never reactivated by
mutation of its resolution fields alone, and there is no state in
which two aggregates exist.

**Check-input MACs**, the storage behind input equivalence, live in
the route-profile resource beside the signatures: per
`(route, check, vantage)`, the keyed MAC of the check's canonical
equivalence inputs, with `mac_key_version`, `projection_version`, and
`observed_at`, refreshed by each qualifying observation at ingest.
Comparisons are valid only within the same key and projection
versions; MAC-key rotation starts the comparison history over
(equivalence is re-demonstrated, never carried across keys). They
follow the route profile's lifecycle: compacted with routes, exported
as route-profile records, erased with the site. **Profile cells are
bounded per pair**, because installation and colo churn would
otherwise grow an active route's storage without limit while the
evidence bound looks the other way: at most **8 unpinned vantage
cells per
`(route, check)`** for signatures and input MACs alike, retired
least-recently-observed-first and after 90 days unobserved - with
one exemption that closes a bypass: **cells referenced by standing
evidence are pinned** and never retire, because evicting the
signature and letting the vantage return "like a first scan" would
skip the document-change gate exactly where a standing entry makes
it load-bearing (pinned cells sit outside the 8; their count is
bounded by the evidence-entry bound). And belt over braces: where a
standing entry's vantage has no stored signature anyway (pre-signature
evidence, key rotation), the hosted scanner spec's **`profile_cold`**
rule applies - same-vantage absence resolution waits for the
signature stability window to rebuild. Retirement of unpinned cells
stays safe by construction: evidence entries
carry their own immutable establishing MACs, so retiring a profile
cell never breaks an existing comparison - it only means a future
equivalence claim waits for a fresh observation of that vantage,
which is the conservative direction.

Records additionally carry one flag, **`pending_fresh_evidence`**: set
when a shielded (historical) presence sighting contradicts the record's
current status, recorded alongside a `stale_presence_recorded` event and
deduplicated per occurrence (setting it again is idempotent). The flag
is a durable record field, not a status: the record's status is
untouched until real evidence arrives. It is served in occurrence reads,
surfaces in the desktop and in CI gate output, participates in recovery
like every other record field, and clears when the next governing
observation covering the pair applies, whichever way that observation
goes.

Two boundary rules keep the flag coherent. A historical sighting can
reference an identity with no existing record; asserting `known` from
stale evidence would be a false presence claim, so such a sighting
creates a **candidate record**: identity plus the flag and no
established status, excluded from group-verification math and from
alerting, resolved by the next governing observation (which either
establishes it as a real occurrence or confirms absence and removes
it). On the wire this is a discriminated kind: every occurrence record
is `kind: "established"`, with status required, or `kind: "candidate"`,
with no status field at all, in reads, export, and recovery alike.
Confirmation applies the ordinary rules as if the confirming observation
had first observed the occurrence: establishment emits `new_occurrence`,
or the regression events where the group stands `verified_fixed`,
because the fresh evidence is what asserts presence, never the stale
sighting that raised the question. And flagged records are **exempt from age-based compaction** while
the flag stands: retiring an unanswered request for fresh eyes would
silently discard the question. The flag does not stand forever: if no
governing observation covers the pair within 90 days, an
`evidence_request_expired` event records the outcome explicitly, the
flag clears, and unestablished candidates are removed.

Group verification is derived, never asserted, and **never vacuous**: a
group reaches `verified_fixed` only when it has at least one established
occurrence record, every established record is `verified_absent`, and no
new occurrence has appeared; candidates count neither for nor against. A `claimed_fixed` group with no known occurrence identity has
nothing to check absence against, so it records
`verification inconclusive` and stays `claimed_fixed`; it can never slide
into `verified_fixed` on the strength of an empty set. This is why
bootstrap carries last-known occurrence identities for claimed and
verified groups (below). A group regresses when any of its records does.

Evidence requirements are asymmetric at this level too: **absence** needs
coverage (the pair covered and unexcepted in a comparable observation),
but **presence** needs only valid execution: a finding emitted by a
successfully executed check on a route proves the finding is there even
if unrelated routes in the same scan failed. Requiring complete coverage
to believe a sighting would mean a scan that saw the bug with its own
eyes could not report it.

Alertability, restated in these terms: the state layer records four
alert-relevant event classes: new group, new occurrence within an
existing group, regression (group-level or of a `verified_absent`
occurrence), and verification outcomes. Which of them wakes a human,
which land in digests, and how severity weighs in is the wake-up policy,
owned by the alert and report delivery spec; the state contract's job is
to make sure the distinction survives to that layer. `active`,
`dismissed`, and `claimed_fixed` states as such never wake anyone.

### Transition authority

- **User mutations** (desktop, authenticated by installation token) may
  perform any group transition except into `verified_fixed`; the user's
  terminal claim is `claimed_fixed`. Reopening (`dismissed` to `active`)
  is an explicit transition, never an inferred one. Every mutation is
  revision-guarded (below).
- **Observations** (hosted scans, and synced local or CI snapshots) may:
  - create `active` groups for previously unknown canonical ids, and
    record `new_occurrence` events within known groups;
  - move `verified_fixed` to `regressed` on comparable presence evidence
    for any of its occurrences (valid execution of that pair; subject to
    the staleness shield below), and this is the alertable regression;
    mark individual occurrence records `regressed` the same way;
  - mark occurrence records `verified_absent`, and derive
    `verified_fixed` for `active`, `regressed`, or `claimed_fixed`
    groups, only on governing, covering, comparable absence evidence per
    the derived-verification rule above;
  - move `claimed_fixed` back to `active` on comparable presence
    evidence (valid execution of the pair; staleness shield applies),
    recording a `claim_not_confirmed` verification outcome. This
    surfaces in the fix loop and digests, never as a wake-up alert: the
    issue was never verified, so its persistence is not a regression;
  - execute a stored dismissal policy (`snoozed` expiry at read time,
    `ignored` reopen on re-observation), with the event attributed to the
    policy;
  - record the re-observation of a `blocked` group as an event, which
    never changes state and never alerts.
- **A scan can never override a user decision.** It may execute a policy
  the user stored, verify or fail a claim the user made, and regress a
  fix the service itself verified; it may never turn `blocked` into
  anything, un-snooze early, or invent a dismissal.
- Conflicting truths resolve by the revision protocol and the evidence
  rules, never by client timestamps. There is no last-write-wins anywhere
  in the contract.

## The sync surface

Sync is partitioned by submitter and by source, and every submission
names exactly what its coverage proves. Nothing can delete state it does
not own, and absence is meaningful only where coverage proves
observation, which is already the local model's rule ("only successful
coverage may resolve absent findings", `ScanCoverageManifest` in
`core/normalized_scan.rs`).

- **Desktop submission** (`POST /v1/sites/{site}/sync/desktop`,
  installation token): one request carrying one or both source-specific
  snapshots, `web` and `code`, each from a successfully completed scan,
  each with its own `observed_at`, `based_on_event_sequence`, `versions`,
  coverage, and occurrences. A snapshot for a scan that did not complete
  successfully is rejected (`422 incomplete_snapshot`); the desktop
  simply does not sync failed scans.
- **CI submission** (`POST /v1/sites/{site}/sync/ci`, CI token): a code
  snapshot computed inside the checkout, with embedded deployment facts.
  The submission atomically creates or matches the deployment record by
  provider deployment identity (retry-safe by construction; differing
  immutable facts are `409 deployment_conflict`), and the snapshot is
  bound to that record and therefore to an exact commit SHA. It cannot
  touch groups, web state, or the desktop's partitions.
  `POST /v1/sites/{site}/deployments` remains for deploy notification
  without a code scan.
- **Hosted observations** are server-owned. No client writes them.

### Evidence ordering

Client wall clocks are never a concurrency authority, and ephemeral
runners never carry counters they cannot keep:

1. **Stateful desktop producers order themselves.** Each installation
   has a `submission_sequence`, keyed to its stable installation
   identity rather than its current credential, so token rotation
   continues the counter instead of resetting the namespace: a
   client-persisted monotonic counter, strictly increasing across
   submissions, surviving restarts.
   The server rejects a non-increasing sequence with
   `409 stale_submission`. A desktop that scans offline submits its
   backlog in scan order when it reconnects. Idempotency replay is
   evaluated **before** sequence validation (and before every other
   guard), so a retried request returns its original result instead of
   tripping the sequence check it already consumed.
2. **CI runners carry no sequence.** CI jobs are concurrent and
   disposable, with no shared persistent counter to increment, so a CI
   submission never has a `submission_sequence`. CI ordering comes from
   the deployment identity it embeds: provider ordering facts order the
   deployments, create-or-match deduplicates the record, and the
   `Idempotency-Key` header deduplicates the submission. Two jobs for the
   same deployment converge; jobs for different deployments order by the
   deployment-ordering rules.
3. **Across producers**, server receipt order (`event_sequence`) is the
   only cross-producer order. `observed_at` is display metadata:
   validated against skew (future-dated beyond 10 minutes is `422`, the
   telemetry worker's posture), recorded, shown, but never used to
   resolve conflicts.
4. **Desktop snapshots declare their basis.** Each desktop snapshot
   carries `based_on_event_sequence`: the site event sequence the
   desktop had last pulled when the scan ran. It is the staleness shield
   below, and it is a fact about what the producer knew, not a clock.
   CI snapshots carry none; their basis is their deployment, and the
   shield reads deployment ordering for them instead (below). Hosted
   observations declare a basis too: each captures, at scan start, the
   deployment head identity (or the explicit no-deployment state), the
   `scope_revision`, and the `event_sequence`. The currency predicate
   is exact: an observation is current-basis iff its captured head
   equals the site's current head at submission (two no-deployment
   states match) **and** its captured `scope_revision` is still
   current. A head change or a scope change mid-flight makes the whole
   observation history-only with a replacement scan scheduled;
   movement of `event_sequence` alone (alerts, mutations, other
   observations) never invalidates it. The hosted scanner spec owns
   the mechanics. At bootstrap the watermark is
   the genesis value `0`: bootstrap precedes every site event (scans and
   hooks are disabled until it commits), so nothing exists for the
   shield to engage against. Every post-bootstrap snapshot carries a
   genuinely pulled watermark, and a backlog scan performed before
   connection submits with `0`, where the shield governs it like any
   other historical evidence.

### Evidence precedence

Presence and absence are asymmetric, which is what keeps stale evidence
from ruling from the grave:

- **Presence is accepted from any comparable producer.** A finding
  emitted by a successfully executed check on a route establishes
  presence (`known`, or `regressed` where the record was verified
  absent), in receipt order, regardless of how the rest of the scan
  fared. Discovery is never blocked by precedence, and older absence
  evidence never suppresses newer presence evidence: if the finding
  fired, it is there, whoever saw it.
- **The staleness shield.** Presence evidence whose
  `based_on_event_sequence` is older than the event sequence of the
  governing absence evidence for that pair is **historical**: a laptop
  that scanned while offline, before the fix deployed, must not fake a
  regression when its upload lands after the hosted scanner verified the
  fix. The stale sighting is recorded as an observation, changes no
  current status, emits no regression, and instead triggers an
  authoritative rescan of the affected pairs (scheduling mechanics are
  the hosted scanner spec's), so a real regression the stale evidence
  happened to see is confirmed by fresh eyes rather than asserted by old
  ones. Presence evidence with no newer governing absence applies
  normally.

  The shield covers CI through deployment currency, and it is a
  positive requirement, not merely a staleness test: **CI presence
  evidence mutates current state only when its deployment is already
  current or atomically becomes current** through its own qualifying
  ordering fact. Evidence from a deployment that is superseded, or
  whose ordering is `creation_sequence` or `unknown`, is recorded as
  historical: a delayed D1 result must not regress what the current D2
  verified, and "cannot prove D1 is old" is not proof that it is
  current. On sites whose deployments carry no ordering facts at all,
  CI submissions are visible history rather than state authority - and
  no producer inherits the authority CI lacks: the desktop's
  `code_basis` is a predicate against the ordered deployment head, so
  on exactly these sites it degrades to `unknown` (the
  no-deployment-basis rule below) and code absence stays inconclusive
  on the wire until the first ordered deployment lands. Unordered
  evidence has no governing reading, from any producer.
  Confirmation differs by source: stale
  web sightings trigger a hosted rescan, but the hosted scanner cannot
  rescan private code, so stale code sightings set the
  `pending_fresh_evidence` flag defined under occurrence status, and
  the next governing code observation (a CI run at the then-current
  deployment, or a fresh desktop snapshot) resolves them.

- **Absence requires governing evidence, and governance is evaluated
  per evidence entry, not per occurrence.** An observation resolves an
  evidence entry only when all three hold: it **governs that entry**,
  its coverage covers the pair unexcepted, and it is comparable. For
  web occurrences, governance is vantage-local: an observation governs
  exactly the entries of its own vantage family - hosted observations
  govern hosted entries, desktop web snapshots govern desktop entries
  **with provenance `observed`, always**, including where hosted also
  covers the route (seeded entries carry the one exception defined at
  bootstrap: a governing hosted observation may resolve them), because
  an observed desktop entry is the desktop vantage's own sighting and
  nothing else can honestly speak to it. Cross-vantage conflict is
  handled by the entries themselves, not by precedence. For code
  occurrences there is one evidence lane, but the lane is not a blank
  check -
  **clearing inside it is provenance-gated**, because fingerprint-key
  possession proves project and path identity, never checkout state,
  and a shared lane without a provenance gate would let a clean scan
  of a stale checkout on one machine clear a dirty-branch finding
  another machine established. A CI submission with exact provenance
  governs **only while its deployment is current** (supersession ends
  its authority, so pre-deploy evidence can never keep declaring
  post-deploy code clean); a desktop code snapshot resolves absence
  only where no current exact CI covers the pair **and its
  snapshot-level `code_basis` vouches for that pair**. The basis
  exists because per-occurrence provenance cannot gate clearing - a
  clean snapshot has no occurrence for the finding it clears, so the
  authority fact must ride the snapshot itself:
  `code_basis: { commit_sha, kind, unvouched: [...] }`, where `commit_sha`
  is nullable only when no Git checkout identity exists. A non-Git code scan
  still sends its findings with `kind: unknown` and `commit_sha: null`; it
  informs presence and clears nothing instead of dropping the code snapshot.
  `kind` is `exact_checkout` (the working tree is the current deployment's
  SHA, clean - named distinctly from the CI door's OIDC-attested
  `exact`, because this one is the desktop's own claim at desktop
  trust level), `compatible` (the
  known-ancestor-with-unchanged-files predicate
  the desktop computes with git - machine-independent, so
  installation B's compatible snapshot soundly clears what
  installation A established), `stale`, or `unknown` - and
  `unvouched` lists the `(check, location_hash)` pairs the basis
  does **not** cover, because compatibility is per path: one
  snapshot can vouch for findings in untouched files while its
  branch has diverged exactly where another finding lives. Absence
  resolves for a code pair only under a `exact_checkout` or
  `compatible` basis with the pair not in `unvouched`; `stale` and
  `unknown` bases inform presence and never resolve absence. Both
  qualifying kinds are predicates **against the site's current
  ordered deployment head**, so they are evaluable only where one
  exists: on a site with no ordered deployment (no CI door, no
  provider webhook, ordering unknown), every basis degrades to
  `unknown` server-side and code absence records
  `verification inconclusive (no deployment basis)` - visibly, until
  the first ordered deployment lands. That is the honest reading of
  deploy-anchored verification, not a gap: without a deployment
  identity there is no server-side fact for "the current code" to
  mean, the desktop's own local verification remains fully
  functional (it is the free product), and the wire state stays
  `claimed_fixed` rather than pretending a machine-checked
  verification nobody could define.
- **Presence crosses vantages; absence does not - tracked per
  vantage, not per last establisher.** A web occurrence record holds
  **standing presence evidence per vantage family** that has observed
  it present; a "last established by" pointer would rotate to
  whichever vantage saw it most recently and let that vantage's clean
  variant clear evidence another vantage still holds. Any comparable
  producer's presence evidence counts from any vantage (and adds or
  refreshes that vantage's entry), but a clean observation resolves
  **only its own vantage's entry**, and the occurrence reaches
  `verified_absent` only when **every** vantage entry is resolved. A
  hosted-only clean run against a desktop-and-hosted-established
  occurrence therefore yields the honest partial state: absent at the
  hosted vantage, unresolved at the desktop vantage, surfaced as
  `verification inconclusive (content variant)` with the vantages
  named and "run a local scan to confirm" as the next step - never a
  verification.
- **The only cross-vantage clearing is check-input equivalence.** The
  route-signature comparison is a drift detector, not an absence
  authority: two pages can share status, title, scripts, and
  landmarks while differing in exactly the input a check reads. A
  vantage's clean observation may resolve another vantage's entry
  only when the check's **complete canonical inputs** ride the
  transient projection and the observing vantage's projection of
  those inputs MACs equal to the entry's stored
  `establishing_context.input_mac` - never any refreshed copy -
  under the same projection and key versions - identical
  inputs produce identical verdicts by construction, so the crossing
  is sound for exactly those checks and no others (the hosted
  scanner spec names which checks qualify). Everything else waits
  for same-vantage evidence, indefinitely if necessary, visibly
  always.
- **Absence resolves backward, never forward.** A governing absence
  observation resolves presence evidence received before it;
  non-historical presence evidence received after it re-establishes
  presence (that is exactly a regression). There is no receipt-order
  last-write-wins between conflicting equal-authority claims: the only
  conflict class, presence versus absence, resolves to presence going
  forward when the presence is fresh and to a rescan when it is
  historical, and a wrongly-verified pair self-corrects at the next
  fresh observation that sees the finding.

In practice: the hosted scanner governs web truth on a connected site
(it observes production on every deploy and on schedule). On sites with
an ordered deployment head, exact-provenance CI governs code truth at
its deploy point while that deploy is live, and desktop snapshots with a
qualifying `code_basis` govern between deploys. On sites with no ordered
deployment head, **nothing governs code absence on the wire** - the
desktop still verifies locally (the free product is untouched), but that
verification is local display, never connected state, per the
no-deployment-basis rule above. Desktop web vantage entries are governed
by desktop web snapshots always, per the vantage-local rule - web
governance never depends on deployments. This is also why
`verified_by: "local_scan"` is real but rare for web occurrences on
connected sites.

### Coverage-scoped application

A snapshot updates only what its coverage proves, at pair granularity:
**only a covered, unexcepted `(route, check)` pair resolves absence.** A
web snapshot covering three routes updates the web occurrences of exactly
the pairs its coverage claims and does not except; occurrences on
uncovered routes, and occurrences whose pair is excepted, persist
untouched with their existing evidence. A code snapshot with `project`
coverage covers the code partition; with `rule_set` coverage it covers
only those rules' pairs. Absence resolution respects pair coverage;
presence needs only the pair's own successful execution; and there is no
route-level wholesale replacement.

### The scan scope

Coverage describes what a completed scan observed; it cannot define what
future scans should observe, so scope is its own resource, not a
projection of coverage. The scan scope is a revisioned per-environment
configuration object: the selected routes (the same canonical route
form as occurrences) and the expected check families. The desktop sets
it (`PUT /v1/sites/{site}/scope`, installation token), guarded by its
own `scope_revision` with the same stale-rejection semantics as every
other guard, bounded by the coverage limits (5,000 routes), served in
`GET /v1/sites/{site}/state` summaries, included in export, and erased
with the site. The hosted scanner reads it as the authority for what to
scan; scope changes are recorded events, and removing a route from
scope does not delete its occurrence records (retention and compaction
govern those), it only stops future observation. Occurrence records
whose authored `scope_routes` all leave scope carry the orthogonal wire field
`scope_membership: "out_of_scope"` (a first-class tri-state record
field, `in_scope | pending_reentry | out_of_scope`, in reads, export,
and recovery, not a prose label): retained as history until
compaction, excluded from current-state aggregation, verification
targets, and group-state derivation, and a group left with no in-scope
records carries the derived wire field `dormant: true` (kept, silent,
excluded from active views) rather than being deleted. **Re-entry is
not resurrection, and it never expires into exclusion**: when a route
returns to scope, its existing records enter `pending_reentry`, a
state that only a fresh governing observation resolves (to `in_scope`
with current status, or removal on proven absence). It is deliberately
**not** the `pending_fresh_evidence` flag, whose 90-day expiry would
otherwise quietly strand a user-selected route as excluded forever; a
`pending_reentry` record that observations keep failing to resolve
stays visibly pending and surfaces as operationally unhealthy. Site
state exposes `scope_over_plan`, the grace expiry, the effective route
count, and the overflow count; post-grace truncation reserves the
**environment entry route first** (origin-scoped checks require the
entry page, so lexicographic order must never truncate it away),
followed by the remaining routes in stable canonical order
(lexicographic by canonical route string), so which routes fall into
overflow is deterministic and documented. Scope validity is also a standing
condition, not a `PUT`-time check: an entitlement downgrade that leaves
a stored scope above the new cap puts the site in a visible
`scope_over_plan` state with a 14-day grace window during which the
full scope keeps scanning; after grace, scans cover the plan-cap prefix
in stable route order with the overflow **visibly excepted** in every
coverage report until the user trims - and the truncation says what
happens to **session-scoped checks**, whose coverage requires the
complete route set to have run: on a post-grace truncated site they
are marked inconclusive with the explicit cause
`coverage_truncated`, attributed to the `scope_over_plan` state with
trim-or-upgrade as the named remedy, never silently degraded (the
scanner spec's decision 8 carries this as its one stated
exception). Protection degrades loudly; it
never quits quietly and never truncates silently. A site cannot leave
`pending_bootstrap` until both bootstrap and an initial scope have
committed, because a connected site with no scope would be a guardian
watching nothing.

The wire limit of 5,000 routes bounds the resource; the **effective
scannable scope** is bounded by the entitlement's connected-scope cap
(a plan value set outside this specification; the hosted scanner's v1 ceiling is 100). **The environment's entry URL counts toward the effective cap**
(deduplicated when it is also listed, exactly as the scanner spec
counts it as a route), so a maximal scope is 100 routes including
the entry - never a 101-route scan against a 100-route budget. A
`PUT` exceeding the effective cap is rejected with
`422 scope_exceeds_plan` naming the cap, never silently truncated. The
request carries `{ "based_on_scope_revision": n, "routes": […], "check_families": […] }`
and the response returns the new `scope_revision`; a stale basis is
`409 stale_revision` whose problem details carry the current scope.

### Bootstrap and the mutation outbox

A site moves through explicit phases: `pending_verification`,
`pending_bootstrap`, `connected`. Scans, hooks, and webhook processing
are disabled until bootstrap commits, so a hosted observation cannot
create groups before the desktop's lifecycle arrives. Bootstrap is
recorded as `bootstrapped_at` on the site; a second bootstrap answers
`409 already_bootstrapped` **from that marker, never from group-set
emptiness**, because a legitimate bootstrap can contain zero groups and
must still commit the phase transition.

Bootstrap carries the group set with, for every group whose local state
is `verified`, the claimed state and the last-known occurrence
identities plus authored Web scope provenance from local scan history:
without them the server would have nothing comparable to verify absence
against, and the group would be stuck
inconclusive. **Bootstrap never asserts `verified_fixed`.** Imported
claims land as `claimed_fixed`, and the bootstrap transaction then
derives `verified_fixed` (with `verified_by: "local_scan"`) only where
the accompanying snapshots prove every last-known occurrence absent
under the derivation rules: covered, unexcepted, comparable. Groups the
accompanying evidence does not prove stay `claimed_fixed` and verify
through the ordinary loop, typically on the first hosted scan. Derived
verification stays derived even at import time.

After bootstrap, group changes travel exclusively as revision-guarded
mutations (`POST /v1/sites/{site}/mutations`). No replacement operation
on groups exists in the protocol.

Offline decisions keep their original basis. When the desktop changes a
group's lifecycle while connected-but-stale or offline, it records the
intent at decision time in a persisted **connected-mutation outbox**: the
target group, the intended transition, the group revision the user's
decision was actually based on, and a pre-assigned idempotency key. On
reconnect the outbox submits with that **original** `based_on_revision`,
even when the desktop has since pulled newer server state: silently
relabeling an old decision as based on state the user never saw would
defeat the guard. A conflicting server change therefore surfaces as
`409 stale_revision` for explicit reconciliation, exactly as intended.
The lifecycle table stores neither server revisions nor pending intent;
both live in the desktop stores described in implementation contract item 4
below.

The desktop submission payload, complete except the optional
`transient` projection envelope (elided here; bounds in this spec's
transient-projections section, schema owned by the hosted scanner
spec):

```json
{
  "schema_version": 1,
  "site_id": "site_9f2c81d0a4b3",
  "environment": "production",
  "submission_sequence": 1,
  "groups": {
    "mode": "bootstrap",
    "entries": [
      {
        "check": "security.csp",
        "state": "dismissed",
        "dismissal": { "kind": "snoozed", "until": 1754870400000 },
        "state_changed_at": 1754784000000,
        "sources": ["web"]
      },
      {
        "check": "seo.canonical",
        "state": "claimed_fixed",
        "state_changed_at": 1754697600000,
        "sources": ["web"],
        "last_known_occurrences": [
          { "route": "/", "query_dependent": false, "scope_routes": ["/"] },
          {
            "route": "/pricing/",
            "query_dependent": false,
            "scope_routes": ["/pricing"]
          }
        ]
      },
      {
        "check": "code_scan.security",
        "state": "active",
        "state_changed_at": 1754784000000,
        "sources": ["code"]
      }
    ]
  },
  "snapshots": {
    "web": {
      "observed_at": 1754784000000,
      "based_on_event_sequence": 0,
      "versions": {
        "engine_release": "1.5.4",
        "fingerprint_schema": 1,
        "canonicalizer": 1,
        "crawl_profile": 1
      },
      "manifest_digest": "9e4b…",
      "evaluation_time": 1754783990000,
      "execution_profile": {
        "browser": { "engine": "webkit", "build": "621.1.15" },
        "axe_version": "4.11.2",
        "resolver": "system",
        "transport_adapter": "desktop-reqwest@1",
        "tls_adapter": "rustls-webpki@1",
        "trust_authority": "webpki_roots",
        "scan_profile": "full",
        "layers_run": ["transport", "browser"]
      },
      "stack_facts": { "framework": "nextjs", "framework_version": "14" },
      "coverage": {
        "kind": "page_set",
        "complete": true,
        "routes": ["/", "/pricing", "/docs"],
        "checks": ["security.csp", "performance.lcp"],
        "exceptions": [
          {
            "route": "/docs",
            "checks_not_run": ["performance.lcp"],
            "reason": "check_skipped"
          }
        ]
      },
      "occurrences": [
        {
          "check": "security.csp",
          "route": "/pricing",
          "query_dependent": false,
          "severity": "high",
          "confidence": "confirmed"
        }
      ],
      "measurement_samples": [
        { "check": "performance.lcp", "route": "/pricing", "value": 2140, "unit": "ms" }
      ]
    },
    "code": {
      "observed_at": 1754780400000,
      "based_on_event_sequence": 0,
      "versions": {
        "engine_release": "1.5.4",
        "fingerprint_schema": 1,
        "fingerprint_key_version": 1,
        "canonicalizer": 1
      },
      "manifest_digest": "9e4b…",
      "evaluation_time": 1754780390000,
      "execution_profile": {
        "layers_run": ["code"]
      },
      "key_commitment": "5d2a…",
      "code_basis": {
        "commit_sha": "45822983…",
        "kind": "compatible",
        "unvouched": []
      },
      "coverage": { "kind": "project", "complete": true },
      "occurrences": [
        {
          "check": "code_scan.security",
          "location_hash": "8c1f…64 hex…",
          "instance_count": 1,
          "severity": "critical",
          "confidence": "needs_review",
          "provenance": { "commit_sha": "45822983…", "kind": "compatible" }
        }
      ]
    }
  },
  "correlation_pairs": {
    "fingerprint_key_version": 1,
    "pairs": [
      {
        "web": { "check": "security.csp", "route": "/pricing" },
        "code": { "check": "code_scan.security", "location_hash": "8c1f…" }
      }
    ]
  }
}
```

Note the `claimed_fixed` group has no occurrence entry in the web
snapshot but carries `last_known_occurrences` in bootstrap. That is the
resource model working: the finding is gone from the latest scan, the
group survives awaiting verification, the tombstone identities tell the
verifier where to look, and occurrences reappearing under it fail the
claim.

The CI submission payload is a single `code` snapshot in the same shape,
plus a required embedded `deployment` object (create-or-match semantics
above) and no `groups`, `correlation_pairs`, `submission_sequence`, or
`based_on_event_sequence`. Its occurrences' `provenance.kind` is
**server-assigned, never client-asserted**: `exact` when the CI
provenance binding's OIDC constraints hold, `unattested` otherwise -
the client does not send the field at all on the CI door.

Field notes:

- `site_id` is a server-issued opaque identifier minted at connection.
- The site alias is **not** in this payload: it is site metadata, set at
  connection and updated through `PATCH /v1/sites/{site}` under its own
  `metadata_revision` guard, because a notification label has no business
  riding scan submissions.
- `verified_good` is **not** in this payload: the last verified-good
  profile is derived server-side from accepted observations of the
  public URL (hosted scans and accepted web snapshots), so it cannot
  disagree with the evidence that produced it. The hosted scanner spec
  defines which drift checks read it.
- `stack_facts` carries version-level detection results only, sourced from
  the same detection the desktop already runs (`detected_stack`,
  `framework` on `scan_runs`). Never dependency lists, never lockfile
  contents.
- `severity` uses the existing closed set
  (`critical | high | medium | low`). `confidence` is the desktop's
  existing optional `IssueConfidence`
  (`confirmed | high | needs_review`; absent means a full-weight
  deterministic observation, exactly as `scoring::dedup` treats it).
  It rides the wire because the hosted report's score is computed by
  the same extracted scorer the desktop uses (hosted scanner spec's
  tier-one artifact), and that scorer's confidence weighting, cap
  eligibility, and dedup are functions of these fields; without them
  the hosted score would be a second implementation, which is
  forbidden. Group wire state supplies the scorer's active-set
  predicate (dismissed and verified groups excluded, `regressed`
  counts), and check category resolves through the capability
  manifest, not per occurrence. Occurrence `provenance.kind` is a
  discriminated union with one authority per kind: `exact` is
  server-assigned on the CI door when the OIDC constraints hold;
  `unattested` is server-assigned to every other CI submission
  (non-governing, non-causal - it informs, it never verifies and
  never supports "this deploy broke it" language); `compatible`,
  `stale`, and `unknown` are desktop-correlation claims carrying the
  RFC's predicates (`compatible` requires a known-ancestor SHA with
  the relevant files unchanged since - a fact only the side holding
  git can compute, which is why no server-side corroboration can
  mint it). Occurrence provenance is a **presence** fact; the
  authority to **clear** code pairs rides the snapshot-level
  `code_basis` (evidence-precedence section), whose `exact_checkout`
  kind is deliberately a different name from this door's attested
  `exact` - same working-tree fact, different trust level, and the
  vocabulary refuses to blur them.
- **Coverage is pair-precise.** Flat route and check lists cannot prove
  that a specific check completed on a specific route, and verification
  needs exactly that pair. The encoding is claim-plus-exceptions:
  `complete: true` asserts every listed check ran successfully on every
  listed route (or on the project, for code kinds), and `exceptions`
  enumerates the pairs that assertion does not cover
  (`{ route, checks_not_run }` entries, or `{ check, routes_not_run }`
  where that is smaller). Verification of an occurrence requires its
  `(route, check)` pair to be covered and unexcepted. Every exception
  carries a `reason`, so a gap is always attributable: the desktop emits
  `check_skipped` and `session_incomplete`, and the hosted scanner's gate
  adds `bot_challenge`, `document_changed`, `profile_cold`, and
  `coverage_truncated` with the lane that produces them. A family prefix
  in the claim (`accessibility.axe.`) means the family's RUNNER executed,
  which is the only thing a fixed finding leaves behind: its own id is
  gone. Members that ran without concluding are excepted by id, and an
  exception always beats the family claim. `ScanCoverageManifest` in
  `sitecmd_engine::coverage` is this encoding, shared by every producer;
  its `covers(route, check)` is the decision, and no consumer reimplements
  it.
- `correlation_pairs` is keyed by **stable installation identity**, not
  by credential: each installation's pair set is replaced by that
  installation's own latest submission (its `submission_sequence` orders
  only itself; independent counters are never compared), and the server
  serves the validated union across installations, deduplicated by
  identity tuple. Pair sets are pinned to the fingerprint key version
  their code side was computed under and retired at key rotation. Pairs
  link occurrences by their identity tuples only; both sides are already
  synced, so a pair adds no new information beyond the association.

Never present, restated as a schema-level ban with the payload builder as
the enforcement point: source code, file contents, raw file paths, line
numbers, code-scan evidence or excerpts, `raw_data`, `detail_json`, issue
descriptions, fix prompts, integration data, and analytics contents. The
payload builder lives in the public desktop repository, and the sync
inspector and `--dry-run` render exactly these objects.

## Credentials

Two credential families. **Bearer credentials** are opaque random
tokens following the catalog precedent (`sitecmd_cat_` plus 32 random
bytes hex, stored server-side only as SHA-256;
`apps/sitecmd-activation/src/lib/activation.ts`,
`apps/sitecmd-catalog/src/lib/entitlement.ts` in SiteCMD-Web).
**Capability tokens** are narrow, single-purpose, and mostly
single-use; each grants exactly one operation on exactly one resource,
and the complete inventory lives with the public-surface table below -
there is no such thing as an unlisted way in.

| Credential           | Kind       | Scope                                          | Issued by                             | Held by                 |
| -------------------- | ---------- | ---------------------------------------------- | ------------------------------------- | ----------------------- |
| Installation token   | bearer     | Sites assigned to one installation             | Activation exchange (license + nonce) | Desktop OS keychain     |
| CI token             | bearer     | Submit and read deployment cursor for one site | Desktop, under installation token     | CI secret store         |
| Webhook secret       | bearer/mac | Trigger scans for one environment              | Desktop, under installation token     | Provider webhook config |
| Erasure status token | bearer     | Read one erasure job's status                  | Service, at erase                     | Requester               |
| Report link token    | capability | Render one report until TTL or revocation      | Service, at report creation           | Email or clipboard      |
| Alert nonce          | capability | Redeem one alert view, once                    | Service, at alert delivery            | The alert email         |
| Alert view session   | capability | View one alert for 30 minutes                  | Service, at redemption                | HttpOnly cookie         |
| Confirmation token   | capability | Confirm one destination, once                  | Service, at destination creation      | The confirmation email  |
| Unsubscribe token    | capability | Demote one destination's cadence               | Service, per message                  | `List-Unsubscribe-Post` |
| OAuth state token    | capability | Complete one provider authorization, once      | Service, at connection creation       | The authorize URL       |

- **Installation token.** Issued through the same exchange shape as the
  catalog credential: license key plus `installation_id` plus a persisted
  nonce, refused unless the subscription is entitled. The activation
  worker remains the single subscription-trust authority; connected
  credentials live in the same credential store with a scope
  discriminator, so the existing webhook-driven suspension, restoration,
  retier, and the six-hourly reconcile sweep govern connected entitlement
  with no parallel machinery. Stored in the desktop keychain through the
  app-secrets layer. Holding an installation token grants nothing about a
  site until the installation is assigned to it - and site assignment
  grants nothing about the account, because account administration is
  a flag on the **stable installation membership** (the same identity
  that keys `submission_sequence`), never on the token: rotating a
  credential preserves admin, and stealing a token confers exactly
  the membership's standing. The subscription's first installation is
  admin; an admin can grant or revoke admin on other installations
  (`POST /v1/account/admins`, `DELETE /v1/account/admins/{installation}`).
  The **last-admin invariant is atomic**: revocation is a single
  conditional statement that fails unless another admin row exists at
  that moment, so two admins revoking each other concurrently cannot
  both succeed - one gets the `409`. The flag is visible in the
  tokens list. Losing the sole admin device is recoverable without
  web accounts through the **subscription-owner recovery flow**: any
  installation of the subscription may request admin recovery; the
  request creates a visible pending state, notifies every verified
  destination and surfaces on every installation, and completes only
  through the exposure-gated predicate defined with the account
  endpoints below - 72 hours after an owner-controlled channel
  demonstrably received it (a verified destination accepted the
  notice, or an installation that already held admin when the
  request was made acknowledged the pending state), or 14 days with
  no exposure ever demonstrated, as the last resort - unless an
  existing admin cancels it first, and the 72-hour clock runs from
  that exposure, so the owner always keeps a response window. The
  security claim is stated exactly, not rounded up: the license key
  alone **cannot self-satisfy the 72-hour branch** - installations
  minted from the key are not owner-controlled channels and
  demonstrate nothing - while the 14-day branch **is** a
  license-key-only takeover path for an account whose admin device
  is gone and whose alarms never demonstrably land: an explicitly
  accepted recovery risk, priced against the alternative of
  permanently locking the paying owner out of erasure, export, and
  their own pager wiring, and mitigated only by fourteen days of
  visible pending state on every response.
  Every grant, revocation, request, cancellation, and completion is
  an audited event. Admin is required for every account-wide surface -
  provider connections, destinations, protected sites, account export,
  and account erasure - so a secondary installation assigned to one
  client site cannot enumerate the account's destination addresses,
  rewire another site's delivery, or erase the account; without admin,
  those endpoints answer the ordinary `403`. Account erasure
  additionally requires an explicit confirmation echo: the request
  body must carry the account-scope id the caller is destroying
  (`{ "confirm": "<scope_id>" }`, from `GET /v1/account`), so no
  automation path can erase an account by hitting an endpoint with an
  empty body.
- **CI token.** Minted from the desktop, bound to exactly one site, shown
  once, stored hash-only, chained to the owning subscription for
  suspension. Repository identity is recorded as both the canonical
  `owner/repo` and GitHub's immutable decimal repository id when a trusted
  workflow is pinned. The desktop resolves both directly from GitHub before
  minting, so a repository rename or later reuse of the old name cannot
  satisfy the OIDC binding. These are additional constraints the server
  checks against submitted deployment facts, not an alternative scope. It
  can submit deployments, CI sync payloads, and coverage for its site. Its
  only state read is `GET /v1/sites/{site}/deployment-head`, which returns
  the active ordering authority only when the credential's immutable
  repository, workflow, and ref pins derive that selected authority, plus the
  current provider deployment id and an explicit `submission_attestation`
  capability. Workflow-pinned credentials report `github_oidc` even when they
  do not own the selected authority, while generic credentials report
  `unattested`. Generic and non-selected credentials see a null authority and
  continue in the history-grade lane; the response returns no findings,
  groups, account data, or lifecycle state. The other read-shaped answer is
  the gate verdict: `POST /v1/sites/{site}/gate` evaluates a candidate
  branch's fingerprints against the baseline and returns pass or fail
  with the new-finding identities, evaluating and discarding the
  submission without mutating any state (semantics in the alert and
  report delivery spec).
- **Webhook secret.** Per environment and provider. Generic-door requests
  are HMAC-signed with it over the raw body, following the LemonSqueezy
  verification pattern already in production (constant-time hex compare,
  fail-closed on empty secret). Vercel and Netlify doors use the
  provider's own signing; mechanics belong to the hosted scanner spec, but
  the credential object and its rotation live here.
- **Report link.** An opaque random token following the bearer-credential
  precedent above (32 random bytes, base64url); the service stores only
  its SHA-256 hash, in the report's registry row alongside the row's
  expiry. The render path looks the row up by the presented token's hash
  and checks expiry and revocation there, never in the token itself.
  Contents and redemption are the alert and report delivery spec's.

Rotation and revocation are first-class endpoints for all three held
credentials. Revocation is a permanent tombstone, mirroring
`catalog_credentials.revoked_at`. Every credential row records
`last_used_at`, and `GET /v1/sites/{site}/tokens` lists the site's
credentials, cursor-paginated like every other list (revocation
tombstones accumulate), with scope, creation time, `last_used_at`, and
key-version watermark where applicable, so the desktop can show which CI
secrets and webhook configurations are live and which are stale.

Suspension semantics: an unknown or revoked credential answers a uniform
`401 unauthorized` with no detail, exactly like the catalog. A valid
credential whose subscription is suspended answers
`403 entitlement_suspended`: the caller has proven possession, and the
owner of a lapsed subscription must be told why protection stopped,
because a guardian that quits silently violates the RFC's own promise.

## API protocol

One new worker in SiteCMD-Web (`apps/sitecmd-connect`, custom domain
`connect.sitecmd.com`), following the repository's established conventions:
its own D1 database with `migrations_dir`, migrations applied before deploy
under a shared concurrency group - by the restore orchestrator, which CI
triggers without ever holding the D1 edit credential (the physical write
strategy section owns the credential model: one platform permission covers
migrate and restore alike) - rate limits that fail closed through the
shared helper, `nodejs_compat`, observability on. It additionally binds the
entitlement database read-only-by-convention for credential validation,
exactly as the catalog worker does today.

The worker implementation is owned by SiteCMD-Web. Conformance is judged
against this protocol and its route inventory, not a dated deployment note in
the public client specification. Four properties are load-bearing:

- **The lifecycle rules are executed, not just written down.** Bootstrap
  commits from its own marker rather than from group-set emptiness;
  imported claims land as `claimed_fixed` and become `verified_fixed`
  only where the accompanying snapshots prove every last-known
  occurrence absent under coverage read pair by pair; a code snapshot
  clears nothing from a basis it cannot vouch for, and nothing at all
  for a pair its `unvouched` list names; the staleness shield drops any
  record whose newest evidence postdates what the producer had pulled;
  and mutation batches are atomic, refusing whole and naming every
  stale group. Each of those has a negative control that was run: the
  rule removed, exactly the relevant test red, the rule restored.
- **A site is reached by assignment AND account, never by either
  alone.** Installation ids are machine identities, so one laptop on two
  subscriptions carries a single id in two accounts; an assignment
  lookup keyed on the id alone reads the other account's site. That case
  was found by a negative control that passed, and both halves of the
  predicate now have a repo guardrail behind them.
- **Problem details are the reconciliation path.** Every non-2xx on a
  bearer `/v1` route is RFC 9457 problem details, because the desktop
  reads `code` to recognize `stale_revision` and the top-level
  `stale_groups` member to reconcile without a second read. A guardrail
  fails the build when a 4xx or 5xx is answered outside them.
- **Customer-origin egress is fully disclosed.** Ownership verification
  queries the named DNS resolver or fetches the customer's well-known route,
  and hosted scans fetch only the configured public routes. `/scanner` names
  both senders, their User-Agents, the Worker-proxied rendered-page path, and
  the controls an operator can use. It deliberately publishes no runner address list: Workers
  egress varies across Cloudflare's network and has no stable per-customer
  range. `network-facts.ts` and the trust pages enumerate the remaining
  provider and delivery destinations.

Two things about the credential foundation are worth restating, because
later sections depend on them too:

- **The installation token is real and is issued.** Catalog migration
  0009 added the `scope` discriminator this spec's credential section
  calls for, and `POST /v1/connect/activate` on the activation worker
  mints one through the same exchange as the catalog credential: same
  nonce replay, same fingerprint binding on that replay, same refusal
  to mint without a subscription id, same entitled gate. It carries no
  seat cap, because device caps are not the sold quantity. Suspension, restoration, retier, and the
  six-hourly sweep reach it without a line of new machinery, which is
  the whole reason the credential lives in that store; the activation
  worker's suite executes each of those four paths and asserts both
  scopes moved.
- **The unauthenticated surface is a list the code reads.** It is
  currently empty, and the router consults it rather than trusting each
  handler to remember. A repo guardrail fails the build when a route is
  matched before the caller is resolved, so an endpoint added above the
  authentication check is a red build rather than an open door.

**The CI gate is live end to end.** The CI token is real: minted from
the desktop under an installation token (`POST /v1/sites/{site}/tokens`),
bound to one site, shown once, stored hash-only in this service's own
store, listed and revoked by a public handle, and chained to the
subscription by reading the canonical state rather than caching it - so
the same suspension paths reach it with no machinery of its own.
`POST /v1/sites/{site}/gate` evaluates a candidate's code fingerprints
against the baseline and answers with the new identities and a verdict,
persisting nothing; a repo guardrail fails the build if that module ever
gains a write. A verified-absent record does not count as prior art,
which is what makes a returning regression fail rather than merge. The
credential reaches its own site's four CI doors - the deployment-ordering
cursor read, the gate, deployment notification, and the CI submission door -
and 404s on every other route, because the binding is the authorization and a
runner's secret store is readable by anyone who can edit a workflow file. The
cursor read returns only the selected authority and current deployment id;
every other reach is a write, and every surface describing the credential
names all four. `sitecmd gate` builds its candidate
through the same payload builder desktop sync uses, so the gate cannot
disagree with sync about what a finding is, and the composite action at
`.github/actions/sitecmd-gate` installs the published CLI and reports a
blocked merge as exit 1 and an unreachable service as neither.

The detector-change rule is decided per check. The baseline instrument's
check inventory is stored beside its manifest digest (`site_code_checks`,
replaced on a digest change and unioned on a matching one, fed from the
governing code snapshots' coverage claims), so when a candidate arrives
from a different instrument only a finding under a check the baseline
never evaluated is warned as instrument-caused; a finding under a check
the baseline already ran fails normally, whatever the digest says. That
closes the window where an engine update spared every new finding for
one default-mode gate run. A baseline recorded before the inventory
existed has no rows, and for it every check stays sparable - the old
reading, stated rather than guessed past - until its next governing
code snapshot populates the inventory.

Since that account was written, the remaining connected-service surfaces
have landed: hosted triggers, deployment ordering, alert delivery, provider
connections, reports, reconnect, key rotation, retention, and erasure. Their
current wire shapes are frozen in the OpenAPI document named below.

The OpenAPI document this spec obligates exists now, at
`apps/sitecmd-connect/openapi.yaml` in the SiteCMD-Web repository. It
freezes only shapes with an implementation behind them; its header
names the absent surfaces so a path that answers 404 is a bug and a
capability it does not describe is one the service does not have.

### HTTP conventions

- **Authentication** is `Authorization: Bearer <token>` on every
  `/v1/*` endpoint except the hook doors, which authenticate by
  signature as specified per door. The erasure status token is a bearer
  token under this same rule: it travels in the header, never in the
  URL, because URLs leak into logs. Everything reachable without a
  bearer token is enumerated in the public-surface table below;
  a route not in that table does not exist unauthenticated.

### The public surface

Every internet-reachable route that does not take an installation or
CI bearer, normative and closed, in **two route classes** with
different rules, because provider webhooks and mail systems are not
browsers and must not be handed browser assumptions:

- **Server-to-server doors** (the four hook doors, the RFC 8058
  unsubscribe and the deploy's storage probe): no origin policy and no
  cookies - the callers cannot and need not establish browser context;
  authentication is the signature or single-purpose token alone.
  Responses are bare status codes with empty or minimal JSON bodies
  and **never redirect**. The unsubscribe door implements RFC 8058
  exactly: it accepts the mail-receiver's context-free POST with the
  `List-Unsubscribe=One-Click` form body, answers `2xx` on success,
  and performs the cadence demotion with no confirmation page and no
  redirect chain, because the caller is a mail system acting on the
  user's gesture.
- **Browser-form routes** (the OAuth callback, alert landing, redeem,
  view, and resend, destination confirmation, report render): render
  HTML, including their failures - the `/v1/*` problem details do not
  apply here; the error page is an HTML page with the same
  security headers. POSTs are same-origin form posts; the only cookie
  in the system is the alert view session
  (`HttpOnly` + `SameSite=Strict`), so capability possession is the
  CSRF defense everywhere else.

Both classes: every response is `Cache-Control: no-store`; capability
tokens in paths are redacted from access logs to their resource id,
and **query strings on public routes are redacted wholesale** (the
OAuth `state` and the provider's authorization `code` arrive as query
parameters; the code exists in memory for the exchange and is never
stored or logged); rate limits come from the beta operating
configuration, which carries per-class keys (hook doors per site,
Resend intake globally, browser-form routes per source address per
resource).

| Method + path                    | Authentication                             | Single-use             | TTL                            | Behavior                                                                     |
| -------------------------------- | ------------------------------------------ | ---------------------- | ------------------------------ | ---------------------------------------------------------------------------- |
| `POST /v1/hooks/vercel`          | Provider signature (per provider contract) | Dedup by event id      | n/a                            | Deploy event; unverifiable = dropped and counted, never applied              |
| `POST /v1/hooks/netlify`         | Provider signature (per provider contract) | Dedup by event id      | n/a                            | Same contract as above                                                       |
| `POST /v1/hooks/{site}/deploy`   | `sha256=` HMAC over raw body               | Dedup by `event_id`    | 5-minute skew window           | Generic deploy door; body schema below; duplicate `event_id` converges `200` |
| `POST /v1/hooks/resend`          | Svix signature over raw body               | Dedup by `svix-id`     | 5-minute tolerance             | Bounce and complaint intake (delivery spec)                                  |
| `GET /connect/callback`          | OAuth `state` token (single-use, hashed)   | Yes                    | 15 minutes                     | Provider code exchange, server-side; completion page carries no tokens       |
| `GET /a/{alert}/{nonce}`         | None (landing renders nothing sensitive)   | No (non-consuming)     | 72h from first send initiation | Alert landing page: one button, no alert content                             |
| `POST /a/{alert}/{nonce}/redeem` | Alert nonce (bound to `{alert}`)           | Yes                    | 72h from first send initiation | Exchanges nonce for the 30-minute view session cookie                        |
| `GET /a/view`                    | Alert view session cookie                  | No                     | 30 minutes                     | The alert view (delivery spec's content ceiling)                             |
| `POST /a/{alert}/{nonce}/resend` | The nonce record (used or expired counts)  | Rate-limited           | Nonce TTL + 7 days             | Fresh link to the currently verified destination only; generic `200` always  |
| `GET /d/{token}`                 | None (landing, non-consuming)              | No                     | 24h from first send initiation | Destination confirmation landing: one button                                 |
| `POST /d/{token}/confirm`        | Confirmation token                         | Yes                    | 24h from first send initiation | Confirms the destination (double-opt-in completes)                           |
| `POST /u/{token}`                | Unsubscribe token (RFC 8058)               | Yes, idempotent replay | 30d from first send initiation | Sets destination policy per its message class; expired answers `410`         |
| `GET /r/{token}`                 | Report link token plus registry check      | No                     | Report TTL, revocable          | Renders the stored report projection                                         |
| `GET /v1/internal/storage-probe` | Deploy probe bearer, constant-time         | No                     | n/a                            | Deploy check: writes, reads back and deletes one row; no tenant data         |

The generic deploy door's body, exact:

```json
{
  "schema_version": 1,
  "event_id": "d-2f8c…",
  "environment": "production",
  "sent_at": 1754790000,
  "deployment": { "…": "the same deployment-facts object CI embeds" }
}
```

The signature is computed over `{sent_at}.{raw body}` with the
`sitecmd_whs_` secret and carried as
`X-SiteCMD-Signature: sha256=<lowercase hex>` plus
`X-SiteCMD-Timestamp: {sent_at}`; a timestamp outside the skew window
or a header/body timestamp mismatch is rejected before parsing, a
duplicate `event_id` inside retention converges `200`, and the
deployment object follows the create-or-match semantics deployments
already have. There is no hosted notification-settings page: the
settings link in every email is the desktop deep link
(`sitecmd://connected/...`), because settings mutation requires the
installation token and no web accounts exist.

The alert path carries the **opaque alert id beside the nonce** (the
delivery spec always specified "no metadata in the URL beyond the
opaque alert id"; the id is what survives): the nonce is bound to
that alert at mint and redemption checks the binding, and after the
nonce record's retention ends, the landing page can still offer the
working desktop deep link (`sitecmd://connected/alerts/{alert}`)
because the id is in the path - a fallback that needed nothing
secret, only a route that did not throw the id away, and one
**bounded by alert retention**: past the alert's 90-day retention
the landing page states that the alert has aged out and offers no
deep link (a link to a record that no longer exists is an offer,
not a fallback), and the desktop's deep-link handler has a defined
not-found state for an unresolvable alert id - the connected alert
timeline with an aged-out notice, never a dead end or an error
dialog. The resend
action's authority, precisely: the path nonce identifies
the alert-and-destination binding by hash lookup for as long as the
nonce record exists (its TTL plus the 7-day retention window), used
and expired nonces included - that is the whole point of the
expired-link page. It sends only to the currently verified
destination, is rate-limited per destination and per nonce, and
answers a generic `200` regardless of outcome so it cannot be used as
an oracle for destination or alert existence - including when
rate-limited: over-limit resends are dropped, counted on the ops
lane, and still answered `200` (the browser-form classes' generic
pages are the one place the global `429` convention deliberately
does not apply). Past the retention
window the landing page's remaining offers are the deep link and
nothing else, which is the honest answer.

- **Errors:** every refusal from a **bearer-authenticated `/v1/*`
  route** is RFC 9457 problem details, served as
  `application/problem+json` - the public surface has its own response
  matrix instead: browser-form routes answer every failure, `429`
  included, with an HTML page carrying the same security headers;
  server-to-server doors answer bare status codes with minimal JSON
  bodies; and the resend action's anti-oracle generic `200` overrides
  even that, as its row states. A refusal:

  ```json
  {
    "type": "about:blank",
    "title": "Conflict",
    "status": 409,
    "detail": "The lifecycle state changed after revision 41.",
    "code": "stale_revision",
    "request_id": "req_0123456789abcdef",
    "stale_groups": [
      {
        "check": "security.csp",
        "current_state": "active",
        "current_state_revision": 43
      }
    ]
  }
  ```

  `type`, `title`, `status` and `detail` are RFC 9457's standard
  members (the service sends no `instance`): `type` is `about:blank`
  and `title` is the status's reason phrase, because `code`, not a URI,
  names the problem, and `detail` is the sentence a person reads.
  `code` and `request_id` are extension members every refusal carries:
  `code` is a closed vocabulary, and `request_id` correlates with the
  service's logs. Any other member carries the refusal's own facts.
  No refusal ever echoes payload contents.

- **Status codes:** `200` action results, reads, and idempotent no-op
  redeliveries; `201` with a `Location` header for site creation; `202`
  for accepted asynchronous work (erase); `204` for completed idempotent
  deletions and disconnections; `400` malformed request; `401` unknown or
  revoked credential, uniform; `403` valid credential refused
  (`entitlement_suspended`, `unverified_site`, scope violations); `404`
  unknown resource within the caller's scope; `409` conflicts
  (`stale_revision`, `stale_submission`, `stale_key_version`,
  `key_commitment_mismatch`, `request_in_progress` with `Retry-After`,
  `secret_already_issued` with the member `issued`,
  `deployment_conflict`, `already_bootstrapped`, `rotation_in_progress`
  with the member `pending`, `last_admin` with the member `remedy`, and
  `destination_in_use` with the member `sites`); `410`
  `cursor_expired`; `413` `payload_too_large` for a body over its
  route's limit, naming no bound; `415` `unsupported_media_type` for a
  JSON body sent without `Content-Type: application/json`; `422`
  well-formed but invalid content (schema violations, unknown fields,
  oversized vectors, excessive clock skew, `idempotency_conflict` for an
  `Idempotency-Key` reused on a different request,
  `incomplete_snapshot`, `record_capacity`, `scope_exceeds_plan` with
  the members `cap` and `effective_routes`, and `report_too_large` with
  the members `actual`, `bound` and `limit`); `429` with `Retry-After`
  from the shared rate-limit helper; `503` fail-closed when a binding or
  upstream dependency is unavailable. `stale_revision` carries the
  current state in a member that depends on the write: `stale_groups`
  (every stale group's `check`, `current_state` and
  `current_state_revision`) on the mutation batch
  (`POST /v1/sites/{site}/mutations`); `current_revision` on the
  notification settings and destination policy writes
  (`PUT /v1/sites/{site}/notification-settings`,
  `PATCH /v1/destinations/{id}`); and `current` on the scope write
  (`PUT /v1/sites/{site}/scope`, the stored scope or `null`), the site
  metadata write (`PATCH /v1/sites/{site}`, `alias` and
  `metadata_revision`), the verified-good acceptance
  (`POST /v1/sites/{site}/verified-good/accept`, `field` and
  `profile_revision`) and the protected-list write
  (`PUT /v1/account/protected-sites`, `revision` and `site_ids`).
- **Caching:** every authenticated response and every error carries
  `Cache-Control: no-store`.
- **Idempotency is transport-level.** An authenticated client mutation
  whose operation declares it takes an `Idempotency-Key` header of 1 to
  255 printable ASCII characters; any other value is
  `400 malformed_request`. The CI submission requires the key
  (`400 idempotency_key_required` without it); every other such
  operation takes it as optional. The service keeps one record per
  account, operation and key, and never stores the key itself: the
  record holds the key's SHA-256 and the SHA-256 of the canonical
  request (method, path, credential, body).
  Replay is evaluated before every other guard (sequence, revision,
  conflict), so retries converge on the original result. The first
  request takes the record `in_progress` under a three-minute lease; a
  retry inside the lease is `409 request_in_progress` with a
  `Retry-After` of the lease's remaining seconds, rounded up, and a
  retry of the same request after the lease lapses takes the record
  over and applies, while the holder it replaced commits nothing. A
  completed record holds the `2xx` answer and replays it byte for byte
  for 24 hours, after which the key is free again. A refusal is never
  stored: a non-`2xx` answer deletes the record, so the same request
  runs again once its cause is fixed. The same key on a different
  request (another body, path or credential) is
  `422 idempotency_conflict`, never the first request's result.
  **Secret-issuing operations are the one documented divergence:**
  plaintext credentials are shown once and stored hash-only, so their
  record keeps only what was created, never the answer, and a retry is
  `409 secret_already_issued` whose `issued` member names the created
  resource's kind and id; the remedy for a lost secret is
  revoke-and-recreate. An effect outside the service that a request
  under a record causes, such as a webhook delivery or a mail send,
  either commits with the record's completion or carries a key derived
  from the record that a takeover does not change, so a receiver that
  deduplicates by that key sees one effect. Provider hooks do not use
  the header: their idempotency is the provider event identity, as
  specified under deployment records. Local precedent exists in
  `scan_executions.idempotency_key UNIQUE`; server precedent in the
  activation nonce and the hashed webhook event id.
- **Limits, v1 values:** request bodies are bounded per route (4 KiB
  unless the route states otherwise, a route that takes an
  `Idempotency-Key` and reads no body of its own included, since the
  key is bound to the body's hash; 4 MiB for the desktop and CI
  submissions, the CI gate, the mutation batch and the scope write;
  512 KiB for a capability manifest; 64 KiB for a fix-job result;
  256,000 bytes for the GitHub, Vercel and Netlify webhook doors and
  the site's own deploy door; 64,000 bytes for the Resend webhook
  door), each stated in bytes as the route's `x-body-limit` in the
  OpenAPI document, and a body over its route's limit is refused with
  `413 payload_too_large`, whose problem names no bound; 50,000
  occurrences per snapshot and 2,000 groups per bootstrap; 200
  entries per mutation batch; coverage bounded at 5,000 routes, 1,000
  checks, and 20,000 exception entries per snapshot, with an expanded
  route-by-check product cap of 2,000,000 pairs; page `limit` on
  cursor reads is optional, default 100, maximum 500. Requests over a
  count limit are `422` whose problem details name the offending
  bound.
- **Version evolution:** request bodies reject unknown fields (the
  activation and catalog-pack `deny_unknown_fields` posture), clients
  must ignore unknown response fields, and breaking changes bump
  `schema_version`. The server supports one prior `schema_version`
  during a migration window so desktop and CI updates are not forced in
  lockstep.

### Revisions and sequences

Ordering state, per site unless noted:

- **`state_revision`** increments only when group lifecycle changes:
  bootstrap, mutation batches, and server-executed transitions
  (verification outcomes, policy executions, regressions). Mutations
  guard on it, per group. Each group records the `state_revision` of its
  last change.
- **`event_sequence`** increments for every appended event: observations,
  snapshots, deployments, transitions, submissions. It exists for
  cursors, catch-up, cross-producer ordering, and the staleness shield.
- **`alert_sequence`**, per account, increments for every alert minted
  across all of the account's sites. `GET /v1/alerts` spans every site
  assigned to the calling installation, so its cursor pages over this
  account-level stream, filtered to the caller's assigned sites.
- **`submission_sequence`**, per stable installation identity
  (credential rotation continues the same counter and the server's
  watermark follows the installation, not the token), client-persisted,
  orders that desktop producer's own submissions and nothing else:
  independent producers' counters are never compared. CI credentials
  have none (see evidence ordering).

Snapshots carry no revision guard: they hold no lifecycle, and
coverage-scoped application under the evidence rules makes them safe to
apply in producer order. Mutation batches
(`POST /v1/sites/{site}/mutations`) are atomic. Each entry targets a
group and carries that group's `based_on_revision`; the server validates
every entry, applies all or none, and the whole batch produces one new
`state_revision`. If any entry is stale the batch fails
`409 stale_revision` and its `stale_groups` member carries the current
state and revision of every stale group, so the client reconciles and
resubmits without a second read. Stale mutations are never merged.

### Recovery

Events expire after 90 days, so the event stream cannot be the only road
back to a correct picture. Full state is always reconstructible, and the
consistency contract is watermark-plus-replay, not frozen pages:

1. Read `GET /v1/sites/{site}/state` and capture the **recovery
   watermark**: the current `state_revision` and `event_sequence`
   together (occurrence evidence changes advance `event_sequence`
   without touching `state_revision`, so both are needed).
2. Page through `GET /v1/sites/{site}/groups` and
   `GET /v1/sites/{site}/occurrences`. Pages serve from live state;
   every group item carries the `state_revision` of its last change and
   every occurrence item the `event_sequence` of its last evidence, so
   nothing mutated mid-pagination is silently torn.
3. Replay `GET /v1/sites/{site}/events` from the watermark's
   `event_sequence`. Anything that changed during pagination appears in
   the replay, which reconverges the picture.

`410 cursor_expired` on the event stream always has this fallback; it is
degraded catch-up (the individual missed events are gone), never data
loss (current state never expires). Alert recovery has its own
account-level path: `GET /v1/alerts` without a cursor returns the newest
page plus `current_sequence`, so a client whose alert cursor expired
resumes from now without needing any per-site state.

### Endpoints

Site lifecycle (installation token):

- `POST /v1/sites` - create a connected site; `201` with `Location`,
  the `site_id`, and the ownership-verification challenge. The site
  starts in `pending_verification`.
- `POST /v1/sites/{site}/verify` - complete ownership verification. Two
  routes: provider-attested (the request names
  `{connection_id, external_project_id}` from a provider connection,
  and the provider confirms the project serves the domain; the
  binding is stored on the site) or direct (DNS TXT record or
  well-known token file).
  Moves the site to `pending_bootstrap`. No scan runs and no webhook is
  honored before the site is `connected`.
- `PATCH /v1/sites/{site}` - site metadata (the notification alias),
  guarded by `metadata_revision`.
- `PUT /v1/sites/{site}/scope` - the scan scope (routes and expected
  check families), guarded by `scope_revision`; semantics in the
  scan-scope section.
- `PUT /v1/sites/{site}/ordering-authority` - select or change the
  environment's ordering authority, guarded by the current authority
  epoch; the transition semantics live in the deployment-ordering
  section.
- `POST /v1/sites/{site}/installations` - assign another installation to
  the site, authorized by an already-assigned installation. The
  fingerprint key travels separately, by local export (see key custody).
- `POST /v1/sites/{site}/key-rotations` - claim the next fingerprint key
  version; `POST /v1/sites/{site}/key-rotations/abort` - clear a pending
  claim (see key custody).
- `DELETE /v1/sites/{site}` - disconnect: triggers stop, credentials for
  the site revoke, state is retained for the retention window; `204`.
- `POST /v1/sites/{site}/reconnect` - resume a
  disconnected-but-retained or dunning-suspended site; semantics in
  the allowance-transitions section (allowance check, retention-clock
  cancel, credential remint, webhook reprovisioning, all evented).
- `POST /v1/sites/{site}/erase` - deletion: physical removal, defined
  below; `202` with `{ "job_id": "…", "status_token": "…" }`.

State and sync:

- `GET /v1/sites/{site}/state` - site phase, current `state_revision`,
  `event_sequence`, per-producer `submission_sequence` watermarks, group
  and occurrence summaries, the current deployment head with its
  ordering watermarks, entitlement state, and the key-migration
  status (current version, pending claim, per-actor version watermarks).
- `POST /v1/sites/{site}/sync/desktop` - the desktop submission
  (installation token), including bootstrap.
- `POST /v1/sites/{site}/mutations` - atomic lifecycle batch
  (installation token).
- `POST /v1/sites/{site}/deployments` - deployment facts without a code
  scan (CI token).
- `GET /v1/sites/{site}/deployment-head` - the ordering authority, when the
  CI token's mint-time workflow pins own it, and current provider deployment
  id, plus `submission_attestation` (`github_oidc` for a workflow-pinned
  credential, `unattested` for generic CI). A generic or non-selected token
  receives a null authority.
- `POST /v1/sites/{site}/sync/ci` - the CI submission with embedded
  deployment (CI token).
- `POST /v1/sites/{site}/gate` - the pre-merge gate verdict (CI
  token): candidate fingerprints in, pass-or-fail with new-finding
  identities out, nothing persisted, no state mutated (alert and
  report delivery spec).

Reads (installation token), cursor-paginated, keyset or sequence based as
specified:

- `GET /v1/sites/{site}/groups?cursor=&limit=` - all lifecycle groups
  with state, policy, and last-change revision.
- `GET /v1/sites/{site}/occurrences?cursor=&limit=` - all occurrence
  records with kind, status (established records only), identity,
  redirect-aware `scope_routes` provenance for every Web producer,
  `scope_membership`, and last-evidence sequence. The legacy scalar
  `scope_route` is a compatibility projection only; `scope_routes` is the
  authoritative set.
- `GET /v1/sites/{site}/route-profiles?cursor=&limit=` and
  `POST /v1/sites/{site}/route-profiles/reset` - the server-owned
  route-profile resource (page signatures as keyed MACs, the
  `document_changed` flag, per-route profile revision): reads are
  paginated like every list; reset is revision-guarded per route
  (`based_on_revision`, `409 stale_revision` on mismatch) and recorded
  as an event, which is what makes the hosted scanner spec's
  user-visible reset implementable rather than promised. Route
  profiles ride export, are erased with the site (including the
  content-MAC key), have their own retention row, and are compacted
  with their routes: profiles of routes out of scope beyond 180 days
  retire under the same cumulative bound as occurrence records, so
  route churn cannot grow them without limit.
- `GET /v1/sites/{site}/measurements?check=&route=&vantage=&from=&to=&cursor=&limit=` -
  measurement series per the measurement contract, vantage-filtered.
- `GET /v1/sites/{site}/events?cursor=&limit=` - the append-only site
  stream: observations, deployments, verification outcomes, transitions.
  Cursors are opaque tokens minted from `event_sequence`.
- `GET /v1/sites/{site}/tokens?cursor=&limit=` - the site's credentials
  with scope, creation time, `last_used_at`, and key-version watermarks;
  revocation tombstones accumulate, so this list pages like any other.
- `GET /v1/alerts?cursor=&limit=` - the account-level alert stream
  filtered to sites assigned to the calling installation; cursors are
  opaque tokens minted from `alert_sequence`; no cursor returns the
  newest page. Content rules in the delivery spec.

Paginated responses are
`{ "items": […], "next_cursor": "…" | null, "current_sequence": 912 }`.
Records sharing a timestamp cannot be skipped because cursors are
sequence- or keyset-based, never time-based. A cursor pointing at
history that has aged out of retention answers `410 cursor_expired`; the
recovery section defines the fallback.

Erasure status (status-token bearer, see deletion):

- `GET /v1/erasures/{job_id}` - erasure-job status. `job_id` is a plain
  identifier; authorization is the erasure **status token** presented in
  the `Authorization` header like every other bearer, which is what
  makes completion confirmable after the site and its credentials are
  gone without ever putting a secret in a URL.

Provider connections (**admin** installation token; semantics in the
provider connections section):

- `POST /v1/provider-connections` - begin a provider authorization;
  returns the pending connection and the provider authorize URL.
- `GET /v1/provider-connections` and
  `GET /v1/provider-connections/{id}` - list and read, metadata only,
  never provider credentials.
- `GET /v1/provider-connections/{id}/projects` - enumerate the
  provider projects visible to the connection, for site verification.
- `DELETE /v1/provider-connections/{id}` - revoke: deprovision
  provider webhooks, discard provider credentials, degrade dependent
  sites' triggers visibly.

Delivery management (installation token; content semantics in the
alert and report delivery spec):

- `GET` and `PUT /v1/sites/{site}/notification-settings` - mute,
  severity floor, digest cadence, and content mode, guarded by
  `notification_revision`.
- Destinations are **account-level** (one address, one verification,
  one policy - however many sites deliver to it; site-scoped
  destination rows could not represent the cross-site digest or the
  destination-level unsubscribe), and destination management is
  **admin-only** because the list is a list of email addresses and
  the policy is every subscribed site's pager; a non-admin
  installation reads only the verification and health status of the
  destinations its own sites reference, never the address list:
  `POST /v1/destinations` - add an alert destination (starts
  unverified; double-opt-in);
  `GET /v1/destinations` - list with verification, suppression, and
  policy state;
  `POST /v1/destinations/{id}/resend` - resend verification,
  rate-limited;
  `PATCH /v1/destinations/{id}` - the destination **policy**, guarded
  by `destination_revision`; suppression is **not** writable here,
  only re-verification clears it;
  `DELETE /v1/destinations/{id}` - deletes an **unreferenced**
  destination immediately; one still referenced by any site's
  notification settings answers `409 destination_in_use` naming the
  sites, so removal is always an explicit detach-then-delete and a
  shared pager is never silently unplugged from sites the caller
  forgot.
  Policy is **two independent suppression bits**, not a ladder,
  because "digest only" and "digest off" suppress different channels
  and are incomparable - any single ordering re-enables one channel
  while suppressing the other. The bits:
  `{ immediate_disabled, digest_disabled }`. An immediate-class
  unsubscribe token sets `immediate_disabled`; a digest token sets
  `digest_disabled`; **tokens only ever set bits true** (monotonic
  OR, so no token, however old or replayed, can re-enable any mail),
  while the admin `PATCH` may clear either bit. Both bits true means
  no **alert** email to that destination - the in-app timeline is
  unaffected - and the derived display states (normal, digest-only,
  immediates-only, silent) are presentation, never storage. The
  bits govern **alert** cadence, not every message class; which
  message class may reach which destination in which state is the
  **delivery spec's mail eligibility matrix**, the single authority
  on that question - this spec contributes the stored bits and the
  rule that no automatic send ever reaches a suppressed destination
  (the explicit, rate-limited re-verification resend is the one
  deliberate exception, because it is the path out of suppression
  and is a human's own request).
  **Every** mutation of the resource
  advances `destination_revision`: token redemptions, bounces and
  complaints, confirmation, re-verification, policy `PATCH` - so a
  desktop write racing a newer unsubscribe fails its revision guard
  instead of silently overwriting it. Address identity is
  **normalized and unique**: normalization trims whitespace and
  lowercases the domain part (the local part stays byte-exact, per
  the mail RFCs), and a `UNIQUE (account, normalized_address)`
  constraint is the convergence point - creating a destination whose
  normalized address exists returns the existing resource (`200`,
  not a duplicate row), and two concurrent creates converge on one
  row at the constraint instead of splitting sites across duplicate
  resources that would defeat destination-level unsubscribe.
  Addresses are
  immutable: "changing where alerts go" is a notification-settings
  association switch to a different destination, and that switch -
  not any address mutation - owes the courtesy note to the
  previously subscribed address. The note is not a hope: the switch
  transaction writes an **outbox row keyed by
  `(site, notification_revision)`** alongside the settings update,
  and delivery drains the outbox with at-least-once retries. The
  guarantee is stated honestly: the row key prevents duplicate
  _rows_, not duplicate _sends_ - a worker can send, crash before
  recording success, and retry - so the send itself carries a
  deterministic provider idempotency key derived from the outbox
  identity, which deduplicates retries within the provider's
  idempotency retention window (24 hours at Resend); a retry beyond
  that window is delivered at-least-once, possibly twice, and the
  contract says so rather than pretending exactly-once across an
  unbounded horizon (delivery spec owns the content).
  A site subscribes to a destination through its notification
  settings (`destination_id` reference); the settings also hold the
  site's **measurement threshold rows**
  (`{series_id, bound: upper | lower, value, hysteresis}`, opt-in,
  none by default - crossing and hysteresis semantics are the
  delivery spec's), revision-guarded with the rest of the settings;
  and destination policy
  **takes precedence over** site notification settings: digest-only
  demotes every subscribed site's immediates, digest-off silences
  the digest to that address entirely, both visibly.
- `POST /v1/sites/{site}/alert-webhooks` - create an outbound alert
  webhook (secret minted and shown once);
  `GET /v1/sites/{site}/alert-webhooks` - metadata and secret
  fingerprint, never the secret;
  `POST /v1/sites/{site}/alert-webhooks/{id}/test` - signed,
  explicitly-marked test delivery;
  `POST /v1/sites/{site}/alert-webhooks/{id}/rotate` - secret
  rotation with a bounded dual-validity overlap;
  `DELETE /v1/sites/{site}/alert-webhooks/{id}`.

Reports (installation token; rendering rules in the delivery spec):

- `POST /v1/sites/{site}/reports` - create a report registry row from
  current connect state with explicit content toggles; returns the
  `report_id` and the link.
- `GET /v1/sites/{site}/reports` - the registry with provenance.
- `POST /v1/sites/{site}/reports/{id}/revoke` - immediate revocation;
  the render path looks the token up by hash in the registry, so
  revocation takes effect regardless of the token's own expiry.

Baselines (installation token):

- `GET /v1/sites/{site}/verified-good` - the current verified-good
  profile per fact family, with the provenance of each fact and the
  revision the acceptance endpoint guards on.

Account (**admin** installation token; the admin flag, its grant and
revocation endpoints, and the erasure confirmation echo are defined
with the credentials):

- `GET /v1/account` - entitlement snapshot: allowance, slots in use,
  slot leases with release times, the over-plan set, subscription
  state, the account-scope id, and the admin list.
- `POST /v1/account/admins` and
  `DELETE /v1/account/admins/{installation}` - grant and revoke the
  admin flag; revoking the last admin answers `409 last_admin` (the
  atomic invariant with the credentials).
- The recovery flow is an API, not prose - and its read is
  deliberately **not** admin-gated, because the requester is by
  definition not an admin:
  `POST /v1/account/recovery` (any installation of the subscription) -
  create the pending request; at most one exists, and a replay or a
  second requester gets `200` with the existing pending state, never
  a second request. Creation is transactional with its alarm bell:
  the same transaction that commits the pending row writes the
  security notices into a **reserved-priority security outbox**
  (one row per **verified destination** - and only those, matching
  the delivery spec's matrix; installations have no email address or
  push endpoint, so their defined notification channel is the
  pending-recovery header on every authenticated response plus the
  authenticated `GET` - a **channel, never an exposure fact**: reads
  stay safe-method reads, and exposure is recorded only through the
  explicit acknowledgment action below, only from a request-time
  admin), so a
  crash after commit cannot leave the 72-hour timer running with
  nobody warned - the timer and the warnings are one write. The
  security lane is exempt from the per-destination and per-account
  send caps (the delivery spec's caps backstop alert mail, not the
  takeover alarm) and drains with the same at-least-once,
  provider-idempotency-keyed contract as the courtesy outbox. A
  queued row is not yet a warned owner, so promotion runs on **one
  complete persisted predicate**, with the exposure facts stored on
  the recovery record as they occur. Both exposure classes are
  channels the license key cannot mint, because the activation
  exchange means "some other installation fetched" is a fact the
  requester can manufacture with a second activation - request from
  A, fetch from B, admin at hour 72 without an owner ever seeing
  anything - so a plain other-installation read is **not** exposure.
  The facts are: `notice_accepted_at`, the first provider-accepted
  security notice to a verified destination (destinations are
  admin-created and owner-confirmed, so the key alone cannot add
  one); and `acknowledged_by_admin_at`, the first acknowledgment -
  `POST /v1/account/recovery/ack`, idempotent, defined with the
  endpoints below - by an installation, other than the requester,
  that **held admin when the recovery was requested and still holds
  it, under the same grant, at the moment of the ack**. The
  request-time end: the admin set is snapshotted onto the recovery
  record at creation, each membership with its grant identity (every
  grant is an audited event, so each has one), so an admin the
  completed recovery itself would mint can never be its own witness.
  The ack-time end: a membership revoked mid-pending stops being a
  witness the moment the revocation lands, because revocation is
  exactly how an owner declares a device distrusted - the stolen
  admin laptop whose flag was just pulled must not be able to arm
  the 72-hour clock by auto-acking the banner. Same grant, not
  merely admin-again: a revoke-and-regrant is a new grant and does
  not silently restore witness standing for a recovery that predates
  it (the live admin who performed the regrant can ack or cancel
  themselves - conservative costs nothing here). The desktop surfaces the
  `X-SiteCMD-Recovery-Pending: {eligible_at}` header, carried on
  every authenticated response while a recovery pends, as a blocking
  banner whose render fires the acknowledgment POST automatically -
  exposure is still display, not a user ceremony, but it rides a
  write verb, because a `GET` that mutates account-authority state
  breaks safe-method semantics and turns cache warmers and
  prefetchers into witnesses. Every installation acks; only the
  prior-admin device's ack is the recorded exposure fact - an admin
  who sees the alarm and chooses not to cancel is exposure, anyone
  else is just an audience the key could have hired. The completion
  CAS evaluates the whole predicate, not part of it: pending, and
  uncancelled, and either (an exposure fact is set **and** 72 hours
  have elapsed **since the first one** - the response window: the
  owner gets three full days to cancel after the alarm demonstrably
  reached them, however late that happens) or (**14 days elapsed
  with no exposure fact ever recorded** - the last-resort branch).
  The branches are **mutually exclusive**, which is what makes the
  "three full days, however late" promise true rather than
  approximately true: exposure on day 13 makes eligibility day 16,
  and exposure landing after day 14 - the fallback ripe but the
  timer not yet fired - retracts fallback eligibility and starts the
  72-hour window, the conservative direction (an owner's device
  coming online late buys the owner time, never the requester;
  `first_exposure_at` is immutable once set, so the window cannot be
  re-extended). Anchoring the 72
  hours to exposure rather than to the request is load-bearing: a
  request-anchored clock with exposure at hour 120 promotes the
  requester in the same instant the admin's device first renders the
  banner - an alarm and a verdict in one breath, no cancellation
  window at all - and since exposure can never precede the request,
  the exposure branch still never completes before hour 72. The
  last-resort branch is deliberately exposure-free
  because the topology it serves cannot demonstrate exposure: the
  last-admin invariant means a lost admin device always leaves its
  membership behind, so "sole installation" never describes this
  case, and an account whose only destinations are suppressed or
  unverified would otherwise deadlock forever - locked out precisely
  because its pager was broken, which is when recovery matters most.
  Fourteen days of a visible pending state, a header on every
  response, and attempted notices is the stated, accepted residual
  risk; an implementation that omits either branch is wrong in one
  of two opposite ways (permanent lockout, or exposure-free
  promotion at 72 hours), which is why the predicate is written out
  here;
  `GET /v1/account/recovery` (any installation) - the pending state:
  requester, requested time, eligible time, or none - a read with no
  side effects;
  `POST /v1/account/recovery/ack` (any installation) - the explicit,
  idempotent acknowledgment: records the caller's ack timestamp once,
  sets `acknowledged_by_admin_at` only when the caller is in the
  request-time admin snapshot, **currently holds admin under that
  snapshot's same grant**, and is not the requester, and answers
  `200` with the pending state either way (replays are `200` no-ops).
  The live-grant check and the exposure write are **one conditional
  statement, never a read followed by a write**: a check-then-write
  pair leaves a window where the ack reads grant G live, the owner
  revokes G, and the ack still writes the exposure fact - the
  distrusted device arming the clock after its authority was pulled,
  exactly what the same-grant rule exists to prevent. The write is a
  single guarded update whose predicate joins the live admin row on
  the snapshot's grant identity (one atomic statement or batch), so
  ack and revocation serialize with no third interleaving, and the
  recovery fixtures pin both serial orders plus the later-channel
  case: revocation first means **this ack writes no
  `acknowledged_by_admin_at`** - it silences that installation only,
  and a later provider-accepted notice, or an ack from another
  installation that still qualifies under the request-time snapshot,
  establishes exposure exactly as ever (the third fixture pins it:
  revocation wins the race, a valid notice then lands, and the
  72-hour window opens); ack first means the exposure stands,
  because it was recorded while the grant was demonstrably live and
  the revocation landed after a valid witness had already seen the
  alarm;
  `DELETE /v1/account/recovery` (admin) - cancel. Completion is
  server-side through one conditional update whose predicate is
  **exactly**:
  `pending && uncancelled && ((exposure_exists && now >= first_exposure_at + 72h) || (!exposure_exists && now >= requested_at + 14d))`
  - the full predicate, in the CAS itself, never a reduced one: a
    CAS that checks only elapsed time either promotes an unexposed
    request at 72 hours or is paired with scheduling that starves an
    exposed one, and `first_exposure_at` (the earliest recorded
    exposure fact) is immutable once set - later exposure facts never
    move it. `eligible_at` is **derived display, never an input**,
    and it reports exactly what the CAS will do:
    `first_exposure_at + 72h` when exposure exists and
    `requested_at + 14d` otherwise, recomputed the moment exposure
    is recorded. The recovery fixtures pin the boundary trio:
    exposure on day 13 (eligible day 16, never day 14), exposure at
    exactly day 14, and exposure landing after day 14 with
    completion not yet fired (no fallback eligibility; eligible at
    exposure plus 72 hours). Completion is timer-driven against the
    predicate; no write promotes in the same breath it warns.
    Completion and cancellation race on a
    single row and exactly one wins. A pending recovery refuses no
    request: the `X-SiteCMD-Recovery-Pending` header announces it on
    every authenticated response until it completes or is cancelled.
    `last_admin` and `destination_in_use` are members of the closed
    error vocabulary like every other code in this spec.
- `PUT /v1/account/protected-sites` - the user-chosen protected list
  the over-plan selection rule consults, revision-guarded.
- `GET /v1/account/export` - account-wide export: every site's export
  stream plus account-scoped records, same record registry.
- `POST /v1/account/erase` - account-level erasure: every connected
  site's erase cascade plus account-scoped state (provider
  connections, protected list, account settings), with the same job,
  status-token, and receipt contract as site erasure.

Export (installation token):

- `GET /v1/sites/{site}/export` - the tenant's stored state as
  streamed NDJSON, one record per line, every line
  `{ "record_type": …, "schema_version": …, … }` drawn from the
  versioned export record registry in the retention section. What the
  service holds is small and enumerable by design; export is the
  proof, so the registry is closed both ways: every stored family is
  classified there into exactly one of its four classes
  (tenant-exportable, operational, security, secret), everything
  tenant-exportable appears in the stream, and every exclusion
  carries its class, retention, and rationale.

Triggers (webhook credentials; execution semantics in the hosted scanner
spec, contract shape here):

- `POST /v1/hooks/vercel`, `POST /v1/hooks/netlify` - provider doors.
- `POST /v1/hooks/{site}/deploy` - generic door, HMAC-signed.

Verified-good baseline (installation token):

- `POST /v1/sites/{site}/verified-good/accept` - the explicit
  accept-as-new-baseline action for a drifted profile field, distinct
  from dismissing the drift finding. The request names the field, the
  `based_on_profile_revision`, and the expected value digest (or source
  observation id), so a delayed acceptance cannot bless a value the
  user never saw: a newer value having arrived is `409 stale_revision`
  whose problem details carry the current state. The response returns
  the new profile revision and the accepted source provenance.
  Lifecycle semantics in the hosted scanner spec.

Credential management (installation token): `POST /v1/tokens/ci`,
`POST /v1/tokens/webhook`, `POST /v1/tokens/{id}/rotate`,
`DELETE /v1/tokens/{id}`.

**Internal service-binding surface.** The scan worker commits hosted
observations to connect over the service binding, never over the public
API: `commitHostedObservation` carries the scan id, **the scan
generation**, a payload digest, the captured basis (deployment head or
no-deployment state, `scope_revision`, `event_sequence`, and the site
`erasure_epoch` the scan started under), `evaluation_time`, the
execution profile and manifest digest, coverage, occurrence outcomes,
measurement samples, external-corpus input and result digests where
applicable, and the terminal status; the response states `applied`,
`history_only`, or `rejected` with the reason and the current basis,
so the coordinator knows whether to schedule a replacement scan.

**Generation crosses the fence, and connect is the linearization
authority.** A service-binding call is asynchronous: a generation-N
execution can pass its local fence, start the call, lose authority to
a recovery that creates N+1, and still reach connect first. Local
bump-then-register would leave exactly that window open, so the order
is inverted: connect mints `(scan_id, generation: 1)` when it requests
the scan, and recovery **advances the generation at connect first**,
via `advanceScanGeneration(scan_id, expected_current, next)`, a
compare-and-swap with three outcomes: `advanced` (the CAS won;
generation N is now rejected forever, and the coordinator adopts N+1
locally and resumes), `already_committed` (the scan completed under
the old generation while this recovery was starting; recovery stops,
there is nothing to resume), or `stale` (another recovery already
advanced further; adopt the returned current generation). The call is
idempotent by `(scan_id, next)`, so a crash between the connect CAS
and local adoption re-runs the same advance and converges. Connect
accepts a commit only under its registered generation, and commit
idempotency is by `(scan_id)` with a hard rule: the same scan id
arriving with a different generation or a different payload digest is
rejected, never replayed. The interleaving fixtures include
old-generation-versus-recovered-generation commits and a
crash-between-CAS-and-adoption recovery.

**The apply is fenced at connect, not only at the scanner.** The scan
coordinator's Durable Object fence protects the scanner's own storage;
it cannot extend a transaction across a service-binding call, and
tenant truth lives at connect. Connect therefore applies every
observation through a per-site authority check **inside the same
database transaction as the application itself**: the site row's
`{phase, erasure_epoch, current head, scope_revision}` are compared as
conditional predicates of the applying transaction, and disconnect,
erase, deployment recording, and scope mutation update that same row
in their own transactions, so a commit racing any of them loses
deterministically (`history_only` on basis change, `rejected` on phase
or epoch change) instead of writing tenant state that was erased or
re-scoped mid-flight. One implementation rule is normative because the
database makes it easy to get wrong: **a failed authority predicate
must fail a statement and abort the batch**, not merely update zero
rows, because batch rollback triggers only on statement failure; the
predicates are therefore written to violate a constraint when the
authority check does not hold. The conformance suite includes explicit
interleaving fixtures: erase-during-commit, disconnect-during-commit,
deploy-during-commit, and scope-change-during-commit. The operation is
idempotent by scan id and appears in the OpenAPI document's internal
section with the same rigor as the public surface.

## Provider connections

Vercel and Netlify are connected through a first-class
`provider_connection` resource; nothing in this protocol assumes an
ambient, already-connected provider. Connections are **many per
account**, uniquely keyed by
`(provider, external account/team/installation id)`, because the
target customer manages client sites that live across different
provider teams and client-owned accounts; a single-connection model
would exclude exactly the agency shape the RFC targets. A site binds
`{connection_id, external_project_id}`.

- **Creation.** `POST /v1/provider-connections` with the provider name
  creates a `pending` connection and returns the provider's authorize
  URL carrying a connect-minted single-use `state` token (bound to the
  connection id, 15-minute TTL, hash-stored). The desktop opens that
  URL in the system browser; the provider redirects to connect's
  callback, which validates `state`, performs the code exchange
  entirely server-side, and stores the provider credential encrypted
  at rest. The desktop polls `GET /v1/provider-connections/{id}` for
  the `active` transition; the completion page in the browser carries
  no tokens. No provider credential ever passes through the desktop or
  appears in a URL, a log, or an export.
- **Scope.** The minimum the two jobs need: reading the project list
  (for site verification) and provisioning deploy webhooks. Granted
  scopes are recorded on the resource and shown before authorize.
- **Project binding.** The provider-attested verification route names
  `{connection_id, external_project_id}`; the binding is stored on the
  site, and the projects endpoint exists so the desktop can present
  the choice. One provider project backs at most one connected site;
  the ownership claim is exclusive.
- **Webhook provisioning.** On site connection, connect provisions the
  provider webhook for the bound project and holds the provider-side
  signing secret; the hook points at the matching provider door.
  Provisioning state (`provisioned | failed | removed`) is site state:
  a webhook the provider reports gone is a protection degradation
  (delivery-spec wake-up), never a silent gap. Whether reaching a
  given Vercel plan requires an Integration rather than an account
  webhook is a recorded build-time verification item (hosted scanner
  spec); the resource is provider-generic so either mechanism hangs
  off the same lifecycle, including an Integration's own
  configuration-removed and secret-rotation events.
- **Revocation, both directions.** `DELETE` deprovisions webhooks
  (best-effort, outcome recorded), discards the provider credential,
  and degrades dependent sites' deploy triggers visibly. Uninstall or
  revocation on the provider side surfaces as failed delivery or a
  provider notification and degrades the same way, with the
  connection marked `revoked` and the observed cause. Reconnecting is
  a new authorize round on the same resource.
- **Custody.** Provider credentials are never exported, never logged,
  and erased in the account cascade; the export registry excludes
  them by name.

## Notification settings, destinations, and outbound webhooks

The delivery spec's user controls exist as revisioned resources, not
prose:

- **Notification settings** (`GET`/`PUT`, `notification_revision`
  guard): per-site mute, severity floor, digest cadence, and content
  mode. `PUT` is full replacement under the guard, and every change is
  an event, so the timeline can explain why the pager went quiet.
- **Destinations** are account-level resources (endpoint inventory)
  with their own small lifecycle: created
  `unverified`, double-opt-in always (content owned by the delivery
  spec), promotion to `verified` only by the confirmation action,
  resend rate-limited, deletion **conditional** (`409
destination_in_use` while any site references it, exactly as the
  endpoint contract states - this sentence used to say "immediate"
  and lost). Two overlays ride the
  resource, both visible in the list and in every subscribed site's
  protection health: **suppression** (bounces and complaints,
  cleared only by re-verification) and **policy** (digest-only or
  digest-off, set by the unsubscribe token, reversed through the
  revision-guarded `PATCH`). Policy beats site settings; suppression
  blocks every **automatic** send, with the explicit, rate-limited
  re-verification resend as the one human-initiated exception (the
  delivery spec's eligibility matrix is the authority).
  Sites reference destinations from their
  notification settings; deleting a site removes its references,
  deleting the account removes the destinations.
- **Outbound alert webhooks** are machine destinations with secrets:
  secret minted and shown once, listed thereafter only as a
  fingerprint, tested via an explicitly-marked signed test delivery,
  rotated with a bounded dual-validity overlap so consumers can roll
  without a delivery gap, deleted immediately. Deliveries are signed
  in the [Standard Webhooks](https://www.standardwebhooks.com/)
  format: `webhook-id` (the attempt id, stable across retries),
  `webhook-timestamp` (each try's own send time), and
  `webhook-signature` (`v1,` plus base64 HMAC-SHA256 over
  `{webhook-id}.{webhook-timestamp}.{raw body}`, with both
  generations' signatures space-separated during a rotation
  overlap). The secret is shown as `whsec_` plus base64, and
  receivers verify with any Standard Webhooks library, which also
  refuses a stale timestamp, so a captured delivery cannot be
  replayed.

All three ride export as registry record types and erase in the
cascade.

## Report registry

Hosted reports are registry rows first, links second:

- Creation requires the installation token. The alert-view nonce
  cannot create reports because its authority is limited to the alert
  view.
- **A report is a frozen snapshot, not a live view.** Creation
  records `as_of_event_sequence` and stores a
  **`report_projection` (version 1)**: structured JSON, never HTML,
  in the registry row itself (D1, inside its 2 MB row bound), capped
  at **256 KB** with per-collection item bounds (severity and
  category rows at most 50, trend series at most 400 points, every
  string length-bounded). A projection that would exceed a bound
  **fails generation visibly** (`422 report_too_large`, naming the
  bound; the user narrows the content toggles) - deterministic
  refusal, never silent truncation. The render path serves exactly
  that stored projection with its "as of" time displayed, under the
  delivery spec's context-aware HTML escaping contract (DOM text
  nodes or autoescaping template, never raw-HTML or in-script
  interpolation; its hostile-alias report fixture executes in a real
  browser), so
  a shared link never silently changes underneath the client it was
  shared with, a revoked-then-erased report has nothing left to
  render, and the score shown was computed once, at creation, by the
  shared scorer.
  The projection rides export with the row. Retention follows the
  retention table, with rows retained for the life of the site and
  links bounded by their TTL.
- The row also records content toggles, creator installation,
  creation time, TTL, and revocation state. The link is an opaque
  random token (32 bytes, base64url); the row stores only its
  SHA-256, alongside the row's own expiry. There is no signing key
  and nothing to rotate: the render path looks the row up by the
  presented token's hash and requires it to be present, unexpired,
  and not revoked, so `revoke` is immediate regardless of the
  token's own expiry.
- The render path is `GET /r/{token}` on the connect origin with
  `Cache-Control: no-store`, `X-Robots-Tag: noindex`, a strict CSP,
  no third-party assets, and `Referrer-Policy: no-referrer`. What a
  report may contain at each toggle is the delivery spec's contract.
- The report's score is computed by the shared scorer artifact
  (hosted scanner spec, tier one) from the score inputs this
  protocol carries - occurrence severity and confidence, group state
  for the active-set predicate, manifest category. An independent
  reimplementation of the score in worker TypeScript is forbidden by
  the parity contract.

## Transient projections at ingest

The hosted scanner spec's route-profile MACs and the server-derived
verified-good baseline consume canonical projections of observed
content. This is the wire contract that carries them; without it,
connect could not mint MACs or seed baselines from desktop evidence at
all.

- The desktop web snapshot gains an optional `transient` envelope,
  typed and bounded: per route, the canonical document projection the
  route-profile MAC is minted from, plus the fact families the
  verified-good baseline needs (certificate identity and expiry, the
  security-header allowlist projection - never the raw header set -
  resolved origin and DNS facts, and the detected library set). The
  hosted scanner spec owns the projection schema
  (`transient_projection: 1`, exact DTOs, canonicalization and
  bounding rules, the header and TXT allowlists) and its version;
  this spec owns the envelope bounds: at most 256 KB per route and
  4 MB per submission inside the existing body limit, and an oversize
  envelope is rejected whole (`422`), never truncated - nothing
  silently truncates.
- `commitHostedObservation` carries the same typed projections for
  hosted scans, alongside the digests it already carries.
- **Never persisted, never logged.** Projections live exactly as long
  as ingest needs to mint MACs and update baseline candidates, inside
  the sanitize-before-persist boundary the hosted scanner spec names.
  They never appear in storage, exports, logs, or error payloads;
  what persists is what always persisted: keyed MACs, derived
  baseline facts, digests. The hostile-fixture suite includes a
  projection-echo probe proving error paths do not reflect envelope
  content.
- The derived baseline is readable: the verified-good endpoint
  returns the current per-family profile with the provenance of each
  fact (which observation seeded or promoted it) and the revision the
  acceptance endpoint guards on.

## CI provenance binding

`exact` is an authority claim - it lets code evidence govern at its
deployment - so it cannot be self-asserted by whoever holds a copied
CI token:

- **GitHub Actions door.** The CI submission presents the workflow's
  GitHub OIDC token alongside the `sitecmd_ci_` credential. Connect
  validates issuer, audience (the connect origin), and token
  lifetime, then binds the `repository_id`, `sha`, `ref`, and
  `workflow_ref` claims. `provenance.kind: "exact"` is granted only
  when the OIDC `sha` equals the submission's deployment SHA **and**
  the claims match the constraints recorded on the CI token at
  creation: the repository identity, and an expected `workflow_ref`
  pattern plus ref constraint the user pins when minting the token
  (the trusted workflow is chosen once, not inferred per request). A
  submission whose OIDC claims fall outside the pinned constraints is
  rejected with a visible error, not silently downgraded, because a
  wrong-workflow submission is a misconfiguration or an attack and
  either deserves a loud answer. The claims used are recorded on the
  submission for audit. The shipped CLI obtains this witness from GitHub's
  runner-provided `ACTIONS_ID_TOKEN_REQUEST_URL` and
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, with the connect origin as audience; the
  job must grant `permissions: id-token: write`. A GitHub Actions submission
  that cannot obtain the witness fails visibly rather than silently entering
  the generic lane.
- **Generic CI is `unattested`, permanently non-governing and
  non-causal.** Not `compatible`: that kind carries the RFC's
  known-ancestor-with-unchanged-files predicate, which an unverified
  bearer cannot prove any more than it can prove exactness. There is
  no corroboration upgrade: an ordering authority confirming a SHA
  exists proves the deployment happened, not that the submitted
  fingerprints were computed from that checkout, so it must not
  confer governing authority on a bearer who could have invented a
  clean snapshot naming the real SHA. The only future path to
  `exact` for non-GitHub CI is a verifiable workload identity or a
  signed artifact-provenance attestation that binds repository, SHA,
  trusted workflow identity, and the submitted snapshot digest;
  until a provider's mechanism meets that bar, its submissions
  inform but never verify.
- A stolen generic CI token therefore buys non-governing observation
  submission; a stolen GitHub CI token buys nothing outside its
  pinned workflow. The residual trust boundary is the pinned workflow
  itself: a compromised trusted workflow can lie about its own
  checkout, which is exactly the boundary every OIDC-based deploy
  trust model shares, and is stated here so nobody mistakes the
  guarantee for more. Rotation and revocation are unchanged.

## Physical write strategy and the shard key

The v1 limits (4 MiB submission bodies, 50,000 occurrences, 20,000
coverage exceptions, 200-mutation batches) must be physically writable inside
D1's real invocation limits: bounded statements per batch, bounded
bound parameters per statement, serial per-database execution. The
contract:

- **Staged, then flipped.** Large applications write in two phases:
  non-authoritative staging rows in bounded chunks (each chunk an
  ordinary D1 batch well inside statement and parameter limits,
  idempotent by submission identity plus chunk index), then one
  guarded finalize statement that validates the fence predicates
  (phase, erasure epoch, head, scope revision, revision guards) and
  flips snapshot visibility atomically. Readers never see a partial
  application because visibility is a single flipped row; an
  abandoned staging run is garbage-collected by TTL. The capacity
  transaction already stages; this generalizes the same shape to
  every large apply.
- **Staging is fenced at every chunk, not just at finalize.** A
  staging row is tenant data the moment it lands, so a chunk written
  after erasure would recreate what erasure just destroyed and let it
  sit until TTL. Every chunk insert is therefore a guarded
  `INSERT … SELECT` that atomically requires the site row to exist in
  the expected phase at the expected `erasure_epoch` (inserting zero
  rows, and failing the chunk visibly, when the guard misses), and
  staging tables carry a cascading foreign key to the site row, so
  the erase cascade removes in-flight staging in the same delete and
  any later chunk from a delayed worker or a redelivered queue
  message finds no parent to select against. Fixtures:
  chunk-after-erase, erase-between-chunks, and
  queue-redelivery-after-erase all prove zero surviving rows.
- **Benchmarked, not assumed.** A conformance benchmark at the exact
  contract maxima runs against a real D1 database and is a release
  gate for the connect worker, so a platform-limit change fails a
  test instead of a customer. The limits table is only as true as
  this benchmark.
- **The shard atom is the account; `site_id` partitions within it.**
  Every tenant-scoped table keys on `site_id` first, but the unit
  that moves together is the account, because real account-global
  state exists and is promised: the `alert_sequence` stream, the
  allowance and its leases, the protected list, account export and
  erasure. Sharding below the account would turn every one of those
  into a cross-database protocol for no benefit. One global D1 is
  the v1 deployment, not the contract: because no query joins across
  accounts, moving a hot **account** to its own database later is a
  routing change, not a data-model migration - and that is the claim,
  deliberately not made for individual sites.
- **The control store is its own database, physically outside every
  tenant shard.** The safety journal, the receipt-ledger records,
  the `restoring` state with its restore epochs, and the monotonic
  fencing counters live in a dedicated control D1 database with its
  own binding, never co-located with tenant rows - its entire job
  is surviving a tenant-shard restore, and a journal inside the
  shard it protects would be overwritten with it. Consistency:
  single writer per scope (the orchestration and the outcome
  recorders), serial per-database execution, journal-then-apply as
  the cross-store protocol (retention section). Failure behavior is
  **fail closed**: an authority-removing transition that cannot
  journal does not apply, and a claim that cannot read the
  restoring state does not send. **The control store's own history
  is an append-only R2 archive, not merely its D1**, and the
  cross-store protocol is crash-safe by declared write order, not
  by luck - there is no atomic commit spanning D1 and R2, so each
  phase has one authoritative sequence and every boundary a
  defined crash meaning, all fixtured: D1 row `preparing` first,
  then the R2 **prepared-marker** object, then the D1 CAS to
  `prepared`, then the shard apply, then the D1 outcome, then the
  R2 **outcome-marker** object (immutable, referencing its
  prepared-marker - `committed` and `aborted` are archive facts,
  never mutations of the prepared object). Restore replay reads
  the archive alone: prepared-marker plus committed marker
  replays, plus aborted marker skips, and a **prepared-marker
  with no outcome-marker repairs by the operation's declared
  repair class** - which deliberately makes the two
  indistinguishable crashes (R2 write landed but the D1 `prepared`
  CAS did not, versus a legitimate D1 row lost to Time Travel)
  harmless, because both repair identically; a D1 `preparing` row
  with no archive object is unborn and is aborted by the resolver,
  never replayed. **The archive's immutability is enforced by lock,
  facade, and chain together, with the platform's limits stated
  rather than wished away**: the archive prefix carries a Bucket
  Lock (ordinary R2 durability does not prevent deletion - the
  platform's retention mechanism does), and because **no
  create-only R2 credential exists** (tokens grant Object Read &
  Write or Read; a Worker binding exposes `put` and `delete`
  alike), least privilege here is an **application facade, named
  as such**: the appender module issues only conditional
  create-only puts (a put that fails rather than overwrites when
  the key exists), the pruner is an isolated job and the only code
  path that calls `delete`, a static guardrail forbids `delete`
  outside it, and the binding underneath remains write-capable -
  the Bucket Lock, not the credential, is the platform-enforced
  backstop. **Appends are serialized through one archive appender**
  (a Durable Object; its authority state lives in D1 and R2, so
  its own eviction or restore loses nothing), because D1
  serializes statements, not the D1-to-R2 sequence - without a
  single appender, head-before-write leaves a permanent gap under
  the lock and head-after-write lets concurrent writers fork the
  chain onto one predecessor. The position protocol is exact,
  and it knows that **a lost response is not a failed write**:
  the reservation records the expected object's digest and type,
  then the appender writes the object at `n` with the conditional
  create, then CASes `reserved` to `written`.
  **Self-referential objects get a three-state variant, because
  the digest rule and the position-nonce rule are circular for
  them**: a wrap envelope's content depends on its own position
  (the nonce), so its digest cannot exist at reservation time.
  The sequence is `nonce_reserved -> materialized -> written`:
  persist the reservation at `n` with no digest, encrypt
  **exactly once** using `n` as the nonce, CAS the computed
  digest into the reservation (`materialized`), then write the
  object - and this position **is** the wrap operation's
  prepared-marker position, not a second one. Recovery from
  `nonce_reserved` never retries in place: the nonce may already
  have been spent on a discarded ciphertext, so `n` is burned
  with its abort marker and the retry reserves a fresh position -
  a nonce encrypts at most once even across crashes. From
  `materialized` onward the ordinary rules below apply.
  Recovery on next
  wake reads position `n` first: if the expected object is there
  (digest validated), the PUT succeeded and only the response was
  lost - CAS to `written` and continue; if `n` is empty,
  conditionally create the **immutable abort marker**; if an
  unexpected object occupies `n`, that is an integrity fault and
  an alarm, never a shrug. **The abort create can itself lose the
  race** - the original timed-out PUT can commit between the read
  and the conditional create, which then fails - so recovery is a
  **loop over a four-way classification, not a three-arm
  sequence**, because recovery must recognize **its own committed
  abort marker**: abort markers are deterministic, so their
  canonical digest is derivable at the reservation, and the arms
  are expected object (advance to `written`), **valid abort
  marker** (advance to `aborted` - a lost abort response or a
  crash after abort commit lands here, not in an integrity
  fault), empty (conditionally create the abort marker), and
  invalid occupant (integrity alarm). On any conditional-create
  precondition failure, re-read and re-classify; advance the
  reservation only once one known object is confirmed; the loop
  terminates because an occupied position is
  immutable. The read-empty-then-PUT-lands overlap, the lost
  abort response, and the crash-after-abort-commit are each their
  own fixture. Always writing the abort marker would
  wedge the head on exactly the ordinary lost-response boundary,
  because the conditional create at an occupied position must
  fail - so that boundary is its own named fixture. Every
  consumed position bears exactly one
  object, the chain has no holes by construction, and abort
  markers are chain members like any other. **Checkpoint
  objects** embed the cumulative chain hash on a stated cadence -
  **at most 7 days apart**, well inside the 30-day restore
  horizon, with an **immutable genesis checkpoint written before
  the first member**, because a cadence alone leaves a new
  archive's first month without an anchor at
  `now - restore_horizon` - and the pruning anchor is an
  equation, not a
  sentiment: the cutoff is
  `max(archive_genesis_at, now - restore_horizon)`, retain the
  newest checkpoint at or before it plus every chain member after
  it, prune
  only strictly older objects; with the genesis rule, the 60-day
  journal lock, and
  the 7-day cadence, the anchor exists from the first object and
  is always still
  locked when it is needed - fresh-archive and idle-archive
  fixtures prove both edges. Restore replay
  **fails closed on
  any gap or chain break** - a missing tail is an alarm, never a
  shorter history - and concurrent-append, every crash boundary,
  and prune-then-restore are fixtured. An erasure's pending tombstone is archived
  before any fencing or deletion begins, because a control-store
  restore
  overwrites the very database holding the tombstones: an erasure
  completed after the chosen restore point would otherwise lose
  both its receipt and its tombstone, and a later tenant-shard
  restore would resurrect the erased data with nothing left to
  say so. Restoring the control store is therefore not
  break-glass-and-hope: restore the D1, then **replay the R2
  archive tail past the restore point before serving anything** -
  the archive is the authority, the D1 a queryable projection of
  it. The exact per-record retention table below governs both
  stores; the archive is Security-class in the derived inventory
  like the rows it mirrors. **Throughput and storage are budgeted
  with numbers, not adjectives**, and the budget is honest about
  what is per-delivery: first-initiation timestamps and terminal
  delivery outcomes **are** per-delivery volume, so they journal
  in the owning account's write coordinator (Durable Object
  storage - **isolated from tenant-shard restoration, not
  restore-immune**: SQLite-backed Durable Objects have their own
  30-day point-in-time restore, and new namespaces are
  SQLite-backed by platform policy, so the coordinator store is a
  third store with the same obligations as the other two - its
  PITR is a privileged operation run only through the restore
  orchestration, which fences the coordinator, restores, replays
  its delivery facts, and resumes by CAS; ordinary eviction and
  recreation preserve storage and reconcile nothing), never in
  the global control store. **The replay source exists and is
  named**, because facts that live only in a restorable store
  guard nothing: the coordinator flushes its delivery facts -
  first-initiation timestamps and terminal outcomes, monotonic
  and batched, each record site-keyed - to a **per-account R2
  delivery stream** under the
  same conditional-create facade and chain shape as the archive
  (own prefix, own per-account chain, journal lock rule), written
  by the account's own coordinator so per-delivery volume never
  funnels through the global appender. **The stream honors
  erasure by crypto-shredding, because nothing else can**: Bucket
  Locks forbid deleting the objects and the hash chain forbids
  holes, so stream records are encrypted under **stream keys**
  (distinct from the attempt-body keys) - and the key assignment
  follows the delivery shapes the schema actually permits, not a
  one-site fiction: each record splits into an **attempt-global
  projection** (no site fields) under the **account stream key**,
  plus **one per-site dependency projection per member site**
  (only that site's fields) under that site's key; pure
  account-scope deliveries carry only the account projection. A
  digest spanning sites A and B therefore has three encrypted
  pieces, and erasing A shreds exactly A's piece: B's recovery
  evidence survives, A's fields are unreadable, and replay
  converges the projections by attempt id, treating a
  missing-projection site as erased - which the tombstone
  confirms; the digest-erasure fixture runs from both directions.
  Site erasure destroys the site's stream key; account erasure
  destroys the account key **and every site-key generation** -
  journaled, replayed-on-restore destructions, all **before the
  receipt is issued** - and what the
  locked objects retain thereafter is ciphertext without a key,
  disclosed as exactly that in the retention table and the
  delivery spec's erasure language: **no ordinary read path
  returns the data after the receipt** - the ordinary-serving
  clause, verbatim - and the unreadable residue prunes with the
  lock. The forbidden phrase "every readable copy is gone" is
  banned by a guardrail because it contradicts the
  privileged-recovery clause every time it does.
  **The stream keys have a registry, a wrapping contract, and a
  KEK lifecycle - and the crypto-shredding claim is scoped to what
  the platform can actually keep**: each stream key is a data key
  (DEK) wrapped under a **versioned KEK** held in the worker's
  secret bindings, with a control-store registry row per generation
  (`{scope: account | site, scope_id, generation, kid, kek_version, wrapped_key, created_at, destroyed_at}`,
  Security-class). The wrap is its own exact stored envelope, and the envelope -
  whole - is the journal replay payload:
  `{wrap_version, kek_version, nonce, ciphertext}` with AES-256-GCM
  under the named `kek_version`, a 96-bit nonce stored raw, the
  128-bit tag appended to the ciphertext, and AAD binding the
  registry identity `{scope, scope_id, generation, kid}` - a
  wrapped key cannot be transplanted between rows any more than a
  body can. The nonce construction is exact, because "derived from a
  unique identity" is an assertion, not a construction (hashing
  or truncating unique ids can collide, and uniqueness is owed
  across **every** wrap under the same KEK): the wrap nonce is
  the **96-bit big-endian encoding of the wrap operation's
  archive chain position** - globally unique, reserved before
  use, and non-rollback by the chain's own construction (a
  consumed position bears exactly one object forever, a crashed
  wrap's position gets its abort marker and the retry reserves a
  fresh position, so a nonce encrypts at most once and an
  orphaned wrap's discarded ciphertext never shares a nonce with
  its successor). Global uniqueness trivially satisfies the
  per-KEK requirement, and no new allocator machinery is needed -
  the position protocol already is one. Concurrency, retry, and
  restore fixtures pin it. Stream records are sealed the way attempt
  bodies are, as a jose flattened JWE with a random IV, with the
  additional authenticated data binding
  `{account, scope, generation, stream_position, record_type}`;
  R2 object keys and metadata are tenant-free (opaque positions
  under account-hash prefixes). **Key lifecycle operations are
  journal members like every other authority transition, and a
  generation has states, not just existence**:
  `pending`, `active`, `destroyed` - **encryption is permitted
  only against an `active` generation, and activation is its own
  persisted final phase, not an afterthought of the marker**: an
  explicit idempotent `pending -> active` D1 CAS runs after
  validating the committed R2 outcome marker, because the general
  cross-store sequence ends at the marker and a crash right there
  would otherwise leave the generation `pending` forever - an
  encryption outage with no rule to resolve it. Recovery
  re-runs the CAS with **three outcomes, because absence and
  unavailability are different facts - and a successful empty
  read is not absence either**: a valid committed marker
  activates (idempotently); an abort happens only after the
  position resolver has confirmed an **immutable abort marker**
  at the position, never on a raw empty lookup, because a
  timed-out marker PUT can commit immediately after the empty
  read - the exact race the position protocol's recovery loop
  already closes, and an activation rule that trusted the empty
  read would reopen it as an aborted D1 generation under a
  committed R2 marker; and a timeout, 5xx, invalid
  marker, or chain-integrity failure is **neither** - the
  generation stays `pending`, alarms, and retries, because
  treating an unreachable archive as authoritative absence would
  abort live keys during any blip. All three arms, the
  lost-activation-response boundary, and the
  empty-lookup-then-original-PUT-commits race are fixtured. The gate exists
  because a registry row visible at `prepared` is an invitation
  for a coordinator to encrypt under a generation that recovery
  is about to abort, orphaning the ciphertext in the window. The
  members: create (its replay payload carries the complete
  wrapped-DEK envelope, so a
  control-store restore to before a live generation's creation
  does not orphan the ciphertext written after it; prepared
  creates abort - nothing encrypted under them, by the activation
  gate), rotate (compound, and its committed replay payload is
  the **complete new wrapped-DEK envelope** - never an
  instruction to re-run the unwrap, because after the old KEK
  retires there is nothing left to unwrap with: a restore to
  before the re-wrap resurrects the old wrapped value, and replay
  overwrites it with the archived new envelope), and destroy
  (removing: replays) - because a registry
  outside the journal was a live-site outage one legitimate PITR
  away. Destruction removes the wrapped
  material for **every historical generation** of the scope,
  advances the key generation so every cached unwrapped key dies
  with the epoch check already on each claim, and is journaled.
  **The KEK is the independently erasable root, and its lifecycle
  is what makes cryptographic erasure eventually true - with the
  platform's version semantics respected, not wished away**: a KEK
  held as an ordinary per-worker secret would survive its own
  deletion, because worker versions capture bindings and an older
  version remains rollbackable with the old value still inside.
  The KEK therefore lives in the **account-level secrets store,
  resolved at runtime through its binding** - never captured into
  a worker version - with **one immutable store entry per
  `kek_version`, never edited** (the platform documents that
  editing replaces the value for every consuming service, so a
  PATCH would be a silent global rotation), and the rotation
  deployment binds both the outgoing and the incoming version for
  the overlap. The store's deletion semantics are stated at their
  documented strength, no stronger: the platform documents
  create, get, and delete - **not** irreversible provider-side
  destruction of retained values, and a black-box test can prove
  only that SiteCMD can no longer call `get()`. The conformance
  item therefore proves what it can (no SiteCMD path recovers),
  the provider-side residual is named, and **the public privacy
  guarantee anchors on the 90-day confirmed deletion of the
  ciphertext itself** - key-independent and **confirmed, not
  "provider-independent"**: R2 holds the objects, so the
  strongest supportable wording is the provider's own documented
  irreversible deletion, executed and verified by us -
  with the 60-day KEK retirement as the earlier,
  SiteCMD-side-recoverability end; if Cloudflare publishes
  written destruction semantics for the store, the public claim
  may tighten to
  60, and not before.
  **Retirement is a sequence with its own deadlines, not a
  timestamp with hopes**: the sequence starts at
  `retirement_start_by = retire_by - 7 days`, each phase carries a
  bounded deadline - fence worker
  versions that referenced the retiring KEK (deployment pinned
  forward, rollback to referencing versions administratively
  disabled), complete the traffic move, drain running invocations
  through the bounded-invocation wait the quiescence machinery
  already defines, and then destroy the store entry - and the
  60-day bound does not wait for any of it: **at `retire_by` the
  runtime unconditionally refuses to wrap or unwrap under the
  version**, checked in code against the registry's immutable
  deadline, even when the store is unreachable and deletion
  cannot be confirmed. A store outage at the deadline delays the
  hygiene, never the cutoff - 60 days is exactly and honestly
  the **SiteCMD-runtime cutoff**, which is what "no
  SiteCMD-operated path" already promised; secret deletion
  follows as hygiene, alarmed if late. KEK
  versions rotate on a monthly schedule - live DEKs are re-wrapped
  under the new version (journaled rotations) - and retirement is
  **hard-bounded by deadlines stamped at activation, not by the
  successor's punctuality**: every version carries immutable
  `stop_wrap_by = activated_at + 30 days` and
  `retire_by = activated_at + 60 days`, because a `retire_by`
  anchored on successor activation inherits every scheduler,
  deployment, and store outage the successor can suffer - a
  delayed successor must never extend the old version's life. At
  `stop_wrap_by` the version stops wrapping **even if no
  successor is ready** (new DEK creation fails closed behind the
  rotation alarm), with re-wrap retries
  and alarms in between; delayed-successor and exact-boundary
  fixtures pin both deadlines; at the deadline, a live scope whose DEK
  still cannot be re-wrapped is **disabled and its stream history
  sacrificed** (the scope re-keys forward under a fresh
  generation, the loss surfaced as a protection-health event),
  the runtime refusal holds the date, and KEK deletion follows as
  hygiene - one broken tenant must not
  extend every erased tenant's recoverability, and if deadline
  events ever recur, the defined evolution is per-account KEKs,
  which contain the blast radius by construction. Runtime retirement makes every historical wrapped copy
  **unusable through SiteCMD** at once - D1 point-in-time
  history, archived payloads, all of them - and deletion of the
  underlying KEK follows as separately verified hygiene, exactly
  as the conformance fixture now distinguishes. The
  claim is therefore staged honestly, and
  a conformance test proves each stage: at the receipt, **no
  ordinary read path returns the data** - the ordinary-serving
  clause verbatim, never "every readable copy is gone", which the
  privileged-recovery clause would immediately contradict; until
  the wrapping
  KEK retires, a **privileged restore path plus the live KEK**
  could still recover erased projections (provider history holds
  wrapped keys up to 30 days, the archived payloads until their
  locks expire), and mandatory reconciliation re-destroys
  before anything serves; at KEK retirement - a **hard 60 days
  after the receipt at worst**, by the deadlines stamped at
  activation - no SiteCMD-operated path can recover; and at the
  90-day confirmed deletion, the ciphertext itself is gone -
  irreversibly, per the provider's own deletion contract - which
  is where the public guarantee
  anchors. The
  fixture decrypts a pre-erasure snapshot under the live KEK
  (must succeed, because claiming otherwise would be false) and
  then exercises **the production unwrap path at `retire_by`**,
  which must refuse - because the guarantee is the runtime
  fence, and a delayed store deletion leaves raw key material
  that still works cryptographically, so a fixture that tested
  raw decryption under "the retired KEK" would be testing the
  hygiene, not the guarantee. Actual store deletion is tested
  separately, as the hygiene it is. Live-site restore (key legitimately survives,
  replayed from the journal),
  erased-site restore (re-destroyed pre-serving), lost-key
  (fail-closed alarm), and partial-destruction fixtures pin the
  remaining edges.
  Coordinator PITR replays
  from that stream, and the bounded un-flushed tail (flush is 60
  seconds or 256 facts, whichever first) is re-derived from the
  live tenant shard's own attempt rows - which is why
  `first_provider_initiated_at` is an **attempt-schema field, not
  a coordinator memory**: both durable copies (shard row and
  coordinator record) are written **before the provider I/O**, in
  that order, a retry reuses the existing timestamp and never
  overwrites it, and no provider request is issued without both
  copies durable - so every partial failure fails toward an
  earlier clock, never a later one, and a flush-window loss cannot
  recreate the lifetime-extension bug the clock exists to prevent. The two
  sources together are complete. **At most one store is restored
  per orchestration run**, so no single run can put both copies
  of a fact behind the same point, and coordinator-only,
  shard-only, and combined-sequential-restore fixtures prove the
  guard each way;
  restore reconciliation consults the coordinators for delivery
  facts, and the coordinator store has its own rows in the
  retention table below - live, erased-account, and physical
  deletion all stated. What remains global is genuinely low-rate - authority
  transitions at human cadence, erasure records, key and counter
  state - budgeted at **10 sustained / 100 burst writes per
  second**, and the maximum-load test proving 10x the budget
  is a release gate beside the D1 conformance benchmark;
  if the budget is ever exceeded, the defined scaling path is
  partitioning the control store by account hash, a routing change
  under the same contract, well before D1's 10 GB bound with
  retention pruning as specified. **D1 edit authority - which on
  this platform includes migrations and restore in one
  permission - is held by the restore orchestrator alone**:
  migrations are applied _by the orchestrator_ as a deploy step it
  owns (CI triggers the orchestrator and never holds the
  credential - a token that can migrate can restore, so "CI
  migrates, orchestrator restores" was a distinction the
  platform's permission model cannot enforce), and human dashboard
  access at the account level is the one remaining path, held by
  the operating owner alone, audited, and named here as the
  residual rather than hidden.

## Allowance transitions

The plan allowance is enforced with states, not
adjectives:

- **Slot leases.** Connecting a site consumes an allowance slot.
  Disconnecting releases the lease only after a cooldown window (a
  beta operating value in the hosted scanner spec's operating
  configuration; the pricing pass may revisit it), so one paid slot
  cannot rotate through many sites inside a period. The account
  endpoint shows every lease and its release time, and connecting
  with all slots leased answers the allowance `422` naming the next
  release.
- **`sites_over_plan`.** When the allowance drops below the number of
  connected sites (downgrade, dunning outcome), the server ranks
  **every** connected site by one total order -
  `(protected descending, connected_at descending, site_id
ascending)` - and the winner set is the first allowance-many sites.
  One order, applied to the protected cohort too, so a protected
  list larger than the allowance still selects deterministically
  (and the account endpoint surfaces that condition visibly).
  `sites_over_plan` is
  the complement - defined this way around so no reading of the rule
  can suspend a protected site while an unprotected one keeps its
  slot. It is site state with the `scope_over_plan` grace shape:
  during grace, full protection with visible warnings; after grace,
  triggers and scheduled scans stop, state is retained under
  disconnected-site retention, and site operations answer the
  suspension-family `403`.
- **Restore and reconnect.** When the allowance rises again, over-plan
  sites resume automatically in winner-set order; resumption is an
  event and a digest line, never silent. For sites that stopped
  harder - disconnected-but-retained, or suspended through dunning -
  `POST /v1/sites/{site}/reconnect` (installation token) is the
  explicit transition: it validates the allowance and lease
  availability, cancels the retention clock, remints revoked site
  credentials (new webhook secret shown once; CI tokens are reminted
  by the user, since theirs live in CI secret stores), reprovisions
  the provider webhook through the stored
  `{connection_id, external_project_id}` binding when the connection
  is still active (and reports a visible degraded trigger state when
  it is not), and resumes triggers - all as recorded events. A site
  past its retention window is gone - physical expiry is real - and
  must be connected fresh.

## Deployment records and ordering

A deployment record is keyed
`(site, environment, provider, provider_deployment_id)` and stores the
provider's own facts: target, provider creation time, commit SHA and ref,
previous SHA when the provider or submitter supplies it, and receipt
time. Rebuilds and rollbacks are ordinary records: the same SHA deployed
twice is two records, because deployment identity is the provider's
deployment, not the commit. Records are created by provider hooks, by
`POST /v1/sites/{site}/deployments`, or embedded in a CI submission; all
three converge on the same identity key.

Redelivery of an event for a known deployment identity with identical
facts is success, not conflict: the response is a `200` no-op carrying
the existing record, mirroring the activation webhook's
`duplicate_ignored` posture, because providers retry deliveries and a
retry must converge, not error. Every new record stores
`immutable_facts_hash`, SHA-256 over the complete canonical fact set:
provider, provider deployment id, commit SHA, ref, previous SHA, target, and
provider creation time, including explicit nulls. `409 deployment_conflict`
is reserved for the same provider deployment identity arriving with a
different hash, which indicates a provider anomaly or a forged submission
and is never silently merged. Legacy rows without the hash are backfilled
only by an exact redelivery of their stored fact set.

Ordering is by deployment identity, never arrival, and **publish order
and creation order are different authorities**. Each adapter emits the
strongest fact the source offers, recorded on the record as `ordering`:

- `promotion` - the provider states this deployment became current for
  the environment (Vercel promotion and aliasing events, Netlify publish
  events). Establishes the current deployment; permits supersession and
  causal attribution. Delayed promotion events follow the same
  discipline as everything else here: promotions order only by facts
  that are actually ordered - an adapter-specific monotonic promotion
  sequence, an exact predecessor deployment id, or authoritative
  current-state reconciliation against the provider's own
  live-deployment answer. A unique event id is not an order, and tied
  timestamps are not a tie-breaker: a promotion that cannot be
  positively ordered against the applied head stays historical rather
  than moving currency on a guess.
- `publish_sequence` - a reliable production publish order without an
  explicit promotion event, and **never receipt order**: two authentic
  publish notifications can arrive swapped, and an older deployment must
  not supersede the real current one because its packet traveled faster.
  Qualifying facts must be genuinely causal: a publish ordinal
  **allocated atomically at successful publication** (an ordinal or run
  number assigned before concurrent jobs finish is creation order
  wearing a publish costume), or an **exact predecessor deployment id**
  advanced by compare-and-swap: the attested predecessor must be the
  record that is currently current. Commit SHAs do not qualify as
  predecessor references, because this contract explicitly permits the
  same SHA to deploy twice; `previous_sha` remains deployment metadata
  for the desktop's commit-range mapping, never an ordering authority.
  When the compare-and-swap fails, the predecessor edge is **stored,
  not discarded**: currency does not move, but when the missing
  intermediate deployment arrives the chain is reevaluated and currency
  advances to wherever the healed chain ends, so out-of-order delivery
  degrades ordering temporarily rather than permanently. The CI and
  generic doors' authenticated publish attestation (`published: true`
  from the pipeline that just deployed production) must carry one of
  those facts to qualify. Establishes the current deployment; permits
  supersession and causal attribution. This is what lets a post-deploy
  GitHub Action door govern at all.
- `creation_sequence` - build or creation order only. Orders records for
  history, but **cannot** establish currency, supersede anything, or
  authorize causal claims: a build finishing second may still publish
  first.
- `unknown` - no usable fact, including parallel deployments that cannot
  be ordered and records with missing `previous_sha` and unreliable
  timestamps.

**One ordering authority per environment.** Promotion facts and publish
attestations are independent ordering domains with incomparable
watermarks, so they cannot share the head: if the provider and the
pipeline disagree about what is current, one of them is wrong, and the
protocol refuses to guess which. The authority is a concrete identity,
not a vague domain:
`{ "kind": "provider" | "publish_attestation", "authority_id": "…", "epoch": n }`,
where `authority_id` pins one ordering namespace (one Vercel project,
one Netlify site, one attestation namespace: two Vercel projects are as
incomparable as Vercel and CI), and `epoch` increments on every
transition. Exactly one authority is active per environment, stored as
environment state independent of the deployment head, because a site
may select its authority before its first deployment ever happens. The
transition is its own operation,
`PUT /v1/sites/{site}/ordering-authority`, installation-token
authorized, idempotent, and guarded by the current epoch, and it is
recorded as an event.

Facts are evaluated against the authority under which they arrive:
facts from a non-authoritative namespace or from an earlier epoch are
recorded as history and never move the head. A transition carries the
standing current deployment across and freezes the old domain's
watermarks, and the new authority starts behind an **activation
barrier**, because its "first qualifying fact" could otherwise be a
delayed pre-transition event that rewinds the head and applies stale
evidence. Provider authority activates with authoritative current-state
reconciliation: the adapter asks the provider what is live now and
seeds the watermark from the answer. Publish-attestation authority
activates only on a fact causally rooted at the carried head (its
predecessor reference names the carried current deployment) or on an
explicitly seeded watermark from the transition request. Anything
earlier stays historical; watermarks do not translate between domains,
and no fact predating its own authority's activation may establish
currency.

A record's ordering fact may be **enriched, never downgraded**: a
deployment first seen through a build event (`creation_sequence`)
upgrades in place when the provider's promotion event or a qualifying
publish attestation for the same deployment identity arrives, and
currency is evaluated at upgrade time. Two conflicting upgrade facts for
one identity are a `409 deployment_conflict`, the same rule as any other
immutable-fact conflict.

Becoming current retroactively has a defined effect on evidence, with a
deterministic winner at every step. Canonical status is per
`(deployment, coverage scope)`: the first accepted CI snapshot for a
scope is that scope's canonical snapshot, so a partial `rule_set`
snapshot arriving early is canonical only for its own scope and can
never lock out a later complete-coverage snapshot, whose scope is its
own. Content equality is a hash over the snapshot body in the
repository's canonical serialization (sorted keys, the catalog packer's
convention; the exact field list lives in the OpenAPI document). The
rules for a later same-scope submission with different content are
explicit: it is **always state-inert**, recorded as an observation,
never applied and never alerting, and the submitting job receives
`200 { "status": "noncanonical_snapshot", "canonical_snapshot_id": "…" }`,
a success, because a matrix job that lost a race did nothing wrong and
retries must converge. An identical resubmission converges as an
ordinary idempotent no-op. Two same-scope snapshots for one deployment
that disagree mean nondeterminism or misconfiguration in the pipeline;
first-accepted-wins is the deterministic arbitration, and the loser
becomes visible history rather than a second competing truth.

Coverage-scope identity hashes the same semantic projection the parser reads:
the closed coverage fields only, with routes, checks, checks-not-run, and
exceptions normalized as deduplicated ordered sets. Unknown members and array
order cannot mint a new scope. One deployment retains at most 32 canonical
coverage scopes; the next distinct scope is refused with
`canonical_scope_limit` before any deployment fact or event is committed.

When chain healing or an ordering upgrade makes a deployment current
whose canonical snapshots were recorded as historical, the head-transition
transaction records a durable reconciliation outbox row. The request attempts
it immediately and the delivery cron retries it after a crash. Reconciliation
replays the deployment's complete pending canonical snapshot set in original
receipt order in **one evidence transaction**, marks the whole set applied
exactly once, removes the outbox row, and only then arms the deploy scan. A
current exact-CI head whose canonical snapshot has not yet been retained or
applied therefore cannot arm a scan. The evidence transaction appends an event
recording deferred application. When a healed chain contains
several snapshot-bearing deployments, **only the terminal head's
canonical set mutates current state or can alert**; the intermediates
were never current at any moment the server can stand behind, so their
snapshots remain historical. The head persists the applied-snapshot
markers naming the canonical snapshots whose evidence currently
governs. Evidence waits for currency; it is not lost to it.

Supersession and causal attribution require `promotion` or
`publish_sequence`. Under `creation_sequence` or `unknown` the record is
kept, scans still run, but nothing is marked superseded, no alert names
the deployment as the cause, and attribution provenance degrades honestly
(`stale` or `unknown`) rather than guessing. CI code-evidence governance
("while its deployment is current") follows the same rule: only a
deployment made current by `promotion` or `publish_sequence` governs. A
late-arriving webhook slots into history where its ordering fact says it
happened; scans and alerts attach to deployment records, not to webhook
deliveries. When a newer deployment for the same environment is recorded
while an older one's scan is pending, the older record is marked
superseded; what the scanner does about in-flight work is the hosted
scanner spec's, but the state contract guarantees the supersession is
recorded and that no alert ever attributes a finding to a superseded
deployment as if it were current.

Deployment records share the 90-day event retention, with one deliberate
exception: the **current deployment head** - the **complete current
deployment record**, enumerated: provider, provider deployment id,
target, commit SHA, ref, `previous_sha`, provider creation time,
receipt time, its ordering fact, and the immutable-facts hash; plus the
per-ordering-domain high watermarks (last applied promotion sequence,
publish ordinal, and predecessor chain head), the active ordering
authority `{ kind, authority_id, epoch }`, and the applied-snapshot
markers - is durable site state, retained for the life of the connected
site. The immutable fields are provider, provider deployment id,
target, commit SHA, ref, `previous_sha`, and provider creation time;
`immutable_facts_hash` is SHA-256 over exactly those fields in the
repository's canonical serialization (sorted keys, the catalog packer's
convention; exact spelling in the OpenAPI document). Ordering facts,
supersession state, and applied-snapshot markers are the enrichable
remainder, upgrade-only as specified above. Retaining the whole record,
not just the identity, is deliberate: exact provenance and the
desktop's commit-range mapping (which needs `previous_sha`) must not
evaporate after ninety quiet days, and a late resubmission of the same
deployment id must still be checkable for `deployment_conflict`. A quiet site must not
forget what is live: without the durable head, ninety silent days would
erase the currency anchor and a delayed old event could then move
currency, resurrecting exactly the staleness failures the ordering rules
exist to prevent. Only non-current history expires. The head appears in
`GET /v1/sites/{site}/state`, is included in export, and is erased with
the site.

## Retention, deletion, and export

Retention values, v1. This spec is the authority for these numbers; the
trust and privacy pages must state them, and the guardrail in the
disclosure section keeps the two in agreement. Precedent for the 90-day
figures: `REPLAY_RETENTION_DAYS = 90` in the activation worker and
`RAW_EVENT_RETENTION_DAYS = 90` in the telemetry worker.

| Data                                            | Retention                                                       |
| ----------------------------------------------- | --------------------------------------------------------------- |
| Current state (groups, occurrence records)      | Life of the connected site, compacted                           |
| Current deployment head and ordering watermarks | Life of the connected site                                      |
| Events, observations, deployments, alerts       | 90 days                                                         |
| Disconnected-site state                         | 30 days after disconnect, then expired                          |
| Idempotency-Key records (key stored as a hash)  | 24 hours                                                        |
| Route profiles (signatures, MAC key)            | Life of the site, compacted with routes                         |
| Measurement series                              | 90 days                                                         |
| Notification settings, alert webhooks           | Life of the connected site                                      |
| Destinations (account-level)                    | Life of the account or explicit delete                          |
| Report registry rows                            | Life of the site; links by their TTL                            |
| Provider connections (metadata and credentials) | Life of the account or until revoked                            |
| Coalescing generation watermark                 | Life of the site; survives disconnect, resets only with erasure |
| `delivery_attempt` rows (every delivery class)  | 7 days after terminal outcome, then deleted                     |
| Admin state (admins, pending recovery)          | Life of the account                                             |
| Erasure receipts (see contents below)           | 1 year                                                          |

**The export record registry, v1.** Every stored data family is
classified into exactly one of four classes, and the classification
itself is part of this registry:

- **Tenant-exportable** rides export as an NDJSON record type. Every
  line names its `record_type` and `schema_version`; the closed set
  is: `group`, `occurrence_record`, `observation`, `deployment`,
  `deployment_snapshot`, `deployment_head`, `scan_scope`, `event`, `alert`,
  `measurement_sample`, `route_profile` (signatures and revisions,
  never the MAC key), `verified_good_profile`,
  `notification_settings` (including its destination references),
  `alert_webhook` (metadata and secret
  fingerprint, never the secret), `report_registry_row` (including
  the stored report projection), `token_metadata` (scopes,
  timestamps, watermarks, never secrets), `site_metadata`, and -
  account export only - `destination` (with verification,
  suppression, and policy state; account-level like the resource),
  `provider_connection` (metadata and granted
  scopes, never provider credentials), `protected_sites`,
  `slot_lease` (site, release time), `account_settings`, and
  `admin_state` (the admin list and any pending recovery request -
  tenant-visible by design, since a non-admin must be able to see a
  recovery in flight).
- **Operational** is service telemetry about the tenant's traffic,
  not tenant content, excluded from export with its retention stated:
  raw per-channel delivery logs (90 days; their outcomes are
  already summarized on the exportable alert record),
  `Idempotency-Key` records (24 hours; the key itself is stored only
  as its SHA-256), rate-limit counters (transient), scan records and
  admission leases (24-hour transient execution state),
  redemption-nonce records (hashes only, TTL plus 7 days), the
  coalescing-generation watermark (a counter, no tenant content;
  survives disconnect so a reconnected site continues its sequence,
  resets only with erasure - scan idempotency is keyed by erasure
  epoch for exactly this), and the **`delivery_attempt` rows - one
  family, one exact schema, for every delivery class** (the
  courtesy and security outbox rows are its earliest members, not a
  parallel mechanism): attempt id; `class` from the delivery spec's
  closed enum; the owning **account**; the **site-dependency set
  with erasure epochs** - every site whose data the frozen body
  contains (one site for site-scoped classes, several for a digest,
  empty for pure account-scope classes); the **source key** - a
  **closed per-class tuple that includes the target identity**:
  `(class, target, dedup basis, generation)`, where target is the
  destination id or webhook endpoint id and the dedup basis is
  **closed per class, enumerated here for all eight**: immediate
  alert `(site, observation)`; storm summary
  `(site, 6-hour window index)`; digest
  `(account, destination, mode, cadence, window)`; confirmation and
  re-verification `(destination, verification round)`, each
  explicit resend a new generation; courtesy
  `(site, notification_revision)`; security notice
  `(recovery request, notice kind)`; fresh-link resend
  `(alert, destination)`, each rate-limited human click a new
  generation; webhook `(site, observation)` for alert deliveries
  and `(endpoint, test idempotency key)` for explicit test sends.
  The **delivery generation** increments on every replacement
  attempt - supersede, erasure rebuild, integrity re-render - and
  is the axis outcomes order on; the **dispatch generation**
  increments on every republication of the **same** attempt (DLQ
  reset, dispatcher re-publish) and exists solely for
  Queue-pointer CAS matching. The axes never mix: a replacement at
  delivery generation 2 outranks any redispatch of generation 1,
  however many times generation 1 was republished, and opaque
  attempt ids order nothing on their own.
  `(source key, delivery_generation)` is the identity outcomes and
  reductions reference; `(attempt, dispatch_generation)` is what
  pointers carry. Unique, so
  creating the same attempt twice converges on one row instead of
  two sends, while one recovery notice **per verified destination**
  and one alert **per webhook endpoint** stay distinct rows rather
  than collapsing under a target-blind constraint; the destination
  or webhook endpoint reference **plus
  the authorization revisions in force at creation** - destination
  revision, notification-settings revision, endpoint secret
  generation, and alert mode, held **per dependency for multi-site
  classes**: a digest's site-dependency set stores one
  authorization snapshot per member
  (`{site, erasure_epoch, notification_revision, alert_mode, destination}`),
  because one scalar revision cannot notice that a single
  constituent site muted, detached, or changed mode before the
  claim - claim revalidation checks **every** member, and any
  mismatch supersedes the attempt; **dispatch state**
  (`created`, `enqueued`, `claimed`, terminal) with
  `dispatch_generation`, `enqueued_at`, and a short
  `redispatch_at`; the **frozen
  provider request** - the
  canonical request bytes, or the canonical projection they are
  deterministically serialized from, frozen at attempt creation,
  because idempotent replay requires identical bytes and an attempt
  re-rendered from a mutable record would change its payload and
  answer `invalid_idempotent_request`, wedging the barrier at
  exactly the moment it must terminate - and **sealed as a JOSE
  flattened JWE by the `jose` library, never by a hand-built AEAD
  envelope**: the protected header is
  `{alg: "dir", enc: "A256GCM", kid}`, so the content key is the
  256-bit key version `kid` names and the header that selects it is
  itself authenticated. The row stores the protected header, the
  96-bit IV, the ciphertext, and the 128-bit tag, the last three as
  raw BLOBs, and keeps `kid` in its own column as well so the key
  retirement rule below is a query. **Every seal draws a fresh
  random IV from jose, and no nonce allocator exists** - no
  reservation, block, cursor, or burn: NIST SP 800-38D allows 2^32
  random-IV encryptions under one key, far above what this store
  seals under one `kid`, and a new `kid` is a new key. The active
  `kid` is the one row marked active in `encryption_kids`, and an
  attempt row is inserted only while its `kid` is still active,
  checked in the same statement, so nothing is sealed under a key
  rotated out mid-flight. Opening accepts only `alg: "dir"` with
  `enc: "A256GCM"` and resolves the key by the protected header's
  `kid`, so any other algorithm is refused before a key is chosen.
  **The JWE additional authenticated data binds the ciphertext to
  the attempt identity** - the UTF-8 bytes of the canonical JSON
  (sorted keys, no insignificant whitespace) of
  `{envelope_version, attempt_id, account, class, target, source_key, idempotency_key}`,
  recomputed from the row at every open and never stored -
  so a valid ciphertext cannot be transplanted
  onto another row. **Authentication failure is a terminal
  integrity event, never a retry**: the attempt closes as a
  never-sent integrity failure, alarms operators, and - the source
  record still being live - a fresh attempt is re-rendered where
  the class still owes delivery. Keys rotate by `kid`, and old
  decryption keys are retained until **no restorable point can
  resurrect ciphertext under them**: no nonterminal row references
  the `kid`, plus the provider's maximum point-in-time horizon (30
  days) beyond that moment, plus completion of any running
  reconciliation - retiring on live references alone would delete a
  key while a restore inside the horizon could still resurrect rows
  encrypted under it. Rotation mid-flight and old-`kid` restore are
  both fixtured. The ciphertext is **Secret-class in the export
  registry** while the row's metadata stays operational. The body
  is encrypted because it
  necessarily embeds live capabilities (the alert nonce, the
  confirmation and unsubscribe tokens) that every capability store
  holds only as hashes, and a plaintext frozen body would make one
  D1 read sufficient to redeem them; transport credentials are
  never part of any body. **Frozen requests have fixed per-class size
  ceilings enforced before insertion**, measured on the **sealed
  body as stored** (IV, ciphertext, and tag included - the bytes D1
  actually holds for the body, against its hard 2,000,000-byte row
  bound; the protected header, like the `kid` column, is a few dozen
  bytes and is not counted): **256 KB per email-class attempt**
  (the report-projection precedent) and **64 KB per webhook
  attempt** - fixed here, not operational configuration, because a
  valid observation can carry 50,000 occurrences and no path may
  serialize an unbounded record into a row. Email bodies cannot
  reach the ceiling by construction (counts and classes, never
  occurrence lists); webhook payloads are a versioned bounded
  projection with **deterministic overflow selection** - members
  ordered by severity, then class, then stable identity, truncated
  at the ceiling with an explicit `overflow: {dropped}` count, so
  two renders of the same alert drop the same members. When
  insertion would still fail (a bug, by definition), the runtime
  outcome is a delivery, not only an alarm: the attempt is created
  with the class's **declared bounded fallback body**, one per
  closed-enum member, each with its own under-ceiling fixture -
  and the members divide by what their body actually carries,
  because the credential inventory is the authority on which
  classes hold a capability at all: alert, digest, and storm
  summaries fall back to counts-only; the capability-bearing
  classes fall back to a fixed template keeping their one
  load-bearing URL with only fixed-length-truncated identifiers -
  confirmation and re-verification keep the confirmation URL,
  fresh-link keeps the fresh nonce URL - because their single job
  is delivering that URL and a counts summary would be a body with
  no function; the courtesy note, which carries **no** capability,
  falls back to its fixed informational sentence with the
  truncated alias; the security notice, which likewise carries
  none, falls back to the fixed takeover-alarm sentence with the
  pending state named and the desktop settings deep link (a
  `sitecmd://` route, not a web capability); webhooks fall back to
  the bounded projection reduced
  to counts with its overflow marker. The owner is still woken -
  or the capability still delivered - while the integrity alarm
  pages the operator.
  Maximum-size conformance fixtures pin the ceilings and the
  fallback. Then: the deterministic
  idempotency key; claim, lease, and recorded-outcome state;
  **`first_provider_initiated_at`** - immutable once set, written
  durably (shard and coordinator both) before the first provider
  call, the activation anchor every emailed capability's TTL runs
  from; and
  the erasure-epoch fences. **At terminal outcome the encrypted
  body is purged**, leaving its hash and the outcome metadata; the
  row itself is deleted 7 days later (the content was already the
  exportable record it was rendered from). **The attempt row is the
  transactional outbox and the Queue is only a doorbell**: Queue
  guarantees begin at a successful `send()` and publication can
  fail, so the row, never the message, is durable truth. A crash
  between inserting the row and publishing its pointer leaves
  dispatch state `created`; a **retrying dispatcher** publishes
  pointers for rows stuck in `created` or unclaimed past the
  message-expiry horizon (Queue messages expire - a lost doorbell
  is re-rung, never a lost delivery); duplicate pointers are
  harmless because the claim CAS admits one claimant; and a
  dead-lettered message is acknowledged **only after** the DLQ
  consumer has CASed the row back to `created` **from exactly the
  pointer's `dispatch_generation` in state `enqueued`**, or
  published a replacement pointer -
  **dead-lettering must accelerate redispatch, never defer it**,
  because acknowledge-and-drop alone would park a critical alert
  behind the queue's multi-day expiry horizon while its row sat
  `enqueued`, trusting a doorbell that already died. The
  exact-generation CAS is what makes stale dead letters safe:
  Queues are at-least-once and delayed duplicates are expected, so
  a dead letter whose generation is no longer the row's current one
  matches nothing and is acknowledged without touching the newer
  generation - the same generation check gates the ordinary claim
  CAS. `redispatch_at`
  keeps the dispatcher's own retry short. Fixtures pin
  both crash windows (before publish, and after publish before
  claim), duplicate pointers, DLQ arrival with prompt redispatch,
  and Queue expiry. Unknown-outcome reconciliation is
  **provider-specific and named per connector**: Resend follows the
  same-key replay contract above; outbound webhooks have no
  idempotency contract at all, so an expired webhook claim closes
  as `outcome_indeterminate` directly, without replay. **Queue
  messages for any delivery class carry no
  tenant content at all** - only the attempt row id, the scope
  fence (erasure epoch), and the **expected `dispatch_generation`
  the pointer was published for** - because Cloudflare Queues offers
  whole-queue purge, not tenant-keyed deletion, and a message can
  persist up to 14 days, so anything
  tenant-bearing in a message could survive erasure for the queue's
  retention: the consumer reloads the still-live row before every
  send and acknowledges-and-drops a message whose row is missing or
  whose fence is stale. Reloading alone still leaves a race - erasure
  could complete between the reload and the provider call - so sends
  are **claimed**: the consumer takes a short-lease claim on the row
  (a CAS marking it claimed with an expiry) before calling the
  provider, records the provider's answer on the row, and **provider
  acceptance is the delivery linearization point**. **A claim
  revalidates authorization, never merely existence**: the frozen
  body is immutable but eligibility is not - an unsubscribe,
  suppression, destination reassignment, alert-mode change, or
  webhook deletion or rotation can land between creation and claim,
  and a claim that checks only the row and the fences would send
  yesterday's authorized mail into today's revoked channel. The
  claim CAS therefore re-evaluates the delivery spec's complete
  eligibility matrix against the destination's **current** state
  and compares the row's stored authorization revisions; any
  mismatch closes the attempt as terminal **`superseded`** (a
  never-sent outcome), and where the class still owes delivery
  under the new state, a new attempt is created - new frozen body,
  new key - exactly as in the erasure rebuild rule. Lease expiry is
  **not an outcome**: expiry cannot cancel external I/O - the worker
  may have died before, during, or after the provider call, Cloudflare
  documents that in-flight work can still process, and a request the
  runtime started can be accepted after the lease lapses - so a claim
  that expires without a recorded answer becomes `outcome_unknown`,
  and unknowns are **reconciled to terminality**, with the answer's
  strength depending honestly on the provider's idempotency window.
  **Inside the window** (24 hours at Resend), re-issuing the
  identical request with the identical deterministic idempotency key
  is safe (at most one email results whether or not the original
  landed), and its response is classified, not assumed terminal:
  acceptance and refusal are terminal - the send either already
  happened or happens now, known either way - but
  `concurrent_idempotent_requests` (the provider's answer while the
  original request is still processing under that key) is
  **nonterminal by the provider's own contract**, whose documented
  action is retry later with the same key: the reconciler retries
  with bounded backoff, same key, and the claim moves to
  `outcome_indeterminate` only if the window expires without a
  terminal answer. `invalid_idempotent_request` (same key, different
  payload) is never an ordinary refusal: the request body is the
  attempt row's frozen bytes, so that answer means the freeze or
  the serialization broke - an integrity fault that alarms
  operators, not an outcome that closes the claim. Reconciliation
  runs at lease expiry in normal operation, and leases are short, so
  this is the ordinary path. **Beyond the window** the provider has
  forgotten the key: a replay is a fresh send, and its acceptance or
  refusal proves nothing about the original - "was it delivered?"
  has become historically unanswerable, and the spec says so instead
  of pretending: the claim closes as **`outcome_indeterminate`**, a
  terminal recorded outcome meaning possibly delivered exactly once
  at an unknown earlier point. In normal operation an indeterminate
  security notice is then re-sent under a fresh attempt-scoped
  idempotency key - at-least-once on purpose, because for the
  takeover alarm a duplicate warning beats a maybe-never one; during
  erasure it is not (erasure is the owner saying stop). Erasure runs
  a **drain barrier** on this machinery, and the barrier has **two
  named boundaries, because its own reconciliation sends are
  initiated after the first one** - "pre-receipt" is not
  "pre-fence", and a receipt attesting silence from a fence the
  barrier itself sent after would be false on its face.
  `admission_fenced_at` comes first: new ordinary claims fail from
  that moment. The barrier then brings every outstanding claim to a
  terminal recorded outcome - waiting out live leases, reconciling
  in-window unknowns by replay (those replays are initiated after
  `admission_fenced_at` and awaited synchronously), closing
  post-window unknowns as indeterminate - and then waits out the
  platform's maximum invocation wall-clock plus the lease horizon,
  which proves no pre-fence invocation is still running **on our
  side** and therefore that every outcome that could be recorded
  has been. Only then is `send_quiesced_at` recorded - the moment
  after which nothing is initiated, ever - and the completion
  receipt produced. "Nothing is accepted after the receipt" is
  **not a claim this spec can make, so it does not make it**:
  Cloudflare's contracts bound the consumer invocation and Resend's
  bound only its idempotency window - neither bounds provider-side
  processing of a request whose body arrived before the client
  disappeared, so a send initiated before `send_quiesced_at` can,
  in principle, be accepted by the provider after the receipt
  exists. The hard guarantee is **initiation-side**, where every
  fact is ours: SiteCMD initiates no send after `send_quiesced_at`,
  and every recorded accepted or refused outcome is terminal before
  the receipt. A provider
  outage extends the barrier and therefore defers the receipt:
  deletion completeness outranks the completion target, and the
  status endpoint keeps answering in-progress. The terminal outcomes
  are exactly three, honestly bounded: provider-accepted
  strictly before the erasure receipt
  exists; never sent (fenced before any claim, refused terminally,
  or closed `superseded` by the claim-time revalidation); or
  indeterminate - initiated strictly before `send_quiesced_at`,
  with the provider-side outcome unknowable, **and honest
  per connector about multiplicity**: for mail, possibly delivered
  once (the idempotency key bounds it); for webhooks, possibly
  delivered zero, one, or several times - **best-effort with
  bounded retries**, named as such, because bounded retries with
  persistent-failure auto-disable guarantee neither delivery nor
  singleness, and the spec says so rather than promising either
  "exactly once" or "at least once", both of which this connector
  cannot keep - which is why every webhook payload carries a stable
  delivery id for cooperative receiver deduplication. The receipt
  attests "no send initiated after `send_quiesced_at`, and none
  ever will be" - never "no provider finished one after this
  timestamp", a claim that would need a provider-side processing
  bound no contract offers. `send_quiesced_at` itself is **internal
  barrier state, deliberately not a receipt field**: the receipt's
  `deleted_at` is recorded after quiescence, so `deleted_at` is the
  externally attested cutoff - "no send initiated at or after
  `deleted_at`" follows from the quiescence guarantee with no second
  exported timestamp for the schema, the status response, and the
  trust page to disagree over. **The attempt-and-claim authority is
  universal, not an outbox special case**: every externally-visible
  delivery the service initiates - immediate alerts, digests and
  storm summaries, destination confirmation and re-verification
  mail, courtesy notes, security notices, fresh-link resends from
  the public fallback page, and outbound alert webhooks with their
  retries - is initiated only through a scoped, claimed attempt row
  governed by `admission_fenced_at`, in the delivery classes the
  delivery spec enumerates; a send path outside the machinery would
  be a delivery no fence covers, racing erasure into a
  post-quiescence initiation. Browser and public routes never call
  a provider inline - the fallback page's resend enqueues a guarded
  attempt and returns, because a capability-authorized route that
  sent directly would hand a remote nonce holder exactly that race.
  Provider calls run only in the bounded queue-consumer worker,
  because the quiescence wait leans on a documented invocation
  wall-clock bound and HTTP- and Durable Object-driven contexts do
  not document one. The drain barrier drains **every** attempt row
  and scheduled dispatcher for the scope, whatever the class - and
  **scope is resolved through the site-dependency set, never the
  attempt's owner alone**: an account-level digest whose frozen
  body contains site A's alias and findings is within site A's
  erasure scope, or a site-scoped barrier could produce A's receipt
  while an account-scoped attempt it never looked at goes on to
  send A's data. Before its quiescence point, site erasure brings
  every attempt whose dependency set references the site to rest:
  an unclaimed attempt is fenced, and where its class still owes
  delivery to surviving sites (the digest), a **new** attempt is
  created without the erased site's content - new frozen body, new
  idempotency key, never a mutation of the old attempt, which would
  break replay identity; a claimed attempt is brought to a terminal
  recorded outcome under the barrier rules above. The erasure
  fixtures include an erase-race case per delivery
  class, and the digest case runs the race against every lifecycle
  stage: between creation, claim, and provider invocation.
  Rationale:
  they describe the service's behavior, they contain no tenant
  content beyond what the exportable records carry, and exporting raw
  delivery logs would mostly re-export destination addresses.
- **Security** artifacts are excluded because exporting them would
  weaken what they protect: the erasure receipt-ledger records,
  the control-store safety journal, and the R2 archive (retained
  per the exact control-store retention table - receipts a year,
  journal by its restore horizon; they are the proof of deletion
  and the restore tombstones, and the receipts outlive the tenant
  by design) and staging
  rows (transient, fenced, garbage-collected). The control-store
  retention table, exact - it configures the Bucket Locks, so
  ambiguity here is a misconfigured lock:

  | Record                                                                                | Control D1                                                                                                                                                                                                                                                                        | R2 archive                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
  | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | Receipt-ledger (pending, completed)                                                   | **1 year from terminal confirmation, never from creation** - a non-terminal record is a live projection (R2 is the authority) and is never pruned                                                                                                                                 | Bucket Lock 1 year (age rule on `receipts/`); a record still non-terminal near lock expiry gets an **immutable renewal object** (same payload, new age lock, referencing the original) so an authoritative copy stays locked **only while each verified renewal completes by its `renew_by` - running or failing attempts preserve nothing; missing the deadline exhausts the platform lock and enters the documented fail-closed recovery path** (the 30-day-overlap service assumption below); pruned 1 year after confirmation |
  | Prune events (`prune_target_captured`, `confirmation_started`, terminal confirmation) | 1 year from terminal confirmation, with the receipt-ledger record - `confirmation_started` follows the terminal-aware rule and **never expires while non-terminal** (the generic erased-tenant journal purge does not apply to it, or the fence would lapse and admission reopen) | Same rule and renewal mechanism; the confirmation event carries its own age lock (it is created months after the tombstone, so "expires with the receipt" is implemented by pruning at confirmation-plus-a-year, never by pretending one age rule covers both)                                                                                                                                                                                                                                                                    |
  | Journal rows, live tenant                                                             | 90 days (the restore horizon is 30; 3x margin)                                                                                                                                                                                                                                    | Bucket Lock 60 days (age rule on `journal/` - twice the horizon, so an entry created just before an event that extends its need by another horizon is still covered); pruned at 90 by the pruner                                                                                                                                                                                                                                                                                                                                  |
  | Journal rows, erased tenant                                                           | 30 days past the receipt, then purged                                                                                                                                                                                                                                             | Same 60-day lock: every entry a restore can still need is at most 30 days old at the receipt, so its lock outlives the receipt-plus-30 requirement by construction                                                                                                                                                                                                                                                                                                                                                                |
  | Checkpoint objects                                                                    | n/a (R2-only)                                                                                                                                                                                                                                                                     | Journal rule; the pruner keeps the newest checkpoint rooting current verification                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
  | Coordinator store: activation clocks                                                  | Site-keyed in the coordinator DO; retained until capability expiry plus 7 days; site erase purges the site's records through the coordinator behind the fence; account erase `deleteAll`                                                                                          | Per-account delivery stream: journal rule (60-day lock, pruned at 90); erasure crypto-shreds - the site's stream key is destroyed before the receipt, and what the lock retains is ciphertext without a key, disclosed as such                                                                                                                                                                                                                                                                                                    |
  | Coordinator store: terminal outcomes                                                  | Site-keyed in the coordinator DO, 90 days; site erase purges the site's records; account erase `deleteAll`                                                                                                                                                                        | Same delivery-stream rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
  | Coordinator store: epochs, leases, cursors                                            | Account-level operational state in the coordinator DO, transient; account erase `deleteAll` behind the fence                                                                                                                                                                      | n/a - never archived                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

  Coordinator delivery records are **keyed by their
  site-dependency set**, exactly like the attempt rows they
  describe, because the coordinator is shared per account and
  `deleteAll` cannot erase one site without taking its siblings:
  site erasure deletes the site's coordinator records in the same
  cascade that drains its attempts - before the receipt, behind
  the fence - and needs nothing from them afterward, since the
  erasure tombstone and restore reconciliation are what re-kill
  resurrected shard state, not coordinator memory. `deleteAll` is
  reserved for account erasure. The multi-site fixture erases one
  site and proves sibling clocks, outcomes, and cursors intact.

  The lock rules above are the configuration, derived from each
  record's required-until date rather than one blanket age; the
  appender facade is create-only by construction, only the pruning
  job holds delete, and it deletes nothing a lock still covers.

- **Secret** material is never exportable by design: provider
  credentials, MAC and signing keys, token secrets, the
  hash-stored single-use capability records (confirmation,
  unsubscribe, and OAuth state tokens) while they live, and the
  frozen-body ciphertext of nonterminal `delivery_attempt` rows
  (the row's metadata is operational; the ciphertext embeds live
  capabilities and is Secret until purged at terminal outcome).

**The inventory is derived, not remembered**: a guardrail maps every
persistence surface in **every connected-service worker** - D1
tables, Durable Object storage keys (the scan coordinator's and the
admission shards' included), Queue message payloads, and any
tenant-bearing R2 object - to
exactly one registry class, so a stored family nobody classified is a
failing check, not a quiet omission. That is the mechanism behind
"export is the proof".

**Occurrence-record compaction.** Durable records need a cumulative
bound, because route churn otherwise grows state without limit against a
per-snapshot cap that never looks backward. The per-site bound is
250,000 occurrence records. Compaction retires records that carry no
tripwire value: `known` records whose last presence evidence is older
than 180 days and whose route no longer appears in any current coverage
(churned routes), and `verified_absent` records in groups that are no
longer armed tripwires, once the records pass the same 180-day age: a
group that has since become `active` or `regressed` (its state already
says the issue is back) and a group that is `dismissed` (the dismissal
itself disarms the tripwire; the group stays silent regardless).
`verified_absent` tombstones are preserved without aging only while
their group remains `claimed_fixed` or `verified_fixed`, because there
they are the tripwire; they retire when the group leaves those states,
is retired by epoch or key migration, or is erased. Capacity is
enforced against net growth in one atomic application: the snapshot is
**staged**, prospective coverage is computed, retirements that the
staged coverage itself enables are included in the calculation, the
final record count is checked against the bound, and only then does the
whole application commit. Ordering inside the transaction therefore
cannot make incoming coverage invisible to compaction, and rejection
(`422 record_capacity`) happens only when the snapshot's **net-new
insertions** still exceed the bound after every retirement the staged
state allows. A snapshot that adds no records is never rejected, and
one whose coverage makes old records compactable frees its own room, so
a site cannot wedge itself at the cap. The error names the bound:
visible backpressure, never silent dropping.

- **Disconnect** stops triggers and revokes site credentials; state
  remains for the 30-day window, then expires.
- **Erase** physically deletes the tenant's rows: groups, occurrence
  records, the scan scope, route profiles and the content-MAC key,
  the verified-good profile, measurement series, observations,
  deployment records, the deployment head, alerts, events,
  notification settings and their destination references, the
  coalescing-generation watermark, the site's `delivery_attempt`
  rows of every class (account-scoped classes erase with the
  account, below - and any account-level attempt whose
  site-dependency set references this site is cancelled or rebuilt
  without it before the job's quiescence point, per the retention
  section's barrier rule), the site's records in the account's
  write coordinator - activation clocks, terminal outcomes, and
  attempt identifiers, keyed by site-dependency set and purged
  through the coordinator behind the fence, siblings untouched -
  outbound alert webhooks and their secrets, report registry rows
  (rendering a revoked-and-erased report's surviving link fails at
  the registry check), and
  credential rows for the site, plus the site's deletable R2
  objects - locked delivery-stream objects follow the
  single erasure contract in the retention section instead
  (crypto-shredded: keys destroyed before the receipt, ciphertext
  residue pruned with its lock), the control safety archive stays
  privileged-readable per that same contract because it is the
  restore authority, and neither is falsely claimed deleted.
  Account erasure
  runs this cascade for every site and then removes account-scoped
  state: destinations, provider connections and their credentials,
  the protected
  list, account settings, every remaining `delivery_attempt` row,
  and the admin state including any pending
  recovery request and its queued security notices - the erasure
  fixtures cover every family the retention table names, both
  scopes. Erase answers `202`
  with `{ "job_id": "…", "status_token": "…" }`: the job id is a plain
  identifier, and the status token is a high-entropy bearer secret,
  shown once and stored only as a hash, presented in the
  `Authorization` header on `GET /v1/erasures/{job_id}`. That is what
  makes completion confirmable after the site's own credentials are
  revoked, with no secret in any URL. The erasure is typically
  immediate and completes within 24 hours, with one stated exception:
  the receipt waits behind the delivery drain barrier (the
  retention section - every delivery class, resolved through
  site-dependency sets), so a provider outage defers the receipt
  rather than permitting a send to be initiated after it.
- **The erasure receipt** is the one durable artifact, retained one
  year, and its contents are exactly: the job id, the **hash** of the
  status token (so status reads can be verified; the token itself is
  never stored, so a lost token cannot be re-shown), the erasure
  scope as `scope_kind: site | account` plus the matching opaque
  `scope_id` (the site id, or the account-scope id for account
  erasure - one receipt schema serves both endpoints), a
  non-reversible binding of the owning subscription (an
  HMAC of the subscription id, so a repeated account erase from the
  same subscription can be matched after every tenant row is gone),
  and the deletion time - `deleted_at`, recorded after
  `send_quiesced_at` and therefore doubling as the externally
  attested no-initiation cutoff, while the internal quiescence
  timestamp is deliberately not a receipt field. No other
  **tenant data** survives readable; the exact residue contract -
  locked ciphertext without keys, bounded provider history - is
  stated once, in the retention section, this sentence is a
  summary of it, and the status endpoint's live
  `ciphertext_deletion` member is service state about the
  deletion, not surviving tenant data. Retries have one
  contract, consistent with the secret-replay rule: **the status token
  is minted once, never re-shown, never replaced**, and stays valid for
  the receipt's retention, so a poller's token cannot be invalidated
  behind its back. The erase routes keep no `Idempotency-Key` record:
  the delete commits in the request's own transaction, so by the time
  the first answer leaves there is no tenant state left for a retry to
  replay from, and a lost status token stays lost. The two erase routes
  answer a retry after deletion differently. A retried **site** erase
  resolves no site and answers `404 not_found`, the answer for any site
  the caller cannot see; on this route the one thing that `404` can
  mean is that the site is already gone, and the status token from the
  first answer still reads the receipt. The site receipt also records
  the subscription binding when the service holds a binding key, but no
  retry is matched against it. A retried **account** erase after
  deletion authenticates with any valid installation token of the
  owning subscription: the account is gone,
  so the server HMACs the caller's subscription id under every
  configured binding key, matches it against the account receipt's
  binding, advances the erasure once if it is still draining, and
  answers `200` with the envelope the status endpoint serves - status,
  receipt projection, and `ciphertext_deletion` - and no token. Every
  other route answers that caller `404`. The record-deletion fact is
  final, while ciphertext deletion may still be `pending`, which is
  exactly why the envelope carries it and why "no further polling
  needed" was retired as a claim. The account receipt is the durable
  idempotency record for exactly this case, and its contents are
  disclosed here because the minimal-receipt promise has to name every
  field to mean anything.
- **Point-in-time history and restore are part of the deletion
  story, not outside it.** D1 Time Travel is always enabled,
  retains up to 30 days of history, and restoring overwrites the
  live database - so a physically deleted row persists in provider
  history for up to 30 days (unreadable except by restoring), and a
  careless restore would resurrect erased credentials, nonce
  records, report rows, and delivery attempts - and would equally
  roll back later admin revocations, unsubscribes, report
  revocations, and webhook rotations, reactivating authority and
  links their owners already killed. Three rules close this.
  First, **the control store is a safety journal with a real
  transaction protocol, not a list of good intentions**. The
  journaled transition table is **derived, closed, and
  fixture-enforced**: the registry derives from every persisted
  state transition whose rollback can restore authority, egress,
  evidence authority, **or disclosure level** - the same guardrail
  mechanism as the
  persistence inventory, so a qualifying transition nobody
  journaled is a failing check, not a quiet omission - and
  enumerates: admin grants and revocations; the recovery lifecycle
  (request, ack, cancellation, completion); credential
  revocations; site disconnect; provider-connection revocation;
  destination suppression, policy-bit sets, unsubscribes, and
  association switches; notification-settings changes that reduce
  or redirect egress (mutes, severity floors, cadence changes);
  **alert content-mode reductions** (private to minimal is a
  disclosure reduction: restoring behind it must not recreate
  private-mode deliveries carrying alias, severity, and cause -
  minimal wins); report revocations; webhook deletions, secret
  rotations, and
  **auto-disable** (restoring behind an auto-disable must not
  resume delivery to a dead endpoint); fingerprint-key rotation
  completion and ordering-authority transitions (evidence
  authority is authority); capability consumption (a redeemed
  nonce or consumed token must never be un-consumed by a restore);
  first-initiation timestamps and terminal delivery outcomes (the
  per-delivery members - journaled in the account's write
  coordinator, per the physical write strategy, not the global
  store); and erasure
  itself. Each
  journal row is an **operation**: a deterministic operation id,
  the original preconditions (revision guards) it will carry to the
  shard, its ordering position, and a state - **`prepared` before
  the shard write, then `committed` or `aborted` by the shard CAS's
  actual result** - because journal-then-apply without an outcome
  is how a revision-guarded mutation that **lost** its CAS becomes
  a rejected intent lying in wait for replay to apply it. Crash
  recovery resolves stale `prepared` rows continuously by
  inspecting the shard for the operation's effect. Restore replay
  applies `committed` rows in journal order; `aborted` rows never
  replay; and a `prepared` row caught by a restore repairs by the
  member's declared **conservative repair class**, normative per
  member - **removing** replays (the worst case is removing
  authority an owner must re-grant, visible and recoverable),
  **adding** aborts (replaying an add whose shard CAS failed would
  mint authority out of a rejected request), **compound** splits
  into monotonic halves and never replays whole - with the full
  assignment part of the registry and every row fixtured:

  | Journal member                          | Class    | Prepared caught by restore                                                                                                                                                                                                                                                      |
  | --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | Admin grant                             | adding   | Abort; grantor re-grants                                                                                                                                                                                                                                                        |
  | Admin revocation                        | removing | Replay                                                                                                                                                                                                                                                                          |
  | Recovery request / ack                  | adding   | Abort; neither arms a clock it did not provably arm                                                                                                                                                                                                                             |
  | Recovery cancellation                   | removing | Replay                                                                                                                                                                                                                                                                          |
  | Recovery completion                     | adding   | Abort; the CAS re-evaluates on the live predicate                                                                                                                                                                                                                               |
  | Credential revocation                   | removing | Replay                                                                                                                                                                                                                                                                          |
  | Site disconnect                         | removing | Replay                                                                                                                                                                                                                                                                          |
  | Provider-connection revocation          | removing | Replay                                                                                                                                                                                                                                                                          |
  | Suppression / policy bits / unsubscribe | removing | Replay                                                                                                                                                                                                                                                                          |
  | Association switch                      | compound | Detach replays, attach aborts ("alerts unconfigured" warning, never a silent reroute)                                                                                                                                                                                           |
  | Mute / severity floor / cadence change  | removing | Replay                                                                                                                                                                                                                                                                          |
  | Content-mode reduction                  | removing | Replay; minimal wins                                                                                                                                                                                                                                                            |
  | Report revocation                       | removing | Replay                                                                                                                                                                                                                                                                          |
  | Webhook deletion / auto-disable         | removing | Replay                                                                                                                                                                                                                                                                          |
  | Webhook secret rotation                 | compound | Revocation replays, activation aborts (endpoint visibly disabled, never quietly dual-valid)                                                                                                                                                                                     |
  | Fingerprint-key rotation completion     | adding   | Abort; the rotation protocol re-runs its own completion                                                                                                                                                                                                                         |
  | Ordering-authority transition           | adding   | Abort; re-derived from the provider's own facts, never from a lost CAS                                                                                                                                                                                                          |
  | Capability consumption                  | removing | Replay; consumed stays consumed                                                                                                                                                                                                                                                 |
  | First-initiation timestamp              | removing | Replay; an earlier clock start only shortens a capability's life                                                                                                                                                                                                                |
  | Terminal delivery outcome               | removing | Replay; an outcome ends sendability, and the reconciler re-closes anything it disturbs                                                                                                                                                                                          |
  | Stream-key create                       | adding   | Abort; committed creates replay with their wrapped-DEK payload, so ciphertext is never orphaned                                                                                                                                                                                 |
  | Stream-key rotate                       | compound | New-generation add aborts; committed re-wraps replay their archived new wrapped-DEK envelope, never a re-run of the unwrap                                                                                                                                                      |
  | Stream-key destroy                      | removing | Replay; destroyed stays destroyed                                                                                                                                                                                                                                               |
  | `confirmation_started` (erasure fence)  | removing | Replay; restore re-asserts the fence and re-enters `append_or_get`, converging on one terminal object - not necessarily one position: the original position is reused only when the expected terminal object landed there, and a confirmed abort marker forces a fresh position |
  | Erasure                                 | removing | Replay; the pending-first tombstone rule already guarantees it                                                                                                                                                                                                                  |

  Failing toward less authority with a visible degradation is the
  one direction that cannot mint anything. Terminal
  delivery outcomes journal after recording (their truth arrives
  from the provider), and an outcome a crash left unjournaled is
  re-closed by the reconciliation machinery, which is idempotent by
  construction. Second, **the erasure ledger and the receipt are
  one control-store state machine with two faces**: a **pending**
  record - state, scope,
  erasure epoch, status-token hash - is created **before any
  fencing or deletion begins**, pending and completed records alike
  are restore tombstones, and `deleted_at` set at quiescence is
  what completes the record - so a crash after
  deletion but before a separate ledger write can never leave an
  untombstoned erasure, because the tombstone precedes the first
  delete. The **internal control row** (state, epoch, journal
  linkage - reconciliation needs them) is a different schema from
  the **externally disclosed receipt projection**, which is exactly
  the minimal enumeration below and nothing more: "nothing else
  survives" is a disclosure claim about what is retained **for the
  tenant and served to callers**, and the projection is the
  `receipt` member of the status endpoint's exact envelope - the
  endpoint returns the envelope, never the bare projection. Non-erasure journal rows for an erased
  tenant do **not** become a second immortal artifact: they outlive
  the receipt only through the provider's maximum point-in-time
  horizon (30 days - exactly while a restore could still resurrect
  what they re-kill), then purge; the receipt projection alone
  lives the year. Third, **restores run only through
  the restore orchestration, and quarantine is an exclusive write
  path, never a glance**: a check-then-write pair ("observed
  `restoring = false`, then wrote") leaves exactly the window a
  paused worker falls through - and even a commit-time epoch guard
  on the shard's own epoch row has a straggler window, because the
  restored row still holds the pre-restore value until someone
  stamps it, and a worker resuming in that gap passes the guard.
  Tenant-shard writes therefore flow through **one exclusive
  per-account write coordinator** - a Durable Object,
  single-threaded, whose own storage a shard restore never
  touches: the coordinator holds the account's fencing epoch and
  operation leases, issues every shard write batch itself with the
  epoch guard attached, and checks the control store's restoring
  state as the lease holder; **no other code path holds a
  tenant-shard write binding**, enforced by a static guardrail on
  the worker source, so "a straggler writes around the fence" has
  no path to happen on. The
  orchestration fences the coordinators (each rejects new writes
  and drains in-flight ones), waits out **every** registered
  lease - all operations, never delivery claims alone - restores,
  **stamps the new epoch through the coordinator as the shard's
  unconditionally first post-restore write**, replays the full
  safety journal from the
  restore point (erasures re-applied, revocations and rotations
  re-applied, epochs and fences re-advanced), and unfences only
  through a CAS on the restoring state. Traffic during a restore is
  rejected by the exclusive path, not by hope. The retention
  disclosure states the provider bound rather than hiding it:
  **the erasure contract is one statement in five named clauses,
  and every other erasure sentence in either spec copies this
  staged language, never a tidier one**.
  **Ordinary serving**: every mutable tenant store is deleted and
  every stream key destroyed before the receipt exists - no
  ordinary read path returns tenant data after the receipt, ever.
  **Privileged recovery**: until the wrapping KEK version's hard
  retirement, privileged restore authority plus the live KEK
  could still recover delivery-stream projections (wrapped keys
  persist in provider history up to 30 days and in archived
  payloads until their locks expire); mandatory reconciliation
  re-destroys before anything serves, and this window is a
  disclosed fact, not a violation of the first clause.
  **KEK retirement**: at the retiring version's `retire_by` - a
  hard 60 days after the receipt at worst, stamped at activation -
  no SiteCMD-operated path can recover the data; provider-side
  retention of deleted store values is not publicly specified,
  and this contract says so instead of assuming.
  **Confirmed deletion**: locked delivery-stream ciphertext is
  deleted by the pruner through the provider's documented
  **irreversible direct deletion** - never left to lifecycle
  rules, whose timing the platform bounds only as "typically
  within 24 hours" - through a **durable state machine with an immutable,
  linearized, archived completion target, not a hopeful cron**.
  The target is cut into the chain itself, because
  `send_quiesced_at` fences provider sends, not stream appends -
  a buffered flush carrying the erased site could reserve
  position N, time out, and commit after a wall-clock capture
  read N-1, leaving erased ciphertext above a "confirmed"
  target: the erasure appends a serialized **`erasure_cut` chain
  marker** through the account's appender **after every
  dependency-bearing flush has drained and every unresolved
  reservation has settled** (the position protocol's own
  recovery resolves them first), and
  `through_position = the cut marker's predecessor` - a later
  sibling append lands above the cut by chain construction, not
  by timing. The target is **archived before the receipt
  exists**: a deterministic `prune_target_captured` event -
  job id, stream id, `through_position` - written through the
  lost-response-safe archive protocol, because the pending
  tombstone predates fencing (the target is unknown then) and
  the confirmation event postdates pruning by months, so a
  control-store restore in between would otherwise replay the
  tombstone and lose the target, making rederivation impossible
  exactly when it is needed; both this event and the terminal
  confirmation event are rows in the retention table and the
  derived persistence inventory. The
  receipt-ledger control row carries
  `{prune_state: pending | confirmed | overdue, delete_due_at, deletion_confirmed_at, confirmed_prune_through, confirmation_operation_id: string | null}`
  - **explicitly the pruning subrecord of the receipt-ledger
    control row, not the whole row**: the complete row is this
    subrecord plus the state, erasure epoch, and journal linkage
    the two-faces schema defines and the renewal machinery's
    `authoritative_generation`, so one migration and one restore
    projection derive from those definitions together, never from
    this subrecord alone. Within it: **one field name;
    `confirmed_prune_through` is the
    watermark**, not a second concept beside one, and
    `confirmation_operation_id` is the typed internal form of the
    `confirming` marker: reconstructed from the immutable journal
    (never independently authoritative), non-null exactly while
    the fence stands, cleared only after the terminal R2 event is
    resolved, and projected to `pending` on the wire -
    where `delete_due_at = deleted_at + 83 days` exactly (a 7-day
    execution margin inside the 90), the pruner runs from lock
    expiry onward retrying every 24 hours, and confirmation is a
    predicate against the target:
    `confirmed_prune_through >= through_position`, by
    **checkpoint-safe prefix deletion** of whole objects at
    positions at or below the target - safe for siblings because
    every such object is past its 60-day lock and therefore past
    every 30-day replay horizon by the time it is deletable. The
    watermark is defined over **tenant-bearing payload objects
    only; structural objects - checkpoints, abort markers, the cut
    marker itself - are explicitly outside it**, because the
    retained verification-rooting checkpoint would otherwise make
    account-erasure confirmation impossible: the stream stops at
    the cut, the final checkpoint sits at or below the target, and
    a watermark that counted it would either never confirm or
    falsely swear an existing object absent. A sibling record
    appended after the cut sits above
    `through_position` and is never touched; `confirmed_prune_through`
    is the highest position through which every payload object is
    confirmed absent (a crash resumes at the watermark),
    and `deletion_confirmed_at` is set only after a **verified
    absence lookup of every referenced object**, never a
    fire-and-forget delete. **Restore cannot regress any of it**,
    because the state is rederivable, not merely stored: after any
    control-store restore, reconciliation recomputes
    `prune_state` and the watermark from the immutable target plus
    direct R2 absence checks before the status endpoint serves,
    and the terminal confirmation is additionally archived once as
    an immutable receipt-ledger completion event (so a restored
    store cannot forget a confirmation or its timestamp); an
    overdue that rederives as still-overdue re-alarms, and the
    incident record lives on the ops lane outside the restored
    store. Fixtures cover the multi-site digest, the
    sibling-append-after-the-cut, the buffered flush racing the
    cut, the timed-out PUT committing after the cut, account
    erasure with no post-target checkpoint (the payload-only
    watermark confirms; the retained structural checkpoint does
    not block it), checkpoint retention, and a PITR landing
    after every pruning edge, not merely process crashes. The erasure **status endpoint has one exact
    response envelope**, so the minimal-receipt contract and the
    live deletion state stop contradicting each other:
    `{status, receipt, ciphertext_deletion: {state, due_at, confirmed_at}}`,
    **with its variants defined, because polling legally starts the
    moment the `202` returns** - before a receipt, a target, or a
    due date exists: `status` is `in_progress | completed`;
    `receipt` is `null` until completion and then exactly the
    minimal durable projection, nothing more; `ciphertext_deletion`
    is `null` until **completion** - target capture is internal
    cross-store ordering, deliberately not an externally visible
    state, because `due_at` derives from `deleted_at` and a poll
    landing between the archived target and the receipt would
    otherwise have no valid shape - then
    the live derived state machine (it can stay `pending` for
    months, which is precisely why it
    is not a receipt field). The union is discriminated, with the
    per-variant constraints stated rather than implied:
    `in_progress` carries neither receipt nor deletion state;
    `completed` with `pending | overdue` carries the receipt and
    `confirmed_at: null`; `completed` with `confirmed` **requires**
    the confirmation timestamp - a `confirmed` without its
    timestamp, or a timestamp on an unconfirmed state, is a schema
    violation, not a style choice. The OpenAPI document carries
    this union, constraints included, verbatim. A `delete_due_at`
    miss flips `overdue`, pages the operator on the ops lane, keeps
    retrying until confirmed, and is disclosed as
    an incident rather than silently absorbed - and because neither
    the pending phase (a receipt deferred by provider outage) nor
    the overdue phase has an upper bound, **retention is
    terminal-state-aware**: tombstones, targets, and status-token
    hashes stay authoritative until confirmation, the one-year
    clock starts at `deletion_confirmed_at`, and the retention
    table's renewal mechanism keeps a locked authoritative copy in
    R2 for as long as renewal keeps running - a bounded assumption
    stated below, not an unconditional forever. **Renewal is a
    crash-safe, recurring handoff protocol, not a phrase**: it
    runs through the existing serialized appender (chain members,
    the lost-response-safe position protocol), each renewal
    carries a generation, and the control row records
    `authoritative_generation`. The deadline is exact -
    `renew_by = current lock expiry - 30 days`, a stated overlap
    margin, recurring every cycle for as long as the record stays
    non-terminal - and **authority moves only after
    verification**: the appender confirms the new object exists
    (direct R2 writes are read-after-write consistent, so the
    check is real) under the lock-carrying prefix, then CASes
    `authoritative_generation` from `g` to `g + 1`; until that
    CAS, the old object remains authoritative, so a delayed or
    crashed renewal inside the margin never leaves the only
    authoritative copy
    unlocked. **The margin is a stated service assumption, not a
    hidden one**: a renewal outage longer than the 30-day overlap
    exhausts the platform lock, and "authoritative" does not keep
    an object platform-locked - the binding stays write-capable
    and the Bucket Lock is the real backstop, as this spec already
    admits. A missed `renew_by` therefore alarms from day one and
    escalates daily, and the disclosure states exactly which
    guarantee survives an overlap-exceeding outage - and it is
    careful about the word "authoritative", because this spec
    makes R2 the authority and D1 its projection: what survives is
    the control D1 as the **surviving live projection**, protected
    by the
    application facade (create-only appender, pruner-only delete,
    the static guardrail), while the **platform-enforced** lock has
    lapsed and the archive copy is mutable until renewal recovers -
    at which point recovery **re-establishes the locked
    authoritative copy from the surviving projection, verified
    against it**, a stated recovery step rather than an implied
    one; if the unlocked archive object was lost or mutated in the
    gap, that verification fails closed and alarms rather than
    silently re-blessing whatever remains. Weaker, named, and
    alarmed, never silently claimed as "locked
    for however long terminality takes". The
    renewal-unavailable-for-overlap-plus-one-day fixture pins
    which protections remain.
    **Confirmation is an exclusive phase that fences the PUT, not
    merely the CAS**, because a timed-out renewal PUT can commit
    after a naive terminal write - reservation, timeout,
    confirmation, then the original PUT lands, minting an orphan
    whose age lock **begins after** `deletion_confirmed_at` and
    outlives the pruning deadline. The phase therefore begins by making its own existence
    durable: a **deterministic `confirmation_started` operation
    through the R2-backed journal** - prepared and committed under
    the phase protocol, carrying a deterministic **operation id
    and no preallocated terminal-event position** (its own
    prepared and outcome markers consume ordinary journal
    positions like any operation's - what it lacks is a claim on
    where the terminal event will land), because reserving the
    terminal
    position before the drain and the absence check complete would
    wedge the gapless chain: a stalled drain leaves position `N`
    unwritable (writing it would falsely declare deletion
    complete) while every unrelated revocation and erasure behind
    `N + 1` waits on a digest that cannot exist - is written
    **before** admission closes, because an
    in-memory fence dies with its worker: a crash after
    fence-and-drain would otherwise restart into a world where
    nothing says admission is closed, a fresh renewal slips in,
    and confirmation resumes without draining it - or two
    concurrent confirmers append two terminal events with two
    `uploaded` timestamps. Renewal admission **rejects while the
    operation exists**, and convergence keys on the **operation
    id**: the terminal position is allocated only **after** the
    drain and the verified-absence check succeed, immediately
    before the terminal PUT - and the allocation is
    **one appender operation that returns only a completed
    terminal object, never a naked reservation**:
    `append_or_get(operation_id, terminal_snapshot)`. A separate
    operation-to-position marker has no valid home under the
    one-object-per-position invariant - at `N` it collides with
    the terminal event, after `N` it cannot append while `N` is
    empty, and outside the chain it is not "in the replayed
    chain" - so **the terminal event itself is the marker**: the
    `confirmation_operation_id` - globally unique,
    scope-qualified by the erasure job - is embedded in the
    terminal
    object's content, the operation records the **canonical
    digest of its `terminal_snapshot`** (the same
    expected-digest discipline the reservation protocol already
    uses everywhere else), and the appender owns the whole
    sequence -
    look up an existing terminal object for the operation id and
    **validate its digest against the supplied snapshot** -
    idempotent return of position and `uploaded` timestamp on a
    match, an **integrity fault, never a silent adoption**, on a
    mismatch, because two confirmers constructing different
    snapshots under one id would otherwise let the loser accept
    whichever payload won, concealing a stale target or corrupted
    receipt projection; otherwise reserve, PUT the snapshot,
    classify
    through the ordinary read-and-classify recovery, and return
    only once the terminal object occupies a position. The
    same-id-different-content retry is its own fixture. A crash
    anywhere re-enters `append_or_get`, which either finds the
    object (the chain replay reads content, so restore
    reconstruction sees the operation id) or resolves the
    reservation per the position protocol - abort marker, fresh
    position - so neither a chain wedge nor a second terminal
    event is reachable, and the D1 attachment is a projection of
    what the chain already holds. A retry or concurrent
    confirmer adopts the
    operation and receives the same terminal object. Fixtures
    cover a control-store rollback landing before and after the
    append, each combined with a lost terminal-PUT response. The
    control row serves the phase through
    `confirmation_operation_id` - the typed internal field the
    exact schema defines, journal-reconstructed, non-null exactly
    while the fence stands, cleared only after the terminal R2
    event resolves, and mapped to `pending`
    on the wire (the public states stay
    `pending | confirmed | overdue`; a caller does not need to
    distinguish a fence from a wait, and the union stays closed).
    The phase then: **drains every existing renewal
    reservation and uncertain PUT through the position resolver**
    until each has its terminal object (written, or abort marker -
    the same resolution machinery, applied before the clock
    exists); and only then performs the terminal transition,
    whose **linearization point is the R2 terminal event,
    explicitly - D1 is a replayable projection of it**: after the
    drain and the verified-absence check, the terminal event is
    appended and resolved through the position protocol, and
    `deletion_confirmed_at` is **derived from the stored object's
    own authoritative `uploaded` timestamp**, read after the PUT -
    never embedded beforehand, because the object's age lock
    begins when R2 stores it, and a timestamp minted before the
    PUT could not both live inside the object and equal the moment
    its one-year lock starts; the D1 write is then a projection,
    replayed by reconciliation if a crash or restore loses it
    (D1-first would leave the confirmation at the mercy of a later
    D1 restore). So
    every age-locked object the terminal clock covers was created
    no later than the clock, by ordering rather than by hope, and
    the clock is the platform's own stored timestamp. Fixtures pin
    the lost response and crashes immediately before and after
    both the R2 append and the D1 projection. A
    renewal that resolved `written` during the drain simply
    becomes the last pre-terminal generation and prunes with the
    rest; the exact race - confirmation entered after a
    reservation, before its timed-out PUT commits - is its own
    fixture, joined by the crash after fence-and-drain before the
    terminal PUT (restart must find the durable operation, keep
    admission closed, and re-enter `append_or_get` - converging on
    one terminal object, reusing the original position only if the
    expected object landed there, taking a fresh one past a
    confirmed abort marker) and by two
    concurrent confirmers converging on one terminal event. The **terminal confirmation event is a
    self-contained authoritative snapshot** - receipt projection
    and target, with the confirmation time being the object's own
    `uploaded` metadata rather than embedded content - so the
    tombstone, the target
    event, and every renewal generation prune on the terminal
    clock with nothing lost. Crash and recovery
    are fixtured at each state edge, plus the
    still-pending-at-eleven-months renewal, the lost renewal
    response, the crash around handoff, confirmation racing an
    in-flight renewal, a restore landing mid-handoff, and two
    consecutive renewal cycles. The public claim is
    key-independent and **confirmed**, which is the strongest
    wording the provider's contracts support; D1 and Durable Object
    point-in-time history ages out at 30 days.
    **Control archive**: the safety archive - tombstones, receipts,
    journal records - is a different class and is deliberately not
    crypto-shredded: privileged-readable Security-class records on
    their stated schedule (journal to its horizon, receipts one
    year), because it **is** the restore authority that re-kills
    resurrected state, and an erasure that shredded its own
    tombstones would be an erasure no restore could honor.

- The append-only event stream is append-only in operation, not in
  retention: it is partitioned by tenant precisely so that erasure is a
  physical delete. Account deletion cascades erase across every site,
  matching the RFC's account-deletion promise.

## Desktop and CLI implementation contract

The desktop and CLI implement the producer half of this protocol through one
shared engine vocabulary and one canonical payload builder.

1. **Release provenance.** Every persisted scan run carries the engine release,
   capability-manifest digest, canonicalizer, crawl profile, execution profile,
   and captured scope revision. Findings inherit those facts from their run.
   The recorded check inventory makes added, retired, and re-contracted checks
   distinguishable during comparisons.
2. **Pair-precise coverage.** Coverage claims are derived from execution
   outcomes. Verdicts prove execution, skipped checks become explicit
   exceptions, incomplete sessions cannot prove absence, and dynamic families
   declare their executed members. One `covers(route, check)` implementation
   governs local reconciliation and connected submissions.
3. **Verification provenance.** Lifecycle storage records who proved a
   verification. A user claim maps to `claimed_fixed`; only comparable local,
   hosted, or CI evidence can produce `verified_fixed`. Re-observation becomes
   a regression only after evidence had proved absence.
4. **Ordering and offline intent.** Desktop producers allocate durable,
   installation-scoped submission sequences and capture the event watermark at
   scan start. Revision-guarded lifecycle decisions enter a transactional
   outbox with their original basis and idempotency key. Pulling newer state
   never silently rebases an offline decision.
5. **Canonical payload and inspectors.** The database builds the wire payload
   from persisted runs, scope, lifecycle state, coverage, engine stamps, and
   bootstrap tombstones. The desktop inspector and the standalone CLI
   `connected --dry-run` render that exact serialization without allocating a
   sequence or sending it. CI code-gate submissions use the same builder.
6. **Credential custody and transfer.** Installation tokens and project
   fingerprint keys live in the OS credential store, not SQLite. Encrypted
   connection exports carry site metadata and the fingerprint key but never the
   installation token. Key rotation keeps a pending key until the completing
   snapshot commits.
7. **Bootstrap derivation.** Bootstrap is the union of current canonical groups
   and stored lifecycle overrides. Last-known occurrences come from the most
   recent complete execution that saw each group. Unknown or malformed state
   fails closed instead of being repaired by guesswork.
8. **Source boundaries.** Desktop sync can carry Web and Code Scan observations
   plus user lifecycle intent. CI can submit code evidence and deployment
   provenance but cannot mutate groups or claim a desktop submission sequence.

Changes to any of these invariants must update the shared wire types, inspector
serialization, CLI behavior, and conformance fixtures in the same change.

## Disclosure contract

The connected-service network facts, trust pages, and privacy pages enumerate
the payload sections, retention, erasure receipts, and service destinations.
They state that source code, raw file paths, source excerpts, scan evidence, and
local credentials are excluded from connected submissions.

A wire-field or destination change is incomplete until the payload schema,
network-facts entry, trust copy, and their agreement tests all change together.
The maintained-surface matrix records the public claim-bearing surfaces; it is
not a substitute for the schema tests.

## Design decisions

The implementation contract rests on these decisions:

1. **Lifecycle groups, occurrence records, and observations are three
   resources.** Lifecycle on occurrences cannot represent a fixed issue,
   so groups own state and survive with zero present occurrences.
   Occurrence records are durable: `verified_absent` is a tombstone with
   somewhere to live, and bootstrap carries last-known occurrence
   identities for claimed and verified groups so verification has
   evidence to check. Group verification is derived and never vacuous.
2. **Group existence and state are server-owned.** Clients bootstrap
   once (an explicit site phase committed by `bootstrapped_at`, never
   inferred from emptiness) and mutate thereafter; omission never means
   deletion; scans and hooks stay disabled until bootstrap commits.
   Bootstrap itself never asserts `verified_fixed`: imported claims land
   as `claimed_fixed`, and the bootstrap transaction derives
   `verified_fixed` only where the accompanying snapshots prove it.
3. **Occurrence status preserves route-level tripwires.** Policy stays
   group-level; the server tracks each record as known, verified absent,
   or regressed, and records new occurrences inside active groups.
4. **Client clocks are never a concurrency authority, and ephemeral
   producers carry no counters.** Desktops order themselves with a
   persisted `submission_sequence` keyed to stable installation
   identity (credential rotation continues the counter); CI orders
   through deployment identity plus idempotency; server receipt is the
   only cross-producer order; idempotency replay is evaluated before
   every other guard.
5. **Evidence precedence is asymmetric, with a staleness shield.**
   Presence needs only the pair's own successful execution and is
   accepted from any comparable producer; absence requires governing,
   covering, comparable evidence and resolves backward, never forward;
   CI authority ends when its deployment is superseded. Presence
   evidence based on an older event watermark than the governing absence
   (`based_on_event_sequence`) is historical: recorded, never
   status-changing, never a regression, and it triggers an authoritative
   rescan instead, so a delayed offline upload cannot fake a regression
   and a real one gets confirmed by fresh eyes. The shield covers CI
   as a positive currency requirement: CI presence mutates state only
   from a deployment that is current or atomically becomes current, so
   unordered evidence is history, never authority. Stale code sightings
   set the durable `pending_fresh_evidence` flag rather than triggering
   a hosted rescan, which cannot see code; sightings of unseen
   identities create status-less candidate records rather than
   asserting presence from stale evidence; flagged records are exempt
   from age-based compaction and the flag expires explicitly
   (`evidence_request_expired`) after 90 unanswered days. Bootstrap
   uses the genesis watermark `0`, safe because bootstrap precedes
   every site event.
6. **A user claim is `claimed_fixed`, never `verified_fixed`**, and a
   failed claim returns to `active` with a recorded outcome, not a
   wake-up alert.
7. **Web routes sync in the clear; only code locations are keyed-hashed.**
   The hosted scanner must compute matching identity for live findings;
   routes on a connected production site are public by construction.
8. **Line numbers are excluded from code identity**; `instance_count`
   preserves multiplicity.
9. **The server never holds the fingerprint key.** Manual provisioning
   to CI, local export for second desktops, installation assignment as
   separate authorization, rotation as a server-coordinated epoch with
   one-way commitments, completion gated behind complete project
   coverage, and pending claims ending only by completion, abort, or
   72-hour expiry. Version 1 is claimed at site creation, so no
   unclaimed window exists for a later submission to establish a
   conflicting key.
10. **Identity epochs migrate like key rotations.** Durable records are
    pinned to `(fingerprint_schema, canonicalizer)`; old-epoch records
    are never matched, are retired by complete-coverage snapshots under
    the new epoch, and groups carry across untouched because canonical
    ids are epoch-stable.
11. **Dismissals carry explicit policy** (`snoozed` expiry at read time,
    `ignored` reopen-on-reobservation, `blocked` durable), so guardian
    behavior does not depend on whether a laptop is awake.
12. **Snapshots are source-specific and pair-scoped**, only a covered,
    unexcepted `(route, check)` pair resolves absence, and alias and the
    verified-good profile left the payload (site metadata and
    server-derived, respectively).
13. **Offline decisions keep their original basis.** The
    connected-mutation outbox submits the group revision the user
    actually acted on, so conflicts surface as `stale_revision` for
    explicit reconciliation instead of being silently rebased onto state
    the user never saw.
14. **Four counters with four jobs** (`state_revision`,
    `event_sequence`, `alert_sequence`, `submission_sequence`), and
    recovery is watermark-plus-replay over live-served pages, so
    event-retention expiry degrades catch-up but never loses state.
15. **A retried secret-issuing request answers
    `409 secret_already_issued`.** "Shown once, stored hash-only" and
    "replay returns the original result" cannot both hold, and the
    hash-only property wins: the `Idempotency-Key` record keeps only
    what was created, never the answer, and the refusal's `issued`
    member names it; the remedy is revoke-and-recreate. The erasure
    retry is the same principle carried through consistently: the
    status token is minted once and never replaced, and erasure keeps
    no `Idempotency-Key` record to replay. After deletion, a retried
    account erase answers with the completion fact, matched by the
    receipt's account binding, and a retried site erase answers `404`
    because the site is gone.
16. **Correlation pairs are keyed by stable installation identity** and
    merged as a validated union: independent submission counters are
    never compared, and credential rotation cannot orphan or clobber
    another installation's pairs.
17. **Route identity does not merge what it cannot prove equal**: final
    URL after redirects, trailing slashes preserved, query-dependent
    routes flagged and excluded from comparable verification.
18. **Publish order and creation order are different authorities, and
    receipt order is never a publish authority.** Currency,
    supersession, and causal attribution require `promotion` or
    `publish_sequence`, and both require genuinely ordered facts: an
    ordinal allocated atomically at successful publication, an exact
    predecessor deployment id advanced by compare-and-swap, an
    adapter-specific monotonic promotion sequence, or authoritative
    current-state reconciliation; commit SHAs never qualify because one
    SHA can deploy twice, unique-but-unordered event ids and tied
    timestamps never break ties, and unorderable promotions stay
    historical. Each environment has exactly one active ordering
    authority with a concrete identity
    `{ kind, authority_id, epoch }`, stored as environment state
    independent of the head and changed only through its own
    epoch-guarded endpoint; non-authoritative and pre-activation facts
    are recorded history, and every transition starts behind an
    activation barrier (provider authority reconciles against the
    provider's live answer; publish authority requires a fact causally
    rooted at the carried head or an explicitly seeded watermark), so a
    delayed pre-transition event can never rewind the carried head. A
    failed compare-and-swap stores the predecessor edge for
    reevaluation when the chain heals rather than degrading
    permanently; canonical snapshots are per deployment and coverage
    scope (first accepted; later same-scope differing content is
    state-inert `noncanonical_snapshot` history), healing replays only
    the terminal head's canonical set exactly once, with an event, and
    intermediates stay historical. The complete current deployment
    record (fields enumerated, immutable and enrichable split, hash
    serialization pinned), the watermarks, the authority, and the
    applied-snapshot markers are durable for the site's life, so ninety
    quiet days cannot erase the currency anchor, the provenance facts,
    or conflict checking.
    The CI door's publish attestation must carry a qualifying fact,
    which is what lets a post-deploy Action govern. `creation_sequence`
    only orders history, because a build finishing second may still
    publish first; ordering facts enrich in place and never downgrade.
    Identical redelivery converges as success; CI submissions embed
    their deployment with create-or-match semantics.
19. **One environment per site in v1**, fixed to `production`.
20. **Connected credentials reuse the activation worker and entitlement
    store**, and erasure survives credential revocation through a
    status token carried in the `Authorization` header (never a URL),
    with a receipt whose every field is named: job id, status-token
    hash, erasure scope (`scope_kind` plus opaque scope id, one
    schema for site and account jobs), non-reversible account
    binding, deletion time (recorded after send quiescence, so it
    doubles as the attested no-initiation cutoff).
21. **Durable records have a per-site bound with disclosed compaction**
    (250,000 records; the snapshot is staged and its own prospective
    coverage counts toward retirements before the bound is judged, so
    only net-new insertions can be rejected and a site cannot wedge
    itself at the cap; churned known records and aged tombstones of
    groups that are no longer armed tripwires, including dismissed
    ones, retire first; verified-absence tombstones are preserved
    without aging only under `claimed_fixed` and `verified_fixed`;
    exhaustion is visible `422 record_capacity` backpressure, never
    silent dropping).
22. **Suspended subscriptions get a distinct 403** while invalid
    credentials stay uniform 401, diverging from the catalog's
    uniform-401 posture only where the caller has already proven
    possession of a real credential.
23. **Provider connections are a first-class resource** with
    server-side code exchange, recorded scopes, exclusive project
    binding, visible webhook provisioning state, and two-way
    revocation; provider credentials are never exportable and never
    touch the desktop.
24. **`exact` provenance is earned, not asserted**: GitHub Actions
    submissions bind OIDC claims against constraints pinned on the CI
    token at creation (repository, workflow ref pattern, audience,
    lifetime), out-of-constraint claims reject loudly, and generic CI
    is `unattested`, permanently and non-governing - a SHA
    corroboration proves a deployment exists, not that submitted
    fingerprints came from its checkout, so it upgrades nothing. The
    residual boundary is the pinned workflow itself, stated openly.
25. **Large applies are staged then flipped with every chunk fenced,
    benchmarked at the contract maxima, and sharded by account from
    day one** (`site_id` partitions within the account): chunk
    inserts guard on phase and erasure epoch with cascading deletes
    so erasure races cannot resurrect tenant data, and the shard atom
    is the account because alert ordering, allowances, protected
    sites, and account erasure are genuinely account-global - moving
    a hot account later is routing, not migration.
26. **Allowance slots are leased, not toggled**: disconnect releases
    a slot only after a cooldown, the over-plan set is the complement
    of a deterministic active winner set (protected list, then
    connection recency, then stable id tie-break - defined so no
    reading can suspend a protected site first), reconnect is an
    explicit evented transition covering credentials, webhooks,
    leases, and the retention clock, and restoration is automatic -
    so the billable quantity cannot be rotated through unlimited
    sites, and a downgrade never silently chooses which client loses
    its guardian.
27. **The public surface is a closed inventory.** Every route
    reachable without a bearer token exists in one normative table
    with its authentication, single-use, TTL, and rate-limit
    behavior, split into server-to-server and browser-form classes;
    capability tokens are enumerated beside the bearer
    credentials; and a route not in the table does not exist
    unauthenticated. Presence is tracked per vantage and absence
    clears same-vantage only (check-input equivalence is the one
    sound crossing), and reports are frozen, bounded, stored
    projections.
