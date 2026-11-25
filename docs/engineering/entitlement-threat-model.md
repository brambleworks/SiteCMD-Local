# Entitlement threat model

**Status:** Accepted 2026-07-26. Satisfies gate 4 of the paid intelligence
architecture record (private, SiteCMD-Web repository): "Specify fixed
desktop and CI activation schemas, purchase-key handling, retry nonces,
installation UUIDs, allowed store and variants, rate limits, LemonSqueezy
mapping, credential counts, token lifecycle, webhook ordering, reconciliation,
recovery, logging, and retention."

**Audience:** Whoever implements or reviews activation, revocation, or the
catalog credential lifecycle.

**After reading:** A reader should be able to say what each request may carry,
what happens on every retry and failure path, and which mistakes cost money or
lock out a paying customer.

This document exists because entitlement code is cheap to write and expensive
to get wrong. Every failure below has a specific cost: a double charge, a
customer locked out of software they paid for, or an unrevocable credential.

## What changes

Today the desktop app validates a LemonSqueezy license key directly and gates
features client-side. That works only while the source is private. Under the
catalog model:

- A SiteCMD-operated service is the authority on entitlement.
- The client exchanges a purchase key **once** for an opaque catalog token.
- The catalog Worker verifies only that token. It never sees a purchase key.
- Tier gating stops being a client-side redaction of bundled content and
  becomes "does this client hold a token that fetches a pack".

## Assets, ranked by what losing them costs

| Asset                  | Compromise means                                               |
| ---------------------- | -------------------------------------------------------------- |
| LemonSqueezy API key   | Read customer records, issue refunds, revoke licenses at scale |
| Webhook signing secret | Forge subscription events: grant or revoke entitlement freely  |
| Purchase license key   | Impersonate one customer's purchase during activation          |
| Catalog token          | Read one subscriber's catalog stream until revoked             |
| Entitlement store      | Enumerate subscribers; with write access, mint entitlement     |

The purchase key ranks above the catalog token because it can mint tokens; the
token only reads. That ordering is why the exchange is one-way and why the
catalog Worker never accepts a purchase key.

## Activation request

Fixed schema. The endpoint rejects unknown fields rather than ignoring them.

```json
{
  "licenseKey": "<purchase key>",
  "installationId": "<random UUID, generated once, persisted locally>",
  "nonce": "<random, persisted until this request completes>"
}
```

Nothing else. No project name, path, scan result, machine name, or IP-derived
identifier beyond what the transport necessarily exposes.

**The key is a bearer secret, not project data.** Rules, each closing a
specific leak:

- POST body only. Never a URL, query string, or custom header, because those
  reach proxy logs, browser history, and `Referer`.
- Never persisted server-side. The service keeps a server-keyed HMAC
  fingerprint so it can recognize the same purchase again without being able to
  reconstruct the key from a database dump.
- Never logged, cached, traced, put in an analytics event, or echoed in a
  response, including error responses. A validation failure that quotes the
  rejected key back writes it to the client's log file.
- The client sends it once. After exchange, ordinary operation uses the opaque
  token alone.

**Whether the raw key stays in the OS keyring after exchange** (gate 7's open
question): yes, and only for deactivation and re-activation on a new
installation, both of which are user-initiated and need to prove purchase.
Nothing routine reads it.

## Retry, and why the nonce exists

Activation is not idempotent by nature: it consumes a credential slot. A client
that times out and retries must not consume two.

The nonce makes it idempotent. The service stores `nonce -> activation result`
and returns the existing record for a repeat, without a second upstream
operation and without allocating another slot. The client persists the nonce
until the request completes, so a crash mid-flight still retries safely, and
generates a fresh one only for a genuinely new activation.

The nonce is bound to the subscriber who minted it, on both sides. The service
records the key fingerprint beside the nonce and refuses a replay under any
other fingerprint; the client stores the nonce with a hash of its license key
and installation id, and discards it when either changes. Without the binding,
a nonce was a bare global key: one subscriber's pending nonce answered
"already activated" to a different key presenting it, and a client that
switched license keys mid-attempt replayed the old attempt forever.

**The failure this prevents:** a customer on a flaky connection retries three
times, burns all three Core credentials, and is locked out of their own
subscription on the machine they are sitting at.

## Validation before issuing

Every one of these must pass. Any failure returns a generic error to the
client and a specific one to the operator:

1. LemonSqueezy reports the key valid and the subscription active.
2. The store id matches the expected SiteCMD store. A valid key from another
   store is not a SiteCMD purchase.
3. The variant id is one of the four known Core/Pro monthly/annual variants.
   An unrecognized variant means either a new product nobody wired up or a
   forged response; both must fail closed rather than defaulting to a tier.
   The variant that decides the issued tier and its cap is the
   subscription's current one (from the subscriptions lookup in rule 4), not
   the license's: the license names the original order item and never moves
   on a plan change, so deciding from it let a downgraded subscriber keep
   minting under the old cap and pinned an upgraded one to it. The license's
   variant decides only when the subscription response omits the field.
4. The subscription behind the key's order reports an entitled status of its
   own. The key's status does not reflect a paused subscription, so checking
   the key alone made re-activation a suspension bypass. An unrecognized
   subscription status refuses here even though reconciliation leaves it
   alone: this step mints new access, and new access on an unproven status is
   the worse guess.
5. The service's own `subscription_states` record - written by webhooks, the
   reconciliation sweep, and activations, newest observation wins - does not
   say suspended. Checked inside the issuing transaction, so a suspend
   webhook that lands between the upstream fetch and the insert still wins.
6. Issuing this credential would not exceed the tier's active-credential cap.

Rule 3 is the one most likely to be skipped and the most expensive to skip: a
default-to-Core path turns any valid key from any product into Core access.

## Credential cap

Core is three active credentials, across desktop installations and CI scopes
combined. Pro is five desktop plus uncapped internal CI scopes.

The cap counts **active server-issued credentials**, not LemonSqueezy machine
instances. Those are not one-to-one and never were, so deriving the cap from
upstream would drift.

It counts them **per subscription**, not per key fingerprint. The fingerprint
is derived from the key's bytes, so an upstream key regeneration changes it:
a fingerprint-counted cap would see zero seats in use under the new key while
the old key's seats lived on, and deactivating those seats with the new key
would be impossible forever. Deactivation resolves the subscription the same
way, falling back to the fingerprint match only when upstream is unreachable.

**Re-activation replaces the machine's credential, never adds one.** A client
only activates when it holds no usable token, so any active credential for
the same subscription and installation is orphaned by construction; issuing
revokes it in the same transactional batch, and the cap check excludes the
machine's own row. Without the replacement, every suspension cycle consumed
a seat - the 401 clears the client's token, resume re-activates - until the
cap locked the subscriber out of machines they own.

**A plan downgrade does not revoke seats above the new cap.** Existing
credentials keep working; new activations are refused until the active count
is under the new cap. Auto-revoking would have to guess which machines the
subscriber cares least about, and both the guess and the surprise are worse
than a refusal that names the remedy.

At the cap, activation fails with an actionable error naming what to do
(deactivate an installation) rather than a bare rejection. A user who bought
the product and cannot use it will ask for a refund, so the error text is a
retention concern, not just a UX one.

Deactivation revokes the downstream credential and releases its slot
immediately, without waiting on any upstream instance lifecycle.

## Token lifecycle

- Opaque, random, no structure a client can parse or forge.
- Stored server-side as SHA-256 of the token. A store dump yields nothing
  usable, and lookup by hash is the same single read as lookup by value.
- Held client-side in the OS keyring, never in SQLite.
- Revoked by marking the record, never by deleting it. A deleted record is
  indistinguishable from one that never existed, so re-adding a key would
  silently undo a revocation.
- Rotatable without touching the purchase key.

## Webhooks

LemonSqueezy sends subscription events. Each is a request to change entitlement,
so each is a target.

- **Verify `X-Signature` first.** An unverified webhook endpoint is an
  unauthenticated "grant me entitlement" API.
- **Idempotent.** The same event id delivered twice must produce one effect.
  Providers retry; a non-idempotent handler double-applies.
- **Ordered.** Store the event timestamp and refuse to apply one older than the
  state it would overwrite. The failure this prevents: a delayed `cancelled`
  arrives after a `renewed` and cancels a customer who has paid.
- **Reconciliation.** A periodic sweep repairs missed deliveries, because a
  webhook that never arrives is silent.

## Subscription lapse

The [Terms of Service](https://sitecmd.com/terms) say cancellation takes effect
at the end of the free trial or the paid period and SiteCMD stops watching
your sites when the subscription ends.

The CLI runs Code Scan and local site checks through the embedded module
without checking subscription status. For public-site scans, it calls the
hosted scanner, where the service enforces entitlement.

## Logging and retention

Production logs keep the minimum for abuse prevention and operations:
timestamp, outcome, coarse error class, and a token hash prefix. Never a
purchase key, a full token, or any project-derived value.

Activation records retain the HMAC fingerprint and upstream subscription
identifiers for the life of the subscription plus the published retention
window, because refunds and disputes arrive after cancellation.

## Rate limits

- Activation: per IP and per key fingerprint. A key-fingerprint limit is what
  stops credential-stuffing a stolen key list; an IP limit alone does not.
- Catalog reads: per IP and per token, already implemented in the catalog
  Worker.
- A missing limiter binding fails closed. An unthrottled activation endpoint in
  front of a paid API is worse than a brief outage.

## Accepted, not solved

- **A lost activation response can strand a LemonSqueezy instance.** The
  desktop client never calls `api::activate` when the entered key is already
  installed and active, and every other path tears the predecessor down
  first, so no _deterministic_ flow mints an instance it cannot later
  release. What remains is the transport case: the provider commits an
  instance and the response never arrives, so the client holds no instance
  id and a retry mints another. The license API offers activate, validate,
  and deactivate only - no way to enumerate a key's instances without the
  vendor API key, which must never ship in a client - so reconciliation from
  the client is not possible. Stranded instances are visible in the
  LemonSqueezy dashboard and releasable by support. The catalog seat
  replaces itself on the next activation only while the installation id is
  unchanged; a keychain wipe mints a new instance id, so the client's Fresh
  path releases the old row's seat and instance with the entered key before
  minting. What that reclaim cannot cover is a machine that is simply gone
  (lost, wiped entirely): its catalog seat holds a cap slot until an
  operator revokes the credential row, because `/v1/deactivate` requires
  the installation id and only the departed machine's flow ever presents
  it. A self-service seat list is a post-launch feature, not a launch
  control; the cap refusal in the app names the deactivate-a-machine
  remedy.

- **Token sharing.** A subscriber can hand their token to someone else. The cap
  counts issuance, not use, and the RFC says so. Detection is a later
  behavioral question, not a launch control.
- **Pack copying.** The client must read the pack, so a subscriber can keep or
  copy it. One copied pack is a stale snapshot; the product is the maintained
  stream.
- **A compromised entitlement store** can mint entitlement. The intended
  mitigation was to scope the store's write credential to the activation
  surface, but Cloudflare D1 bindings are read-write and there is no read-only
  mode, so that is not available. What exists instead is a code boundary: the
  catalog Worker contains no write path, and activation is a separate Worker
  with its own deploy path and review surface. A runtime compromise of either
  could still write. Recorded here rather than claimed as solved.
