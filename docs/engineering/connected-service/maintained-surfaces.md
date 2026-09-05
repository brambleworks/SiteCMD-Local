# Connected service: the maintained-surface matrix

**Status:** Maintained inventory for the publication sweep. Technical review
keeps this matrix reconciled; release acceptance is recorded privately.

**Audience:** Whoever executes the sweep, and anyone adding a surface that
asserts a boundary, pricing, or privacy claim.

**After reading:** A reader should be able to say, for any claim-bearing
surface, what it asserts, which generated facts it agrees with, what evidence
reconciled it, and where the final release decision belongs.

## Why a list and not a phrase ban

A phrase ban catches verbatim survivals of the superseded contract. It does not
catch semantic ones: a page that never says "unlock details" can still describe
a product where the paid value is remediation depth. The list exists so that
the sweep is bounded and checkable rather than a grep and a hope, and so that a
new claim-bearing surface has to be added deliberately.

Two rules follow from that, and both are enforced by
`tools/scripts/lib/guardrail-publication-record-rules.mjs`:

- Every local claim-bearing surface has a row here, and every row that names a
  local path points at a file that exists.
- A product-truth document that asserts a boundary, pricing, or privacy promise
  and is not on this list is itself a finding. The sweep is over root Markdown,
  `apps/*/PRODUCT.md`, the agent guides, and `docs/product/`; the engineering
  specifications are excluded by construction, because they define the contract
  rather than assert it to a customer.

## What counts as a claim

- **Boundary**: what is free, what is paid, what is open source, what runs where.
- **Pricing**: prices, plan inclusions, allowances, caps, and what happens at a
  limit.
- **Privacy**: what leaves the machine, what a SiteCMD service receives or
  retains, and what is promised never to travel.

A document that only describes mechanism (how redaction is implemented, how an
entitlement is read) is not making a claim. A document that tells a reader what
they get, or what will never happen to their data, is.

## This repository

| Surface                                                | Claims                                                        | Must agree with                             | Reconciliation evidence                                                                                                                                                               |
| ------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `README.md`                                            | Privacy posture, license, what the product is                 | `product-facts.json`, publication decision  | Reconciled 2026-08-20: local and connected boundaries remain explicit; the Code Scan CLI links its public installer source and an inspect-before-run path                             |
| `CONTRIBUTING.md`                                      | What is open, what lives elsewhere, contribution boundaries   | Publication decision                        | Reconciled 2026-08-13: public contribution scope and private service boundary match the repository layout                                                                             |
| `SECURITY.md`                                          | The privacy boundary as a security boundary, reporting scope  | Trust and privacy pages                     | Reconciled 2026-08-13: desktop, connected API, hosted scan, delivery, and privacy-boundary reporting are covered                                                                      |
| `SUPPORT.md`                                           | Support expectations                                          | `terms.astro`                               | Reconciled 2026-08-13: support scope and commercial record do not invent a paid local feature boundary                                                                                |
| `CHANGELOG.md`                                         | What shipped, including tier and boundary changes             | Release tags                                | Reconciled 2026-08-13: publication entries describe the free-complete migration and connected-service implementation as shipped                                                       |
| `AGENTS.md` and the directory guides                   | Shipped entitlement and redaction behavior                    | `product-facts.json`                        | Reconciled 2026-08-17: guidance states there is no local feature gating, documents the shipped `sitecmd audit` path, and points paid entitlement to the server-side connected service |
| `apps/desktop/PRODUCT.md`                              | Product truth, the paid axis, the privacy promise             | `product-facts.json`, connected-service RFC | Reconciled 2026-08-17: local workbench is complete and free; connected automation and maintained intelligence are the subscription boundary; outbound payloads are named              |
| `apps/desktop/DESIGN.md`                               | None; visual brief only                                       | Nothing generated                           | Reconciled 2026-08-13: inspected as a watch-only surface; it makes no pricing or privacy promise                                                                                      |
| `docs/engineering/adding-a-detector.md`                | Public contributor scope and local detector workflow          | `CONTRIBUTING.md`, `product-facts.json`     | Fixtures, baseline guides, and engine tests are in this checkout; catalog release operations remain maintainer-owned                                                                  |
| `docs/engineering/entitlement-threat-model.md`         | What client-side enforcement can and cannot promise           | `product-facts.json`                        | Reconciled 2026-08-13: local enforcement is not treated as the paid boundary; connected entitlement is server-authoritative                                                           |
| `docs/engineering/repository-release-security-spec.md` | Release and signing trust claims                              | Release workflows                           | Reconciled 2026-08-20: implemented tag, candidate, signing, verification, and publication controls are separated from external setup and future hardening                             |
| `docs/engineering/connected-service/`                  | The public connected implementation contract                  | Each other                                  | Reconciled 2026-08-20: protocol, hosted-runner, delivery, and maintained-surface documents contain current normative text without point-in-time implementation diaries                |
| `docs/product/`                                        | What a new user is told the product does                      | `product-facts.json`                        | Reconciled 2026-08-13: product language uses the free-complete local boundary and the connected-service beta status                                                                   |
| `docs/qa/` and `docs/operations/`                      | Test expectations and runbook steps that encode tier behavior | `product-facts.json`                        | Reconciled 2026-08-20: runbooks exercise the free CLI, explicit local database inspection, connected entitlement, in-place public cutover, PR release prep, and signed release tags   |
| `product-facts.json`                                   | The generated cross-repository fact channel                   | Its own sources, guardrail-enforced         | Reconciled 2026-08-13: regenerated facts are identical across repositories and consumed by the site claims tests                                                                      |
| Licensing and upsell copy in `apps/desktop/src`        | Tier labels, gate strings, upgrade prompts                    | `product-facts.json`                        | Reconciled 2026-08-17: local FeatureGate, history caps, report gates, and redaction copy are absent; subscription copy describes connected and catalog status only                    |

## SiteCMD-Web

Checked by the sweep in that repository and listed here so the contract has one
inventory rather than two.

| Surface                                                       | Claims                                                      | Must agree with                              | Reconciliation evidence                                                                                                                                         |
| ------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/engineering/publication-decision.md`                    | License, public scope, tiers, both privacy boundaries       | Commercial terms spec, connected-service RFC | Reconciled 2026-08-13: private strategy record has one current contract and is protected from links in the public repository                                    |
| `docs/engineering/paid-intelligence-rfc.md`                   | The catalog boundary and the Free content contract          | Publication decision                         | Reconciled 2026-08-13: catalog mechanics remain private; local issue detail is not sold as the subscription boundary                                            |
| `docs/engineering/connected-service/connected-service-rfc.md` | Product direction, privacy semantics, beta graduation gates | Publication decision                         | Reconciled 2026-08-13: full connected beta is the product baseline and its acceptance signals are graduation evidence, not implementation gates                 |
| `docs/engineering/connected-service/commercial-terms-spec.md` | Commercial structure, measurement program, pricing pass     | Publication decision                         | Reconciled 2026-08-13: connected-service access is free during the beta, public pricing remains unset, and no unmeasured overage claim is published             |
| `pricing.astro`, `PricingToggle`                              | Prices, plan inclusions, what each tier gets                | `product-facts.json`                         | Reconciled 2026-08-13: beta-window copy says complete local workbench, comped connected beta, and no invented public price                                      |
| `pricing-claims.test.ts`                                      | Enforces the boundary in both directions                    | `product-facts.json`                         | Reconciled 2026-08-13: tests pin free local depth, connected paid boundary, free beta access, and unset public pricing                                          |
| `network-facts.ts`                                            | Every outbound destination and what it carries              | The payload schema                           | Reconciled 2026-08-13: connected API, scan, verification, provider, delivery, and telemetry destinations are enumerated and agreement-tested                    |
| `/trust` and the privacy pages                                | The privacy promise, retention, subprocessors               | `network-facts.ts`                           | Reconciled 2026-08-13: payload, retention, erasure, Browser Run, Resend, and server-side enforcement disclosures match the network facts                        |
| `/scanner`                                                    | What a scanned site receives and who sent it                | `product-facts.json`                         | Reconciled 2026-08-15: both senders are named; Worker-proxied browser traffic, unsigned identity, and Cloudflare egress variability replace a fake address list |
| `apps/sitecmd-connect/README.md`                              | What the service stores and what it never can               | The connected specs                          | Reconciled 2026-08-13: hosted execution, binding-only operations, encrypted-at-rest envelopes, and current egress disclosure are documented                     |
| Docs site: tiers, FAQ, glossary, guides                       | What each tier includes                                     | `product-facts.json`                         | Reconciled 2026-08-17: CLI, CI, Code Scan, FAQ, and editor guides document free local source auditing and signature-verified pinned CI installation             |
| `terms.astro`                                                 | The commercial promise of record                            | Commercial terms spec                        | Reconciled 2026-08-13: connected subscription, suspension, allowance, beta access, and no-metered-overage terms match the commercial record                     |
| `llms.txt`                                                    | The machine-readable product summary                        | `product-facts.json`                         | Reconciled 2026-08-13: generated summary states the complete local boundary and the connected beta status                                                       |

## Release decision

This matrix is evidence for the release decision, not the decision itself.
Repository guardrails and agreement tests can prove structural consistency;
they cannot accept product claims on the founder's behalf. The publication
checklist requires the founder to review the complete matrix and keep the
dated acceptance in the private release record. Names, dates, signatures, and
completed acceptance checkboxes do not belong in this public document, and an
agent must never add them.

## The superseded-contract phrases

Data for the sweep, not a substitute for semantic review. These phrases
describe retired contracts and may not appear in customer-facing copy:

- "unlock details", "unlock this finding", and the unlock-meter framing
- "3 free AI fixes" and any monthly agent-fix allowance
- the Core-as-detailed-guides framing: remediation depth as the headline paid
  value
- device-cap sales language: seats or installations sold as the scarce resource
- daily scan limits, history caps, and local site caps described as tier
  features

The migration has retired these contracts. Guardrails and claim tests enforce
the current boundary on customer-facing and product-truth surfaces. Accepted
specifications contain only the current normative contract; Git retains their
history.

## Adding a row

A new surface that asserts a boundary, pricing, or privacy claim goes on this
list in the same change that creates it. State what it claims, name the
generated facts it has to agree with (or "nothing generated", honestly), and
record the evidence that reconciles it. Technical evidence may be produced by
automation or review. The final human release decision remains private under
the publication checklist.
