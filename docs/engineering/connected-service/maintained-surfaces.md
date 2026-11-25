# Connected service: the maintained-surface matrix

**Status:** Maintained inventory for the publication sweep. Technical review
keeps this matrix reconciled; release acceptance is recorded privately.

**Audience:** Whoever executes the sweep, and anyone adding a surface that
asserts a boundary, pricing, or privacy claim.

**After reading:** A reader should be able to say, for any claim-bearing
surface, what it asserts, which product contracts it agrees with, what evidence
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

- **Boundary**: what is free, what is paid, which source is open, and where the engine module and services run.
- **Pricing**: prices, plan inclusions, allowances, caps, and what happens at a
  limit.
- **Privacy**: what leaves the machine, what a SiteCMD service receives or
  retains, and what is promised never to travel.

A document that only describes mechanism (how redaction is implemented, how an
entitlement is read) is not making a claim. A document that tells a reader what
they get, or what will never happen to their data, is.

## This repository

| Surface                                                | Claims                                                        | Must agree with                             | Reconciliation evidence                                                                                                                                                                                                                                           |
| ------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `README.md`                                            | Privacy posture, license, what the product is                 | `docs/product/`, `LICENSE`, engine boundary | The CLI and host source are open, and releases embed the separately licensed engine module. The Code Scan CLI links its public installer source and an inspect-before-run path.                                                                                   |
| `CONTRIBUTING.md`                                      | Open CLI and host, private checks, contribution boundaries    | `LICENSE`, engine boundary                  | Public contribution scope covers the CLI and host source. Checks ship in the engine module compiled from private source.                                                                                                                                          |
| `docs/engineering/engine-boundary.md`                  | Local data access, engine isolation, outbound requests        | CLI and host source, embedded engine module | The host source and the module's import list let readers verify the filesystem and network boundaries.                                                                                                                                                            |
| `SECURITY.md`                                          | The privacy boundary as a security boundary, reporting scope  | Trust and privacy pages                     | Reconciled 2026-08-13: desktop, connected API, hosted scan, delivery, and privacy-boundary reporting are covered                                                                                                                                                  |
| `SUPPORT.md`                                           | Support expectations                                          | `terms.astro`                               | Reconciled 2026-08-13: support scope and commercial record do not invent a paid local feature boundary                                                                                                                                                            |
| `CHANGELOG.md`                                         | What shipped, including tier and boundary changes             | Release tags                                | Reconciled 2026-08-13: publication entries describe the free-complete migration and connected-service implementation as shipped                                                                                                                                   |
| `AGENTS.md` and the directory guides                   | Shipped entitlement and redaction behavior                    | `docs/product/`                             | Reconciled 2026-08-17: guidance states there is no local feature gating, documents the shipped `sitecmd audit` path, and points paid entitlement to the server-side connected service                                                                             |
| `docs/engineering/repository-release-security-spec.md` | Release and signing trust claims                              | Release workflows                           | Reconciled 2026-08-20: implemented tag, candidate, signing, verification, and publication controls are separated from external setup and future hardening                                                                                                         |
| `docs/engineering/connected-service/`                  | The public connected implementation contract                  | Each other                                  | Reconciled 2026-09-28: account access, token scopes, session routes, leaked-token notices, and credential-keyed producers follow Connect; the shipped desktop's installation token is refused, and its omitted response fields use false, null, and zero defaults |
| `docs/product/`                                        | What a new user is told the product does                      | Connected product contract                  | Reconciled 2026-08-13: product language uses the free-complete local boundary and the connected-service beta status                                                                                                                                               |
| `docs/qa/` and `docs/operations/`                      | Test expectations and runbook steps that encode tier behavior | `docs/product/`                             | Reconciled 2026-08-20: runbooks exercise the free CLI, explicit local database inspection, connected entitlement, in-place public cutover, PR release prep, and signed release tags                                                                               |
| `docs/engineering/entitlement-threat-model.md`         | What client-side enforcement can and cannot promise           | `docs/product/`                             | Reconciled 2026-08-13: local enforcement is not treated as the paid boundary; connected entitlement is server-authoritative                                                                                                                                       |

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
public contracts it has to agree with, and record the evidence that
reconciles it. Technical evidence may be produced by
automation or review. The final human release decision remains private under
the publication checklist.
