# Documentation

The maintained public documentation for this repository: engineering references, the
connected-service specifications, operations runbooks, product notes, and QA commands. Outside
readers use it to verify the CLI's privacy and network claims, so it describes current behavior
and accepted decisions only.

## Code map

- `README.md`: the docs index, linked from the root `/README.md`.
- `engineering/engine-boundary.md`: how a reader verifies the CLI's filesystem and network
  boundary and the engine module's empty import list.
- `engineering/connected-service/connected-protocol-spec.md`: the connected-service wire contract.
- `engineering/connected-service/alert-delivery-spec.md`: alert and report delivery.
- `engineering/connected-service/maintained-surfaces.md`: the maintained-surface matrix, one row
  per surface that asserts what is free, paid, or transmitted.
- `engineering/guardrails.md`: how guardrails are structured, added, and ratcheted.
- `engineering/ai-assisted-development.md`: how coding agents are directed here.
- `engineering/repository-release-security-spec.md`, `engineering/release-tag-signing.md`,
  `engineering/release-signing-key-rotation.md`, `engineering/macos-code-signing.md`,
  `engineering/windows-code-signing.md`: release trust and signing.
- `engineering/entitlement-threat-model.md`, `engineering/security-review-cadence.md`,
  `engineering/naming-conventions.md`: threat model, review cadence, and naming.
- `operations/releasing.md` and `operations/launch-smoke.md`: release and smoke runbooks.
  `operations/publication-checklist.md` is the historical record of the public cutover.
- `product/scanner-accuracy-log.md`: scanner accuracy notes.
- `qa/native-tests.md`: how to run the Rust workspace tests.

## Entry points

Readers arrive through `README.md` here and the Documentation list in `/README.md`.
`/CONTRIBUTING.md` sends contributors to `engineering/engine-boundary.md` first.

## How it works

Each document states current truth. Generated plans, review transcripts, one-off audits,
acceptance results, design exports, and session artifacts stay out of Git; promote a durable
conclusion into the right document instead. Business records kept outside this repository are
named in plain text, never linked.

## Invariants

- No em dashes: `/tools/scripts/lib/guardrail-em-dash-rules.mjs`.
- No machine-specific absolute paths or links: `/tools/scripts/lib/publication-hygiene-rules.mjs`
  and `/tools/scripts/lib/guardrail-doc-rules.mjs`.
- No link to a private business record, and every product document that makes a boundary,
  pricing, or privacy claim has a row in the matrix, whose listed paths exist:
  `/tools/scripts/lib/guardrail-publication-record-rules.mjs`.
- Connected-service specs reach their first normative section within 60 lines, keep no review
  transcript, never defer a rule to a private record, and specify no retired Connect contract:
  `/tools/scripts/lib/guardrail-publication-record-rules.mjs` and
  `/tools/scripts/lib/guardrail-public-face-rules.mjs`.
- `README.md` marks the publication checklist historical on the line that links it and says the
  connected-service specifications are public: `/tools/scripts/lib/guardrail-public-face-rules.mjs`.
- Product documents describe what the CLI does, not product intent:
  `/tools/scripts/lib/guardrail-public-face-rules.mjs`.
- Local links in `README.md` and `engineering/engine-boundary.md` resolve:
  `/tools/scripts/documentation-contract.test.mjs`.
- A `--filter` names a real workspace package, and no document names the retired local
  verification command: `/tools/scripts/lib/guardrail-publication-record-rules.mjs` and
  `/tools/scripts/lib/guardrail-local-delivery-rules.mjs`.

## Testing

From the repository root:

```bash
pnpm guardrails:repo
pnpm exec vitest run tools/scripts/documentation-contract.test.mjs tools/scripts/product-claims.test.mjs
pnpm exec prettier --check docs
```

## Boundaries

- The specs in `engineering/connected-service/` are the contract between this repository's
  `sitecmd-protocol` sync types and the connected service, which lives outside this repository.
- `engineering/engine-boundary.md` describes code in `/apps/desktop/src-tauri/crates/engine-host/`
  and `/apps/desktop/src-tauri/src/core/`; change it when that boundary changes.
- `qa/native-tests.md` repeats the test commands in `/apps/desktop/src-tauri/AGENTS.md`.

## Guide triggers

- `README.md`
- `engineering/connected-service/*.md`
- `engineering/engine-boundary.md`
- `qa/native-tests.md`
- `engineering/ai-assisted-development.md`
- `operations/releasing.md`
