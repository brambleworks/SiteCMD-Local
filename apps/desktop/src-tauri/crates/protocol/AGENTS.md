# Protocol

`sitecmd-protocol` holds the wire types and pure helpers shared by the CLI runtime, the engine
host, and the engine module, and the wire contract the connected service reads: the engine ABI,
the connected sync payload, the scan vocabulary, identities, route canonicalization, and log
redaction. Its production code does no I/O and reads no clock.

## Code map

- `Cargo.toml`: the package. `jiff` builds without `std` so timestamps never come from an
  ambient clock; the `test-support` feature adds `regex-automata`.
- `src/lib.rs`: the module list.
- `src/engine_abi/`: the module ABI. `src/engine_abi/mod.rs` holds `ENGINE_ABI_VERSION`,
  `EXPORTS`, and the audit limits; `src/engine_abi/types.rs` holds tasks, wants, answers, and
  reports; `src/engine_abi/frame.rs` encodes and decodes messages; `src/engine_abi/guest.rs` holds
  the module-side helpers the stand-in uses; `src/engine_abi/fixes.rs` and
  `src/engine_abi/local_site_wire.rs` hold fix and local page messages.
- `src/sync/`: the connected payload. `src/sync/wire.rs` and `src/sync/wire_grammar.rs` hold
  validated wire identifiers; `src/sync/payload.rs` and `src/sync/snapshot.rs` hold the submission
  shapes; `src/sync/fingerprint.rs` holds the project fingerprint key and its one-way digests.
- `src/vocab.rs`: `Severity`, `Category`, `CheckStatus`, `CheckResult`, and `IssueConfidence`.
- `src/code_scan.rs`, `src/code_scan/abi.rs`, `src/code_domain.rs`, `src/identity.rs`: Code Scan
  reports, domains, and delimiter-aware check and producer rule identities.
- `src/route.rs`: versioned route canonicalization; `src/url_path.rs` and `src/network_class.rs`
  hold path comparison, address classification, and URL identity.
- `src/log_sanitizer.rs` and `src/log_sanitizer/`: redaction of credentials and secrets in logs
  and evidence.
- `src/time.rs` and `src/time/`: timestamp and calendar types for wire and stored data.
- The other files in `src/` each hold one shared concern: scores, coverage, capability manifests,
  release provenance, page facts, stacks, the storage gate, skipped scopes, header lines, scanner
  identity, brief copy, dotenv database declarations, and project path lookup.
- `tests/time_compatibility.rs`: timestamp formatting compatibility.

## Entry points

This is a library. Callers use `engine_abi::{encode_request, decode_answer}` and the types in
`engine_abi::types` to talk to the module, `sync` types to build connected submissions, and
`log_sanitizer` to redact text before it is logged or sent.

## How it works

The host and the module exchange framed JSON messages defined in `src/engine_abi/`. A request
carries a task; the module replies with a `Step` of wants or a `Done` result. The module reports
its `abi_version` in `engine_info`, and the host refuses any version but `ENGINE_ABI_VERSION`.

Connected submissions are built from `src/sync/` types. Wire identifiers validate on
construction and on deserialization, so an invalid value cannot be built or decoded. Code
findings travel as rule-level check IDs with location hashes made from the project fingerprint
key, never as source text or paths.

## Invariants

- Every source file and module is listed in `/tools/scripts/lib/guardrail-protocol-contents-rules.mjs`.
  Adding a file means adding it there. The same rule keeps `include!` paths literal and inside the
  crate, bans engine crate dependencies, and limits the `storable` gate to the engine.
- `src/vocab.rs` keeps the canonical `Severity` and `Category` helpers, and
  `/apps/desktop/src-tauri/src/core/scan_types.rs` re-exports them:
  `/tools/scripts/lib/guardrail-protocol-vocab-rules.mjs`.
- `CheckResult` carries `IssueConfidence` with a serde default:
  `/tools/scripts/lib/guardrail-protocol-contents-rules.mjs`.
- `src/sync/wire.rs`, `src/sync/wire_grammar.rs`, `src/manifest.rs`, and `src/route.rs` are
  reviewed serializers pinned by SHA-256 in `/tools/scripts/lib/guardrail-connected-request-rules.mjs`
  (tested by `/tools/scripts/guardrail-connected-request-rules.test.mjs`). An edit needs review and
  a new digest there.
- `ProjectFingerprintKey` is never serializable and never prints its bytes, and the sync payload
  keeps `SCHEMA_VERSION` and bans finding content and source location fields:
  `/tools/scripts/lib/guardrail-sync-payload-rules.mjs`.
- `src/route.rs` keeps `CANONICALIZER_VERSION`; a rule change is a new version:
  `/tools/scripts/lib/guardrail-scan-scope-rules.mjs`.
- Text is redacted whole before it is truncated, sliced, or windowed, and scan evidence uses
  evidence redaction: `/tools/scripts/lib/guardrail-redaction-order-rules.mjs`.
- Wire identifiers accept and reject exactly the examples in
  `../../tests/fixtures/parity/wire_identifiers.json`: `src/sync/wire_tests.rs`.
- No ambient clock: `/tools/scripts/lib/guardrail-ambient-clock-rules.mjs`.

## Testing

From `/apps/desktop/src-tauri`, with the environment from `../../AGENTS.md`:

```bash
cargo test --locked -p sitecmd-protocol
```

## Boundaries

- The engine module is built against `src/engine_abi/` and must report the same
  `ENGINE_ABI_VERSION`; the module itself lives outside this repository and is pinned by
  `/engine.lock`. The stand-in in `../engine-host/standin/` implements the same ABI for tests.
- The connected service reads the payloads in `src/sync/`. The contract is
  `/docs/engineering/connected-service/connected-protocol-spec.md`; change the spec and the types
  together.
- `../engine-host/` and the runtime in `../../src/` depend on this crate.

## Guide triggers

- `Cargo.toml`
- `src/lib.rs`
- `src/engine_abi/*.rs`
- `src/sync/*.rs`
- `src/vocab.rs`
- `src/route.rs`
- `src/manifest.rs`
- `src/code_scan.rs`
- `src/identity.rs`
