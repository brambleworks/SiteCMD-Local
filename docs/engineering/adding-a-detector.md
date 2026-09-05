# Adding a detector

This walkthrough follows `config.deprecated_html`, a pure Web Scan check, from
page input to a displayed finding. It is also a template for adding a new check
in a fork or an invited contribution. It requires only the public repository,
Rust, and the Node/pnpm versions described in the root README. No account,
catalog credentials, hosted service, or desktop signing key is needed.

The contribution policy in [CONTRIBUTING](../../CONTRIBUTING.md) still applies.
For an accuracy report, share a minimized fixture through the false-positive
issue form before attempting a change to the rule's semantics.

## Run the existing check

Start from the repository root:

```bash
cd apps/desktop/src-tauri
cargo test -p sitecmd-engine deprecated_html
cargo test -p sitecmd-engine --test golden_checks
```

The first command runs the detector's focused tests; the second exercises the
shared page-artifact corpus. Neither launches Tauri nor makes network requests.

Read these files in order, relative to `apps/desktop/src-tauri/`:

| File                                                 | Responsibility                                               |
| ---------------------------------------------------- | ------------------------------------------------------------ |
| `crates/engine/src/checks/config/deprecated_html.rs` | Pure verdict and focused positive/negative examples          |
| `crates/engine/src/page.rs`                          | Page facts and injected evaluation time                      |
| `src/checks/config/mod.rs`                           | Native registry that schedules the check                     |
| `crates/engine/src/manifest/registry/config.rs`      | Stable result identity, revision, and hosted capability      |
| `crates/engine/tests/golden_checks.rs`               | Dispatcher and explicit semantic assertions for corpus cases |
| `crates/engine/fixtures/checks/golden.json`          | Portable inputs and exact serialized results                 |

The baseline fix guide is
`apps/desktop/src/lib/fix-guides/config.ts`, keyed by the same canonical check id.

## Define the behavior before adding a rule

Write down the observed fact, the conclusion that fact supports, and the
smallest useful remediation. Choose a stable id independent of a URL or file
path. Set severity and confidence separately: an obvious markup match may be
high-confidence while its actual impact is low severity.

Use `config.deprecated_html` as a concrete example:

- `<marquee>Sale</marquee>` produces a Low warning.
- `<main>Sale</main>` passes.
- `<font-awesome-icon>` passes because a custom element is not `<font>`.
- A commented-out tag or tag text inside a script does not count as page markup.

For a new check, add similarly small positive, negative, and misleading-input
fixtures. Assert status, canonical id, severity, and relevant evidence directly.
Include skipped/unavailable outcomes when missing data cannot establish a pass.
Do not make an accuracy assertion depend only on a regenerated snapshot.

## Implement and register

1. Put synchronous verdict logic under the engine's category module and expose
   it from that module's `mod.rs`. Use `PageContext` or an existing typed fact
   schema. The engine accepts evaluation time as input and performs no I/O.
2. Add the check to the appropriate native `sync_checks()` registry. For a
   check that needs HTTP, DNS, or browser facts, use the existing probe or
   browser architecture; transport belongs outside the pure engine. See
   [Unified scan architecture](unified-scan-architecture.md).
3. Register every emitted canonical result id in
   `crates/engine/src/manifest/registry/`. A multi-result detector needs an entry
   for each result, or the supported dynamic family. Choose the truthful scope
   and hosted lane; increment its revision when changing existing semantics.
   When the check supports hosted page evaluation, also register its runner in
   `crates/engine/src/evaluation/runners.rs`; a manifest entry alone does not
   execute the detector.
4. Add the local guide under `apps/desktop/src/lib/fix-guides/`: a short
   explanation, bounded baseline steps, and an effort consistent with the
   existing guide types. Code Scan uses `lib/code-fix-guides/` instead.
5. Add a corpus case and its dispatcher arm, plus an explicit verdict assertion
   in the relevant golden test. Reuse page, probe, or browser corpora according
   to the facts the detector consumes.

The private intelligence catalog is a maintainer release task. A public patch
must stand on its own with complete local behavior and baseline guidance;
reviewers do not need private repository access to build or test it.

## Regenerate and verify

From `apps/desktop/src-tauri/`, deliberately regenerate changed artifacts and
then review their diffs:

```bash
cargo test -p sitecmd-engine --test golden_checks -- --ignored regenerate
cargo test -p sitecmd-engine --test capability_manifest -- --ignored regenerate
cargo test -p sitecmd-engine
```

For probe or browser changes, use `golden_probes` or `golden_browser` in place
of `golden_checks`. Regeneration records the implementation's current output;
the independent semantic assertions must still pass.

From the repository root:

```bash
pnpm facts:generate
pnpm test:desktop
pnpm guardrails:repo
pnpm guardrails:repo:test
pnpm typecheck
pnpm lint
pnpm format:check
```

Before a merge, run the repository's complete required checks, including the
Rust workspace suite. After committing, `pnpm verify:push` is the authoritative
local push gate. Keep generated benchmark runs and review transcripts out of Git.

## Code Scan differences

Code Scan reads a bounded source inventory and has a separate registry at
`src/core/code_scan/registry.rs`. Its detectors live under
`src/core/code_scan/`, with positive and negative fixtures in the corresponding
test modules. Follow an existing check in the same domain, preserve its stable
canonical identity, and use the shared file/path and text-budget helpers.

Exercise a Code Scan change through the actual checkout CLI:

```bash
pnpm sitecmd -- audit ./path-to-minimal-fixture --format json
```

Use a disposable fixture and verify both the finding and its disappearance
after a correction. Local database inspection requires a separate explicit
option and must remain off for an ordinary static audit.
