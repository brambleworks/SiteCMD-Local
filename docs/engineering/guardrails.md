# Repo guardrails

SiteCMD leans on a fleet of static "guardrails" that run on every commit and in
CI. They are cheap, deterministic checks that lock in decisions the type system
and tests cannot express on their own: line-budget caps on hot files, bans on
regression patterns (broker bypass, inline `reqwest::Client::new()`, em-dashes),
cross-app parity, and ordering invariants. This doc explains how they are
structured, how to add one, and the ratchet rules that keep them honest.

If you came here from a failing `pnpm guardrails:repo`, jump to
[Ratchet semantics](#ratchet-semantics): the fix is almost never to raise a
budget.

## Where they live

- `tools/scripts/check-repo-guardrails.mjs` - the runner. It builds one
  `failures` array, appends the results of every rule module, and exits non-zero
  with the collected messages. Run it with `pnpm guardrails:repo`.
- `tools/scripts/lib/guardrail-*.mjs` - the rule modules. Each
  exports one or more `<name>Failures(...)` functions that return an array of
  human-readable failure strings (empty array = pass). Rules are grouped by
  family (Rust, frontend, release, telemetry, publication, and others) so no single
  file becomes a monolith.
- `tools/scripts/lib/guardrail-script-budgets.mjs` - the per-file line budgets
  for the guardrail scripts themselves.
- `tools/scripts/lib/guardrail-text-utils.mjs` - shared parsing helpers
  (`indexOfAny`, `orderedBefore`, `findInvokeCalls`, ...). Reuse these instead of
  hand-rolling string scans.
- `tools/scripts/repo-guardrail-*.test.mjs` - focused self-test suites. Every rule
  should have a test proving it fails on a planted regression. Shared fixture
  plumbing lives in `tools/scripts/guardrail-test-support.mjs`.
- `tools/scripts/check-budget-ratchet.mjs` - the meta-guardrail. It blocks any
  commit that raises a budget or grows a `*_LIMIT` without an audited bypass
  token. Runs as a `commit-msg` hook and a CI gate.
- `tools/scripts/check-commit-message.mjs` - the commit and pull-request title
  validator. Its pure rules live in `lib/commit-message-rules.mjs` so tests can
  exercise the same contract used by local hooks and CI.

## The helper API

Rule functions receive a small set of root-relative filesystem helpers from the
runner, so a rule never touches `process.cwd()` or absolute paths directly:

| Helper                      | Returns                                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------- |
| `read(relativePath)`        | File contents as a string (throws if missing).                                                            |
| `readJson(relativePath)`    | Parsed JSON.                                                                                              |
| `exists(relativePath)`      | Boolean.                                                                                                  |
| `listFiles(dir, predicate)` | Root-relative paths under `dir` matching `predicate`, recursively (skips `node_modules`/`dist`/`target`). |

The runner resolves paths against the repo root, or against
`SITECMD_GUARDRAILS_ROOT` when set. The self-test harness sets that env var to a
throwaway clone so a test can mutate a fixture file and run the real scanner
against it. Because everything is root-relative, rules are portable between the
live tree and the fixture with no special-casing.

## Rule classes

Most rules fall into one of these shapes. Reach for the lightest one that
expresses the invariant.

1. **Line-budget caps.** Hot files (schedulers, App shell, large check families)
   get a maximum line count. When a file nears its cap, extract a hook or split
   a rule family - do not raise the budget (see [Ratchet semantics](#ratchet-semantics)).
   Guardrail-script budgets live in `guardrail-script-budgets.mjs`; unlisted
   guardrail scripts default to 400 lines.

2. **Pattern bans.** A substring or regex that must not appear in a given scope:
   `reqwest::Client::new()` outside the shared client, `style={{` blobs, raw
   `safeListen` outside the event fabric, em-dashes in maintained docs and
   tooling. Prefer a narrow scope (a specific directory or file set) so the ban
   cannot false-positive on unrelated code.

3. **Structure checks.** Prefer compiler-checked types, parsed configuration,
   or syntax-aware checks for registrations and call placement. When inspecting
   Rust or TypeScript text, use `stripNonCode` with the source filename so
   comments and literals cannot satisfy the rule. Scope the check to its actual
   entry point; an unrelated call elsewhere in a file proves nothing about it.
   Behavioral assertions belong in executable tests, not checks for test names.
   The scan-persistence rule demonstrates call-placement checks and regression
   fixtures for comments, raw strings, unrelated calls, and missing awaits.

4. **Ordering pins.** Assert that A appears before B (rate-limit before auth,
   test before deploy, migrations before deploy). Use
   `orderedBefore(source, first, second)` from `guardrail-text-utils.mjs`, never
   a hand-rolled `source.indexOf(a) < source.indexOf(b)`: the raw form silently
   passes when an anchor is absent (indexOf returns -1 and the comparison
   collapses to a vacuous truth). `orderedBefore` returns false unless both
   markers exist and are correctly ordered. When ordering matters only inside one
   function, scope the source to that function body first (split on its
   signature) so unrelated textual occurrences cannot fool the check.

5. **Parity fixtures.** See [The parity-fixture pattern](#the-parity-fixture-pattern).

## How to add a rule

1. **Pick a home.** Add to the matching `guardrail-<family>-rules.mjs`, or create
   a new module if it is a new family. Export a `<name>Failures(read, exists, listFiles)`
   function that returns an array of failure strings.
2. **Register it.** Import it in `check-repo-guardrails.mjs` and append its result:
   `failures.push(...<name>Failures(read, exists, listFiles));`
3. **Budget the file.** If you created a new guardrail module and expect it to
   grow past the 400-line default, add an explicit (lower) entry to
   `guardrail-script-budgets.mjs`.
4. **Self-test it.** Add a case to the matching `repo-guardrail-*.test.mjs`
   suite that plants a regression and asserts the rule catches it in process:

   ```js
   it("fails when <the thing> regresses", () => {
     expectGuardrailFailure(
       myRuleFailures,
       (fixtureRoot) => {
         const p = "path/to/file";
         writeFixtureFile(fixtureRoot, p, `${readFixtureFile(fixtureRoot, p)}\n<the regression>\n`);
       },
       "<substring of your failure message>",
     );
   });
   ```

   For a rule with an exemption path (an allow-marker, an excluded subtree), add a
   second test proving the exemption is honored (assert the run does not mention
   that path). Pure helpers like `orderedBefore` also get a direct unit test of
   their contract.

5. **Run the suite.** `pnpm guardrails:repo` (the scan) and
   `pnpm guardrails:repo:test` (the self-tests).

## Commit message semantics

Default-branch history uses short plain-English subjects: a capitalized
imperative verb followed by the specific object being changed. Subjects are at
most 10 words and 60 characters, with no Conventional Commit type, scope,
ticket prefix, colon, or ending punctuation. A body is optional and limited to
four non-empty lines of non-obvious reasoning. File lists, generated summaries,
and test output belong in the pull request instead.

`check-commit-message.mjs` reads the proposed message file in the local
`commit-msg` hook. Pull-request CI passes the title through an environment
variable rather than interpolating untrusted title text into a shell command.
Squash merges use only the validated pull-request title as the final commit
subject.

## Ratchet semantics

The one rule that overrides all others: **budgets only go down.**
`check-budget-ratchet.mjs` compares the committed values against `HEAD` and
blocks any commit that raises a guardrail line budget, expands an override map,
or grows a top-level `*_LIMIT` constant. It runs both as a `commit-msg` hook and
as a hard CI gate, so a local bypass cannot slip through review.

When a budget genuinely must rise (a real structural reason, not "make the check
pass"), include an audited bypass token in the commit message:

```
[budget-raised: <real reason> (#123)]
```

The token must carry a non-placeholder reason and an issue/PR reference; the
raise is then logged forever in `git log` and surfaced in the ratchet output for
audit. Default to splitting or refactoring instead - the bypass exists for the
rare case where a raise is the honest call.

## The parity-fixture pattern

Some invariants span two implementations that must agree: the Rust backend and
the TypeScript MCP server, or a Rust computation and its generated data asset.
Rather than hand-write a fixture that can drift from reality, generate it from
the source of truth and let a test fail loudly on any diff.

- **Generated data assets.** The MCP server ships four `src/*.json` files
  (`causal_graph.json`, `fix_locations.json`, `impact_score.json`,
  `license_constants.json`). Each is regenerated by a Rust parity test that
  self-heals the file and fails asking you to commit the diff, so the TS copy can
  never silently diverge from the Rust algorithm it mirrors.
- **Schema-seeded fixtures.** MCP tests seed their SQLite fixture from the
  desktop's generated `schema_snapshot.sql` (via `test/helpers/schema-fixture.mjs`),
  never a hand-written `CREATE TABLE`. This is why a query against a phantom
  column fails in test instead of shipping green - the fixture is the real
  schema. A static guardrail (`guardrail-mcp-schema-rules.mjs`) additionally
  checks every SQL literal in `src/db.ts` against the snapshot.

When you add a cross-implementation invariant, prefer this shape: one side owns
the truth, the other is generated or checked against it, and a test/guardrail
enforces the equality.

## Escape hatches

Guardrails occasionally need a sanctioned exception. These are same-line markers,
kept rare and greppable:

- `// allow-inline-duration` - permits a `Duration::from_secs(N)` literal that is
  genuinely module-intrinsic (OAuth TTL, backoff base, test sleep) rather than a
  tuning value that belongs in `constants.rs`.
- `allow-em-dash` - permits an em-dash on a line where it is a detection needle
  (a guard that itself bans em-dashes in some rendered output). Do not use it to
  keep an em-dash in prose; fix the prose.

If you find yourself wanting a broad exemption (a whole-glob skip, a disabled
rule), that is usually a signal the rule is miscalibrated or the code needs the
fix. Narrow the rule or fix the code before reaching for a wide exemption.
