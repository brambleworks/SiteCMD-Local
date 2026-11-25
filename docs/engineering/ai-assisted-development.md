# AI-assisted development

SiteCMD is built by one maintainer directing AI coding agents. That is stated
here rather than left to be inferred, because it changes what a reader should
look for. The useful question is not whether an agent wrote a given function; it
is whether the repository can tell the difference between a change that holds
and one that only looks finished. This document points at the machinery that
answers that question. All of it runs in this repository and can be read, run,
and disagreed with.

## How agents are directed

Guidance lives in `AGENTS.md` files, one per surface, read before editing that
surface:

- `AGENTS.md` (root) - product contract, repository map, commands, data and
  scoring invariants, the shared-source list, and code and comment style.
- `apps/desktop/src-tauri/AGENTS.md` - the Rust workspace, database worker,
  migrations, and portable check contracts.

The `CLAUDE.md` beside each one is a thin pointer to its `AGENTS.md`, so a rule
has a single home no matter which tool reads it.

The rules that matter most are the ones a type checker cannot state. The root
guide's shared-sources list names the one authority for time formatting,
severity ordering, score bands, HTTP client construction, outbound URL policy,
audit logging, and webhook signing, because the characteristic failure of an
agent is a plausible second copy rather than a syntax error.

Guidance is itself checked. `tools/scripts/audit/check-agents-md.mjs` runs in
GitHub CI and local verification. It fails when an `AGENTS.md` cites a
file path, a `pnpm` script, or a Tauri command that does not exist, so guidance
cannot rot into confident false statements.
`tools/scripts/lib/guardrail-agent-guidance-rules.mjs` requires the per-surface
guide and its pointer to exist, keeps the styling instructions aimed at the
current CSS layout, and caps guidance prose line length.

## What stands in for a second reviewer

There is one maintainer, so there is no second human reviewer.
[GOVERNANCE.md](../../GOVERNANCE.md) says so directly: automated review and
deterministic checks add scrutiny but are not represented as independent human
approval. What follows is what that automation is.

`tools/scripts/check-repo-guardrails.mjs` imports ninety rule modules from
`tools/scripts/lib/`, several of which compose further modules. Each exports
functions that return failure strings, and the documented expectation is that
every rule carries a self-test planting the regression it claims to catch
(`pnpm guardrails:repo:test`). [guardrails.md](guardrails.md) covers the rule
shapes and how to add one. The categories that bear directly on agent-written
work:

- **Copy tone.** `guardrail-machine-smell-copy-rules.mjs` bans the upgrade verb
  "unlock" and the word "queue" from visible product copy, matching only inside
  quoted spans and JSX text so identifiers are not caught.
- **Comment quality.** `guardrail-comment-quality-rules.mjs` extracts comments
  from TypeScript, CSS, and Rust without matching comment syntax inside string
  literals, then rejects filler such as "basically", "essentially", "note that",
  and "as we can see". It also rejects comments that cite maintainer-only
  tooling absent from this repository as a design authority.
- **Punctuation.** `guardrail-em-dash-rules.mjs` bans U+2014 across maintained
  docs, per-app guides, tooling scripts, Rust, and scanner fixtures.
  The same-line `allow-em-dash` marker is reserved for a line where
  the character is the thing being detected.
- **Publication hygiene.** `publication-hygiene-rules.mjs` pins the required
  public files, allows a fixed set of root files and directories, and rejects
  agent session directories such as `.claude`, `.codex`, `.cursor`, and
  `.superpowers` at any depth, so working artifacts never become repository
  content.
- **Line budgets.** Hot files carry a maximum line count, and
  `tools/scripts/check-budget-ratchet.mjs` blocks any commit that raises a
  budget or grows a `*_LIMIT` without an audited `[budget-raised: ...]` trailer.
  It runs as a `commit-msg` hook and as a CI gate. The documented default is to
  split the file instead.

## Where the gates run

`lefthook.yml` defines three hook tiers. Pre-commit runs typecheck, ESLint,
Prettier, `cargo fmt`, and gitleaks over staged files. Commit-msg runs the
message-format check and the budget ratchet. Pre-push validates outgoing
history for public remotes.

`tools/scripts/verify-push.mjs` builds the stand-in engine module, runs static
checks and JavaScript tests, then runs the Rust checks. Tier 4 runs nextest,
both Clippy checks, and both MSRV checks one at a time because they share a
Cargo build directory. Each uses the full worker budget unless the caller sets
`CARGO_BUILD_JOBS`. Checks in other tiers can run concurrently within their
tier. `pnpm verify:push:all` continues through every tier after a failure.

`pnpm guardrails:repo` is one command over four runners: the rule fleet,
repository label and protection contracts, and publication hygiene.

Public contributions go through a pull request to `brambleworks/SiteCMD-Local`.
GitHub runs the required checks and approved pull requests merge by squash.
`pnpm protection:check` verifies the check names for the current checkout.
The `--live` option checks that repository's protection settings against
its contract in `.github/repository-protection.json`.

## The product audits this repository

SiteCMD's Code Scan looks for what fast, assisted development leaves behind. The
`placeholder-density` check measures the density of `TODO`, `FIXME`, `HACK`,
`XXX`, `CHANGEME`, and `PLACEHOLDER` markers. The agent instruction checks
read a project's own instruction files and report a guide with almost no
meaningful content, several substantive instruction files where none points
at another, a credential-shaped literal in an instruction or MCP
configuration file, and a superseded single-file rule format. These findings
are Reliability, except that the secret rule is Security. This repository's
`CLAUDE.md` pointers satisfy the fragmented instructions check by pointing to
their corresponding `AGENTS.md` files.

The same scanner runs against this repository.
In SiteCMD-Local, the `Audit repository code` check runs Code Scan on pull
requests. High-severity findings fail the required check. The job publishes a
summary and uploads a review artifact.

## What this process does not claim

- No fraction of this codebase is claimed to be agent-written or
  human-written. The proportion is not tracked and would not be checkable.
- Automated review is not human review. Deterministic checks catch the
  regressions someone thought to encode; they do not judge whether a design is
  right. The decisions that need a person are listed in
  [security-review-cadence.md](security-review-cadence.md) precisely because no
  check can make them.
- A guardrail is evidence, not proof. [guardrails.md](guardrails.md) is explicit
  that wanting a wide exemption usually means the rule is miscalibrated, and the
  ratchet exists because the tempting fix for a failing budget is to raise it.
