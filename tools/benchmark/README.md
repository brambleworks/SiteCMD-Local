# Agent workflow benchmarks

Use the [evaluation protocol](../../docs/qa/agent-workflow-benchmark.md) to measure
repair quality, compute efficiency, and developer effort. The paired workflow
tooling freezes assignments, runs subscription evaluations in an isolated
desktop, imports evidence, records blinded reviews, and reports uncertainty.
This guide is for the operator preparing and executing those evaluations. The
subscription runner supports the completed five-case pilot and the explicit
Whoogle real-application calibration. Both eight-case repository studies and the
v2 supplement are invalidated, diagnostic-only, and cannot be run again. A
separate scripted test exercises full-repository submissions without model calls.
Arbitrary repositories and Web Scan are not supported trial targets.

The [benchmark VM](vm/README.md) supplies a separate Linux environment for building
the desktop and running trials. Host projects and accounts are not mounted.
Only a committed source archive is exported for the product build; subscription
credentials must be created through login inside the guest.

## Configure the subscription pilot

```bash
pnpm benchmark pilot
```

`pilot` prints the approved settings from `pilot-policy.json`. It is a
policy, not an execution command. Once the VM is prepared and running,
`pnpm benchmark:vm doctor` reads the guest's installed
Codex/Claude versions and saved authentication status without issuing prompts.
It prints no account identifiers or credential values. Exit code 2 means a client
or subscription login is missing. The separate `pnpm benchmark doctor` probes the
host, not the guest. Neither doctor approves execution.
Successful authentication does not verify model access, quota, global configuration
isolation, or disabled paid overage.

The included corpus contains four seeded repairs (CORS, redirect, SQL injection,
and path traversal) and a parameterized-query negative control. Ordinary tests
are visible to agents; separate behavioral graders are not. These small, owned
examples are calibration, not representative customer projects or marketing evidence.

Redirect checks cover URL normalization, same-host network-path references and
double-resolution escapes. Download checks preserve POSIX filenames and a `/`
root, allow contained symlinks, and reject directories and named pipes. The
download case assumes filesystem entries are stable during a call; it does not
measure protection against concurrent filesystem replacement.

On a new VM, prepare the environment and build the committed product:

```bash
pnpm benchmark:vm setup
pnpm benchmark:vm:tools
pnpm benchmark:vm:build
pnpm benchmark:vm:smoke
pnpm benchmark:vm:selftest
pnpm benchmark:cases:validate
pnpm benchmark:cases:scan
```

These commands make no model calls. Building excludes uncommitted changes.
`benchmark:vm:build --install-existing` installs or checks an already completed
build without compiling again. The smoke test uses the shipped desktop/MCP flow
and owned CORS and path-traversal reference repairs, not an AI agent. It covers
Claude-style staged writes and retries against a closed attempt. Validation runs baseline and
reference checks three times each. Scanning records actual full reports, including
missed defects; a clean scan is not independent proof that a case is safe.
The self-test checks staging-directory access, then file-channel submissions inside
the actual Codex sandbox and a pinned standalone Anthropic sandbox runtime after
Claude client initialization without a user prompt, including denial of response
forgery and credential-directory reads. The standalone runtime check is not a full
Claude model trial. Synthetic Node clients and quota fixtures then exercise
grading, evidence validation, and timeouts. None of these checks contact models.

Use the exact evidence paths printed by validation and scanning as the first two
arguments, and choose a new run directory:

```bash
pnpm benchmark:prepare GRADES_JSON SCANS_JSON tools/benchmark/.work/calibration-run
```

Replace `GRADES_JSON` and `SCANS_JSON` with those paths. Preparation freezes the
45 assignments, product, sources, graders, reports, protocol and runner. Client
versions are Codex `0.153.0-alpha.5` and Claude Code `2.1.260`, both at explicit
high reasoning. Changed runner or grader bytes require a new registration, not
editing an existing plan. No agent has run merely because a plan exists.

After a runner-only correction, continue a partially executed calibration in a
new directory without rerunning earlier assignments:

```bash
pnpm benchmark:prepare GRADES_JSON SCANS_JSON NEW_RUN_DIRECTORY --continue-from PRIOR_RUN_DIRECTORY --reason "Describe the runner correction"
```

The continuation retains the complete executed prefix, including failures, and
copies its original quota baseline. It schedules only the unrun suffix, with the
same cases, models, prompts, protocol, limits and assignment order. Previous
records, artifacts and quota baselines throughout the continuation chain are
rechecked before every trial. Each retained assignment keeps its original study
identity. Report every runner version separately;
their records still cover one original population, not replacement trials.

Claude's known empty sandbox protection files are created and captured before
the first prompt. Only those recorded empty files are omitted from candidate
patches. Nonempty changes, unknown hidden files and unsafe links remain failures.
Executable-mode changes are also retained and checked, including on empty guards.
The controller also prepares `.claude/.cc-writes` with a per-directory ACL: Claude
can write, SiteCMD can read and traverse, and other users have no access. Its
identity and both parent and staging permissions are checked before submissions.
An existing private parent directory also receives the scanner's read-only ACL.
Changed permissions or replaced directories stop the trial; home and credential
permissions are unchanged.

All trial environments set `PYTHONDONTWRITEBYTECODE=1` and redirect explicit
bytecode compilation to the trial's temporary filesystem; Codex also receives
both settings in its shell-environment policy. Python fixtures use
`python3 -B -m unittest discover -s app/api`.
The sandbox self-test checks that ordinary Python imports do not
create bytecode. This prevents incidental cache files instead of hiding them:
snapshots still retain all other untracked and binary additions. An intentional
no-op must leave the submitted tree unchanged.

Changes to these fixture instructions or behavioral checks require fresh
validation and a new registration. Do not apply them retroactively to frozen
patches, grades or review decisions.

If Code Scan does not produce the repair handoff, the MCP assignment records a
pre-agent product error with zero calls. Keep it in the assigned population;
do not substitute an easier case. Inspect the scan evidence before interpreting
workflow differences.

### Subscription logins

Open the guest shell and sign into the subscriptions there:

```bash
pnpm benchmark:vm shell
codex login --device-auth
claude auth login --claudeai
```

Follow each login's instructions, opening its URL in the host browser if needed.
Do not select Console/API billing or copy host credential files. Exit the guest
shell, then run `pnpm benchmark:vm doctor`. Login success does not prove either
requested model is available. The first real assignment must establish that;
an unavailable or different model is a failure, never permission to fall back.

### Account quota evidence

Preparation creates blank quota files in the ignored run directory. Fill them
from actual provider readings. Use UTC timestamps for `capturedAt` and each `resetsAt`, stable
non-identifying account labels, `authMode: "subscription"`, and
`extraUsageEnabled: false` only after verifying those facts. Record an evidence
reference in `source`; preserve the complete provider reading privately. The
template deliberately fails validation until completed.

Record **used** percentages, not remaining percentages. Include every applicable
weekly, model-specific, and short-session limit. Add model-specific windows as
needed; remove a template window only if the provider confirms it does not exist,
not because its usage is unknown. The checker cannot discover omitted provider
windows or authenticate a manual reading. Do not store API keys, OAuth tokens, or
email addresses in these snapshots.

An explicitly inactive session with zero usage and no reset date remains in the
snapshot with `inactive: true` and `resetsAt: null`. This is allowed after its
recorded reset, or when the baseline already records it as inactive. Missing or
contradictory state still blocks execution; weekly windows always need a reset date.

Some providers expose rolling weekly meters whose next-reset timestamp changes as
older usage expires. When that happens, add `accountingEpochs` to the weekly window.
The first epoch starts at the frozen baseline percentage and reset timestamp; every
later epoch starts at zero. Keep the highest observed percentage for each epoch.
The checker sums those high-water deltas, so a rolling window or earned reset never
replenishes the study allowance. Refreshers must append epochs and must not remove
or lower an earlier peak.

Freeze `quota-baseline.json` before the first real trial. Save a new current snapshot
before and after every trial and at each submission; do not overwrite the baseline.
Keep snapshots with the trial evidence, including readings that paused the batch.

```bash
pnpm benchmark quota --baseline tools/benchmark/.work/calibration-run/quota-baseline.json --current tools/benchmark/.work/calibration-run/quota-current.json
```

Exit 0 means only that the supplied quota readings passed. Exit 2 means pause;
invalid input exits 1. Readings older than five minutes, changed accounts, an
unaccounted weekly transition, unknown extra usage, or either account reaching a
stop threshold block the batch. A short-session reset does not replenish the weekly allocation. These are
checks made by the quota command, not a live quota collector or process supervisor.
The VM executor enforces the time/submission limits, stops on reported rate limits,
and never requests a fallback model. Provider percentages are not precise
in-flight cost caps.

Future studies can freeze `billing.quotaScope: "active-provider"` to apply allowance
and remaining-capacity thresholds only to the account running that assignment.
An unrelated account reaching its limit then leaves the active trial running.
Account identity, subscription authentication, disabled paid overage, fresh
snapshots, and conservative weekly accounting still apply to both accounts.
Omitting the scope retains the existing study-wide policy. A quota check without
an active provider checks both accounts. This option does not amend frozen plans
or allow assignments to be reordered around unavailable quota.

### Run one assignment

With both logins verified, extra paid usage disabled, and actual baseline/current
quota files in the run directory:

```bash
pnpm benchmark:run tools/benchmark/.work/calibration-run
```

Each invocation runs only the next unrecorded assignment. It serializes guest
execution, creates a fresh source tree and desktop database, and imports the
result before returning. Keep `quota-current.json` refreshed from actual readings
while it runs, before its five-minute freshness window expires. The host forwards
changes to the guest; the supervisor checks them every five seconds and at each
submission. It does not collect provider quota automatically. Stale readings stop
the current trial, which remains a recorded failure rather than being retried.

When the agent stops, the command asks for new readings from both providers and
waits up to five minutes before exporting. A still-fresh pretrial reading is not
post-trial evidence. Missing closing readings record an infrastructure failure.
Quota bookkeeping happens after the timed repair; no model keeps running while
the command waits. The quota baseline is immutable once execution begins; never
reset it to replenish the pilot allowance. Nonzero
exit status means inspect the failure and preserved evidence before continuing.
Do not rerun an assignment after model usage. If transport or import fails, retain
the guest trial directory and recover/import that evidence instead of deleting it
to start over. Ctrl-C stops the active agent; keep the VM running for evidence export.

If a provider changes quota-window bookkeeping after a confirmatory batch starts,
fix only the controller and record the boundary before resuming:

```bash
pnpm benchmark:controller:amend RUN_DIRECTORY "Explain the quota controller correction"
```

The amendment is fail-closed. It compares the frozen and corrected runner byte by
byte, permits only the quota controller and its evidence plumbing to differ, pins
the complete executed prefix and original quota baseline, and refuses an amendment
after any assignment in the registered primary population. Every later trial
embeds the receipt. A prompt, grader, corpus, model, limit, or product change still
requires a new study and never authorizes rerunning an observed assignment.

Normal/report workflows submit through the provided local submission command.
MCP repairs submit through the real `request_verification` tool. Requestable
attempts are checked before capture; candidates count only after the server
accepts the request. Rejected captures remain evidence without consuming a
submission, and an unknown response pauses execution. Every candidate
is frozen before forwarding verification, and hidden grader feedback is withheld
in every workflow. Editing after the final submission prevents final acceptance.
The product's verification result is retained separately from independent grading.

### Historical v2 supplemental completion

The v2 repository run stopped after 75 of 96 assignments when its registered
allowance closed. An explicitly authorized calibration run completed the exact
21-assignment suffix under a separately recorded allowance. Its cases, product,
source records, failures, and authorization receipts remain immutable.
Both runs are now invalidated because of grader defects. Their preparer and runner
reject further execution; readers can still load and audit the original evidence.
The supplement never repaired the original run's incomplete confirmatory status.

### Model identity evidence

New trials write `model-identity.json` with the transcript digest, assurance
source, response-field locations when available, and completeness checks. Import
recomputes this receipt from the preserved transcript. Missing, conflicting, or
incomplete evidence blocks claim review; older records remain readable without
being rewritten or silently upgraded.

A passing submission from a real trial with unverified model selection cannot
count as first-attempt or final acceptance. A valid terminal usage receipt remains
usable even if the client exits unsuccessfully; the failed status is preserved.
Partial, truncated, malformed, or reopened invocations remain unmeasured. A
controller-confirmed failure before client launch is the only inferred zero.

Claude Code supplies response-model metadata and per-model usage, which must
match the requested model. The pinned Codex `exec --json` stream does not expose
a response-model field. Codex trials therefore use a different, explicitly
labeled assurance: the runner passes one exact model through strict CLI
configuration and requires one clean lifecycle from `thread.started` through
`turn.completed`, with no fallback. This establishes which configuration was
requested and completed; it is not provider-response metadata or cryptographic
attestation.

## Qualify a real repository

Benchmark operators can validate the included historical Tornado redirect case
without issuing model prompts. This separate command prepares sources, runs
behavioral checks and records Code Scan output. It does not add assignments to
the subscription pilot or support arbitrary-repository agent trials.

Use the prepared VM and a product receipt from its installed build. Fetch the
pinned fix and its parent into a new bare repository; no checkout, dependency
installation or third-party code execution is needed on the host:

```bash
git init --bare tools/benchmark/.work/tornado-source.git
git -C tools/benchmark/.work/tornado-source.git fetch --no-tags --depth=2 https://github.com/tornadoweb/tornado.git 32ad07c54e607839273b4e1819c347f5c8976b2f
pnpm benchmark:repository:qualify tools/benchmark/.work/tornado-source.git tools/benchmark/.work/tornado-qualification PRODUCT_RECEIPT
```

Replace `PRODUCT_RECEIPT` with the receipt printed by the VM build command.
Choose unused source/output directories; existing evidence is never overwritten.
The command verifies both pinned source digests and the installed scanner binary.
Git objects preserve every tracked file, including licenses, hidden files, binary
data and executable modes. Symlinks, submodules, unsafe paths, files larger than
4 MiB and sources exceeding 1,000 files or 16 MiB are rejected, not silently removed.

Baseline and reference checks each run three times, offline inside the existing
restricted VM sandbox. They cover redirect behavior, normal static-file serving
and four existing upstream test classes, not the complete Tornado test suite.
Raw reports, source snapshots, runtime versions and harness bytes remain in the
private evidence directory. Exit zero means the expected baseline/reference
checks passed and both scans produced reports; it does not mean the scanner found
the defect. Keep missed defects and unrelated findings in the evidence.

Tornado is a framework, not an end-user application. Its public historical fix
may have appeared in model training. This case is runner-development calibration,
not held-out confirmation or evidence of agent improvement.

### Linkding asset isolation

Operators can also qualify the historical Linkding asset-view repair. This is
a Django application case, separate from both Tornado and the subscription pilot.
Prepare a new bare source cache, then build its runtime inside the existing VM:

```bash
git init --bare tools/benchmark/.work/linkding-source.git
git -C tools/benchmark/.work/linkding-source.git fetch --no-tags --depth=2 https://github.com/sissbruecker/linkding.git 0834f79c0f5dd2cd93642527fece583e2dc407ef
pnpm benchmark:repository:runtime tools/benchmark/.work/linkding-source.git tools/benchmark/.work/linkding-runtime.json
pnpm benchmark:repository:qualify --linkding tools/benchmark/.work/linkding-source.git tools/benchmark/.work/linkding-qualification PRODUCT_RECEIPT tools/benchmark/.work/linkding-runtime.json
```

As above, replace `PRODUCT_RECEIPT` with the installed product's receipt. Use
unused output paths. Runtime setup requires public download access and creates
a distinct guest installation without replacing system Python or earlier runtimes.
It pins Python 3.13.7 and uv 0.8.13 by archive checksum, installs the original
locked default and development dependencies, and uses checksum-pinned build tools.
Native builds run as the unprivileged builder with bounded resources. Installation
logs remain in the guest; failed installations are retained for inspection.

The setup command freezes interpreter and dependency file hashes in its receipt.
Qualification rechecks ownership, permissions, links and file hashes before
executing code. Do not regenerate a receipt over a changed installation.
Reuse an unchanged receipt, or prepare a new installation and new qualification.

Browser qualification requires the VM's WebKitGTK and WebKitWebDriver packages
at `2.52.6-0ubuntu0.24.04.1`, plus Xvfb. It uses the installed native driver,
not a host browser or a Playwright download. Qualification records installed
package versions and hashes the browser, JavaScript engine, process helpers,
driver, display server and sandbox launcher. These identities are checked again
before and after every browser probe. Other system libraries are recorded by
package version, not individually content-hashed.

All baseline files and licenses are preserved. The upstream change also modifies
tests, so the reference imports only its asset-view implementation change. Its
separate identity records both source snapshots without claiming to be the full
upstream commit. Existing tests stay unchanged.

Each variant runs three times with fresh temporary SQLite databases and asset
storage, an isolated network namespace, and read-only source and dependencies.
Checks cover the enforced sandbox header, asset bytes, compression, inline
filenames, HEAD, private access and sharing, plus 28 existing asset view, model
and API tests. The visible task explicitly requires a sandbox without permission
exceptions; additional CSP directives and separate policies are accepted.

Browser probes use real Django HTTP responses over guest loopback. They check
plain and compressed HTML snapshots/uploads, authenticated sharing and public
sharing. Each document must render its original body while blocking embedded
scripts and access to application-origin cookies and local storage. An
unsandboxed control must demonstrate working scripts and both storage mechanisms.
Blank pages, browser errors, resource-limit failures and incomplete observations
fail qualification. The baseline must reproduce all three unsafe behaviors in
every asset view; the reference must prevent them.

Only browser probes launch as the VM's dedicated unprivileged grader account.
Temporary read-only input mounts make the selected source and probe helpers
available without exposing controller directories. The mounts are released after
each probe. WebKit's process sandbox is explicitly enabled and its seccomp,
privilege and mount-namespace state is checked. Limits are 1 GiB, 256 tasks and
90 seconds for a browser probe; non-browser Linkding checks retain their existing
512 MiB, 32-task and 40-second limits. No host credentials or external network
access are available to either probe.

This is one browser engine, not a cross-browser matrix, the complete application
suite, a frontend build or the production Docker deployment. Other sandbox
permissions are checked through the header contract, not separate browser
interactions. Raw scanner reports retain missed defects and unrelated findings.
It is historical runner-development evidence, not a held-out case, an agent
trial or a marketing claim. Existing qualification receipts remain unchanged;
the browser checks produce a new qualification and harness identity.

### Whoogle named configuration confinement

The historical Whoogle case exercises a Flask application path-traversal repair
that SiteCMD detects as `code_scan.python-path-traversal`. Prepare its pinned
source, frozen runtime, qualification, and desktop workflow evidence as follows:

```bash
git init --bare tools/benchmark/.work/whoogle-source.git
git -C tools/benchmark/.work/whoogle-source.git fetch --no-tags --depth=2 https://github.com/benbusby/whoogle-search.git 3a2e0b262e4a076a20416b45e6b6f23fd265aeda
pnpm benchmark:repository:runtime --whoogle tools/benchmark/.work/whoogle-source.git tools/benchmark/.work/whoogle-runtime.json
pnpm benchmark:repository:qualify --whoogle tools/benchmark/.work/whoogle-source.git tools/benchmark/.work/whoogle-qualification PRODUCT_RECEIPT tools/benchmark/.work/whoogle-runtime.json
pnpm benchmark:repository:workflow --whoogle tools/benchmark/.work/whoogle-source.git tools/benchmark/.work/whoogle-workflow PRODUCT_RECEIPT tools/benchmark/.work/whoogle-runtime.json
```

Runtime setup pins Python 3.11.13 and uv 0.8.13 by archive checksum. It resolves
the complete dependency set no later than the source commit, requires the frozen
lock digest, installs wheels for every dependency except hash-locked Stem 1.8.1,
and freezes a dedicated guest environment. Runtime creation executes no project
code and makes no model calls.

Qualification uses Whoogle's real Flask application, test client, session,
configuration model, pickle serialization, and filesystem operations in an
offline sandbox. Controlled benign dictionaries exercise traversal and absolute
reads and writes. Unnamed configuration, valid named save/load behavior, redirects,
sessions, and the configuration-disable policy must keep working. The reference
copies only the upstream named-configuration route and required import; unrelated
changes from the same commit remain excluded.

The historical baseline must fail confinement while preserving ordinary behavior
in all three repetitions. The narrow reference must pass both sets of checks in
all three repetitions. SiteCMD must report the target on the baseline and clear it
on the reference, and all three desktop workflow arms must reach a ready prompt.
These are runner-development checks around a public historical defect, not
held-out confirmation or marketing evidence.

### Full-repository submission integrity

The Tornado, Linkding, and Whoogle submission self-tests use an owned Node process
in the VM, not an AI client:

```bash
pnpm benchmark:repository:selftest tools/benchmark/.work/tornado-source.git
pnpm benchmark:repository:selftest --linkding tools/benchmark/.work/linkding-source.git tools/benchmark/.work/linkding-runtime.json
pnpm benchmark:repository:selftest --whoogle tools/benchmark/.work/whoogle-source.git tools/benchmark/.work/whoogle-runtime.json
```

Each test submits the full broken tree, applies only the pinned repair, and verifies that an edit to
the license is rejected without grading. A final executable-mode change must
invalidate the submitted snapshot. Snapshots retain all tracked files, including
existing tests, hidden configuration and binary data, plus executable modes.
Each run creates new private evidence
and imports it through the same receipt checks used for agent trials.

Repository tasks use `sourceFormat: "git-tree-v1"`, the frozen snapshot digest and
an exact `editableFiles` list of existing implementation paths. Changes outside
that list, new files and executable-mode changes fail integrity. Candidate bytes
and modes are saved per submission; import verifies their digests and rechecks
the edit policy against the frozen source. These are controller consistency
checks, not independent attestations. This path currently supports the included
Tornado, Linkding, and Whoogle graders and does not install arbitrary project
dependencies. Linkding reuses its frozen Python runtime and captures the installed browser
identity before registering the scripted test. Both receipts are preserved and
checked against the registration during evidence import. The grader identity
covers the full frozen harness, including browser and sandbox helpers. Whoogle
preserves and verifies its single frozen Python receipt during the same export.

Each valid Linkding submission runs the same response, browser and 28 existing
test checks used in qualification. The script receives only a submission receipt,
not grader feedback. Its seven-minute deadline and 210-second submission timeout
apply only to this no-model self-test; browser process limits and subscription
trial limits are unchanged. A passing self-test means its deliberately broken,
repaired and invalid submissions were classified correctly, not that the final
deliberately mutated candidate was accepted.

A broader corpus is still needed for general conclusions. The scripted self-tests
do not authorize subscription use; only a separately frozen execution policy and
study plan can do that.

### Check desktop workflow setup

```bash
pnpm benchmark:repository:workflow SOURCE_GIT NEW_OUTPUT_DIRECTORY PRODUCT_RECEIPT
pnpm benchmark:repository:workflow --linkding SOURCE_GIT NEW_OUTPUT_DIRECTORY PRODUCT_RECEIPT LINKDING_RUNTIME_RECEIPT
pnpm benchmark:repository:workflow --whoogle SOURCE_GIT NEW_OUTPUT_DIRECTORY PRODUCT_RECEIPT WHOOGLE_RUNTIME_RECEIPT
```

This uses the same pinned Tornado, Linkding, or Whoogle source and installed
product receipt as qualification. It starts a fresh desktop database and source workspace for each
of `normal`, `report` and `mcp`. It captures CLI reports, desktop scan results,
MCP requests and responses, and the exact prompt that would reach a model. No
model client starts, no repair is applied, and no trial is added to the pilot.

The normal prompt excludes SiteCMD findings. The report prompt includes the
complete report. A rejected MCP repair handoff produces `product_error` and no
prompt; it is never replaced by an unrelated finding. A case without a registered
SiteCMD check produces `handoff_unmapped`, not a fabricated check ID or claimed
MCP rejection. Its actual scan and issue responses are still captured. Linkding
currently has no registered check for its asset sandbox defect. Whoogle must reach
a real `start_fix` handoff for its registered path-traversal finding.

File bytes and executable modes must remain unchanged after setup. The receipt distinguishes a successful
mechanics check (`passed`) from an available product handoff (`handoffAvailable`);
exit zero does not mean the scanner detected the defect or the product repaired it.

Source-only screening is not case qualification. Preserve pinned source and
license information, runtime/dependency requirements and rejected candidates
before running scanners or agents. Upstream repairs that also change tests or
unrelated features need an explicitly derived implementation-only reference,
unchanged baseline tests and independent acceptance checks. Do not treat a whole
release as one repair or silently strip files to fit runner limits.

### Freeze the Whoogle subscription calibration

After producing fresh Whoogle qualification and workflow directories with the
same runner identity, freeze the dedicated agent plan:

```bash
pnpm benchmark:repository:prepare WHOOGLE_QUALIFICATION_DIRECTORY WHOOGLE_WORKFLOW_DIRECTORY tools/benchmark/.work/whoogle-repository-calibration
```

Preparation rechecks the pinned sources, narrow reference, frozen runtime,
three-repetition grades, scanner target, desktop handoff, product receipt, and
runner bytes. It then freezes 12 assignments: normal, report, and MCP once for
Codex `gpt-5.6-sol`, Claude Code `claude-opus-5`, Codex `gpt-6-astra`, and Codex
`gpt-daybreak-blue-latest`, all at high reasoning. Paid fallback and automatic
resets remain disabled, and the study stops at the same subscription allowance
limits as the original pilot.

The frozen Python environment is active on the agent's path. Whoogle's mutable
static and configuration storage is copied to a per-trial scratch directory so
`python -m pytest` cannot add generated assets, keys, or cache files to the
candidate tree. The prompt names that test command and prohibits `./run test`,
which mutates the checkout before launching pytest.

After a runner-only failure, create a continuation from fresh qualification and
workflow receipts. Earlier outcomes and the original allowance remain immutable:

```bash
pnpm benchmark:repository:prepare NEW_QUALIFICATION NEW_WORKFLOW NEW_RUN_DIRECTORY --continue-from PRIOR_RUN_DIRECTORY --reason "Describe the runner correction"
```

Fill the new run's quota baseline/current files from fresh provider readings,
then use `pnpm benchmark:run RUN_DIRECTORY` once per assignment. The first actual
response establishes model availability; the runner never substitutes a fallback.
This single historical task can expose executor or workflow failures and estimate
case-specific behavior. It cannot support a general product or marketing claim.

## Retired repository confirmation

`sitecmd-repository-confirmatory-v1` completed 96 assignments across six repairs,
two negative controls, three workflows, and four model configurations. A post-run
validity review found three material protocol defects:

- The Appium task and the registered scanner finding referred to different code.
- Raw-HTML scanning and fix verification treated multiple sinks in one file as one
  target, so an unrelated change could clear or verify the wrong occurrence.
- The Outerbase chart grader did not directly assert required whitespace
  preservation.

The run is retained as diagnostic evidence only. Do not quote its success rates or
token measurements as product evidence. `invalidated-studies.json` prevents its
study ID from being executed again and forces every generated report to withhold
claim readiness.

The next confirmation must use a new study ID and cases that no repair agent has
seen. Before freezing it:

1. Register an exact scanner fingerprint, path, and semantic source anchor for
   every task.
2. Require the baseline finding's source excerpt to contain that anchor.
3. Qualify each repeated finding as an independent occurrence through the desktop
   handoff and verification loop.
4. Assert every observable task requirement directly in the hidden grader.
5. Rebuild source, scanner, behavioral, workflow, and product receipts from the
   corrected implementation.

The earlier `repository-held-out-v1.json` intake remains selection-attrition
evidence: all 12 candidates passed source screening, but none produced its intended
registered finding. Those cases and all eight executed v1 cases cannot be reused as
held-out confirmation tasks.

## Check the pipeline locally

Requires the repository's Node and pnpm versions, but no account, model, desktop,
API calls, or Docker daemon. Run from the repository root, choosing a new output
directory whose parent exists:

```bash
mkdir -p tools/benchmark/.work
pnpm benchmark:test
pnpm benchmark fixture --out tools/benchmark/.work/workflow-fixture
pnpm benchmark report --run tools/benchmark/.work/workflow-fixture
pnpm benchmark report --run tools/benchmark/.work/workflow-fixture --json
```

Choose another output name for another run; existing runs are never overwritten.
The fixture demonstrates nine assignments: two synthetic repair cases and a
negative control, each in three workflows. It checks a known-broken source and
reference implementation with independent owned tests. Usage, time, reviews, and
MCP traces are explicitly synthetic. This is not a real agent comparison, a
calibration corpus, or measured evidence about SiteCMD.

The generated `plan.json`, `inputs/*/trial.json`, and neighboring receipts are
complete examples of the schemas. Copy their shape, not their synthetic values,
when implementing a real runner. Keep generated runs in `.work/` or `results/`,
both ignored by Git. Evidence directories use owner-only permissions.

## Freeze a real study

Prepare and independently validate the case corpus before creating a plan. Use a
calibration phase first. The study JSON requires:

| Field                                 | Contract                                                                                                                                                                                                                      |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schemaVersion`, `id`, `phase`        | `1`, lowercase kebab-case identifier, and `calibration` or `confirmatory`.                                                                                                                                                    |
| `protocol`, `protocolSha256`          | Protocol version and digest of the exact registered protocol bytes.                                                                                                                                                           |
| `seed`, `repeats`, `arms`             | Unsigned 32-bit seed, positive repeat count, and exactly `normal`, `report`, `mcp` in that order.                                                                                                                             |
| `limits`                              | Positive `trialSeconds` and `submissions`. API studies also require positive `trialTokens`, `trialCostUsd`, and `studyCostUsd`. Subscription studies require zero dollar caps and may use `trialTokens: null`.                |
| `billing`                             | For subscriptions, copy the pilot billing object: subscription mode, disabled paid fallback/resets, weekly allocation, remaining-allowance floor, and quota freshness limit. Omit for legacy API/fixture accounting.          |
| `sitecmd`                             | Version, full commit SHA, dirty status, and SHA-256 of the actual bundled MCP entry point. Archive its dependencies/environment too.                                                                                          |
| `configurations`                      | Unique IDs with exact agent, agent version, model, reasoning, and environment.                                                                                                                                                |
| `tasks`                               | Unique IDs, repository cluster, repair/negative-control kind, code/web surface, category, prompt, requirements, provenance, held-out status, source/reference/grader/report hashes, baseline/reference checks, and validator. |
| `registration`, `sampleSizeRationale` | Required for confirmation, along with a clean SiteCMD build and held-out tasks.                                                                                                                                               |

For source, reference, and grader digests, hash immutable archives or a documented
canonical file manifest. Record that encoding in the protocol and preserve the
bytes. The planner validates the supplied hashes' shape; the case validator must
actually compare them against the corpus and run baseline/reference tests.

```bash
pnpm benchmark plan --study tools/benchmark/.work/calibration.json --out tools/benchmark/.work/calibration-run
```

The planner stores a canonical study digest and randomized paired assignments.
Do not edit the plan after creation. It reports maximum per-trial-cap exposure
and the study cap; neither authorizes a purchase or enforces an external runner's
spend. Get explicit operator budget approval before starting paid trials.

## Execute and import assignments

Follow the frozen assignment order with fresh isolated workspaces. Use the actual
SiteCMD desktop/MCP flow for `mcp`, not the older brief-only harness. Preserve the
first submitted candidate before returning external feedback, and freeze the
final candidate before teardown. The grader must inspect those exact snapshots.
Record unsuccessful and interrupted trials too.

A trial JSON includes its assignment ID and study digest, model selection/agent
version, fixture flag, status, elapsed time, measured human-active time or `null`,
warm/cold setup, submissions, reviews, transcript path, and usage. Non-completed
statuses require a failure explanation. MCP trials also need a server digest and
complete trace artifact. Submission times must be ordered and within trial time.
The VM runner records its explicit CLI model request separately from identities
actually emitted by the provider. Claude requires matching response metadata.
Codex requires the strict requested model and one complete, clean event lifecycle,
because its pinned JSON stream has no response-model field. Missing, conflicting,
or incomplete evidence blocks claim review.
A setup failure before client launch has `agentInvoked: false`, no model, no
submissions, and zero calls. Interrupted or truncated usage remains unknown.

All artifact paths are relative to the trial JSON's directory. Only referenced
files are imported. Paths cannot be absolute, contain traversal, or use symlinks.
Each artifact is limited to 64 MiB and a trial to 256 MiB. For larger transcripts,
retain the private original and reference a documented, bounded lossless archive
or split raw usage logs; do not silently truncate the evidence used for review.

Each submission identifies `patch`, `patchSha256`, `elapsedMs`, `graderSha256`,
`acceptancePass`, `regressionsPass`, `integrityPass`, and a grading `receipt`.
The patch includes untracked additions and binary changes. An intentional no-op
uses an empty patch with its actual SHA-256, plus a triage explanation.

The grader receipt contains the trial/study/source/patch/grader identities, executor,
environment, nonempty `acceptance` and `regressions` check lists, and an `integrity`
object with `passed` and `reason`. Each check records its command, exit code
(`null` if interrupted), and log artifact. Only zero exit codes pass. The
independent grader, not the agent, produces these receipts.

Usage fields are disjoint `inputTokens`, `outputTokens`, `cacheReadTokens`,
`cacheWriteTokens`, `includesAllAgents`, `costUsd`, `costBasis`, and `receipt`.
Use `null` for unknown counts or cost and `unknown` for an unknown cost basis;
otherwise identify cost as `estimated` or `billed`. Reasoning tokens already
included in provider output must not be counted twice.

For subscription studies, use `costBasis: "subscription"`, `costUsd: null`, and
separate `incrementalCostUsd` and `apiEquivalentCostUsd`, each a nonnegative amount
or `null`. The first is verified additional spending; the second is a hypothetical
API estimate. Neither supplies a dollar-efficiency comparison. Unknown additional
spending blocks claim readiness; measured overages are retained and flagged.

The usage receipt contains the same usage object without `receipt`, an
`accountant`, a `method`, and a nonempty `raw` list of provider evidence paths.
When provider usage is unavailable, preserve the failure log and explain the
missing amount. Receipt equality proves consistency, not the truth of an
operator's accounting. Audit the provider records before publishing.

The `claudeUsage` normalizer accepts one final Claude result and prefers
whole-tree `modelUsage` over root-only `usage`. It counts cache reads/writes and
labels the reported dollar amount as an estimate. Root-only usage remains
incomplete unless the runner proves subagents were disabled. Do not sum cumulative
result messages. `codexUsage` accepts one `turn.completed` event, subtracts cached
input from total input, and does not double-count reasoning output. Codex cache
writes have no separate reported category and remain within uncached input. Codex
accounting is incomplete unless subagents were disabled or the runner separately
accounts for the whole tree and all turns. Deduplicate event records, not repeated
numeric counts, when assembling a trial receipt.

Both normalizers accept `billingMode: "subscription"`. They leave extra charges
unknown unless the caller supplies a verified `incrementalCostUsd`; they never
infer zero charges from a subscription login. Evidence must cover all calls,
including interrupted turns, retries, and delegated work. There is no generic
token guesser or automatic price lookup.

```bash
pnpm benchmark record --run tools/benchmark/.work/calibration-run --input tools/benchmark/.work/trial-evidence/trial.json
```

Import checks evidence consistency, copies referenced artifacts, and records their
digests. A second import for the same assignment fails. Loading results rechecks
digests and receipt contents. A partial import remains an explicit error, not an
omitted losing trial. Preserve damaged evidence for investigation rather than
overwriting it. Hashes detect changes, not a dishonest operator who rewrites both
data and hashes.

## Review and report

Import `reviews: []` when independent review is pending. Each review identifies a
submitted patch hash, reviewer, `blinded: true`, `decision: "accept"` or `"reject"`,
and a concrete reason. An inline review also references a JSON receipt with those
same fields. For a later review, provide just those fields without `receipt`:

```bash
pnpm benchmark review --run tools/benchmark/.work/calibration-run --trial TRIAL_ID --input tools/benchmark/.work/review.json
pnpm benchmark report --run tools/benchmark/.work/calibration-run
```

Reviews are appended without rewriting the original trial. Duplicate reviewers
for the same patch are rejected, and any rejection prevents acceptance. Do not
show reviewers the assignment arm or agent transcript before their decision.

Reports keep failures in the denominator, withhold complete rates when records or
reviews are missing, and separate surfaces and negative controls. Configurations
remain separate unless the study preregisters a fixed weighted mixture; even then,
the report retains every disaggregated configuration result.
Efficiency includes failed-trial spending; zero accepted repairs yield `n/a`.
Relative change and percentage-point change are separate. Confidence intervals
resample repositories and tasks with paired arms and repeats intact. An unavailable
interval or measurement is never filled in with zero.

The CLI writes reports to stdout and does not overwrite saved reports. Use
`--json` for structured analysis. No report automatically permits a marketing
claim; see the protocol's publication checklist. Configuration limits, MCP trace
presence, reviewer identities, and blinded flags still need operational auditing.

## Older scanner-context experiment

`run-context-benchmark.mjs` compares `blind`, `categories`, and `brief` prompts on
pinned public repositories using Claude Code. It does not exercise the MCP
workflow. Its checkId diff measures scanner clearance, not independent repair
correctness. The legacy aggregation excludes metric-less failures and has no
paired confidence intervals. Do not use its output for numerical product claims.

```bash
node tools/benchmark/run-context-benchmark.mjs --dry-run
node tools/benchmark/render-report.mjs tools/benchmark/results/RUN/raw.json
```

A legacy dry run still builds the Rust CLI, fetches repositories, and scans them;
it only skips paid model calls. It is not the no-network fixture above. Its config
pins target commits. Non-dry runs require Claude Code 2.1.219 or newer, a configured
account, and the fail-closed OS sandbox on macOS, Linux, or WSL2. Native Windows
is not supported. Read its sandbox controls before running untrusted target code.
The scanner does not spend model tokens to produce a brief, but the agent does
consume input tokens when reading it.
