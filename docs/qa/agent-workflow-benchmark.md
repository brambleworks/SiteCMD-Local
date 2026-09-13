# Agent workflow benchmark

This protocol is for an engineer running a reproducible evaluation of SiteCMD's
effect on agent-assisted repairs. It defines how to collect evidence for repair
quality, compute efficiency, and developer effort. It does not assert that
SiteCMD improves any of those outcomes yet.

Protocol version: `agent-workflow-v1`.

The [benchmark operator guide](../../tools/benchmark/README.md) documents the
planner, isolated Linux desktop executor, evidence importer, review receipts, and
report commands. The subscription runner supports the completed five-case owned
pilot and an explicit historical Whoogle runner calibration. The
scanner-enriched repository studies and the v2 supplement are retained as invalidated
diagnostic evidence and cannot be run again. The separate synthetic fixture exercises
the evidence pipeline, not the product's benefit. Calibration and invalidated results do not
establish a marketing claim.

## Comparisons

Give every workflow the same actionable task, repository snapshot, requirements,
agent/model configuration, ordinary development tools, and budget. Do not make
the baseline rediscover an unspecified problem that SiteCMD has already located.

| Workflow | Information and tools                                                                                                  |
| -------- | ---------------------------------------------------------------------------------------------------------------------- |
| `normal` | Actionable bug report, source, existing tests, ordinary agent tools; no SiteCMD output or MCP connection.              |
| `report` | The same inputs plus the complete relevant SiteCMD report pasted into the conversation; no SiteCMD MCP connection.     |
| `mcp`    | The same task plus the shipped SiteCMD handoff and actual MCP tools, including the fix brief and verification request. |

`mcp` versus `normal` measures the workflow package. `report` versus `normal`
measures the value of supplied scanner context. `mcp` versus `report` measures the
additional effect of retrieval and workflow integration. Do not call the last
comparison a pure transport effect: the tools can expose different information
and actions. Count all information the agent consumes.

Declare one primary comparison and endpoint in the registered protocol before
running confirmatory trials. Use `mcp` versus `normal`, first-attempt acceptance,
for the primary Code Scan configuration unless the registered study says
otherwise. Report the other comparisons as secondary. The generated intervals
are descriptive, not adjusted for multiple comparisons; independent statistical
review is required before making several simultaneous superiority claims.

## Cases and independent acceptance

Use calibration to validate the runner, estimate usage and paired disagreement
rates, and identify flaky graders. Do not use calibration outcomes as
confirmation. Freeze the final sample size, cases, configurations, endpoints,
and stopping rules before confirmatory model trials. Do not stop when a favorable
result appears.

The first registered repository study completed 96 assignments across six repairs,
two negative controls, four model configurations, and three paired workflows. A
post-run validity review invalidated it because one scanner target did not match
the task's semantic location, raw-HTML findings and fix verification were not
occurrence-specific, and one grader omitted a required whitespace regression.
Its negative outcome remains useful for diagnosing the product and protocol, but
none of its rates or token measurements may support a product or marketing claim.
The invalidation registry makes the runner reject that study ID and makes reports
label its evidence diagnostic-only.

The v2 follow-up is also invalidated. Its extension grader lacked standard DOM
operations used by valid repairs. Its shell grader required direct Windows `.cmd`
execution without a command shell, contradicting the platform's execution model.
These defects invalidate both success counts and accepted-repair token denominators.
Preserve the original records; any corrected regrading is a separate diagnostic
analysis, not a replacement preregistered result.

Start with Code Scan. Evaluate Web Scan separately with controlled, resettable
deployments; it must have its own sufficient sample. Neither code-only results
nor a small combined sample justify a broad claim about all website repairs.

Choose cases across supported languages, frameworks, rule categories, difficulty,
repository size, and single-file versus multi-file repairs. Sample from a defined
population, not just rules expected to benefit from SiteCMD. Record provenance
and licenses. Historical real defects are preferable to exclusively seeded
examples. Do not select cases after seeing an agent's result. Keep calibration
and confirmation separate at repository level where practical, and disclose
possible model exposure to public historical fixes.

A replacement confirmation requires a fresh corpus that no repair agent has seen.
Each registered finding must overlap a task-specific semantic source anchor, and
every repeated rule in a file must remain a separate scanner, handoff, and
verification target. Graders must assert the complete observable contract,
including formatting or whitespace where relevant. The earlier source-first
intake of 12 historical repairs passed source screening but produced no eligible
target detections; those misses remain selection-attrition evidence. Results from
any scanner-enriched corpus are conditional on SiteCMD detecting the issue and do
not estimate scanner recall or performance over all software defects.

Each case needs:

- A frozen source snapshot, actionable prompt, expected behavior, relevant full
  report, and independently maintained grader, with content digests.
- An explicit observable contract wherever multiple safe repairs differ. State
  whether invalid values must be rejected or normalized, which existing values
  remain valid, and whether persisted identifiers must retain their exact bytes.
- A baseline that fails the defect-specific acceptance check but passes the
  unrelated regression checks. Demonstrate both before measuring agents.
- A reviewed reference patch that passes acceptance and regression checks.
  Run baseline and reference checks repeatedly to reject flaky cases.
- Test multiple independent valid repairs and deliberate near-miss repairs before
  freezing the grader. A test double must not reject a supported API merely because
  it differs from the reference implementation. Use real browser or operating-system
  execution for platform-dependent claims; mocked process arguments do not prove
  a Windows command actually runs.
- A validator, provenance, category, surface, and held-out status.
- Hidden acceptance checks for the behavior, plus existing and independent
  regression tests. Agents may run ordinary project tests but cannot edit or
  inspect the hidden grader before submitting.

Negative controls include valid instructional security examples, intentionally
suppressed findings, and already-correct implementations. They start with passing
behavior checks. A justified no-op or appropriate triage can be accepted, but is
never counted as a repaired defect. Review unnecessary changes and false-positive
fixes separately from repair success.

Scanner clearance is a secondary observation, not acceptance. Renaming a file,
disabling a rule, hiding a finding, weakening a test, breaking functionality, or
removing a required feature does not fix the defect.

## Subscription pilot

The [pilot policy](../../tools/benchmark/pilot-policy.json) fixes this first batch:

- Exact models listed in the policy, through Codex and Claude Code subscription logins.
- Five Code Scan cases: four repairs and one negative control, three workflows,
  one repeat, totaling 15 trials per model configuration.
- Twenty minutes and three submitted candidates per trial. Tokens are measured;
  there is no separate token cap for this allowance-based batch.
- No additional spending, API fallback, extra credits, or automatic usage resets.
- Pause after consuming 20 percentage points of either account's weekly allowance,
  or if any applicable account window falls below 30% remaining.

Record exact agent versions and explicit reasoning settings in the real manifest
before freezing it. The policy pins models but does not establish their availability
under an account, create cases, or select a reasoning level. Do not switch models
if an entitlement or rate-limit error occurs.

The quota guard uses fresh readings from both accounts, no older than five minutes.
Check before and after each trial, and at each submission boundary. Account usage
includes other work and can be delayed or rounded; treat all allowance consumption
since baseline as consuming the pilot allocation. Percentages are operational stop
signals, not token measurements or a guaranteed exact cap during an in-flight trial.
Keep the original weekly baseline. A weekly reset or account change pauses the
batch for review; it must not silently grant another allocation. A normal short
session reset does not reset the weekly budget.

Saved subscription authentication alone does not prove paid overage is disabled.
Verify that setting and reject API-key or provider-routing overrides in the runner.
Keep provider quota/billing evidence privately. Unknown usage, reset times, billing
mode, or extra-usage status means pause, not permission to spend.

Subscription trials report tokens and outcomes, not dollar savings. Record
additional charges separately from API-equivalent estimates. An estimate returned
by Claude Code is not a charge against this pilot's zero-extra-spend cap. A verified
zero additional charge does not imply the compute or subscription was free.

## Running a trial

Freeze the protocol, case manifest, SiteCMD commit and bundled MCP digest, model
identifier, agent version, reasoning setting, environment, tool permissions,
network policy, and limits before creating the plan. Preserve immutable snapshots
of prompts, reports, graders, and dependency locks outside the agent workspace.
Do not use floating model aliases when a stable version is available; record any
provider-side version uncertainty.

The planner randomizes task/configuration/repeat blocks and workflow order within
each block. Follow that order. Each assignment gets a fresh source copy,
conversation, agent memory, and isolated SiteCMD database. Never reuse one arm's
patch, transcript, fix state, or project memory in another. Run paired trials close
together under equivalent hardware and load. Keep task customizations identical
across workflows, except the explicitly varied SiteCMD access.

Use disposable containers or VMs with bounded CPU, memory, processes, disk,
network, and wall time. Preinstall pinned dependencies and keep grading offline
where possible. Never execute arbitrary generated patches or dependency hooks
on the maintainer's host. Do not mount host credentials, the Docker socket,
production data, or a user's SiteCMD database into the runner.

The real MCP workflow requires a running desktop instance that owns the isolated
database and processes verification. A recorded `request_verification` response
is not proof that the desktop completed a scan. Preserve the complete tool trace,
server identity, pending/error responses, and final verification state. Do not
replace the real server with a benchmark stub or bespoke briefing logic.

The desktop currently resolves its normal application data directory rather than
honoring `SITECMD_DB_PATH`. That variable isolates the CLI/MCP database only, not
the desktop verification worker. Do not point benchmark tools at the maintainer's
live database. The included executor uses a separate guest user and XDG data
directory, the actual desktop binary, and its bundled MCP server. The account
doctor verifies neither this workflow nor model availability.

The first corpus uses owned, single-file Node/Python examples with ordinary
regression tests: credentialed CORS, redirect destinations, SQL injection,
document paths, and a parameterized-query negative control. Each baseline and
reference must pass its expected independent checks three times. Source hashes
use canonical filename-to-content JSON; grader hashes cover the assertions,
candidate adapters, and sandbox launcher. Preserve those bytes with the plan.
This small seeded corpus tests the machinery, not real-project representativeness.
If a defect has no SiteCMD repair handoff, record the MCP assignment as a pre-agent
product error, with zero calls, and retain it in the denominator.

Record setup as cold or warm and keep conditions identical across workflows.
Cold includes installation, connection, and initial scan; warm begins with the
tools configured and a fresh scan available. Report setup costs separately and
state which condition a claim describes. The current report refuses to treat
mixed conditions as claim-ready evidence.

### Submission and stopping rules

An attempt is a submitted candidate patch, not a model turn, tool call, or local
test run. Snapshot and hash the first candidate before returning any external
grader feedback. In the MCP workflow this boundary is the first verification
request. Give other workflows an equivalent explicit submission boundary.

An agent may inspect code, edit, and run ordinary local tests before its first
submission. Do not let one workflow inspect hidden tests while another submits
blindly. Freeze an equivalent external feedback policy. Independently grade every
submitted snapshot, even if the product later reports the finding resolved.

The included runner withholds all hidden-grader feedback, captures candidates
before forwarding the real MCP verification request, and requires an explicit
submission in the other workflows. Ordinary project tests remain available.
Unsubmitted edits or an interrupted run cannot count as final acceptance.
Record explicit model selection separately from provider-observed identity.
Claude Code must provide complete matching response metadata. The pinned Codex
client does not emit a response-model field, so its evidence is the exact strict
CLI selection plus one complete, clean event lifecycle; label that assurance
accordingly and never describe it as provider-observed identity. Incomplete,
conflicting, or unexpected evidence stops the trial and must not contribute a
successful fix to the requested model's results.

Enforce token, dollar, submission, and elapsed-time caps in the execution adapter,
including delegated agents and tool-triggered model calls. The importer detects
recorded overages; it cannot enforce budgets on an external process. Stop the
study before starting a trial whose reserved maximum would exceed the separately
approved remaining budget. A configured limit is not spending authorization.

Record every assigned trial, including timeouts and product, agent, and
infrastructure failures. Preserve any measurable usage on failures. An unknown
amount is `null`, never zero. Missing trials and unresolved reviews block complete
rates. Do not rerun only the losing workflow or choose the best repeat.

If infrastructure requires replacement trials, apply a preregistered whole-block
policy and retain the original records. The current importer does not exclude or
replace trials; exclusions require a separately versioned analysis showing both
denominators. Product failures are product outcomes, not infrastructure exclusions.

## Metrics and analysis

An accepted submission passes independent behavior, regression, and integrity
checks, meets the limits, and receives a blinded review. Show reviewers the task,
patch, and checks without the arm label or model identity. Any rejection prevents
acceptance. Preserve reasons and disagreements. Reviewers must check for weakened
tests, suppression-only changes, and changes outside the task's requirements.

- **First-attempt acceptance:** accepted first submissions divided by all assigned
  trials. Failed first submissions stay failures even after successful retries.
- **Final acceptance:** accepted final submitted candidates divided by all assigned
  trials. A later broken candidate cannot inherit an earlier candidate's success.
- **Tokens per accepted repair:** all trial tokens divided by accepted final
  repairs, including tokens spent on failed trials and retries. Count uncached
  input, cached reads, cache writes, output, and delegated agents without overlap.
- **Cost per accepted repair:** all measured trial costs divided by accepted final
  repairs. Distinguish provider estimates from billed charges; disclose model
  prices and cache treatment. Missing accounting withholds efficiency estimates.
  This metric is unavailable for subscription runs; extra charges and hypothetical
  API equivalents do not allocate the subscription price to individual repairs.
- **Time and effort:** preserve end-to-end elapsed time and separately measured
  human-active time. Unknown human effort remains unavailable. Do not call agent
  latency developer time saved.
- **Harm and reliability:** report regressions, integrity failures, negative-control
  outcomes, product/agent errors, timeouts, missing evidence, and budget overages.

The token denominator defines a combined quality/efficiency metric, not the cost
of fixing exactly the same subset of defects. A matched-success subset can be a
secondary diagnostic, but cannot replace the full-trial result. Zero accepted
repairs yield an undefined ratio, not infinite savings.

Keep scan surfaces, repair tasks, and negative controls separate. Keep model
configurations separate unless a fixed configuration mixture and its weights were
preregistered. A fixed multi-configuration confirmation uses its preregistered
weights and always shows disaggregated results. Repeats estimate variability; they
do not create new independent tasks.
The report uses a seeded 95% hierarchical bootstrap, resampling repositories and
then tasks while preserving all configurations, repeats, and paired workflows
within a task. Fewer than two repository clusters cannot produce an interval;
few clusters remain weak evidence even when an interval can be calculated.
Undefined bootstrap ratios are reported as unavailable rather than discarded to
make an interval look stable.

Report absolute percentage-point differences and relative changes together. A
hypothetical change from 40% to 60% is 20 percentage points and 50% relative
improvement, not 50 percentage points. Do not use that example as a SiteCMD result.
An interval spanning zero does not establish an improvement. Publish neutral or
negative results as well as favorable ones.

## Developer-effort study

Use a separate randomized study to support claims about human workflow. Recruit
developers representative of the intended audience. Give them equivalent training
and comparable, unfamiliar tasks; counterbalance workflow order and avoid giving
the same person the same defect twice. Pilot with a small group, then determine
participant and task counts from variability rather than a desired headline.

Measure consented screen/task activity or a task timer: setup, locating evidence,
copy/paste, handoff, reviewing patches, waiting, and retries. Record total elapsed
and human-active time separately, plus accepted repairs. Analyze paired tasks with
participant and repository clustering. Record prior tool familiarity. Do not infer
human effort from agent telemetry or use an automated runner to impersonate users.

## Publication checklist

Publish the frozen protocol and digest, selection process, exact versions,
denominators, all outcomes, confidence intervals, raw-data schema, graders,
permitted reproduction artifacts, and analysis code. Remove credentials and
personal or proprietary data from a separate release copy, not the private raw
evidence. Hashes detect accidental changes; they are not signatures or proof that
an operator ran a fair experiment. Independently review raw traces and execution
conditions before publishing.

State the tested population and comparison next to a numerical claim. Prefer
"On [N] registered scanner-detected Code Scan repairs using
[agent/model/version], [X]% versus [Y]% were accepted on the first submission"
over "AI fixes issues [Z]% better."
For efficiency, say "[Z]% fewer total tokens per independently accepted repair,
including failed trials" if that is what was measured. Never publish placeholders.

Calibration and fixtures cannot substantiate confirmatory claims. A report marked
ready for claim review still needs a reviewer to assess study validity, precision,
scope, raw evidence, and the proposed wording. It is not publication approval.
An entry in `tools/benchmark/invalidated-studies.json` permanently blocks claim
readiness regardless of statistical output.

## Methodological references

- [Anthropic: designing agent evaluations](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)
- [SWE-bench: reproducible patch evaluation](https://www.swebench.com/SWE-bench/guides/evaluation/)
- [METR: measuring experienced developer productivity](https://metr.org/blog/2025-07-10-early-2025-ai-experienced-os-dev-study/)
- [Claude usage accounting](https://code.claude.com/docs/en/agent-sdk/cost-tracking)
- [Codex noninteractive execution and usage events](https://learn.chatgpt.com/docs/non-interactive-mode)
- [Claude Code subscription automation policy](https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan)
- [Claude Code API-key precedence](https://support.claude.com/en/articles/12304248-manage-api-key-environment-variables-in-claude-code)
