import {
  CI_WORKFLOW,
  DEPENDENCY_AUDIT,
  ENGINE_PIN_ONLY,
  PR_ONLY,
  PUBLIC_TREE_PR,
  PUBLIC_TREE_SKIP,
  QUEUE_OR_DISPATCH,
  requiredSkips,
} from "./ci-workflow-contract.mjs";
import {
  children,
  readJobs,
  runCommand,
  scalar,
  sequence,
  workflowEvents,
  workflowFields,
  workflowJobSteps,
} from "./guardrail-workflow-yaml.mjs";
import { checkInventory } from "./ci-inventory-rules.mjs";
import {
  checkActionPins,
  checkGuardrailTestSetup,
  checkLockedCargoFetch,
  checkToolPins,
  commandWords,
  conditionOf,
} from "./ci-step-pins.mjs";
import { sharedRustCacheFailures, sharedRustCaches } from "./guardrail-rust-cache-env.mjs";
import { ENGINE_CRATES, ENGINE_PATHS } from "./publication-history-rules.mjs";

const WORKFLOWS = ".github/workflows";
const CACHE = `${WORKFLOWS}/cache.yml`;
const POLICY = ".github/ci-workflow-policy.json";
const VISIBILITY = ".github/ci-job-visibility.json";
const TEST_SCRIPT = /^(?:test|vitest|e2e|perf)$|^test:[\w:-]+$|^[\w:-]+:test$/;

function runsTests(source) {
  return commandWords(source).some(([command, ...args]) => {
    if (command === "pnpm" || command === "npm") return args.some((arg) => TEST_SCRIPT.test(arg));
    const cargoCommand = args[0]?.startsWith("+") ? args[1] : args[0];
    return (
      command === "vitest" ||
      (command === "playwright" && args[0] === "test") ||
      (command === "node" && args.includes("--test")) ||
      (command === "cargo" && ["test", "nextest", "llvm-cov"].includes(cargoCommand))
    );
  });
}

function checkAllowedSkips(jobs, input, failures, exported) {
  const pins = [...jobs.keys()].filter(
    (id) => id.startsWith("engine-pin-") && id !== "engine-pin-paths",
  );
  const queue = [...jobs.keys()].filter((id) => conditionOf(jobs.get(id)) === QUEUE_OR_DISPATCH);
  const expected = [
    "${{ github.event_name != 'pull_request' && 'pr-title' || '' }}",
    `\${{ (${PUBLIC_TREE_SKIP}) && 'public-tree' || '' }}`,
    "${{ github.event_name != 'workflow_dispatch' && needs.dependency-paths.outputs.dependencies == 'false' && 'dependency-audit' || '' }}",
    `\${{ github.event_name == 'pull_request' && '${queue.join(", ")}' || '' }}`,
    `\${{ (github.event_name == 'pull_request' || (github.event_name == 'merge_group' && needs.engine-pin-paths.outputs.engine == 'false')) && '${pins.join(", ")}' || '' }}`,
  ].join(", ");
  const required = exported ? requiredSkips(jobs).join(", ") : expected;
  if (input?.trim().replace(/\s+/g, " ") !== required) {
    failures.push("CI allowed skips must match the event and engine pin path result.");
  }

  if (conditionOf(jobs.get("pr-title") ?? new Map()) !== PR_ONLY) {
    failures.push("CI allowed skip pr-title must be gated on pull_request.");
  }
  if (conditionOf(jobs.get("public-tree") ?? new Map()) !== PUBLIC_TREE_PR) {
    failures.push("CI public-tree must run only for SiteCMD-Local pull requests.");
  }
  const audit = jobs.get("dependency-audit") ?? new Map();
  if (
    conditionOf(audit) !== DEPENDENCY_AUDIT ||
    !sequence(audit.get("needs")).includes("dependency-paths")
  ) {
    failures.push("CI dependency audit must require changed dependencies or manual dispatch.");
  }
  for (const id of pins) {
    if (
      conditionOf(jobs.get(id)) !== ENGINE_PIN_ONLY ||
      !sequence(jobs.get(id).get("needs")).includes("engine-pin-paths")
    ) {
      failures.push(
        `CI allowed skip ${id} must be gated on the merge group and engine pin path result.`,
      );
    }
  }
  for (const [id, job] of jobs) {
    if (
      !["CI", "pr-title", "public-tree", "dependency-audit", ...pins, ...queue].includes(id) &&
      conditionOf(job) !== null
    ) {
      failures.push(`ci.yml job ${id} must run at both stages or use the merge queue condition.`);
    }
  }
}

function checkAggregator(jobs, steps, failures, exported) {
  const aggregator = jobs.get("CI") ?? new Map();
  const required = [...jobs.keys()].filter((id) => id !== "CI");
  const needs = sequence(aggregator.get("needs"));
  if (needs.length !== required.length || required.some((id) => !needs.includes(id))) {
    failures.push("CI needs every other job in ci.yml exactly once.");
  }
  if (conditionOf(aggregator) !== "always()") {
    failures.push("CI must run with if: always() so failures and cancellations are evaluated.");
  }

  const verdict = (steps.get("CI") ?? []).find((step) =>
    /^re-actors\/alls-green@[a-f0-9]{40}$/.test(scalar(step.get("uses")) ?? ""),
  );
  const inputs = children(verdict?.get("with"));
  if (
    !verdict ||
    conditionOf(verdict) !== null ||
    scalar(inputs.get("jobs")) !== "${{ toJSON(needs) }}"
  ) {
    failures.push("CI must use re-actors/alls-green with the results of every needed job.");
  }
  if (
    [aggregator, verdict].some((part) => part?.has("continue-on-error")) ||
    inputs.has("allowed-failures")
  ) {
    failures.push("CI must reject failed jobs without allowed-failures or continue-on-error.");
  }
  checkAllowedSkips(jobs, scalar(inputs.get("allowed-skips")), failures, exported);
}

function checkVisibility(jobs, visibility, source, failures) {
  if (visibility?.["public-tree"] !== "open") failures.push("ci.yml job public-tree must be open.");
  const comments = new Map(
    [...source.matchAll(/^ {2}# (open|private)(?:\..*|)\n {2}([\w-]+):/gm)].map(([, label, id]) => [
      id,
      label,
    ]),
  );
  for (const id of jobs.keys()) {
    if (!["open", "private"].includes(visibility?.[id])) {
      failures.push(`ci.yml job ${id} must have an open or private visibility label.`);
    } else if (comments.get(id) !== visibility[id]) {
      failures.push(`ci.yml job ${id} must have a visibility comment matching ${VISIBILITY}.`);
    }
  }
  for (const id of Object.keys(visibility ?? {})) {
    if (!jobs.has(id)) failures.push(`${VISIBILITY} names unknown ci.yml job ${id}.`);
  }
}

const privatePrefixes = ENGINE_PATHS.flatMap((path) => {
  const member = /\/crates\//.exec(path);
  if (member) return [path, path.slice(member.index + 1)];
  return path.startsWith("tools/") ? [path] : [];
});

function referencesPrivateCode(source) {
  if (/\bsecrets\s*(?:\.|\[)/.test(source)) return true;
  return (source.match(/[\w./-]+/g) ?? []).some(
    (word) =>
      ENGINE_CRATES.includes(word) ||
      privatePrefixes.some((prefix) => word.includes(prefix) || word.endsWith(prefix.slice(0, -1))),
  );
}

function checkDependencyPaths(steps, failures) {
  const filterStep = (steps.get("dependency-paths") ?? []).find(
    (step) =>
      scalar(step.get("uses"))?.startsWith("dorny/paths-filter@") && conditionOf(step) === null,
  );
  const filters = children(filterStep?.get("with")).get("filters");
  const paths = sequence(workflowFields(filters?.body.join("\n") ?? "").get("dependencies"));
  for (const file of [
    "pnpm-workspace.yaml",
    "THIRD_PARTY_DEPENDENCIES.json",
    "tools/scripts/audit-rust-deps.mjs",
  ]) {
    if (!paths.includes(file)) failures.push(`CI dependency paths must include ${file}.`);
  }
}

function checkCiSteps(jobs, steps, visibility, failures, exported) {
  checkDependencyPaths(steps, failures);
  for (const [id, job] of jobs) {
    if (exported ? id === "CI" : visibility?.[id] !== "open") continue;
    const fields = [...job].filter(([key]) => key !== "steps");
    const expanded = (steps.get(id) ?? []).map((step) => [...step]);
    if (referencesPrivateCode(JSON.stringify([fields, expanded]))) {
      failures.push(`Open CI job ${id} must not reference secrets or engine paths.`);
    }
  }
  const releaseCli = "${{ github.workspace }}/apps/desktop/src-tauri/target/release/sitecmd_cli";
  const env = children(jobs.get("local-engine-tests")?.get("env"));
  if (!exported && scalar(env.get("SITECMD_REAL_CLI")) !== releaseCli) {
    failures.push("local-engine-tests must set SITECMD_REAL_CLI to the release CLI.");
  }
  const workflowLint = steps.get("workflow-lint") ?? [];
  if (
    !workflowLint.some(
      (step) =>
        runCommand(step) === "zizmor --no-progress ." &&
        conditionOf(step) === null &&
        scalar(children(step.get("env")).get("GH_TOKEN")) === "${{ github.token }}",
    )
  ) {
    failures.push("ci.yml must run zizmor online against .");
  }
}

function checkCiJobs(jobs, steps, source, read, failures, exported) {
  const visibility = exported ? null : JSON.parse(read(VISIBILITY));
  checkAggregator(jobs, steps, failures, exported);
  checkInventory(steps, read, failures, { exported });
  if (!exported) checkVisibility(jobs, visibility, source, failures);
  checkCiSteps(jobs, steps, visibility, failures, exported);
  if (exported) {
    for (const action of ["init", "analyze"]) {
      if (
        !steps
          .get("codeql")
          ?.some((step) => scalar(step.get("uses"))?.startsWith(`github/codeql-action/${action}@`))
      )
        failures.push(`Public CI must run CodeQL ${action}.`);
    }
  }
}

export function ciWorkflowFailures(read, listFiles, { exported = false } = {}) {
  const failures = [];
  const rustCaches = [];
  const files = listFiles(WORKFLOWS, (file) => /\.ya?ml$/.test(file));
  if (!files.includes(CI_WORKFLOW)) return ["Missing .github/workflows/ci.yml."];

  const { releasePush, dispatchOnly } = exported
    ? { releasePush: ["release.yml"], dispatchOnly: ["manual.yml"] }
    : JSON.parse(read(POLICY));
  const allowedPush = new Set(["cache.yml", ...releasePush]);
  for (const file of files) {
    const name = file.slice(WORKFLOWS.length + 1);
    try {
      const source = read(file);
      const fields = workflowFields(source);
      const events = workflowEvents(fields.get("on"));
      const jobs = readJobs(fields);
      const steps = workflowJobSteps(jobs);
      rustCaches.push(...sharedRustCaches(file, fields, jobs, steps));
      checkToolPins(file, steps, failures);
      checkGuardrailTestSetup(file, steps, failures);
      checkActionPins(file, jobs, steps, failures);
      if (file === CI_WORKFLOW) {
        checkLockedCargoFetch(steps, JSON.parse(read("package.json")).scripts ?? {}, failures);
        checkCiJobs(jobs, steps, source, read, failures, exported);
        for (const event of ["pull_request", "merge_group", "workflow_dispatch"]) {
          if (!events.has(event)) failures.push(`ci.yml must trigger on ${event}.`);
        }
        if (
          [...events.values()].some((filter) => filter.has("paths") || filter.has("paths-ignore"))
        ) {
          failures.push("ci.yml must not use trigger path filters.");
        }
        if (
          events.has("merge_group") &&
          !sequence(events.get("merge_group").get("types")).includes("checks_requested")
        ) {
          failures.push("ci.yml must run on merge_group checks_requested.");
        }
        if (events.has("pull_request_target"))
          failures.push("ci.yml must not use pull_request_target.");
      } else {
        for (const event of ["pull_request", "pull_request_target", "merge_group"]) {
          if (events.has(event)) {
            failures.push(`${name} must not trigger on ${event}.`);
          }
        }
        if (
          file === CACHE &&
          runsTests(
            source
              .split("\n")
              .filter((line) => !line.trimStart().startsWith("#"))
              .join("\n"),
          )
        ) {
          failures.push("cache.yml must not run tests.");
        }
      }
      if (dispatchOnly.includes(name) && (events.size !== 1 || !events.has("workflow_dispatch"))) {
        failures.push(`${name} must trigger only on workflow_dispatch.`);
      }
      const codeql =
        file === CI_WORKFLOW
          ? /codeql/i
          : /github\/codeql-action\b|\bcodeql[ \t]+(?:database|analyze|pack|resolve)\b/i;
      if (exported && file !== CI_WORKFLOW && codeql.test(source)) {
        failures.push(`${name} must run CodeQL in ci.yml.`);
      } else if (!exported && codeql.test(source)) {
        failures.push(`${name} must defer CodeQL for private code.`);
      }
      if (events.has("push") && !allowedPush.has(name)) {
        failures.push(`${name} must not trigger on push.`);
      }
    } catch (error) {
      failures.push(`${file}: ${error.message}`);
    }
  }
  return [...failures, ...sharedRustCacheFailures(rustCaches)];
}
