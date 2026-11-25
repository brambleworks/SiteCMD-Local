import { unconditionalWorkflowStep } from "./guardrail-text-utils.mjs";
import { RUNNER_IMAGES } from "./guardrail-workflow-pins.mjs";
import {
  children,
  readJobs,
  runCommand,
  scalar,
  workflowFields,
  workflowJobSteps,
  workflowSteps,
} from "./guardrail-workflow-yaml.mjs";

const linuxReleaseRunners = {
  "linux-x86_64": "ubuntu-22.04",
  "linux-aarch64": "ubuntu-22.04-arm",
};

const runners = {
  "engine-pin-macos": RUNNER_IMAGES.macos,
  "engine-pin-linux": linuxReleaseRunners["linux-x86_64"],
  "engine-pin-linux-arm64": linuxReleaseRunners["linux-aarch64"],
  "engine-pin-windows": RUNNER_IMAGES.windows,
};

function rustCachePrefix(steps) {
  const cache = steps.find((step) => scalar(step.get("uses"))?.startsWith("Swatinem/rust-cache@"));
  return scalar(children(cache?.get("with")).get("prefix-key"));
}

export function enginePinWorkflowFailures(source) {
  const failures = [];
  const fields = workflowFields(source);
  const jobs = readJobs(fields);
  const steps = workflowJobSteps(jobs);
  const permissions = children(fields.get("permissions"));
  for (const [id, runner] of Object.entries(runners)) {
    const job = jobs.get(id) ?? new Map();
    const jobSteps = steps.get(id) ?? [];
    if (scalar(job.get("runs-on")) !== runner || job.has("strategy")) {
      failures.push(`ci.yml job ${id} must run on ${runner}.`);
    }
    const prefix = `engine-pin-${runner}`;
    if (rustCachePrefix(jobSteps) !== prefix) {
      failures.push(`ci.yml job ${id} must use cache prefix ${prefix}.`);
    }
    if (
      job.has("permissions") ||
      permissions.size !== 1 ||
      scalar(permissions.get("contents")) !== "read"
    ) {
      failures.push(`ci.yml job ${id} must grant only contents: read.`);
    }
    if (job.has("continue-on-error") || jobSteps.some((step) => step.has("continue-on-error"))) {
      failures.push(`ci.yml job ${id} must not set continue-on-error.`);
    }
    if (
      !jobSteps.some(
        (step) =>
          !step.has("if") &&
          runCommand(step)
            ?.split("\n")
            .includes('node tools/scripts/verify-engine-pin.mjs "$binary"'),
      )
    ) {
      failures.push(`ci.yml job ${id} must verify the embedded pin on every runner.`);
    }
  }
  const armSmoke = jobs.get("cli-linux-arm64");
  const armRunner = linuxReleaseRunners["linux-aarch64"];
  if (scalar(armSmoke?.get("runs-on")) !== armRunner) {
    failures.push(`ci.yml job cli-linux-arm64 must run on ${armRunner}.`);
  }
  return failures;
}

function includeRowsForRunner(job) {
  if (scalar(job?.get("runs-on")) !== "${{ matrix.os }}") return [];
  const matrix = children(children(job.get("strategy")).get("matrix"));
  return matrix.size === 1 ? workflowSteps(matrix.get("include")) : [];
}

export function releaseRunnerBaselineFailures(read, { releaseWorkflow = true } = {}) {
  const workflowJobs = (file) => readJobs(workflowFields(read(`.github/workflows/${file}`)));
  const failures = [];
  const release = releaseWorkflow ? workflowJobs("release.yml") : new Map();
  for (const id of releaseWorkflow ? ["build", "verify-release"] : []) {
    const rows = includeRowsForRunner(release.get(id));
    for (const [target, runner] of Object.entries(linuxReleaseRunners)) {
      const matches = rows.filter((row) => scalar(row.get("target")) === target);
      if (matches.length !== 1 || scalar(matches[0].get("os")) !== runner) {
        failures.push(`release.yml job ${id} target ${target} must run on ${runner}.`);
      }
    }
  }

  const cacheJobs = workflowJobs("cache.yml");
  const rows = includeRowsForRunner(cacheJobs.get("warm-engine-pin"));
  for (const runner of Object.values(runners)) {
    const prefix = `engine-pin-${runner}`;
    const matches = rows.filter(
      (row) => scalar(row.get("os")) === runner || scalar(row.get("prefix")) === prefix,
    );
    if (
      matches.length !== 1 ||
      scalar(matches[0].get("os")) !== runner ||
      scalar(matches[0].get("prefix")) !== prefix
    ) {
      failures.push(`cache.yml job warm-engine-pin must warm ${runner} with prefix ${prefix}.`);
    }
  }
  const cacheSteps = workflowJobSteps(cacheJobs).get("warm-engine-pin") ?? [];
  if (rustCachePrefix(cacheSteps) !== "${{ matrix.prefix }}") {
    failures.push("cache.yml job warm-engine-pin must use matrix.prefix as its cache prefix.");
  }
  return failures;
}

export function releasePinStepIsComplete(job) {
  const step = job
    .split(/^ {6}- /m)
    .find((step) => step.startsWith("name: Verify the embedded engine pin\n"));
  return Boolean(
    step &&
    unconditionalWorkflowStep(step) &&
    step.includes('          node tools/scripts/verify-engine-pin.mjs "$binary"\n') &&
    step.includes(
      [
        '          if [ "$TARGET" = darwin-universal ]; then',
        '            lipo "$binary" -thin x86_64 -output cli-check/sitecmd-x86_64',
        "            chmod +x cli-check/sitecmd-x86_64",
        "            node tools/scripts/verify-engine-pin.mjs cli-check/sitecmd-x86_64",
        "          fi",
      ].join("\n"),
    ),
  );
}
