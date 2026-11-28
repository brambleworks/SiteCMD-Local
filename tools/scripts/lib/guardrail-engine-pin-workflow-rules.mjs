import { conditionOf } from "./ci-step-pins.mjs";
import { unconditionalWorkflowStep } from "./guardrail-text-utils.mjs";
import { RUNNER_IMAGES } from "./guardrail-workflow-pins.mjs";
import {
  children,
  readJobs,
  runCommand,
  scalar,
  sequence,
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

function rustCacheInputs(steps) {
  const cache = steps.find((step) => scalar(step.get("uses"))?.startsWith("Swatinem/rust-cache@"));
  return children(cache?.get("with"));
}

function rustCachePrefix(steps) {
  return scalar(rustCacheInputs(steps).get("prefix-key"));
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
  return failures;
}

function includeRowsForRunner(job) {
  if (scalar(job?.get("runs-on")) !== "${{ matrix.os }}") return [];
  const matrix = children(children(job.get("strategy")).get("matrix"));
  return matrix.size === 1 ? workflowSteps(matrix.get("include")) : [];
}

export function publicEnginePinWorkflowFailures(fields, events, jobs, steps) {
  const failures = [];
  const push = events.get("push");
  if (
    events.size !== 2 ||
    events.get("pull_request")?.size !== 0 ||
    push?.size !== 2 ||
    sequence(push.get("branches")).join(",") !== "main" ||
    sequence(push.get("paths")).join(",") !== "engine.lock"
  ) {
    failures.push("module-pin.yml must run on pull requests and engine.lock pushes to main.");
  }

  const job = jobs.get("verify-pin") ?? new Map();
  const jobSteps = steps.get("verify-pin") ?? [];
  const sameRepository = "github.event.pull_request.head.repo.full_name == github.repository";
  if (
    jobs.size !== 1 ||
    conditionOf(job) !==
      `github.repository == 'brambleworks/SiteCMD-Local' && (github.event_name == 'push' || ${sameRepository})`
  ) {
    failures.push("module-pin.yml must skip fork pull requests and run only in SiteCMD-Local.");
  }
  const permissions = children(fields.get("permissions"));
  if (
    job.has("permissions") ||
    permissions.size !== 1 ||
    scalar(permissions.get("contents")) !== "read"
  ) {
    failures.push("module-pin.yml must grant only contents: read.");
  }

  const rows = includeRowsForRunner(job);
  const targetRunners = Object.values(runners);
  const cache = rustCacheInputs(jobSteps);
  if (
    rows.length !== targetRunners.length ||
    !targetRunners.every((runner) =>
      rows.some(
        (row) =>
          scalar(row.get("os")) === runner && scalar(row.get("prefix")) === `engine-pin-${runner}`,
      ),
    ) ||
    scalar(cache.get("prefix-key")) !== "${{ matrix.prefix }}" ||
    scalar(cache.get("shared-key")) !== "engine-pin" ||
    scalar(cache.get("workspaces")) !== "apps/desktop/src-tauri -> target"
  ) {
    failures.push("module-pin.yml must restore the warm-engine-pin caches on all four runners.");
  }

  const commands = jobSteps
    .filter((step) => !step.has("if") && !step.has("continue-on-error"))
    .flatMap((step) => (runCommand(step) ?? "").split("\n"));
  const fetch = commands.indexOf("pnpm engine:fetch");
  const build = commands.indexOf(
    "cargo build --release --locked --manifest-path crates/cli/Cargo.toml",
  );
  const verify = commands.indexOf('node tools/scripts/verify-engine-pin.mjs "$binary"');
  if (job.has("continue-on-error") || fetch === -1 || build <= fetch || verify <= build) {
    failures.push(
      "module-pin.yml must fetch the pinned engine, build the CLI, and verify the embedded pin in order.",
    );
  }
  return failures;
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

  const armSmoke = workflowJobs("ci.yml").get("cli-linux-arm64");
  const armRunner = linuxReleaseRunners["linux-aarch64"];
  if (scalar(armSmoke?.get("runs-on")) !== armRunner) {
    failures.push(`ci.yml job cli-linux-arm64 must run on ${armRunner}.`);
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
