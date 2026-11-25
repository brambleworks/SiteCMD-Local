import { conditionOf } from "./ci-step-pins.mjs";
import { VERIFY_PUSH_STEPS } from "./guardrail-ci-cost-rules.mjs";
import {
  children,
  readJobs,
  runCommand,
  scalar,
  workflowFields,
  workflowJobSteps,
} from "./guardrail-workflow-yaml.mjs";

const INVENTORY = ".github/ci-inventory.json";

function jobCommands(steps) {
  return new Set(
    steps
      .filter((step) => conditionOf(step) === null)
      .flatMap((step) => {
        const action = scalar(step.get("uses"));
        if (action) return [action.split("@", 1)[0]];
        return (runCommand(step) ?? "").split("\n").map((line) => line.trim());
      }),
  );
}

function inventoryHomes(steps, read) {
  const manualJobs = readJobs(workflowFields(read(`.github/workflows/manual.yml`)));
  const hooks = workflowFields(read("lefthook.yml"));
  const commands = children(children(hooks.get("pre-push")).get("commands"));
  const publicTree = children(commands.get("public-tree"));
  const hookCommands =
    scalar(publicTree.get("use_stdin")) === "true" &&
    scalar(publicTree.get("run"))?.startsWith("sh .lefthook/pre-push/public-tree.sh ")
      ? read(".lefthook/pre-push/public-tree.sh")
          .split("\n")
          .map((line) => line.trim())
      : [];
  const workflowHome = (jobSteps, stages) => ({
    commands: new Map([...jobSteps].map(([id, steps]) => [id, jobCommands(steps)])),
    stages,
  });
  return new Map([
    ["ci.yml", workflowHome(steps, ["pr", "queue"])],
    ["manual.yml", workflowHome(workflowJobSteps(manualJobs), ["manual"])],
    [
      "lefthook.yml",
      {
        commands: new Map([["public-tree", new Set(hookCommands)]]),
        stages: ["pre-push"],
      },
    ],
  ]);
}

export function checkInventory(steps, read, failures, { exported }) {
  const inventory = JSON.parse(read(INVENTORY));
  if (!Array.isArray(inventory)) {
    failures.push(`${INVENTORY} must contain an array of check rows.`);
    return;
  }
  const inventoried = new Set();
  const checks = new Set();
  const localSteps = new Set();
  const homes = inventoryHomes(steps, read);
  const codeqlFailure = exported
    ? "The CodeQL inventory row must match the CodeQL job."
    : "The CodeQL inventory row must record the private deferral.";
  for (const row of inventory) {
    const workflow = row?.workflow ?? "ci.yml";
    const home = homes.get(workflow);
    const deferred =
      row?.check === "codeql" &&
      workflow === "ci.yml" &&
      row.job === "none" &&
      row.was === "codeql.yml" &&
      row.command === "GitHub CodeQL analysis" &&
      row.note === "GitHub Code Security for private code is deferred." &&
      Array.isArray(row.stages) &&
      row.stages.length === 0;
    if (!home?.commands.has(row?.job) && !deferred) {
      failures.push(`${INVENTORY} names unknown ${workflow} job ${row?.job}.`);
    }
    if (checks.has(row?.check)) failures.push(`${INVENTORY} repeats check ${row?.check}.`);
    checks.add(row?.check);
    inventoried.add(`${workflow}:${row?.job}`);
    if (row?.was === "gate") localSteps.add(row.check);
    if (
      ![row?.check, row?.command, row?.was].every(
        (part) => typeof part === "string" && part.trim(),
      ) ||
      (!deferred &&
        (!Array.isArray(row?.stages) ||
          row.stages.length === 0 ||
          !row.stages.every((stage) => home?.stages.includes(stage))))
    ) {
      failures.push(
        `${INVENTORY} row for ${row?.job} must name its check, command, stages and previous home.`,
      );
    }
    const commands = home?.commands.get(row?.job);
    if (
      commands &&
      typeof row.command === "string" &&
      !row.command.split("\n").every((command) => commands.has(command.trim()))
    ) {
      failures.push(
        `Inventory check ${row.check} is missing a command in ${workflow} job ${row.job}.`,
      );
    }
    if (row?.check === "codeql" && (exported ? row.job !== "codeql" : !deferred))
      failures.push(codeqlFailure);
  }
  if (!checks.has("codeql")) failures.push(codeqlFailure);
  for (const [workflow, home] of homes) {
    for (const job of home.commands.keys()) {
      if (!inventoried.has(`${workflow}:${job}`))
        failures.push(`${workflow} job ${job} has no inventory row.`);
    }
  }
  const workspaceChecks = new Set(["rust-nextest", "rust-clippy"]);
  for (const step of VERIFY_PUSH_STEPS) {
    if (exported && workspaceChecks.has(step)) continue;
    if (!localSteps.has(step)) failures.push(`verify-push step ${step} has no inventory row.`);
  }
}
