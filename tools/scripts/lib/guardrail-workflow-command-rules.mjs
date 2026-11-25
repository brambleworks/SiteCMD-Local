import { posix } from "node:path";
import { unconditionalWorkflowStep, workflowBlock } from "./guardrail-text-utils.mjs";

const workspace = "apps/desktop/src-tauri";
const pnpmBuiltins = new Set([
  "install",
  "i",
  "add",
  "setup",
  "store",
  "fetch",
  "dlx",
  "--version",
  "--help",
]);
const shellSeparator = /[;&|`()<>\n]/;

// Read command-bearing steps in the workflow's block layout.
export function workflowCommandFailures(file, source) {
  const failures = [];
  const jobs = workflowBlock(source, "jobs");
  const workflowDirectory = defaultsDirectory(source, 0);
  for (const job of jobs.split(/^ {2}(?=[\w-]+:[ \t]*(?:#|$))/m).slice(1)) {
    const jobName = job.slice(0, job.indexOf(":"));
    const steps = workflowBlock(job, "steps", 4)
      .split(/^ {6}- /m)
      .slice(1);
    const jobDirectory = defaultsDirectory(job, 4) ?? workflowDirectory;
    let installed = false;
    for (const step of steps) {
      const fields = `        ${step}`;
      const run = runCommand(fields);
      const commands = run
        .split(shellSeparator)
        .map((segment) => segment.replace(/['"]/g, "").trim().split(/\s+/));
      const directory = workingDirectory(fields, 8) ?? jobDirectory ?? ".";
      if (
        !installed &&
        commands.some((words) =>
          words.some((word, index) => word === "pnpm" && !pnpmBuiltins.has(words[index + 1])),
        )
      ) {
        failures.push(
          `${file} job ${jobName} requires an earlier unconditional pnpm install before running a pnpm script.`,
        );
      }
      if (
        !isWorkspace(directory) &&
        !changesToWorkspace(run, directory) &&
        commands.some((words) =>
          words.some(
            (word, index) =>
              word === "cargo" &&
              !/^\+(?:\d+\.\d+\.\d+|nightly-\d{4}-\d{2}-\d{2})$/.test(words[index + 1] ?? ""),
          ),
        )
      ) {
        failures.push(
          `${file} job ${jobName} must run Cargo from apps/desktop/src-tauri to select the workspace toolchain.`,
        );
      }
      if (unconditionalWorkflowStep(step) && isDirectPnpmInstall(run)) installed = true;
    }
  }
  return failures;
}

function runCommand(fields) {
  const lines = fields.split("\n");
  const run = lines.findIndex((line) => line.startsWith("        run:"));
  if (run === -1) return "";
  let value = lines[run].slice("        run:".length).trim();
  if (value.startsWith("|") || value.startsWith(">")) {
    const body = [];
    for (const line of lines.slice(run + 1)) {
      if (line.trim() && !line.startsWith("          ")) break;
      body.push(line);
    }
    value = body.join("\n");
  } else {
    value = unquote(value);
  }
  return value
    .replace(/^[ \t]*#.*$/gm, "")
    .replace(/\\\r?\n/g, "")
    .trim();
}

function isDirectPnpmInstall(run) {
  if (shellSeparator.test(run)) return false;
  const words = run.split(/\s+/).map(unquote);
  const start = words.findIndex((word) => word !== "env" && !/^[A-Za-z_]\w*=/.test(word));
  const tool = words[start] === "corepack" ? start + 1 : start;
  return words[tool] === "pnpm" && ["install", "i"].includes(words[tool + 1]);
}

function isWorkspace(directory) {
  return directory === workspace || directory.startsWith(`${workspace}/`);
}

function changesToWorkspace(run, directory) {
  // Require the directory change to succeed before Cargo runs.
  const change = /^cd[ \t]+([.\w-][\w./-]*)[ \t]+&&[ \t]+cargo(?=$|[ \t])[\w./+=: \t-]*$/.exec(run);
  return change !== null && isWorkspace(posix.join(directory, change[1]));
}

function defaultsDirectory(source, indent) {
  const defaults = workflowBlock(source, "defaults", indent);
  return workingDirectory(workflowBlock(defaults, "run", indent + 2), indent + 4);
}

function workingDirectory(fields, indent) {
  const prefix = `${" ".repeat(indent)}working-directory:`;
  const line = fields.split("\n").find((line) => line.startsWith(prefix));
  if (!line) return undefined;
  const value = unquote(line.slice(prefix.length).split(" #", 1)[0].trim());
  return posix.normalize(value).replace(/\/$/, "");
}

function unquote(value) {
  return value.replace(/^(['"])(.*)\1$/, "$2");
}
