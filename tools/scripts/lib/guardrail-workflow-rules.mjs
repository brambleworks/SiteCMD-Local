import { CI_WORKFLOW, QUEUE_OR_DISPATCH } from "./ci-workflow-contract.mjs";
import {
  enginePinWorkflowFailures,
  releaseRunnerBaselineFailures,
} from "./guardrail-engine-pin-workflow-rules.mjs";
import { workflowCommandFailures } from "./guardrail-workflow-command-rules.mjs";
import { isVersionedUbuntuRunner } from "./guardrail-workflow-pins.mjs";
import {
  readJobs,
  runCommand,
  scalar,
  workflowFields,
  workflowJobSteps,
} from "./guardrail-workflow-yaml.mjs";

export function workflowSafetyFailures(read, listFiles, { exported = false } = {}) {
  const failures = [];
  const workflowFiles = listFiles(".github/workflows", (file) => /\.ya?ml$/.test(file));
  for (const file of workflowFiles) failures.push(...workflowCommandFailures(file, read(file)));
  const npxWorkflowFiles = workflowFiles.filter((file) => /\bnpx\b/.test(read(file)));
  if (npxWorkflowFiles.length > 0) {
    failures.push(
      `GitHub workflows must use the configured project package manager, not npx: ${npxWorkflowFiles.join(", ")}`,
    );
  }

  const source = read(CI_WORKFLOW);
  const jobs = readJobs(workflowFields(source));
  const steps = workflowJobSteps(jobs);
  const releaseWorkflow = !exported || workflowFiles.includes(".github/workflows/release.yml");
  failures.push(...releaseRunnerBaselineFailures(read, { releaseWorkflow }));
  if (!exported) failures.push(...enginePinWorkflowFailures(source));
  const msrvCommands = steps.get("msrv")?.map(runCommand) ?? [];
  if (
    ![
      "rustup toolchain install 1.95.0 --profile minimal",
      "cargo +1.95.0 check --locked --workspace --all-targets",
      "cargo +1.95.0 check --locked --manifest-path crates/cli/Cargo.toml --all-targets",
    ].every((command) => msrvCommands.includes(command))
  ) {
    failures.push("Rust MSRV CI must compile the workspace and CLI on Rust 1.95.0.");
  }
  const staticCommands = steps.get("static")?.map(runCommand) ?? [];
  if (
    jobs.get("static")?.has("if") ||
    !["pnpm run guardrails:repo", "pnpm run workflows:check", "pnpm run installer:check"].every(
      (command) => staticCommands.includes(command),
    ) ||
    !/ACTIONLINT_VERSION: "1\.7\.12"/.test(source)
  ) {
    failures.push(
      "Repository guardrails must run on every pull request and validate workflows and the public installer.",
    );
  }
  const clippy = jobs.get(exported ? "rust-tests" : "clippy") ?? new Map();
  if (
    !isVersionedUbuntuRunner(scalar(clippy.get("runs-on"))) ||
    scalar(clippy.get("if")) !== QUEUE_OR_DISPATCH
  ) {
    failures.push("ci.yml must run workspace clippy on Linux in the merge queue.");
  }
  if (exported) {
    const commands = steps.get("rust-tests")?.map(runCommand) ?? [];
    if (
      !commands.includes("node tools/scripts/build-standin.mjs") ||
      !commands.some((command) => command?.startsWith("cargo test --locked ")) ||
      !commands.some((command) => command?.startsWith("cargo clippy --locked "))
    ) {
      failures.push("Public CI must build the stand-in and run locked Rust tests and clippy.");
    }
  }
  return failures;
}
