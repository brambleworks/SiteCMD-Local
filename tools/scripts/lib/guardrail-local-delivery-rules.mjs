import { children, scalar, workflowFields, workflowSteps } from "./guardrail-workflow-yaml.mjs";

const retiredCommand =
  /\b(?:pnpm[ \t]+gate|pnpm[ \t]+run[ \t]+gate|lefthook[ \t]+run[ \t]+gate)(?![\w:-])/;
const receiptJob = ["gate", "pass"].join("-");

export function localDeliveryFailures(lefthook, scripts, read, listFiles) {
  const failures = [];
  const hooks = workflowFields(lefthook);
  if (hooks.has("gate")) failures.push("lefthook.yml must not define a hook named gate.");
  const prePush = children(hooks.get("pre-push"));
  if (
    children(prePush.get("commands")).has(receiptJob) ||
    workflowSteps(prePush.get("jobs")).some((job) => scalar(job.get("name")) === receiptJob) ||
    read(".lefthook/pre-push/public-tree.sh").includes(receiptJob)
  ) {
    failures.push("lefthook.yml must not require a local verification receipt before pushing.");
  }
  if (
    Object.hasOwn(scripts, "gate") ||
    Object.values(scripts).some((script) => retiredCommand.test(script))
  ) {
    failures.push(retiredCommandFailure("package.json"));
  }
  const retiredCommandFile = (file) => /\.(?:mjs|cjs|js|ts|sh|md|ya?ml)$/.test(file);
  const files = [
    "AGENTS.md",
    "CONTRIBUTING.md",
    "README.md",
    "lefthook.yml",
    ...listFiles(".github", retiredCommandFile),
    ...listFiles(".lefthook", retiredCommandFile),
    ...listFiles("docs", (file) => file.endsWith(".md")),
    ...listFiles("apps", (file) => file.endsWith(".md")),
    ...listFiles("tools", retiredCommandFile),
  ];
  for (const file of files) {
    if (retiredCommand.test(read(file))) failures.push(retiredCommandFailure(file));
  }
  return failures;
}

function retiredCommandFailure(file) {
  return `${file} must not invoke or document the retired local verification command.`;
}
