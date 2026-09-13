import { requireCondition, requireText } from "./workflow-contract.mjs";
import { canonicalJson } from "./workflow-plan.mjs";

const ARMS = ["normal", "report", "mcp"];

function exactTargetCount(report, target) {
  return (report?.issues ?? []).filter(
    (issue) =>
      issue.checkId === target.checkId &&
      issue.relativePath === target.relativePath &&
      issue.fingerprint === target.fingerprint,
  ).length;
}

export function validateConfirmatoryWorkflowCase(item, receipt) {
  requireCondition(receipt?.id === item.id, "workflow case identity differs from the corpus");
  requireCondition(
    Array.isArray(receipt.results) &&
      receipt.results.length === ARMS.length &&
      ARMS.every((arm) => receipt.results.filter((result) => result.arm === arm).length === 1),
    "confirmatory evidence must cover all three workflows exactly once",
  );
  for (const result of receipt.results) {
    requireCondition(result.status === "ready", `${result.arm} workflow is not ready`);
    requireCondition(result.sourceUnchanged === true, `${result.arm} workflow changed source`);
    requireText(result.prompt, `${result.arm} workflow prompt`);
    requireText(result.issueDetail, `${result.arm} issue detail`);
    requireCondition(
      result.issueDetail.includes(item.targetFinding.checkId),
      `${result.arm} issue detail omitted the registered check`,
    );
    requireCondition(result.report?.exitCode === 0, `${result.arm} CLI report failed`);
    let parsed;
    try {
      parsed = JSON.parse(result.report.raw);
    } catch {
      throw new Error(`${result.arm} CLI report is not JSON`);
    }
    requireCondition(
      canonicalJson(parsed) === canonicalJson(result.report.report),
      `${result.arm} CLI report bytes differ from the parsed report`,
    );
    requireCondition(
      exactTargetCount(parsed, item.targetFinding) === 1,
      `${result.arm} workflow did not retain the exact registered scanner finding`,
    );
  }
  const mcp = receipt.results.find((result) => result.arm === "mcp");
  if (item.kind === "repair") {
    requireCondition(
      Number.isSafeInteger(mcp.attemptId) && mcp.attemptId > 0,
      "repair workflow did not create a fix attempt",
    );
    requireText(mcp.handoff, "repair handoff");
    requireText(mcp.brief, "repair brief");
    const issue = mcp.targetIssue;
    const line = issue?.line;
    requireCondition(
      issue?.fingerprint === item.targetFinding.fingerprint &&
        Number.isSafeInteger(line) &&
        line > 0 &&
        mcp.brief.includes(item.targetFinding.relativePath) &&
        mcp.brief.includes(`:${line}`),
      "repair brief did not identify the exact registered location",
    );
  } else {
    requireCondition(
      mcp.attemptId == null && !mcp.handoff && !mcp.brief,
      "negative-control workflow must not create a fix attempt",
    );
  }
  return receipt;
}
