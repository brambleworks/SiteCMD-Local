import assert from "node:assert/strict";
import { test } from "node:test";
import { validateConfirmatoryWorkflowCase } from "./confirmatory-workflow.mjs";

const fingerprint = `sha256:${"a".repeat(64)}`;
const repair = {
  id: "repair-case",
  kind: "repair",
  targetFinding: {
    checkId: "code_scan.unsafe-html",
    relativePath: "src/render.tsx",
    fingerprint,
  },
};
const targetIssue = {
  ...repair.targetFinding,
  line: 41,
};

function arm(name) {
  return {
    arm: name,
    status: "ready",
    sourceUnchanged: true,
    prompt: `Prompt for ${name}`,
    report: {
      exitCode: 0,
      raw: JSON.stringify({ issues: [targetIssue] }),
      report: { issues: [targetIssue] },
    },
    issueDetail: `Grouped detail for ${repair.targetFinding.checkId}`,
    ...(name === "mcp"
      ? {
          attemptId: 17,
          handoff: "SiteCMD prepared fix attempt #17.",
          brief: `Where to look\n${repair.targetFinding.relativePath}:41`,
          targetIssue,
        }
      : {}),
  };
}

test("confirmatory workflow evidence requires every arm and the exact repair brief", () => {
  const receipt = { id: repair.id, results: [arm("normal"), arm("report"), arm("mcp")] };
  assert.equal(validateConfirmatoryWorkflowCase(repair, receipt), receipt);

  const wrongBrief = structuredClone(receipt);
  wrongBrief.results[2].brief = "Where to look\nsrc/another.tsx:41";
  assert.throws(
    () => validateConfirmatoryWorkflowCase(repair, wrongBrief),
    /exact registered location/,
  );

  const missingArm = structuredClone(receipt);
  missingArm.results.pop();
  assert.throws(() => validateConfirmatoryWorkflowCase(repair, missingArm), /three workflows/);
});

test("negative-control workflow evidence does not invent a fix attempt", () => {
  const control = { ...repair, id: "control-case", kind: "negative_control" };
  const results = [arm("normal"), arm("report"), arm("mcp")];
  delete results[2].attemptId;
  delete results[2].handoff;
  delete results[2].brief;
  const receipt = { id: control.id, results };
  assert.equal(validateConfirmatoryWorkflowCase(control, receipt), receipt);

  receipt.results[2].attemptId = 17;
  assert.throws(
    () => validateConfirmatoryWorkflowCase(control, receipt),
    /negative-control workflow must not create a fix attempt/,
  );
});

test("workflow evidence must retain source and the exact scanner finding", () => {
  const receipt = { id: repair.id, results: [arm("normal"), arm("report"), arm("mcp")] };
  receipt.results[0].sourceUnchanged = false;
  assert.throws(() => validateConfirmatoryWorkflowCase(repair, receipt), /changed source/);

  receipt.results[0].sourceUnchanged = true;
  receipt.results[1].report.report.issues = [
    { ...receipt.results[1].report.report.issues[0], fingerprint: `sha256:${"b".repeat(64)}` },
  ];
  receipt.results[1].report.raw = JSON.stringify(receipt.results[1].report.report);
  assert.throws(
    () => validateConfirmatoryWorkflowCase(repair, receipt),
    /exact registered scanner finding/,
  );
});
