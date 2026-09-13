import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createStudyRun, importTrial, writeNewJson } from "./workflow-store.mjs";
import { digest } from "./workflow-plan.mjs";

const FIXTURES = fileURLToPath(new URL("../fixtures/", import.meta.url));
const bytes = (name) => readFileSync(path.join(FIXTURES, name));
const PATCH =
  '--- a/cors.mjs\n+++ b/cors.mjs\n@@ -1,3 +1,3 @@\n export function allowOrigin(origin) {\n-  return origin;\n+  return origin === "https://example.com" ? origin : null;\n }\n';

export function fixtureStudy() {
  const task = {
    kind: "repair",
    surface: "code",
    category: "security",
    prompt: "Reject untrusted CORS origins without breaking the configured allowed origin.",
    requirements: "Only https://example.com may be reflected; other origins return null.",
    provenance: "Owned synthetic harness fixture, not a real repository or measured agent task.",
    holdout: false,
    sourceSha256: digest(bytes("cors-before.mjs")),
    referenceSha256: digest(bytes("cors-after.mjs")),
    graderSha256: digest(Buffer.concat([bytes("acceptance.mjs"), bytes("regressions.mjs")])),
    reportSha256: digest("Synthetic report: origin reflection"),
    baseline: { acceptancePass: false, regressionsPass: true },
    reference: { acceptancePass: true, regressionsPass: true },
    validatedBy: "fixture checks",
  };
  return {
    schemaVersion: 1,
    id: "workflow-fixture",
    phase: "fixture",
    seed: 42,
    repeats: 1,
    arms: ["normal", "report", "mcp"],
    protocol: "agent-workflow-v1-fixture",
    protocolSha256: digest("Synthetic workflow demonstration, not study evidence"),
    limits: {
      trialSeconds: 60,
      trialTokens: 10000,
      trialCostUsd: 1,
      studyCostUsd: 9,
      submissions: 2,
    },
    sitecmd: {
      version: "fixture",
      commit: "0".repeat(40),
      dirty: true,
      mcpSha256: digest("fixture-only"),
    },
    configurations: [
      {
        id: "fixture",
        agent: "none",
        agentVersion: "fixture",
        model: "no-model",
        reasoning: "none",
        environment: "owned local fixtures",
      },
    ],
    tasks: [
      { ...task, id: "repair-a", repository: "fixture-a" },
      { ...task, id: "repair-b", repository: "fixture-b" },
      {
        ...task,
        id: "negative-a",
        repository: "fixture-a",
        kind: "negative_control",
        sourceSha256: task.referenceSha256,
        baseline: { acceptancePass: true, regressionsPass: true },
      },
    ],
  };
}

export function fixtureRecord(plan, assignment) {
  const task = plan.study.tasks.find((item) => item.id === assignment.task);
  const patch = task.kind === "negative_control" ? "" : PATCH;
  const patchSha256 = digest(patch);
  const subscription = plan.study.billing?.mode === "subscription";
  return {
    schemaVersion: 1,
    trialId: assignment.id,
    studySha256: plan.studySha256,
    fixture: plan.study.phase === "fixture",
    status: "completed",
    elapsedMs: 1000,
    humanActiveMs: null,
    setup: "warm",
    agentVersion: "fixture",
    model: "no-model",
    transcript: "transcript.txt",
    usage: {
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 30,
      cacheWriteTokens: 0,
      includesAllAgents: true,
      costUsd: subscription ? null : 0.001,
      costBasis: subscription ? "subscription" : "estimated",
      ...(subscription ? { incrementalCostUsd: 0, apiEquivalentCostUsd: null } : {}),
      receipt: "usage.json",
    },
    submissions: [
      {
        patch: "patch.diff",
        patchSha256,
        elapsedMs: 900,
        graderSha256: task.graderSha256,
        acceptancePass: true,
        regressionsPass: true,
        integrityPass: true,
        receipt: "grade.json",
      },
    ],
    reviews: [
      {
        patchSha256,
        reviewer: "synthetic-reviewer",
        blinded: true,
        decision: "accept",
        reason: "Synthetic acceptance for harness testing only",
        receipt: "review.json",
      },
    ],
    ...(assignment.arm === "mcp"
      ? { mcp: { serverSha256: plan.study.sitecmd.mcpSha256, trace: "mcp.jsonl" } }
      : {}),
  };
}

function runCheck(check, candidate) {
  const result = spawnSync(
    process.execPath,
    [path.join(FIXTURES, check), path.join(FIXTURES, candidate)],
    {
      encoding: "utf8",
      timeout: 10000,
      maxBuffer: 1024 * 1024,
      env: {},
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  return {
    status: result.status,
    log: `${result.stdout ?? ""}${result.stderr ?? ""}${result.error?.message ?? ""}`,
  };
}

export function writeFixtureEvidence(directory, plan, assignment, checks) {
  mkdirSync(directory, { mode: 0o700 });
  const record = fixtureRecord(plan, assignment);
  const task = plan.study.tasks.find((item) => item.id === assignment.task);
  const { receipt: usageReceipt, ...usage } = record.usage;
  const { receipt: reviewReceipt, ...review } = record.reviews[0];
  const write = (name, value) =>
    writeFileSync(path.join(directory, name), value, { flag: "wx", mode: 0o600 });
  write("patch.diff", task.kind === "negative_control" ? "" : PATCH);
  write(
    "transcript.txt",
    "SYNTHETIC FIXTURE: no agent or SiteCMD MCP server was invoked. All timing and usage values are fabricated test inputs.\n",
  );
  write("mcp.jsonl", '{"fixture":true,"realMcpServer":false}\n');
  write("raw-usage.json", JSON.stringify({ fixture: true, ...usage }));
  write("acceptance.log", checks.acceptance.log);
  write("regressions.log", checks.regressions.log);
  writeNewJson(path.join(directory, usageReceipt), {
    usage,
    raw: ["raw-usage.json"],
    accountant: "fixture",
    method: "Synthetic inputs, not model usage",
  });
  writeNewJson(path.join(directory, reviewReceipt), review);
  writeNewJson(path.join(directory, "grade.json"), {
    trialId: record.trialId,
    studySha256: plan.studySha256,
    sourceSha256: task.sourceSha256,
    patchSha256: record.submissions[0].patchSha256,
    graderSha256: task.graderSha256,
    executor: "owned fixture checks",
    environment: process.version,
    acceptance: [
      {
        command: "node acceptance.mjs cors-after.mjs",
        exitCode: checks.acceptance.status,
        log: "acceptance.log",
      },
    ],
    regressions: [
      {
        command: "node regressions.mjs cors-after.mjs",
        exitCode: checks.regressions.status,
        log: "regressions.log",
      },
    ],
    integrity: {
      passed: true,
      reason: "Owned fixture with fixed test inputs; no untrusted patch execution",
    },
  });
  writeNewJson(path.join(directory, "trial.json"), record);
  return path.join(directory, "trial.json");
}

export function runFixture(directory) {
  const baseline = runCheck("acceptance.mjs", "cors-before.mjs");
  const baselineRegression = runCheck("regressions.mjs", "cors-before.mjs");
  const checks = {
    acceptance: runCheck("acceptance.mjs", "cors-after.mjs"),
    regressions: runCheck("regressions.mjs", "cors-after.mjs"),
  };
  if (
    baseline.status === null ||
    baseline.status === 0 ||
    baselineRegression.status !== 0 ||
    checks.acceptance.status !== 0 ||
    checks.regressions.status !== 0
  ) {
    throw new Error("Owned fixture failed baseline/reference validation");
  }
  const plan = createStudyRun(fixtureStudy(), directory);
  mkdirSync(path.join(directory, "inputs"), { mode: 0o700 });
  writeNewJson(path.join(directory, "fixture-validation.json"), {
    baseline,
    baselineRegression,
    checks,
  });
  for (const assignment of plan.assignments) {
    const input = writeFixtureEvidence(
      path.join(directory, "inputs", assignment.id),
      plan,
      assignment,
      checks,
    );
    importTrial(directory, input);
  }
  return plan;
}
