import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { digest } from "../lib/workflow-plan.mjs";
import { writeNewJson } from "../lib/workflow-store.mjs";
import { trialUsage } from "../lib/workflow-trial-usage.mjs";
import { summarizeModelIdentity } from "../lib/workflow-model-identity.mjs";
import { loadTrialSource } from "../lib/trial-source.mjs";
import { gradeCase } from "./calibration-grader.mjs";
import { gradeRepository } from "./repository-grader.mjs";
import {
  candidateIdentity,
  candidatePatch,
  candidateRecord,
  compareCandidate,
  readCandidate,
} from "./trial-snapshot.mjs";
import {
  captureRuntimeFiles,
  prepareRuntimeFiles,
  withoutRuntimeFiles,
} from "./trial-runtime-files.mjs";

export function createEvidence(directory, plan, assignment, item, source, workspace) {
  const task = plan.study.tasks.find((task) => task.id === item.id);
  const { files, modes, editableFiles } = loadTrialSource(source, task);
  const grader = task.sourceFormat ? "gradeRepository" : "gradeCase";
  const runtimes = [
    ["runtimeSha256", "repositoryRuntime", "repository-runtime.json"],
    ["browserRuntimeSha256", "browserRuntime", "browser-runtime.json"],
  ].filter(([field, input]) => task[field] !== undefined || item[input] !== undefined);
  for (const [field, input] of runtimes)
    if (!item[input] || task[field] !== digest(item[input]))
      throw new Error("Repository runtime differs from its registration");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (task.sourceFormat) writeNewJson(path.join(directory, "source.json"), source);
  for (const [, input, file] of runtimes) writeNewJson(path.join(directory, file), item[input]);
  const submissions = [];
  const attempts = new Set();
  let runtimeFiles = [];
  let writeStaging;
  let captures = 0;
  const captureArtifacts = [];
  const log = (name, value) =>
    appendFileSync(path.join(directory, name), `${JSON.stringify(value)}\n`, { mode: 0o600 });
  const initialized = () => {
    writeStaging = prepareRuntimeFiles(workspace, files, { writeStaging: true });
    runtimeFiles = captureRuntimeFiles(files, readCandidate(workspace), modes);
    writeNewJson(path.join(directory, "runtime-files.json"), {
      capturedAt: new Date().toISOString(),
      stage:
        plan.study.phase === "fixture"
          ? "Synthetic runtime preparation; no model client initialized"
          : "Client initialized before first user prompt",
      emptyProtectionFiles: runtimeFiles,
      writeStaging: writeStaging.receipt,
    });
  };
  const normalize = (snapshot) => ({
    ...snapshot,
    files: withoutRuntimeFiles(snapshot.files, runtimeFiles, snapshot.modes),
  });
  const submit = (summary, elapsedMs, attemptId, { defer = false } = {}) => {
    writeStaging?.verify();
    const index = ++captures;
    const prefix = `submission-${index}`;
    const snapshot = normalize(readCandidate(workspace));
    const options = { originalModes: modes, candidateModes: snapshot.modes, editableFiles };
    const integrity = compareCandidate(files, snapshot.files, snapshot.violations, options);
    const staging = path.join(directory, prefix);
    const patch = candidatePatch(staging, files, snapshot.files, options);
    const patchSha256 = digest(patch);
    const snapshotSha256 = candidateIdentity(snapshot);
    writeNewJson(path.join(directory, `${prefix}-candidate.json`), candidateRecord(snapshot));
    writeFileSync(path.join(directory, `${prefix}.diff`), patch, { flag: "wx", mode: 0o600 });
    const grade = integrity.passed
      ? task.sourceFormat
        ? gradeRepository(item, path.join(staging, "candidate"))
        : gradeCase(item, path.join(staging, "candidate"))
      : { acceptancePass: false, regressionsPass: false, skipped: integrity.reason };
    writeNewJson(path.join(directory, `${prefix}-checks.json`), { ...grade, integrity, summary });
    const receipt = {
      trialId: assignment.id,
      studySha256: plan.studySha256,
      sourceSha256: task.sourceSha256,
      patchSha256,
      snapshotSha256,
      graderSha256: task.graderSha256,
      executor: "Independent guest behavioral assertions",
      environment: plan.study.configurations[0].environment,
      acceptance: [
        {
          command: `${grader} acceptance assertions`,
          exitCode: integrity.passed ? (grade.acceptancePass ? 0 : 1) : null,
          log: `${prefix}-checks.json`,
        },
      ],
      regressions: [
        {
          command: `${grader} regression assertions and existing project tests`,
          exitCode: integrity.passed ? (grade.regressionsPass ? 0 : 1) : null,
          log: `${prefix}-checks.json`,
        },
      ],
      integrity,
    };
    writeNewJson(path.join(directory, `${prefix}-grade.json`), receipt);
    const submission = {
      patch: `${prefix}.diff`,
      patchSha256,
      candidate: `${prefix}-candidate.json`,
      snapshotSha256,
      elapsedMs,
      graderSha256: task.graderSha256,
      acceptancePass: grade.acceptancePass,
      regressionsPass: grade.regressionsPass,
      integrityPass: integrity.passed,
      receipt: `${prefix}-grade.json`,
    };
    captureArtifacts.push(
      `${prefix}.diff`,
      `${prefix}-checks.json`,
      `${prefix}-grade.json`,
      `${prefix}-candidate.json`,
    );
    let committed = false;
    const commit = () => {
      if (committed) return;
      committed = true;
      submissions.push(submission);
      if (attemptId) attempts.add(attemptId);
    };
    if (!defer) commit();
    return {
      commit,
      integrity,
      snapshotSha256,
    };
  };
  const finish = ({
    status,
    failure,
    elapsedMs,
    configuration,
    quotaAllowed,
    agentInvoked = true,
    evidenceComplete = true,
  }) => {
    const raw = readFileSync(path.join(directory, "transcript.jsonl"), "utf8");
    const identity = summarizeModelIdentity(
      configuration.agent,
      configuration.model,
      raw,
      evidenceComplete,
    );
    const observedModels = agentInvoked ? identity.observed : [];
    if (agentInvoked) writeNewJson(path.join(directory, "model-identity.json"), identity);
    const usage = trialUsage(configuration.agent, raw, { agentInvoked, evidenceComplete });
    const { receipt, ...counts } = usage;
    writeNewJson(path.join(directory, receipt), {
      usage: counts,
      accountant: agentInvoked ? "Pinned CLI event normalizer" : "Guest setup controller",
      method:
        plan.study.phase === "fixture"
          ? "Synthetic provider-shaped events from an owned test process; not inference or spending evidence."
          : agentInvoked
            ? "Terminal provider receipts; delegated tools disabled. Process errors retain valid receipts; incomplete or truncated usage remains unknown. Additional charges require billing review."
            : "Setup failed before launching a model client; no inference calls or additional charges occurred.",
      raw: [
        "transcript.jsonl",
        "stderr.log",
        "configuration.json",
        "quota-events.jsonl",
        "quota-baseline.json",
        "quota-current.json",
        ...(existsSync(path.join(directory, "controller-amendment.json"))
          ? ["controller-amendment.json"]
          : []),
        ...(task.sourceFormat ? ["source.json"] : []),
        ...runtimes.map(([, , file]) => file),
        ...(agentInvoked ? ["prompt.txt", "final-candidate.json"] : []),
        ...(existsSync(path.join(directory, "runtime-files.json")) ? ["runtime-files.json"] : []),
        ...(assignment.arm === "mcp" ? ["mcp.jsonl"] : []),
        ...captureArtifacts,
      ],
    });
    const record = {
      schemaVersion: 1,
      trialId: assignment.id,
      studySha256: plan.studySha256,
      fixture: plan.study.phase === "fixture",
      agentInvoked,
      status: quotaAllowed ? status : "infrastructure_error",
      ...(status !== "completed" || !quotaAllowed
        ? { failure: failure || "Quota evidence failed after the trial; batch paused" }
        : {}),
      elapsedMs,
      humanActiveMs: null,
      setup: "warm",
      agentVersion: configuration.agentVersion,
      model: agentInvoked && observedModels.length === 1 ? observedModels[0] : null,
      ...(agentInvoked
        ? {
            modelSelection: {
              requested: configuration.model,
              observed: observedModels,
              source: "explicit-cli-request",
              receipt: "model-identity.json",
              assurance: identity.assurance,
              verified: identity.verified,
            },
          }
        : {}),
      transcript: "transcript.jsonl",
      submissions,
      reviews: [],
      usage,
      ...(assignment.arm === "mcp"
        ? { mcp: { serverSha256: plan.study.sitecmd.mcpSha256, trace: "mcp.jsonl" } }
        : {}),
    };
    writeNewJson(path.join(directory, "trial.json"), record);
    return record;
  };
  return {
    submissions,
    attempts,
    submit,
    log,
    finish,
    initialized,
    normalize,
    snapshotIdentity: (snapshot) => candidateIdentity(normalize(snapshot)),
  };
}
