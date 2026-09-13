import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createEvidence } from "../guest/trial-evidence.mjs";
import { createPlan, digest } from "./workflow-plan.mjs";
import { fixtureStudy } from "./workflow-fixture.mjs";
import { materializeRepositorySnapshot } from "./repository-snapshot.mjs";
import { readCandidate } from "../guest/trial-snapshot.mjs";
import { totalTokens } from "./workflow-usage.mjs";

test("a complete provider receipt survives a failing process exit", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-failed-exit-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const study = fixtureStudy();
  for (const task of study.tasks) task.sourceSha256 = digest({});
  Object.assign(study.configurations[0], { agent: "codex", model: "gpt-6-astra" });
  const plan = createPlan(study);
  const assignment = plan.assignments[0];
  const evidence = createEvidence(root, plan, assignment, { id: assignment.task }, {}, root);
  writeFileSync(
    path.join(root, "transcript.jsonl"),
    [
      { type: "thread.started", thread_id: "thread-1" },
      { type: "turn.started" },
      {
        type: "turn.completed",
        usage: { input_tokens: 100, cached_input_tokens: 60, output_tokens: 20 },
      },
    ]
      .map((event) => JSON.stringify(event))
      .join("\n"),
  );
  const record = evidence.finish({
    status: "agent_error",
    failure: "Agent exit 1",
    elapsedMs: 1,
    configuration: study.configurations[0],
    quotaAllowed: true,
    evidenceComplete: true,
    providerCompleted: false,
  });
  assert.equal(record.status, "agent_error");
  assert.equal(record.failure, "Agent exit 1");
  assert.equal(totalTokens(record.usage), 120);
  assert.equal(record.modelSelection.verified, true);
});

test("Linkding evidence rejects runtime receipts that differ from the registration", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-runtime-evidence-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repositoryRuntime = { fixture: "Python runtime" };
  const browserRuntime = { fixture: "browser runtime" };
  const study = fixtureStudy();
  study.tasks = [
    {
      ...study.tasks[0],
      id: "linkding-asset-sandbox",
      sourceSha256: digest({}),
      runtimeSha256: digest(repositoryRuntime),
      browserRuntimeSha256: digest(browserRuntime),
    },
  ];
  const plan = createPlan(study);
  for (const changes of [
    { repositoryRuntime: undefined },
    { browserRuntime: undefined },
    { repositoryRuntime: { changed: true } },
    { browserRuntime: { changed: true } },
  ])
    assert.throws(
      () =>
        createEvidence(
          root,
          plan,
          plan.assignments[0],
          { id: "linkding-asset-sandbox", repositoryRuntime, browserRuntime, ...changes },
          {},
          root,
        ),
      /runtime.*registration/i,
    );
});

test("Linkding evidence preserves both registered runtime receipts for export", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-runtime-export-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repositoryRuntime = { fixture: "Python runtime" };
  const browserRuntime = { fixture: "browser runtime" };
  const study = fixtureStudy();
  study.tasks = [
    {
      ...study.tasks[0],
      id: "linkding-asset-sandbox",
      sourceSha256: digest({}),
      runtimeSha256: digest(repositoryRuntime),
      browserRuntimeSha256: digest(browserRuntime),
    },
  ];
  const plan = createPlan(study);
  const evidence = createEvidence(
    root,
    plan,
    plan.assignments[0],
    { id: "linkding-asset-sandbox", repositoryRuntime, browserRuntime },
    {},
    root,
  );
  writeFileSync(path.join(root, "transcript.jsonl"), "No model calls\n");
  evidence.finish({
    status: "completed",
    elapsedMs: 0,
    configuration: study.configurations[0],
    quotaAllowed: true,
    agentInvoked: false,
  });
  const usage = JSON.parse(readFileSync(path.join(root, "usage.json")));
  for (const [file, receipt] of [
    ["repository-runtime.json", repositoryRuntime],
    ["browser-runtime.json", browserRuntime],
  ]) {
    assert.ok(usage.raw.includes(file));
    assert.deepEqual(JSON.parse(readFileSync(path.join(root, file))), receipt);
  }
});

test("Whoogle evidence preserves its registered repository runtime", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-whoogle-runtime-export-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repositoryRuntime = { fixture: "Whoogle Python runtime" };
  const study = fixtureStudy();
  study.tasks = [
    {
      ...study.tasks[0],
      id: "whoogle-named-config-path",
      sourceSha256: digest({}),
      runtimeSha256: digest(repositoryRuntime),
    },
  ];
  const plan = createPlan(study);
  const evidence = createEvidence(
    root,
    plan,
    plan.assignments[0],
    { id: "whoogle-named-config-path", repositoryRuntime },
    {},
    root,
  );
  writeFileSync(path.join(root, "transcript.jsonl"), "No model calls\n");
  evidence.finish({
    status: "completed",
    elapsedMs: 0,
    configuration: study.configurations[0],
    quotaAllowed: true,
    agentInvoked: false,
  });
  const usage = JSON.parse(readFileSync(path.join(root, "usage.json")));
  assert.ok(usage.raw.includes("repository-runtime.json"));
  assert.deepEqual(
    JSON.parse(readFileSync(path.join(root, "repository-runtime.json"))),
    repositoryRuntime,
  );
});

test("deferred candidates count only when accepted and rejected captures remain preserved", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-capture-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const workspace = path.join(root, "workspace");
  mkdirSync(workspace);
  writeFileSync(path.join(workspace, "README.md"), "Changed protected contract");
  const study = fixtureStudy();
  for (const task of study.tasks) task.sourceSha256 = digest({ "README.md": "Original" });
  const plan = createPlan(study);
  const assignment = plan.assignments[0];
  const directory = path.join(root, "evidence");
  const evidence = createEvidence(
    directory,
    plan,
    assignment,
    { id: assignment.task },
    { "README.md": "Original" },
    workspace,
  );
  const first = evidence.submit("First", 1, 1, { defer: true });
  assert.equal(evidence.submissions.length, 0);
  first.commit();
  first.commit();
  assert.equal(evidence.submissions.length, 1);
  evidence.submit("Rejected by MCP", 2, 2, { defer: true });
  assert.equal(evidence.submissions.length, 1);
  evidence.submit("Third", 3, 3, { defer: true }).commit();
  assert.deepEqual(
    evidence.submissions.map((row) => row.patch),
    ["submission-1.diff", "submission-3.diff"],
  );
  assert.equal(existsSync(path.join(directory, "submission-2.diff")), true);
  assert.deepEqual([...evidence.attempts], [1, 3]);
});

test("finished trials derive model identity from the preserved transcript", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-identity-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const study = fixtureStudy();
  for (const task of study.tasks) task.sourceSha256 = digest({});
  Object.assign(study.configurations[0], { agent: "claude", model: "claude-opus-5" });
  const plan = createPlan(study);
  const assignment = plan.assignments[0];
  const evidence = createEvidence(root, plan, assignment, { id: assignment.task }, {}, root);
  writeFileSync(
    path.join(root, "transcript.jsonl"),
    [
      { type: "assistant", message: { id: "message-1", model: "claude-opus-5" } },
      { type: "result", subtype: "success", is_error: false },
    ]
      .map((event) => JSON.stringify(event))
      .join("\n"),
  );
  const record = evidence.finish({
    status: "completed",
    elapsedMs: 1,
    configuration: study.configurations[0],
    quotaAllowed: true,
    observedModels: ["do-not-trust-a-caller-supplied-model"],
  });
  assert.equal(record.model, "claude-opus-5");
  assert.equal(record.modelSelection.verified, true);
  assert.equal(record.modelSelection.receipt, "model-identity.json");
  const receipt = JSON.parse(readFileSync(path.join(root, record.modelSelection.receipt)));
  assert.deepEqual(receipt.observed, ["claude-opus-5"]);
  assert.equal(receipt.observations[0].line, 1);
});

test("repository submissions retain source and modes while rejecting protected-file edits", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-repository-evidence-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const content = {
    schemaVersion: 1,
    commit: "1".repeat(40),
    tree: "2".repeat(40),
    files: [
      { name: "src/handler.py", mode: "100644", base64: Buffer.from("source").toString("base64") },
      { name: ".github/test.yml", mode: "100644", base64: Buffer.from("tests").toString("base64") },
      { name: "run.sh", mode: "100755", base64: Buffer.from("exit 0\n").toString("base64") },
    ],
  };
  const source = { ...content, sha256: digest(content) };
  const workspace = path.join(root, "workspace");
  materializeRepositorySnapshot(source, workspace);
  const study = fixtureStudy();
  study.tasks = [
    {
      ...study.tasks[0],
      sourceFormat: "git-tree-v1",
      sourceSha256: source.sha256,
      editableFiles: ["src/handler.py"],
    },
  ];
  const plan = createPlan(study);
  const assignment = plan.assignments[0];
  const directory = path.join(root, "evidence");
  const evidence = createEvidence(
    directory,
    plan,
    assignment,
    { id: assignment.task },
    source,
    workspace,
  );
  writeFileSync(path.join(workspace, ".github/test.yml"), "weakened tests");
  const submission = evidence.submit("Disallowed test edit", 1);
  assert.equal(submission.integrity.passed, false);
  assert.deepEqual(JSON.parse(readFileSync(path.join(directory, "source.json"))), source);
  const captured = JSON.parse(readFileSync(path.join(directory, "submission-1-candidate.json")));
  assert.equal(captured.modes["run.sh"], "100755");
  assert.equal(evidence.submissions[0].snapshotSha256, digest(captured));
  assert.equal(submission.snapshotSha256, evidence.snapshotIdentity(readCandidate(workspace)));
  chmodSync(path.join(workspace, "run.sh"), 0o644);
  assert.notEqual(submission.snapshotSha256, evidence.snapshotIdentity(readCandidate(workspace)));
});
