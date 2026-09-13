import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { writeNewJson } from "../lib/workflow-store.mjs";
import { collectEvidence } from "../lib/workflow-artifacts.mjs";
import { loadTrialSource } from "../lib/trial-source.mjs";
import { createEvidence } from "./trial-evidence.mjs";
import { launchAgent } from "./trial-supervisor.mjs";
import { createTrialBridge } from "./trial-bridge.mjs";
import { createWorkspace, closeWorkspace } from "./trial-workspace.mjs";
import { candidateRecord, readCandidate } from "./trial-snapshot.mjs";
import { systemCommand } from "./desktop-session.mjs";

const {
  plan,
  assignment,
  item,
  files: source,
  reference,
  mode,
  executable,
  protectedFile,
} = JSON.parse(readFileSync(0, "utf8"));
if (plan.study.phase !== "fixture" || !["repair", "timeout", "repository"].includes(mode))
  throw new Error("Executor self-tests require an explicitly synthetic fixture study");
const task = plan.study.tasks.find((task) => task.id === item.id);
const { files, modes } = loadTrialSource(source, task);
if (mode === "repository") {
  assert.equal(modes[executable], "100755");
  assert.equal(Object.hasOwn(files, protectedFile), true);
  assert.equal(task.editableFiles.includes(protectedFile), false);
}
const directory = `/srv/sitecmd-benchmark/trials/${assignment.id}`;
const workspace = createWorkspace(assignment.id, files, modes);
const evidence = createEvidence(directory, plan, assignment, item, source, workspace);
const capturedAt = Date.now();
const quota = {
  schemaVersion: 1,
  capturedAt: new Date(capturedAt - 120000).toISOString(),
  source: "Synthetic self-test only, not a provider reading or permission for model calls",
  accounts: ["codex", "claude"].map((provider) => ({
    provider,
    account: `${provider}-fixture`,
    authMode: "subscription",
    extraUsageEnabled: false,
    windows: [
      {
        id: "weekly",
        kind: "weekly",
        usedPercent: 0,
        resetsAt: new Date(Date.now() + 86400000).toISOString(),
      },
    ],
  })),
};
quota.accounts[1].windows.push({
  id: "session",
  kind: "session",
  usedPercent: 34,
  resetsAt: new Date(capturedAt - 60000).toISOString(),
});
const currentQuota = structuredClone(quota);
currentQuota.capturedAt = new Date(capturedAt).toISOString();
Object.assign(currentQuota.accounts[1].windows[1], {
  usedPercent: 0,
  resetsAt: null,
  inactive: true,
});
writeNewJson(`${directory}/quota-baseline.json`, quota);
writeNewJson(`${directory}/quota-current.json`, currentQuota);
const configuration = plan.study.configurations[0];
writeNewJson(`${directory}/configuration.json`, {
  fixture: true,
  configuration,
  client: "owned Node script, not an AI agent",
});
writeFileSync(`${directory}/prompt.txt`, "Synthetic executor test; no model call", { mode: 0o600 });
mkdirSync("/run/sitecmd-benchmark", { recursive: true, mode: 0o755 });
const channel = `/run/sitecmd-benchmark/${assignment.id}`;
const publicTools = "/usr/local/lib/sitecmd-benchmark";
mkdirSync(publicTools, { recursive: true, mode: 0o755 });
for (const name of ["bridge-client.mjs", "bridge-files.mjs"])
  copyFileSync(new URL(`./${name}`, import.meta.url), `${publicTools}/${name}`);
let agent, bridge;
try {
  if (mode === "repository") evidence.initialized();
  bridge = await createTrialBridge({
    channel,
    arm: "normal",
    mcp: null,
    onError: (error) => agent?.stop(error.message),
    owner: {
      uid: Number(systemCommand("id", ["-u", "runner"])),
      gid: Number(systemCommand("id", ["-g", "runner"])),
    },
    submit: async (summary) => {
      agent.quota();
      agent.freeze();
      try {
        evidence.submit(summary, agent.elapsed());
      } finally {
        agent.thaw();
      }
      return { recorded: true };
    },
  });
  const script =
    mode === "timeout"
      ? "setInterval(() => {}, 1000)"
      : `
    const fs = require('node:fs');
    const { channel, reference, client, mode, executable, protectedFile, submissionTimeoutMs } = JSON.parse(fs.readFileSync(0, 'utf8'));
    (async () => {
      const {bridgeRequest} = await import(client);
      const submit = summary => bridgeRequest(channel, '/submit', {summary}, {timeoutMs: submissionTimeoutMs});
      console.log(JSON.stringify({type:'thread.started',thread_id:'fixture-thread',synthetic:true}));
      console.log(JSON.stringify({type:'turn.started',model:'fixture-model',synthetic:true}));
      await submit('Scripted baseline, deliberately still broken');
      for (const [name, contents] of Object.entries(reference))
        fs.writeFileSync(name, mode === 'repository' ? Buffer.from(contents, 'base64') : contents);
      await submit('Scripted reference repair');
      if (mode === 'repository') {
        fs.appendFileSync(protectedFile, '\\nIntentional protected-file mutation for the self-test\\n');
        await submit('Deliberately invalid protected-file edit');
        fs.chmodSync(executable, 0o644);
      }
      console.log(JSON.stringify({type:'turn.completed',synthetic:true,usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));
    })().catch(error => {console.error(error); process.exitCode = 1;});
  `;
  agent = launchAgent({
    id: assignment.id,
    workspace,
    directory,
    plan,
    baseline: quota,
    currentQuota: `${directory}/quota-current.json`,
    requestedModel: "fixture-model",
    log: evidence.log,
    prompt: JSON.stringify({
      channel,
      reference,
      mode,
      executable,
      protectedFile,
      submissionTimeoutMs: item.id === "linkding-asset-sandbox" ? 210000 : undefined,
      client: `${publicTools}/bridge-client.mjs`,
    }),
    invocation: {
      command: "node",
      args: ["-e", script],
      env: {},
    },
  });
  let result = await agent.done;
  const final = readCandidate(workspace);
  writeNewJson(`${directory}/final-candidate.json`, candidateRecord(final));
  if (mode === "repository") {
    const last = evidence.submissions.at(-1);
    assert.ok(last, result.failure);
    const captured = JSON.parse(readFileSync(`${directory}/${last.candidate}`));
    assert.deepEqual(candidateRecord(evidence.normalize(final)).files, captured.files);
    assert.notEqual(evidence.snapshotIdentity(final), last.snapshotSha256);
    result = {
      ...result,
      status: "agent_error",
      failure: "Scripted executable-mode edit after the final submission",
    };
  }
  const record = evidence.finish({ ...result, configuration, quotaAllowed: true });
  collectEvidence(record, assignment, plan, directory);
  assert.equal(
    record.status,
    mode === "repository" ? "agent_error" : mode === "repair" ? "completed" : "timeout",
  );
  if (mode !== "timeout") {
    assert.equal(record.submissions.length, mode === "repository" ? 3 : 2);
    assert.equal(record.submissions[0].acceptancePass, false);
    assert.equal(record.submissions[0].regressionsPass, true);
    assert.equal(record.submissions[0].integrityPass, true);
    assert.equal(record.submissions[1].acceptancePass, true);
    assert.equal(record.submissions[1].regressionsPass, true);
    assert.equal(record.submissions[1].integrityPass, true);
    if (mode === "repository") {
      assert.equal(record.submissions[2].integrityPass, false);
      const checks = JSON.parse(readFileSync(`${directory}/submission-3-checks.json`));
      assert.match(checks.skipped, /Outside the registered edit scope/);
    }
  } else assert.equal(record.usage.includesAllAgents, false);
  console.log(JSON.stringify({ fixture: true, mode, status: record.status, passed: true }));
} finally {
  agent?.stop("Self-test teardown");
  if (agent) await agent.done;
  try {
    await bridge?.close();
  } finally {
    closeWorkspace(workspace);
  }
}
