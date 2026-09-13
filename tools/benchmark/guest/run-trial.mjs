import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { digest, validatePlan } from "../lib/workflow-plan.mjs";
import { probeAgentAccounts } from "../lib/workflow-preflight.mjs";
import { evaluateQuota } from "../lib/workflow-quota.mjs";
import { writeNewJson } from "../lib/workflow-store.mjs";
import { loadTrialSource } from "../lib/trial-source.mjs";
import { trialPrompt } from "../lib/trial-prompt.mjs";
import { buildTrialItem } from "../lib/trial-item.mjs";
import { agentVersions, trialInvocation } from "../lib/trial-invocation.mjs";
import { createTrialBridge } from "./trial-bridge.mjs";
import { startDesktop, systemCommand } from "./desktop-session.mjs";
import { openMcp } from "./mcp-session.mjs";
import {
  createWorkspace,
  mountDesktopWorkspace,
  closeWorkspace,
  protectPreviousWorkspaces,
} from "./trial-workspace.mjs";
import { verifyControlIsolation } from "./trial-isolation.mjs";
import { createEvidence } from "./trial-evidence.mjs";
import { launchAgent } from "./trial-supervisor.mjs";
import { prepareProject, trialUrl } from "./trial-setup.mjs";
import { canRequestVerification, readFix, observeVerification } from "./product-observation.mjs";
import { candidateRecord, readCandidate } from "./trial-snapshot.mjs";
import { closingQuota } from "./closing-quota.mjs";
import { verifyWhoogleRuntime } from "./whoogle-runtime.mjs";
import { prepareRepositoryAgentRuntime } from "./repository-agent-runtime.mjs";
import { verifyOnekeyRuntime } from "./replacement-onekey-runtime.mjs";
import { verifyFmdBrowserRuntime } from "./replacement-fmd-runtime.mjs";

if (process.platform !== "linux" || process.getuid() !== 0)
  throw new Error("Guest controller required");
const input = JSON.parse(readFileSync(0, "utf8"));
const { assignment, item, files: source, product, baseline, current, controllerAmendment } = input;
const plan = validatePlan(input.plan);
const controllerSha256 = import.meta.url.match(
  /\/controllers\/([a-f0-9]{64})\/guest\/run-trial\.mjs$/,
)?.[1];
if (controllerAmendment) {
  if (
    controllerAmendment.studySha256 !== plan.studySha256 ||
    controllerAmendment.correctedRunnerSha256 !== controllerSha256
  )
    throw new Error("Controller amendment differs from the installed runner");
} else if (controllerSha256 !== plan.study.runnerSha256)
  throw new Error("Installed runner differs from the frozen study");
if (!plan.assignments.some((entry) => digest(entry) === digest(assignment)))
  throw new Error("Unknown assignment");
const task = plan.study.tasks.find((task) => task.id === assignment.task);
buildTrialItem(item, task);
const { files, modes } = loadTrialSource(source, task);
if (item.entry !== task.entry || item.rule !== task.rule)
  throw new Error("Case entry or rule differs from the frozen study");
if (item.id === "whoogle-named-config-path") verifyWhoogleRuntime(item.repositoryRuntime);
if (item.id === "onekey-http-client-tls-verification") verifyOnekeyRuntime(item.repositoryRuntime);
if (item.id === "fmd-device-text") verifyFmdBrowserRuntime(item.browserRuntime);
if (digest(product) !== plan.study.productSha256)
  throw new Error("Product receipt differs from the frozen study");
const configuration = plan.study.configurations.find(
  (entry) => entry.id === assignment.configuration,
);
if (
  configuration.agentVersion !== agentVersions[configuration.agent] ||
  configuration.reasoning !== "high"
)
  throw new Error("Agent configuration differs from the executor");
const accounts = probeAgentAccounts({
  run: (command, args, options) => spawnSync("sudo", ["-u", "runner", command, ...args], options),
});
if (
  !accounts.subscriptionAccountsVerified ||
  accounts.accounts.some((entry) => entry.version !== agentVersions[entry.agent])
)
  throw new Error(
    "Guest subscription logins and pinned client versions must be verified before execution",
  );
const quota = evaluateQuota(baseline, current, plan.study.billing, Date.now(), configuration.agent);
if (!quota.quotaAllowed) throw new Error(quota.blockers.join("; "));
const budgets = "/srv/sitecmd-benchmark/budgets";
mkdirSync(budgets, { recursive: true, mode: 0o700 });
const budgetFile = `${budgets}/${plan.studySha256}.json`;
if (!existsSync(budgetFile)) writeNewJson(budgetFile, baseline);
if (digest(JSON.parse(readFileSync(budgetFile))) !== digest(baseline))
  throw new Error("Study allowance baseline changed");
for (const [file, hash] of [
  [product.binary, product.binarySha256],
  [product.mcp, plan.study.sitecmd.mcpSha256],
  [product.cli, product.cliSha256],
])
  if (digest(readFileSync(file)) !== hash)
    throw new Error("Installed product changed after freezing");
const directory = `/srv/sitecmd-benchmark/trials/${assignment.id}`;
mkdirSync(directory, { recursive: true, mode: 0o700 });
if (controllerAmendment)
  writeNewJson(`${directory}/controller-amendment.json`, controllerAmendment);
writeNewJson(`${directory}/quota-baseline.json`, baseline);
writeNewJson(`${directory}/quota-current.json`, current);
const workspace = `/srv/sitecmd-benchmark/workspaces/${assignment.id}`;
const evidence = createEvidence(directory, plan, assignment, item, source, workspace);
let desktop, bridge, mcp, agent, mounted;
let workspaceCreated = false;
let result;
let finalSnapshot;
let agentInvoked = false;
let setupStage = "environment";
const channel = `/run/sitecmd-benchmark/${assignment.id}`;
const assertNotCancelled = () => {
  if (existsSync(`/run/sitecmd-benchmark-cancel-${assignment.id}`))
    throw new Error("Trial cancelled by the operator");
};
const publicTools = "/usr/local/lib/sitecmd-benchmark";
try {
  assertNotCancelled();
  createWorkspace(assignment.id, files, modes);
  workspaceCreated = true;
  protectPreviousWorkspaces(workspace);
  mounted = mountDesktopWorkspace(assignment.id, workspace);
  desktop = await startDesktop(assignment.id, product.binary);
  verifyControlIsolation();
  setupStage = "product";
  const prepared = await prepareProject(
    desktop,
    mounted,
    item,
    product,
    configuration,
    assignment.arm,
    evidence.log,
  );
  setupStage = "environment";
  mkdirSync("/run/sitecmd-benchmark", { recursive: true, mode: 0o755 });
  mkdirSync(publicTools, { recursive: true, mode: 0o755 });
  for (const name of ["bridge-files.mjs", "bridge-client.mjs", "mcp-proxy.mjs", "submit.mjs"])
    copyFileSync(new URL(`./${name}`, import.meta.url), path.join(publicTools, name));
  mcp =
    assignment.arm === "mcp"
      ? openMcp(product.mcp, desktop.database, (event) => evidence.log("mcp.jsonl", event))
      : null;
  const owner = {
    uid: Number(systemCommand("id", ["-u", "runner"])),
    gid: Number(systemCommand("id", ["-g", "runner"])),
  };
  bridge = await createTrialBridge({
    channel,
    arm: assignment.arm,
    mcp,
    canVerify: (attemptId) =>
      canRequestVerification(desktop.database, attemptId, prepared.projectId),
    onError: (error) => agent?.stop(error.message),
    owner,
    submit: async (summary, kind, attemptId) => {
      if (!agent || typeof summary !== "string" || !summary.trim() || summary.length > 2000)
        throw new Error("A concise submission summary is required");
      if (evidence.submissions.length >= plan.study.limits.submissions) {
        agent.stop("Submission limit reached", "agent_error");
        throw new Error("Submission limit reached");
      }
      if (assignment.arm === "mcp" && item.kind === "repair" && kind !== "verification")
        throw new Error("Submit repairs through SiteCMD request_verification");
      if (
        kind === "verification" &&
        (!Number.isSafeInteger(attemptId) ||
          readFix(desktop.database, attemptId)?.project_id !== prepared.projectId)
      )
        throw new Error("Verification must refer to this trial's project");
      try {
        agent.quota();
      } catch (error) {
        agent.stop(error.message);
        throw error;
      }
      agent.freeze();
      let captured;
      const commit = () => {
        captured.commit();
        finalSnapshot = captured.snapshotSha256;
      };
      try {
        captured = evidence.submit(summary, agent.elapsed(), attemptId, {
          defer: kind === "verification",
        });
        if (!captured.integrity.passed) {
          commit();
          agent.stop(captured.integrity.reason, "agent_error");
          throw new Error(captured.integrity.reason);
        }
        if (kind !== "verification") commit();
      } catch (error) {
        agent.stop(error.message);
        throw error;
      } finally {
        agent.thaw();
      }
      if (kind === "verification")
        return {
          commit,
          uncertain: (error) => agent.stop(`Verification response unavailable: ${error.message}`),
        };
      return {
        recorded: evidence.submissions.length,
        remaining: plan.study.limits.submissions - evidence.submissions.length,
        message:
          "Candidate recorded. Independent grading feedback is withheld until the trial ends.",
      };
    },
  });
  const agentRuntime = prepareRepositoryAgentRuntime({ item, workspace, channel, owner });
  const invocation = trialInvocation({
    agent: configuration.agent,
    model: configuration.model,
    arm: assignment.arm,
    workspace,
    channel,
    proxy: `${publicTools}/mcp-proxy.mjs`,
    repositoryRuntime: agentRuntime ? item.repositoryRuntime : undefined,
  });
  writeNewJson(`${directory}/configuration.json`, { configuration, invocation, accounts });
  const prompt = trialPrompt({
    task,
    arm: assignment.arm,
    workspace,
    channel,
    publicTools,
    projectId: prepared.projectId,
    url: trialUrl,
    handoff: prepared.handoff,
    report: input.report,
    repositoryRuntime: Boolean(agentRuntime),
  });
  writeFileSync(`${directory}/prompt.txt`, prompt, { flag: "wx", mode: 0o600 });
  assertNotCancelled();
  agent = launchAgent({
    id: assignment.id,
    invocation,
    workspace,
    prompt,
    directory,
    plan,
    baseline,
    currentQuota: `${directory}/quota-current.json`,
    requestedModel: configuration.model,
    provider: configuration.agent,
    log: evidence.log,
    initialized: evidence.initialized,
  });
  agentInvoked = true;
  result = await agent.done;
  const final = readCandidate(workspace);
  writeNewJson(`${directory}/final-candidate.json`, candidateRecord(final));
  const finalHash = evidence.snapshotIdentity(final);
  if (!evidence.submissions.length || finalHash !== finalSnapshot || final.violations.length)
    result = {
      ...result,
      status: result.status === "completed" ? "agent_error" : result.status,
      failure: [
        result.failure,
        "No final submission, or unsubmitted changes remained after the final candidate",
      ]
        .filter(Boolean)
        .join("; "),
    };
  if (mcp)
    for (const attempt of evidence.attempts) {
      const remaining = Math.max(0, plan.study.limits.trialSeconds * 1000 - agent.elapsed());
      const observed = await observeVerification(
        desktop.database,
        attempt,
        mcp,
        evidence.log,
        Date.now() + Math.min(120000, remaining),
      );
      if (!observed || ["briefed", "verify_requested", "verifying"].includes(observed.status))
        result = {
          ...result,
          status: "product_error",
          failure: "Desktop verification did not reach a terminal state",
        };
    }
  result.elapsedMs = agent.elapsed();
  if (result.elapsedMs > plan.study.limits.trialSeconds * 1000)
    result = {
      ...result,
      status: "timeout",
      failure: "Trial deadline reached before final verification completed",
    };
} catch (error) {
  agent?.stop(error.message);
  const stopped = agent ? await agent.done : {};
  result = {
    ...stopped,
    status:
      !agentInvoked &&
      setupStage === "product" &&
      !existsSync(`/run/sitecmd-benchmark-cancel-${assignment.id}`)
        ? "product_error"
        : "infrastructure_error",
    failure: error.message,
    elapsedMs: agent?.elapsed() ?? 0,
  };
} finally {
  for (const cleanup of [
    () => bridge?.close(),
    () => mcp?.close(),
    () => desktop?.close(),
    () => mounted?.close(),
    () => workspaceCreated && closeWorkspace(workspace),
  ]) {
    try {
      await cleanup();
    } catch (error) {
      result = {
        ...result,
        status: "infrastructure_error",
        failure: `${result?.failure ?? ""}; cleanup: ${error.message}`,
      };
    }
  }
}
let quotaAllowed;
let quotaFailure;
try {
  if (agentInvoked) {
    const endedAt = Date.now();
    console.error(
      "The agent has stopped. Refresh quota-current.json with new readings from both providers now; waiting up to five minutes before export.",
    );
    const closing = await closingQuota({
      baseline,
      currentPath: `${directory}/quota-current.json`,
      billing: plan.study.billing,
      provider: configuration.agent,
      endedAt,
      log: evidence.log,
    });
    quotaAllowed = closing.quotaAllowed;
    quotaFailure = closing.blockers.join("; ");
  } else
    quotaAllowed = evaluateQuota(
      baseline,
      JSON.parse(readFileSync(`${directory}/quota-current.json`)),
      plan.study.billing,
      Date.now(),
      configuration.agent,
    ).quotaAllowed;
} catch {
  quotaAllowed = false;
}
if (!agentInvoked) {
  for (const name of [
    "transcript.jsonl",
    "stderr.log",
    "quota-events.jsonl",
    ...(assignment.arm === "mcp" ? ["mcp.jsonl"] : []),
  ])
    // Recording untrusted agent output is what this harness is for. The bytes
    // land in a per-trial directory inside the disposable VM at mode 0600, and
    // the grader reads them back as data, never as code.
    // codeql-allow: js/http-to-file-access
    writeFileSync(
      `${directory}/${name}`,
      `${JSON.stringify({ agentInvoked: false, failure: result.failure })}\n`,
      { flag: "a", mode: 0o600 },
    );
  if (!existsSync(`${directory}/configuration.json`))
    writeNewJson(`${directory}/configuration.json`, {
      configuration,
      accounts,
      agentInvoked: false,
    });
} else if (!existsSync(`${directory}/final-candidate.json`)) {
  writeNewJson(`${directory}/final-candidate.json`, { unavailable: result.failure });
}
const record = evidence.finish({
  ...result,
  failure: [result.failure, quotaFailure].filter(Boolean).join("; ") || null,
  configuration,
  quotaAllowed,
  agentInvoked,
});
console.log(JSON.stringify({ directory, record }));
