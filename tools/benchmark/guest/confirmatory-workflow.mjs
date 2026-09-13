import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { validateConfirmatoryWorkflowCase } from "../lib/confirmatory-workflow.mjs";
import { validateRepositoryConfirmatoryCorpus } from "../lib/repository-corpus.mjs";
import {
  confirmatoryCorpusFilename,
  confirmatoryRegistrationFilename,
  validateRepositoryConfirmatoryRegistration,
} from "../lib/repository-confirmatory-registration.mjs";
import { validateRepositorySnapshot } from "../lib/repository-snapshot.mjs";
import { repositoryScannerTargetIssue } from "../lib/repository-scanner-eligibility.mjs";
import { loadTrialSource } from "../lib/trial-source.mjs";
import { digest } from "../lib/workflow-plan.mjs";
import { trialPrompt } from "../lib/trial-prompt.mjs";
import { startDesktop } from "./desktop-session.mjs";
import { initializeMcp, openMcp } from "./mcp-session.mjs";
import { prepareProject, trialUrl } from "./trial-setup.mjs";
import { candidateIdentity, readCandidate } from "./trial-snapshot.mjs";
import { closeWorkspace, createWorkspace, mountDesktopWorkspace } from "./trial-workspace.mjs";
import { verifyControlIsolation } from "./trial-isolation.mjs";
import { removeConfirmatoryWorkflowState } from "./confirmatory-workflow-cleanup.mjs";

if (process.platform !== "linux" || process.getuid() !== 0)
  throw new Error("Confirmatory workflow checks require the isolated guest controller");
const request = JSON.parse(readFileSync(0, "utf8"));
const corpus = validateRepositoryConfirmatoryCorpus(request.corpus);
const pinnedCorpus = JSON.parse(
  readFileSync(new URL(`../cases/${confirmatoryCorpusFilename(corpus.id)}`, import.meta.url)),
);
const pinnedRegistration = JSON.parse(
  readFileSync(new URL(`../cases/${confirmatoryRegistrationFilename(corpus.id)}`, import.meta.url)),
);
if (
  digest(corpus) !== digest(pinnedCorpus) ||
  digest(request.registration) !== digest(pinnedRegistration) ||
  request.registration.corpusSha256 !== digest(corpus) ||
  request.registration.eligibilitySha256 !== digest(request.eligibility) ||
  request.eligibility.passed !== true ||
  request.qualification.passed !== true ||
  request.qualification.corpusSha256 !== digest(corpus) ||
  request.qualification.eligibilitySha256 !== digest(request.eligibility) ||
  request.qualification.registrationSha256 !== digest(request.registration)
)
  throw new Error("Confirmatory workflow inputs differ from the frozen evidence");
validateRepositoryConfirmatoryRegistration(request.registration, corpus, request.eligibility);
const item = corpus.cases.find((candidate) => candidate.id === request.caseId);
const eligible = request.eligibility.cases.find((candidate) => candidate.id === request.caseId);
const qualified = request.qualification.cases.find((candidate) => candidate.id === request.caseId);
if (!item || !eligible?.eligible || !qualified?.passed)
  throw new Error("Confirmatory workflow case is not qualified");
const targetIssue = repositoryScannerTargetIssue(item, eligible.baseline);
const baseline = validateRepositorySnapshot(request.baseline);
const product = request.product;
if (
  baseline.commit !== item.baselineCommit ||
  !/^[a-f0-9]{40}$/.test(product?.commit ?? "") ||
  product.binary !== "/usr/bin/sitecmd" ||
  product.mcp !== "/usr/lib/SiteCMD/sitecmd-mcp/sitecmd-mcp.mjs" ||
  product.cli !== `/opt/sitecmd-benchmark/products/${product.commit}/sitecmd_cli`
)
  throw new Error("Confirmatory workflow source or product path is invalid");
for (const field of ["binary", "mcp", "cli"])
  if (digest(readFileSync(product[field])) !== product[`${field}Sha256`])
    throw new Error(`Installed ${field} differs from its product receipt`);

const task = {
  ...item,
  sourceFormat: "git-tree-v1",
  sourceSha256: baseline.sha256,
  prompt: item.task,
};
const { files, modes } = loadTrialSource(baseline, task);
const expected = candidateIdentity({ files, modes, violations: [] });
const workflowItem = { ...item, confirmatory: true, targetIssue };
const results = [];
for (const arm of ["normal", "report", "mcp"]) {
  const sessionId = digest({ runId: request.runId, caseId: item.id, arm }).slice(0, 32);
  const trace = [];
  const result = {
    arm,
    sessionId,
    status: "infrastructure_error",
    sourceUnchanged: false,
    prompt: null,
    issueDetail: null,
    modelCalls: 0,
    trace,
  };
  let workspace;
  let mounted;
  let desktop;
  let reader;
  try {
    workspace = createWorkspace(sessionId, files, modes);
    mounted = mountDesktopWorkspace(sessionId, workspace);
    const scan = spawnSync(
      "sudo",
      ["-u", "sitecmd", product.cli, "audit", mounted.path, "--format", "json"],
      { encoding: "utf8", timeout: 120000, maxBuffer: 16 * 1024 * 1024 },
    );
    result.report = {
      exitCode: scan.status,
      raw: scan.stdout,
      stderr: scan.stderr,
      ...(scan.status === 0 ? { report: JSON.parse(scan.stdout) } : {}),
    };
    if (scan.status !== 0)
      throw new Error(`CLI report failed: ${scan.error?.message ?? scan.stderr}`);
    desktop = await startDesktop(sessionId, product.binary);
    verifyControlIsolation();
    const prepared = await prepareProject(
      desktop,
      mounted,
      workflowItem,
      product,
      { agent: "codex" },
      arm,
      (name, event) => trace.push({ name, ...event }),
    );
    result.projectId = prepared.projectId;
    if (prepared.attemptId !== null) {
      result.attemptId = prepared.attemptId;
      result.handoff = prepared.handoff;
      result.brief = prepared.brief;
      result.targetIssue = targetIssue;
    }
    result.prompt = trialPrompt({
      task,
      arm,
      workspace,
      channel: `/run/sitecmd-benchmark/${sessionId}`,
      publicTools: "/usr/local/lib/sitecmd-benchmark",
      projectId: prepared.projectId,
      url: trialUrl,
      handoff: prepared.handoff,
      report: scan.stdout,
    });
    reader = openMcp(product.mcp, desktop.database, (event) =>
      trace.push({ name: "diagnostic", ...event }),
    );
    result.initialization = await initializeMcp(reader, "codex");
    result.issues = await reader.call("get_issues", { url: trialUrl });
    const detail = await reader.call("get_issue", {
      url: trialUrl,
      check_id: item.targetFinding.checkId,
    });
    if (result.issues.isError || detail.isError)
      throw new Error("SiteCMD could not return the scanned issue through MCP");
    result.issueDetail = detail.content?.[0]?.text ?? "";
    result.snapshotSha256 = candidateIdentity(readCandidate(workspace));
    result.sourceUnchanged = result.snapshotSha256 === expected;
    if (!result.sourceUnchanged) throw new Error("Workflow setup changed tracked source or modes");
    result.status = "ready";
  } catch (error) {
    result.error = error.message;
  } finally {
    const cleanupErrors = [];
    let desktopClosed = false;
    let mountedClosed = false;
    let workspaceClosed = false;
    for (const cleanup of [
      async () => reader?.close(),
      async () => {
        desktop?.close();
        desktopClosed = true;
      },
      async () => {
        mounted?.close();
        mountedClosed = true;
      },
      async () => {
        if (workspace) closeWorkspace(workspace);
        workspaceClosed = true;
      },
    ]) {
      try {
        await cleanup();
      } catch (error) {
        cleanupErrors.push(error.message);
      }
    }
    const removable = {
      ...(workspace && workspaceClosed ? { workspace } : {}),
      ...(mounted && mountedClosed ? { mounted: mounted.path } : {}),
      ...(desktop && desktopClosed ? { data: desktop.data } : {}),
    };
    if (Object.keys(removable).length) {
      try {
        removeConfirmatoryWorkflowState(sessionId, removable);
      } catch (error) {
        cleanupErrors.push(error.message);
      }
    }
    if (cleanupErrors.length) {
      result.status = "infrastructure_error";
      result.error = [result.error, ...cleanupErrors.map((error) => `cleanup: ${error}`)]
        .filter(Boolean)
        .join("; ");
    }
  }
  results.push(result);
}
const receipt = {
  schemaVersion: 1,
  capturedAt: new Date().toISOString(),
  purpose: "Confirmatory desktop, CLI, and MCP workflow smoke test without model calls",
  modelCalls: 0,
  agentInvoked: false,
  id: item.id,
  corpusSha256: digest(corpus),
  eligibilitySha256: digest(request.eligibility),
  qualificationSha256: digest(request.qualification),
  registrationSha256: digest(request.registration),
  product,
  results,
  passed: false,
};
try {
  validateConfirmatoryWorkflowCase(item, receipt);
  receipt.passed = true;
} catch (error) {
  receipt.validationError = error.message;
}
console.log(JSON.stringify(receipt));
