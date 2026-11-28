import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import { repoGuardrailFailures } from "./check-repo-guardrails.mjs";
import { OVERLAY_DELETED, overlayIo } from "./lib/repo-overlay-io.mjs";
import { orderedBefore } from "./lib/guardrail-text-utils.mjs";
import { agentGuidanceFailures } from "./lib/guardrail-agent-guidance-rules.mjs";
import { cliSurfaceFailures } from "./lib/guardrail-cli-surface-rules.mjs";
import { codeScanSecurityFailures } from "./lib/guardrail-code-scan-security-rules.mjs";
import { codeOwnerSafetyFailures } from "./lib/guardrail-codeowners-rules.mjs";
import { documentationSafetyFailures } from "./lib/guardrail-doc-rules.mjs";
import { emDashFailures } from "./lib/guardrail-em-dash-rules.mjs";
import { emptyTestBodyFailures } from "./lib/guardrail-empty-test-body-rules.mjs";
import { publicationRecordFailures } from "./lib/guardrail-publication-record-rules.mjs";
import { privateStorageSafetyFailures } from "./lib/guardrail-private-storage-rules.mjs";
import { releaseArtifactSafetyFailures } from "./lib/guardrail-release-rules.mjs";
import { displayImplLogReentrancyFailures } from "./lib/guardrail-rust-display-log-rules.mjs";
import { rustLineBudgetFailures } from "./lib/guardrail-rust-loc-rules.mjs";
import { rustRatchetFailures } from "./lib/guardrail-rust-ratchets.mjs";
import { rustUnwrapBudgetFailures } from "./lib/guardrail-rust-rules.mjs";
import { rustlsCryptoProviderFailures } from "./lib/guardrail-rustls-provider-rules.mjs";
import { desktopScannerBodySafetyFailures } from "./lib/guardrail-open-scanner-body-rules.mjs";
import { supplyChainSafetyFailures } from "./lib/guardrail-supply-chain-rules.mjs";
import { nativeUpdateInventoryFailures } from "./lib/guardrail-update-rules.mjs";
import { versionSyncFailures } from "./lib/guardrail-version-sync-rules.mjs";
import {
  ciCostSafetyFailures,
  deployWorkflowHardeningFailures,
} from "./lib/guardrail-ci-cost-rules.mjs";
import { unifiedScanArchitectureFailures } from "./lib/guardrail-unified-scan-rules.mjs";
import { workflowSafetyFailures } from "./lib/guardrail-workflow-rules.mjs";
import { releaseWorkflowSafetyFailures } from "./lib/guardrail-release-workflow-rules.mjs";
import { commentQualityFailures } from "./lib/guardrail-comment-quality-rules.mjs";
import { guardrailScriptLineBudgets } from "./lib/guardrail-script-budgets.mjs";
import { stripComments, stripNonCode } from "./lib/guardrail-source-text.mjs";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const realRead = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");
export const exportedTree = !fs.existsSync(path.join(ROOT, ".github/ci-job-visibility.json"));
export const GUARDRAIL_TEST_TIMEOUT_MS = 300_000;

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

export function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

let cachedRepoFiles;

function repoFiles() {
  if (cachedRepoFiles) return cachedRepoFiles;
  const output = execFileSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    {
      cwd: ROOT,
    },
  ).toString("utf8");

  cachedRepoFiles = Array.from(new Set(output.split("\0").filter(Boolean)));
  return cachedRepoFiles;
}

export function copyRepoFixture() {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-guardrails-"));

  for (const relativePath of repoFiles()) {
    const sourcePath = path.join(ROOT, relativePath);
    if (!fs.existsSync(sourcePath)) continue;

    const destPath = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });

    const stat = fs.lstatSync(sourcePath);
    if (stat.isSymbolicLink()) {
      fs.symlinkSync(fs.readlinkSync(sourcePath), destPath);
    } else if (stat.isFile()) {
      fs.copyFileSync(sourcePath, destPath, fs.constants.COPYFILE_FICLONE);
    }
  }

  return fixtureRoot;
}

export function writeFixtureFile(fixture, relativePath, source) {
  if (fixture instanceof Map) {
    fixture.set(relativePath, source);
    return;
  }
  const filePath = path.join(fixture, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, source);
}

export function readFixtureFile(fixture, relativePath) {
  if (fixture instanceof Map) {
    const pending = fixture.get(relativePath);
    if (pending === OVERLAY_DELETED) throw new Error(`fixture deleted ${relativePath}`);
    return pending ?? read(relativePath);
  }
  return fs.readFileSync(path.join(fixture, relativePath), "utf8");
}

export function mustMutate(source, searchValue, replaceValue) {
  const mutated = source.replaceAll(searchValue, replaceValue);
  if (mutated === source) {
    throw new Error(
      `negative-control mutation is a no-op; update the search string to match the current source: ${searchValue}`,
    );
  }
  return mutated;
}

export function runGuardrails(fixtureRoot, { cwd = fixtureRoot } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [path.join(ROOT, "tools/scripts/check-repo-guardrails.mjs")],
      {
        cwd,
        env: {
          ...process.env,
          SITECMD_GUARDRAILS_ROOT: fixtureRoot,
        },
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

const RULE_ARGUMENTS = new Map([
  [repoGuardrailFailures, (io) => [io]],
  [agentGuidanceFailures, (io) => [io.read, io.exists, io.listFiles]],
  [ciCostSafetyFailures, (io) => [io.read, io.listFiles, { exported: exportedTree }]],
  [cliSurfaceFailures, (io) => [io.read, io.exists, io.listFiles]],
  [codeOwnerSafetyFailures, (io) => [io.read]],
  [codeScanSecurityFailures, (io) => [io.read]],
  [desktopScannerBodySafetyFailures, (io) => [io.read]],
  [nativeUpdateInventoryFailures, (io) => [io.read]],
  [displayImplLogReentrancyFailures, (io) => [io.read, io.listFiles]],
  [documentationSafetyFailures, (io) => [io.read, io.exists, io.listFiles]],
  [emDashFailures, (io) => [io.read, io.exists, io.listFiles]],
  [emptyTestBodyFailures, (io) => [io.read, io.listFiles]],
  [publicationRecordFailures, (io) => [io.read, io.exists, io.listFiles]],
  [privateStorageSafetyFailures, (io) => [io.read]],
  [releaseArtifactSafetyFailures, (io) => [io.read, io.exists, io.listFiles]],
  [releaseWorkflowSafetyFailures, (io) => [io.read]],
  [rustLineBudgetFailures, (io) => [io.read, io.listFiles]],
  [rustRatchetFailures, (io) => [io.read, io.exists, io.listFiles]],
  [rustUnwrapBudgetFailures, (io) => [io.read, io.exists, io.listFiles]],
  [rustlsCryptoProviderFailures, (io) => [io.read, io.listFiles]],
  [supplyChainSafetyFailures, (io) => [io.read, { root: io.root }]],
  [versionSyncFailures, (io) => [io.read]],
]);

function runRule(rule, io) {
  const shape = RULE_ARGUMENTS.get(rule);
  return shape ? rule(...shape(io)) : rule(io);
}

const cleanFailuresByRule = new Map();
function cleanFailures(rule) {
  if (!cleanFailuresByRule.has(rule)) {
    cleanFailuresByRule.set(rule, runRule(rule, overlayIo(ROOT)).join("\n"));
  }
  return cleanFailuresByRule.get(rule);
}

export function expectGuardrailFailure(rule, mutator, expectedMessage) {
  expect(cleanFailures(rule)).not.toContain(expectedMessage);

  const overlay = new Map();
  mutator(overlay);
  expect(overlay.size).toBeGreaterThan(0);
  expect(runRule(rule, overlayIo(ROOT, overlay)).join("\n")).toContain(expectedMessage);
}

export function guardrailFailuresFor(rule, mutator) {
  const overlay = new Map();
  mutator(overlay);
  return runRule(rule, overlayIo(ROOT, overlay)).join("\n");
}

export const rules = Object.freeze({
  OVERLAY_DELETED,
  agentGuidanceFailures,
  ciCostSafetyFailures,
  cliSurfaceFailures,
  codeOwnerSafetyFailures,
  codeScanSecurityFailures,
  commentQualityFailures,
  deployWorkflowHardeningFailures,
  desktopScannerBodySafetyFailures,
  nativeUpdateInventoryFailures,
  displayImplLogReentrancyFailures,
  documentationSafetyFailures,
  emDashFailures,
  emptyTestBodyFailures,
  guardrailScriptLineBudgets,
  orderedBefore,
  overlayIo,
  privateStorageSafetyFailures,
  publicationRecordFailures,
  releaseArtifactSafetyFailures,
  releaseWorkflowSafetyFailures,
  repoGuardrailFailures,
  rustLineBudgetFailures,
  rustRatchetFailures,
  rustUnwrapBudgetFailures,
  rustlsCryptoProviderFailures,
  stripComments,
  stripNonCode,
  supplyChainSafetyFailures,
  unifiedScanArchitectureFailures,
  versionSyncFailures,
  workflowSafetyFailures,
});
