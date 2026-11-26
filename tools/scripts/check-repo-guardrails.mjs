#!/usr/bin/env node
import fs from "node:fs";
import { ambientClockFailures } from "./lib/guardrail-ambient-clock-rules.mjs";
import { protocolVocabFailures } from "./lib/guardrail-protocol-vocab-rules.mjs";
import { scanRunStampFailures } from "./lib/guardrail-scan-run-stamp-rules.mjs";
import { projectMetadataReadFailures } from "./lib/guardrail-project-metadata-rules.mjs";
import { codeScanHostBoundaryFailures } from "./lib/guardrail-code-scan-host-boundary.mjs";
import { accessibilityNamingFailures } from "./lib/guardrail-accessibility-naming-rules.mjs";
import { desktopScannerBodySafetyFailures } from "./lib/guardrail-open-scanner-body-rules.mjs";
import { verifiedGoodSchemaFailures } from "./lib/guardrail-verified-good-schema-rules.mjs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { testWiringFailures } from "./lib/guardrail-test-wiring-rules.mjs";
import { testWorkerFailures } from "./lib/guardrail-test-workers-rules.mjs";
import { documentationSafetyFailures } from "./lib/guardrail-doc-rules.mjs";
import { emDashFailures } from "./lib/guardrail-em-dash-rules.mjs";
import { supplyChainSafetyFailures } from "./lib/guardrail-supply-chain-rules.mjs";
import { ciCredentialDisclosureFailures } from "./lib/guardrail-ci-credential-disclosure-rules.mjs";
import { stripeKeyLiteralFailures } from "./lib/guardrail-stripe-key-literal-rules.mjs";
import { ciWorkflowFailures } from "./lib/guardrail-ci-workflow-rules.mjs";
import { localDeliveryFailures } from "./lib/guardrail-local-delivery-rules.mjs";
import { ciCostSafetyFailures } from "./lib/guardrail-ci-cost-rules.mjs";
import { connectedSetupFailures } from "./lib/guardrail-connected-setup-rules.mjs";
import { verificationProvenanceFailures } from "./lib/guardrail-issue-state-rules.mjs";
import { submissionOrderingFailures } from "./lib/guardrail-submission-ordering-rules.mjs";
import { connectedOutboxFailures } from "./lib/guardrail-connected-outbox-rules.mjs";
import { connectedBootstrapFailures } from "./lib/guardrail-connected-bootstrap-rules.mjs";
import { cliSurfaceFailures } from "./lib/guardrail-cli-surface-rules.mjs";
import { publicationRecordFailures } from "./lib/guardrail-publication-record-rules.mjs";
import { connectedServicePayloadFailures } from "./lib/guardrail-sync-payload-rules.mjs";
import { commentQualityFailures } from "./lib/guardrail-comment-quality-rules.mjs";
import { coreLayeringFailures } from "./lib/guardrail-core-layering-rules.mjs";
import { emptyTestBodyFailures } from "./lib/guardrail-empty-test-body-rules.mjs";
import { publicRustMemberRoots, versionSyncFailures } from "./lib/guardrail-version-sync-rules.mjs";
import {
  scanRunProjectionFailures,
  unifiedScanArchitectureFailures,
} from "./lib/guardrail-unified-scan-rules.mjs";
import { privateStorageSafetyFailures } from "./lib/guardrail-private-storage-rules.mjs";
import { nativeUpdateInventoryFailures } from "./lib/guardrail-update-rules.mjs";
import { releaseArtifactSafetyFailures } from "./lib/guardrail-release-rules.mjs";
import { rustUnwrapBudgetFailures } from "./lib/guardrail-rust-rules.mjs";
import {
  issueConfidenceFailures,
  protocolContentsFailures,
  isPrivateRustPath,
  RUST_WORKSPACE,
} from "./lib/guardrail-protocol-contents-rules.mjs";
import { redactionOrderFailures } from "./lib/guardrail-redaction-order-rules.mjs";
import { rustlsCryptoProviderFailures } from "./lib/guardrail-rustls-provider-rules.mjs";
import { rustRatchetFailures } from "./lib/guardrail-rust-ratchets.mjs";
import { rustLineBudgetFailures } from "./lib/guardrail-rust-loc-rules.mjs";
import { npmCliPackageFailures } from "./lib/guardrail-npm-cli-rules.mjs";
import { scanScopeFailures } from "./lib/guardrail-scan-scope-rules.mjs";
import { inlineDurationFailures } from "./lib/guardrail-inline-duration-rules.mjs";
import { displayImplLogReentrancyFailures } from "./lib/guardrail-rust-display-log-rules.mjs";
import { checkGuardrailScriptLineBudgets } from "./lib/guardrail-script-budgets.mjs";
import { agentGuidanceFailures } from "./lib/guardrail-agent-guidance-rules.mjs";
import { workflowSafetyFailures } from "./lib/guardrail-workflow-rules.mjs";
import { workflowPinFailures } from "./lib/guardrail-workflow-pins.mjs";
import { codeOwnerSafetyFailures } from "./lib/guardrail-codeowners-rules.mjs";
import { runtimeBoundaryFailures } from "./lib/guardrail-runtime-boundary-rules.mjs";
import { publicFaceFailures } from "./lib/guardrail-public-face-rules.mjs";
const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const ROOT = process.env.SITECMD_GUARDRAILS_ROOT
  ? path.resolve(process.env.SITECMD_GUARDRAILS_ROOT)
  : DEFAULT_ROOT;

/** Bind guardrail I/O to a real or overlaid repository tree. */
export function repoGuardrailIo(root) {
  const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");
  const readJson = (relativePath) => JSON.parse(read(relativePath));
  const exists = (relativePath) => fs.existsSync(path.join(root, relativePath));
  const listFiles = (dir, predicate, files = []) => {
    if (!exists(dir)) return files;
    for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
      if (
        entry.name === ".git" ||
        entry.name === "node_modules" ||
        entry.name === "dist" ||
        entry.name === "target"
      )
        continue;
      const relativePath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        listFiles(relativePath, predicate, files);
      } else if (predicate(relativePath)) {
        files.push(relativePath);
      }
    }
    return files;
  };
  return { root, read, readJson, exists, listFiles };
}

/** Return every guardrail failure for a repository I/O view. */
export function repoGuardrailFailures({ root, read, exists, listFiles }) {
  const failures = [];
  function check(condition, message) {
    if (!condition) failures.push(message);
  }

  const packageJson = JSON.parse(read("package.json"));
  const exported = !exists(".github/ci-job-visibility.json");
  const releaseWorkflow = !exported || exists(".github/workflows/release.yml");
  check(
    typeof packageJson.packageManager === "string" &&
      packageJson.packageManager.startsWith("pnpm@"),
    "Root package.json must declare pnpm as packageManager.",
  );

  // Keep one patch-only TypeScript range across workspaces so installs resolve one compiler.
  const tsSpecFiles = [
    "package.json",
    ...listFiles("apps", (f) => f.endsWith("/package.json") && !f.includes("/.wrangler/")),
  ];
  const tsSpecsByFile = new Map();
  for (const pkgFile of tsSpecFiles) {
    const pkg = JSON.parse(read(pkgFile));
    const spec = pkg.devDependencies?.typescript ?? pkg.dependencies?.typescript;
    if (spec) tsSpecsByFile.set(pkgFile, spec);
  }
  check(
    new Set(tsSpecsByFile.values()).size <= 1,
    `Workspace packages must pin one TypeScript range spec so pnpm resolves a single compiler: ${[
      ...tsSpecsByFile,
    ]
      .map(([f, s]) => `${f}=${s}`)
      .join("; ")}`,
  );
  check(!exists("package-lock.json"), "Root package-lock.json must not exist; use pnpm-lock.yaml.");
  check(!exists("yarn.lock"), "Root yarn.lock must not exist; use pnpm-lock.yaml.");
  checkGuardrailScriptLineBudgets(read, listFiles, check);

  const lefthook = read("lefthook.yml");
  failures.push(...localDeliveryFailures(lefthook, packageJson.scripts ?? {}, read, listFiles));
  check(!/\brun:\s*npx\b/.test(lefthook), "Root lefthook commands must use pnpm exec, not npx.");
  const eslintConfigSource = read("eslint.config.js");
  check(
    packageJson.scripts?.lint === "eslint ." &&
      eslintConfigSource.includes('"tools/scripts/**/*.mjs"') &&
      eslintConfigSource.includes("js.configs.recommended") &&
      eslintConfigSource.includes("globals.node") &&
      eslintConfigSource.includes('"no-unused-vars"'),
    "Repository maintenance scripts must be covered by root ESLint with Node/MJS recommended rules.",
  );

  const workflowFailures = workflowSafetyFailures(read, listFiles, { exported });
  check(
    workflowFailures.length === 0,
    `Workflow quality guardrails failed: ${workflowFailures.join("; ")}`,
  );
  failures.push(...ciWorkflowFailures(read, listFiles, { exported }));
  failures.push(...workflowPinFailures(read, listFiles));
  failures.push(...codeOwnerSafetyFailures(read));
  const ciCostFailures = ciCostSafetyFailures(read, listFiles, { exported });
  check(ciCostFailures.length === 0, `CI cost guardrails failed: ${ciCostFailures.join("; ")}`);
  const setupFailures = connectedSetupFailures(read);
  check(
    setupFailures.length === 0,
    `Connected setup guardrails failed: ${setupFailures.join("; ")}`,
  );
  const supplyChainFailures = supplyChainSafetyFailures(read, { root });
  check(
    supplyChainFailures.length === 0,
    `Supply-chain guardrails failed: ${supplyChainFailures.join("; ")}`,
  );
  for (const [label, failures] of [["Comment quality", commentQualityFailures(read, listFiles)]]) {
    check(failures.length === 0, `${label} guardrails failed: ${failures.join("; ")}`);
  }

  failures.push(...rustUnwrapBudgetFailures(read, exists, listFiles));
  failures.push(...redactionOrderFailures(read, listFiles));
  failures.push(...protocolContentsFailures(read, listFiles));
  failures.push(...rustRatchetFailures(read, exists, listFiles));
  failures.push(...npmCliPackageFailures(read, { releaseWorkflow }));
  failures.push(...scanScopeFailures(read));
  failures.push(...displayImplLogReentrancyFailures(read, listFiles));
  failures.push(...rustlsCryptoProviderFailures(read, listFiles));
  failures.push(...coreLayeringFailures(read, listFiles));
  failures.push(...emptyTestBodyFailures(read, listFiles));

  failures.push(...inlineDurationFailures(read, exists, listFiles));

  failures.push(...releaseArtifactSafetyFailures(read, exists, listFiles, { releaseWorkflow }));
  failures.push(...privateStorageSafetyFailures(read));

  failures.push(...documentationSafetyFailures(read, exists, listFiles));
  failures.push(...emDashFailures(read, exists, listFiles));
  failures.push(...ciCredentialDisclosureFailures(read));
  failures.push(...issueConfidenceFailures(read));
  failures.push(...stripeKeyLiteralFailures(read, exists, listFiles));
  failures.push(...verificationProvenanceFailures(read, exists));
  failures.push(...submissionOrderingFailures(read, exists, listFiles));
  failures.push(...connectedOutboxFailures(read, exists, listFiles));
  failures.push(...connectedBootstrapFailures(read, exists, listFiles));
  failures.push(...cliSurfaceFailures(read, exists, listFiles));
  failures.push(...publicationRecordFailures(read, exists, listFiles));
  failures.push(...connectedServicePayloadFailures(read, exists, listFiles));
  failures.push(...unifiedScanArchitectureFailures(read, exists, listFiles));
  failures.push(...rustLineBudgetFailures(read, listFiles));
  failures.push(...nativeUpdateInventoryFailures(read));

  failures.push(...runtimeBoundaryFailures(read, listFiles, [], { releaseWorkflow }));
  failures.push(...agentGuidanceFailures(read, exists, listFiles));
  failures.push(...versionSyncFailures(read));
  failures.push(...testWiringFailures(read, { root }));
  failures.push(...testWorkerFailures((file) => (exists(file) ? read(file) : "")));
  failures.push(...publicFaceFailures(read, exists, listFiles));

  failures.push(...verifiedGoodSchemaFailures(read));
  failures.push(...desktopScannerBodySafetyFailures(read));
  failures.push(...accessibilityNamingFailures(read, exists, listFiles));
  failures.push(...codeScanHostBoundaryFailures(read, listFiles));
  failures.push(...projectMetadataReadFailures(read));
  failures.push(...scanRunStampFailures(read));
  failures.push(...scanRunProjectionFailures(read));
  failures.push(...protocolVocabFailures(read));
  const crateDirectory = `${RUST_WORKSPACE}/crates`;
  const clockRoots = [
    crateDirectory,
    ...publicRustMemberRoots(read).filter((root) => !root.startsWith(`${crateDirectory}/`)),
  ];
  failures.push(
    ...ambientClockFailures(
      read,
      (root, predicate) => listFiles(root, (file) => !isPrivateRustPath(file) && predicate(file)),
      clockRoots,
    ),
  );
  return failures;
}

// Imports stay side-effect free; direct execution reports failures through exit status.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const failures = repoGuardrailFailures(repoGuardrailIo(ROOT));
  if (failures.length > 0) {
    console.error("Repo guardrails failed:");
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  } else {
    console.log("Repo guardrails passed.");
  }
}
