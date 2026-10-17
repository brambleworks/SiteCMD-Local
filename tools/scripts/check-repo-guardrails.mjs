#!/usr/bin/env node
import { PRODUCT_FACTS_FILE, productFacts } from "./lib/product-facts.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { testWiringFailures } from "./lib/guardrail-test-wiring-rules.mjs";
import { documentationSafetyFailures } from "./lib/guardrail-doc-rules.mjs";
import { emDashFailures } from "./lib/guardrail-em-dash-rules.mjs";
import { supportEmailLiteralFailures } from "./lib/guardrail-support-email-rules.mjs";
import { supplyChainSafetyFailures } from "./lib/guardrail-supply-chain-rules.mjs";
import { pricingConsistencyFailures } from "./lib/guardrail-pricing-rules.mjs";
import { integrationUrlSecretFailures } from "./lib/guardrail-integration-url-secrets.mjs";
import { scanPersistOffThreadFailures } from "./lib/guardrail-scan-persist-offthread.mjs";
import { asyncCommandDbBlockingFailures } from "./lib/guardrail-async-command-db-rules.mjs";
import { desktopCategoryLabelFailures } from "./lib/guardrail-category-rules.mjs";
import { functionBodyContains } from "./lib/guardrail-command-security-manifest-rules.mjs";
import { desktopOAuthSafetyFailures } from "./lib/guardrail-desktop-oauth-rules.mjs";
import { desktopScannerBodySafetyFailures } from "./lib/guardrail-scanner-body-rules.mjs";
import { ciCostSafetyFailures } from "./lib/guardrail-ci-cost-rules.mjs";
import { ciCredentialDisclosureFailures } from "./lib/guardrail-ci-credential-disclosure-rules.mjs";
import { connectedSetupFailures } from "./lib/guardrail-connected-setup-rules.mjs";
import { codeScanInventoryFailures } from "./lib/guardrail-code-scan-inventory-rules.mjs";
import { desktopFrontendJsonSafetyFailures } from "./lib/guardrail-frontend-json-rules.mjs";
import { desktopFrontendDisplayFailures } from "./lib/guardrail-frontend-display-rules.mjs";
import { desktopFrontendStateFailures } from "./lib/guardrail-frontend-rules.mjs";
import { desktopSecurityPageRemovalFailures } from "./lib/guardrail-security-page-removal.mjs";
import { desktopAnalyticsCacheFailures } from "./lib/guardrail-analytics-cache-rules.mjs";
import { desktopIssuesRetirementFailures } from "./lib/guardrail-issues-retirement-rules.mjs";
import {
  issueStateSafetyFailures,
  verificationProvenanceFailures,
} from "./lib/guardrail-issue-state-rules.mjs";
import { submissionOrderingFailures } from "./lib/guardrail-submission-ordering-rules.mjs";
import { connectedOutboxFailures } from "./lib/guardrail-connected-outbox-rules.mjs";
import { connectedBootstrapFailures } from "./lib/guardrail-connected-bootstrap-rules.mjs";
import { cliSurfaceFailures } from "./lib/guardrail-cli-surface-rules.mjs";
import { publicationRecordFailures } from "./lib/guardrail-publication-record-rules.mjs";
import { syncPayloadFailures } from "./lib/guardrail-sync-payload-rules.mjs";
import { mcpSchemaParityFailures } from "./lib/guardrail-mcp-schema-rules.mjs";
import { desktopDefensiveEmptyStatesFailures } from "./lib/guardrail-defensive-empty-states.mjs";
import { desktopStyleConsistencyFailures } from "./lib/guardrail-style-rules.mjs";
import { tailwindRemovalFailures } from "./lib/guardrail-tailwind-removal-rules.mjs";
import { commentQualityFailures } from "./lib/guardrail-comment-quality-rules.mjs";
import { desktopIssueStatusFailures } from "./lib/guardrail-issue-rules.mjs";
import { reportScoreConsistencyFailures } from "./lib/guardrail-report-score-rules.mjs";
import { desktopScanLabelFailures } from "./lib/guardrail-scan-label-rules.mjs";
import { commandWrapperFailures } from "./lib/guardrail-command-wrapper-rules.mjs";
import { queryLayerFailures } from "./lib/guardrail-query-layer-rules.mjs";
import { eventFabricFailures } from "./lib/guardrail-event-fabric-rules.mjs";
import { appShellNavFailures } from "./lib/guardrail-app-shell-nav-rules.mjs";
import { scanSchedulerPersistPathFailures } from "./lib/guardrail-scan-scheduler-rules.mjs";
import { coreLayeringFailures } from "./lib/guardrail-core-layering-rules.mjs";
import { emptyTestBodyFailures } from "./lib/guardrail-empty-test-body-rules.mjs";
import { versionSyncFailures } from "./lib/guardrail-version-sync-rules.mjs";
import { desktopScoreConsistencyFailures } from "./lib/guardrail-score-rules.mjs";
import { scoreArtifactLabelingFailures } from "./lib/guardrail-score-labeling-rules.mjs";
import { unifiedScanArchitectureFailures } from "./lib/guardrail-unified-scan-rules.mjs";
import { desktopSeverityConsistencyFailures } from "./lib/guardrail-severity-rules.mjs";
import { desktopSharedTypeFailures } from "./lib/guardrail-type-rules.mjs";
import { polishCopySafetyFailures } from "./lib/guardrail-polish-copy-rules.mjs";
import { telemetrySafetyFailures } from "./lib/guardrail-telemetry-rules.mjs";
import { telemetryDisclosureFailures } from "./lib/guardrail-telemetry-disclosure-rules.mjs";
import { telemetryConsentFailures } from "./lib/guardrail-telemetry-consent-rules.mjs";
import { performanceGateFailures } from "./lib/guardrail-performance-rules.mjs";
import { privateStorageSafetyFailures } from "./lib/guardrail-private-storage-rules.mjs";
import { desktopUpdateCommandFailures } from "./lib/guardrail-update-rules.mjs";
import { desktopUrlIdentityFailures } from "./lib/guardrail-url-rules.mjs";
import { releaseArtifactSafetyFailures } from "./lib/guardrail-release-rules.mjs";
import { onboardingCopyFailures } from "./lib/guardrail-onboarding-copy-rules.mjs";
import { dossierVerifyCopyFailures } from "./lib/guardrail-dossier-copy-rules.mjs";
import { rustUnwrapBudgetFailures } from "./lib/guardrail-rust-rules.mjs";
import { rustlsCryptoProviderFailures } from "./lib/guardrail-rustls-provider-rules.mjs";
import { rustRatchetFailures } from "./lib/guardrail-rust-ratchets.mjs";
import { rustEventSeverityFailures } from "./lib/guardrail-rust-event-severity-rules.mjs";
import { rustLineBudgetFailures } from "./lib/guardrail-rust-loc-rules.mjs";
import { rustSeverityConsistencyFailures } from "./lib/guardrail-rust-severity-rules.mjs";
import { ambientClockFailures, engineVocabFailures } from "./lib/guardrail-engine-vocab-rules.mjs";
import { browserPayloadFailures } from "./lib/guardrail-browser-payload-rules.mjs";
import { scannerIdentityFailures } from "./lib/guardrail-scanner-identity-rules.mjs";
import { capabilityManifestFailures } from "./lib/guardrail-capability-manifest-rules.mjs";
import { npmCliPackageFailures } from "./lib/guardrail-npm-cli-rules.mjs";
import { engineArtifactFailures } from "./lib/guardrail-engine-artifact-rules.mjs";
import { scanScopeFailures } from "./lib/guardrail-scan-scope-rules.mjs";
import { verifiedGoodFailures } from "./lib/guardrail-verified-good-rules.mjs";
import { engineStampFailures } from "./lib/guardrail-engine-stamp-rules.mjs";
import { coverageFailures } from "./lib/guardrail-coverage-rules.mjs";
import { inlineDurationFailures } from "./lib/guardrail-inline-duration-rules.mjs";
import { severityPolicyChokepointFailures } from "./lib/guardrail-severity-policy-rules.mjs";
import { enginePortFailures } from "./lib/guardrail-engine-port-rules.mjs";
import { displayImplLogReentrancyFailures } from "./lib/guardrail-rust-display-log-rules.mjs";
import { invokeAclFailures } from "./lib/guardrail-invoke-acl-rules.mjs";
import { guardrailScriptLineBudgets } from "./lib/guardrail-script-budgets.mjs";
import { agentGuidanceFailures } from "./lib/guardrail-agent-guidance-rules.mjs";
import { workflowSafetyFailures } from "./lib/guardrail-workflow-rules.mjs";
import { codeOwnerSafetyFailures } from "./lib/guardrail-codeowners-rules.mjs";
import { frontendMaintainabilityFailures } from "./lib/guardrail-frontend-maintainability-rules.mjs";
import { desktopBoundaryFailures } from "./lib/guardrail-desktop-boundary-rules.mjs";
import { crossSurfaceContractFailures } from "./lib/guardrail-cross-surface-contract-rules.mjs";
import { handRolledDialogFailures } from "./lib/guardrail-dialog-rules.mjs";
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
    for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "target")
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
export function repoGuardrailFailures({ root, read, readJson, exists, listFiles }) {
  const failures = [];
  function check(condition, message) {
    if (!condition) failures.push(message);
  }

  const packageJson = JSON.parse(read("package.json"));
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
  check(
    packageJson.scripts?.build === "pnpm run build:all" &&
      packageJson.scripts?.["build:desktop"] === "pnpm --filter @sitecmd/desktop run build" &&
      packageJson.scripts?.["build:all"]?.includes("pnpm run quality:mcp"),
    "Root build scripts must make all-workspace validation explicit: build -> build:all, with build:desktop as the desktop-only escape hatch.",
  );
  check(
    packageJson.scripts?.test?.includes("pnpm run test:desktop") &&
      packageJson.scripts?.test?.includes("pnpm run test:mcp") &&
      packageJson.scripts?.test?.includes("pnpm run guardrails:repo:test") &&
      packageJson.scripts?.["test:desktop"] === "pnpm --filter @sitecmd/desktop run test" &&
      packageJson.scripts?.["test:mcp"]?.includes("pnpm --filter sitecmd-mcp run test"),
    "Root pnpm test must run desktop, MCP, and guardrail tests; keep desktop-only testing behind test:desktop.",
  );
  check(!exists("package-lock.json"), "Root package-lock.json must not exist; use pnpm-lock.yaml.");
  check(!exists("yarn.lock"), "Root yarn.lock must not exist; use pnpm-lock.yaml.");
  const effectiveGuardrailScriptLineBudgets = new Map(guardrailScriptLineBudgets);
  for (const file of listFiles("tools/scripts/lib", (file) => /guardrail-[^/]+\.mjs$/.test(file))) {
    if (!effectiveGuardrailScriptLineBudgets.has(file)) {
      effectiveGuardrailScriptLineBudgets.set(file, 400);
    }
  }
  const oversizeGuardrailScripts = Array.from(effectiveGuardrailScriptLineBudgets)
    .filter(([file, maxLines]) => read(file).split("\n").length > maxLines)
    .map(
      ([file, maxLines]) =>
        `${file} has ${read(file).split("\n").length} lines (budget ${maxLines})`,
    );
  check(
    oversizeGuardrailScripts.length === 0,
    `Repo guardrail scripts must stay within maintainability line budgets; split rule families before growing the monolith: ${oversizeGuardrailScripts.join(", ")}`,
  );

  {
    const expected = `${JSON.stringify(productFacts(read, listFiles), null, 2)}\n`;
    check(
      exists(PRODUCT_FACTS_FILE) && read(PRODUCT_FACTS_FILE) === expected,
      `${PRODUCT_FACTS_FILE} is stale; run \`pnpm facts:generate\` and sync the result to SiteCMD-Web.`,
    );
  }

  const lefthook = read("lefthook.yml");
  check(!/\brun:\s*npx\b/.test(lefthook), "Root lefthook commands must use pnpm exec, not npx.");
  check(
    /typecheck:[\s\S]{0,600}?run:[^\n]*\btsc -b\b/.test(lefthook),
    "lefthook pre-commit typecheck must run `tsc -b`; bare tsc against the solution tsconfig checks nothing.",
  );

  const eslintConfigSource = read("eslint.config.js");
  for (const workspacePath of ["apps/mcp-server"]) {
    check(
      !new RegExp(`["']${workspacePath}["']`).test(eslintConfigSource),
      `Root ESLint must not globally ignore ${workspacePath}; workspaces need the same lint safety net.`,
    );
  }
  check(
    packageJson.scripts?.lint === "eslint ." &&
      eslintConfigSource.includes('"tools/scripts/**/*.mjs"') &&
      eslintConfigSource.includes("js.configs.recommended") &&
      eslintConfigSource.includes("globals.node") &&
      eslintConfigSource.includes('"no-unused-vars"'),
    "Repository maintenance scripts must be covered by root ESLint with Node/MJS recommended rules.",
  );

  const workflowFailures = workflowSafetyFailures(read, listFiles);
  check(
    workflowFailures.length === 0,
    `Workflow quality guardrails failed: ${workflowFailures.join("; ")}`,
  );
  failures.push(...codeOwnerSafetyFailures(read));
  const ciCostFailures = ciCostSafetyFailures(read, listFiles);
  check(ciCostFailures.length === 0, `CI cost guardrails failed: ${ciCostFailures.join("; ")}`);
  const ciDisclosureFailures = ciCredentialDisclosureFailures(read);
  check(
    ciDisclosureFailures.length === 0,
    `CI credential disclosure guardrails failed: ${ciDisclosureFailures.join("; ")}`,
  );
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
  for (const [label, failures] of [
    ["Performance gates", performanceGateFailures(read)],
    ["Telemetry consent", telemetryConsentFailures(read, exists)],
    ["Telemetry privacy", telemetrySafetyFailures(read, exists, listFiles)],
    ["Telemetry disclosure", telemetryDisclosureFailures(read, exists)],
    ["Desktop scanner bodies", desktopScannerBodySafetyFailures(read, listFiles)],
    ["Engine-port", enginePortFailures(read, listFiles)],
    ["Code Scan inventory", codeScanInventoryFailures(read)],
    ["Scanner copy + naming", polishCopySafetyFailures(read, exists, listFiles)],
    ["Onboarding nav copy", onboardingCopyFailures(read)],
    ["Dossier verify copy", dossierVerifyCopyFailures(read, exists, listFiles)],
    ["Tailwind removal", tailwindRemovalFailures(read, listFiles, exists)],
    ["Comment quality", commentQualityFailures(read, listFiles)],
  ]) {
    check(failures.length === 0, `${label} guardrails failed: ${failures.join("; ")}`);
  }

  const mcpServerPackage = readJson("apps/mcp-server/package.json");
  const mcpServerTsconfig = readJson("apps/mcp-server/tsconfig.json");
  const desktopLicenseConfig = read("apps/desktop/src-tauri/src/licensing/config.rs");
  const desktopScanPolicy = read("apps/desktop/src-tauri/src/commands/scan/policy.rs");
  const desktopHistoryLimits = exists("apps/desktop/src/lib/history-limits.ts");
  const mcpDbSource = [
    "apps/mcp-server/src/db.ts",
    "apps/mcp-server/src/db_connection.ts",
    "apps/mcp-server/src/db_correlation.ts",
    "apps/mcp-server/src/db_fix_attempts.ts",
    "apps/mcp-server/src/db_manifests.ts",
  ]
    .map(read)
    .join("\n");
  check(
    mcpServerPackage.scripts?.lint === "eslint src/**/*.ts" &&
      mcpServerPackage.scripts?.typecheck === "tsc --noEmit",
    "apps/mcp-server must expose lint and typecheck scripts so MCP-only changes get the same quality gates.",
  );
  check(
    mcpServerTsconfig.compilerOptions?.noUnusedLocals === true &&
      mcpServerTsconfig.compilerOptions?.noUnusedParameters === true,
    "apps/mcp-server tsconfig must keep noUnusedLocals/noUnusedParameters enabled.",
  );
  check(
    packageJson.scripts?.["quality:mcp"]?.includes("pnpm --filter sitecmd-mcp run lint") &&
      packageJson.scripts?.["quality:mcp"]?.includes("pnpm --filter sitecmd-mcp run typecheck"),
    "Root quality:mcp must lint and typecheck sitecmd-mcp before tests.",
  );
  check(
    !desktopScanPolicy.includes("FREE_HISTORY_LIMIT") &&
      !desktopHistoryLimits &&
      !mcpDbSource.includes("free_history_limit;") &&
      !desktopLicenseConfig.includes("pub enum Feature") &&
      !desktopLicenseConfig.includes("pub fn has_feature") &&
      !exists("apps/desktop/src/components/gates/FeatureGate.tsx") &&
      !read("apps/desktop/src/hooks/useTier.tsx").includes("hasFeature"),
    "Client-side feature gating is retired with the free complete workbench: no history cap keys on a tier, and the Feature enum, has_feature, and FeatureGate must stay deleted - the paid boundary is the connected service, enforced server-side.",
  );
  const mcpWorkspaceSource = read("apps/mcp-server/src/workspace.ts");
  const mcpIndexSource = read("apps/mcp-server/src/server.ts");
  check(
    mcpWorkspaceSource.includes("parseWorkspaceScanResult") &&
      mcpWorkspaceSource.includes("parseWorkspaceIssue") &&
      mcpWorkspaceSource.includes("parseCliConfig") &&
      mcpWorkspaceSource.includes("parsePackageDependencyNames") &&
      mcpWorkspaceSource.includes("readJson(path: string): unknown | null") &&
      mcpWorkspaceSource.includes(
        "readWorkspaceJson(path: string, label: string): unknown | null",
      ) &&
      mcpWorkspaceSource.includes('const raw = readWorkspaceJson(path, "scan cache")') &&
      mcpWorkspaceSource.includes("const scan = parseWorkspaceScanResult(raw)") &&
      mcpWorkspaceSource.includes("parsePackageDependencyNames(readJson(packageJsonPath))") &&
      !mcpWorkspaceSource.includes("JSON.parse(readFileSync(packageJsonPath") &&
      !mcpWorkspaceSource.includes("readJson<WorkspaceScanResult>") &&
      !mcpWorkspaceSource.includes("readJson<CliConfig>"),
    "sitecmd-mcp filesystem JSON reads must parse untrusted workspace and package JSON before using it.",
  );
  check(
    mcpWorkspaceSource.includes("export interface WorkspaceIssue extends Issue") &&
      !mcpIndexSource.includes("as unknown as Issue[]"),
    "sitecmd-mcp workspace fallback issues must be structurally typed, not double-cast to DB issues.",
  );
  const mcpCausalGraphSource = read("apps/mcp-server/src/causal_graph.ts");
  const mcpWorkspaceTests = read("apps/mcp-server/test/workspace.test.mjs");
  const mcpCausalGraphTests = read("apps/mcp-server/test/causal_graph.test.mjs");
  check(
    mcpDbSource.includes("function envUrlVariants") &&
      mcpDbSource.includes("getProjectByUrl(url: string)") &&
      mcpDbSource.includes("getScanHistory(url: string") &&
      mcpDbSource.includes("getLatestScan(url: string)") &&
      (mcpDbSource.match(/WHERE e\.url IN \(\?, \?\)/g)?.length ?? 0) >= 1 &&
      (mcpDbSource.match(/WHERE execution\.environment_scope_key IN \(\?, \?\)/g)?.length ?? 0) >=
        2 &&
      mcpWorkspaceTests.includes("MCP DB URL lookups tolerate trailing slash variants"),
    "sitecmd-mcp URL lookups must normalize trailing-slash variants for projects and scan history.",
  );
  check(
    functionBodyContains(mcpDbSource, "getIssueComparisonForProject", "source = ?") &&
      mcpDbSource.includes("getCodeScanHistoryForProject") &&
      mcpWorkspaceTests.includes("getCodeScanHistoryForProject uses Code Scan timestamps") &&
      mcpWorkspaceTests.includes("Future code issue"),
    "sitecmd-mcp scan comparison must compare Web Scan and Code Scan issues against their own scan-history windows.",
  );
  check(
    mcpCausalGraphSource.includes("export function parseCausalGraph(value: unknown)") &&
      mcpCausalGraphSource.includes("parseCausalLink") &&
      mcpCausalGraphSource.includes("readGraphJson(): unknown") &&
      !mcpCausalGraphSource.includes("as {\n  links: CausalLink[];") &&
      mcpCausalGraphTests.includes("rejects the whole generated graph when any link is malformed"),
    "sitecmd-mcp causal graph JSON must be parsed as unknown generated data before use.",
  );
  const tauriConf = readJson("apps/desktop/src-tauri/tauri.conf.json");
  const agentToolsRust = read("apps/desktop/src-tauri/src/core/agent_tools.rs");
  const mcpBundleScript = read("apps/mcp-server/scripts/bundle.mjs");
  check(
    mcpServerPackage.private === true && mcpServerPackage.bin === undefined,
    "apps/mcp-server must stay private with no bin: the MCP server ships inside the desktop app, not on npm.",
  );
  check(
    !agentToolsRust.includes("npx") &&
      !agentToolsRust.includes("sitecmd-mcp@") &&
      !agentToolsRust.includes("MCP_SERVER_NPM_VERSION"),
    "agent_tools.rs must launch the bundled MCP server via node, never npx or a pinned npm package.",
  );
  check(
    tauriConf.bundle?.resources?.["../../mcp-server/dist-bundle/"] === "sitecmd-mcp/" &&
      tauriConf.build?.beforeBuildCommand?.includes("pnpm --filter sitecmd-mcp run bundle") &&
      tauriConf.build?.beforeDevCommand?.includes("pnpm --filter sitecmd-mcp run bundle") &&
      mcpServerPackage.scripts?.test?.includes("pnpm run bundle") &&
      mcpBundleScript.includes("assertRepositorySchemaContract()"),
    "Tauri dev, builds, and MCP tests must bundle the server through its schema compatibility guard.",
  );

  function countLines(source) {
    if (source.length === 0) return 0;
    const lineCount = source.split(/\r\n|\r|\n/).length;
    return source.endsWith("\n") ? lineCount - 1 : lineCount;
  }

  const sourceSizeBudgets = [
    { file: "apps/desktop/src-tauri/src/lib.rs", maxLines: 600 },
    { file: "apps/desktop/src-tauri/src/core/severity_policy.rs", maxLines: 80 },
  ];
  const oversizedSourceFiles = sourceSizeBudgets
    .map(({ file, maxLines }) => ({ file, maxLines, lineCount: countLines(read(file)) }))
    .filter(({ lineCount, maxLines }) => lineCount > maxLines);
  check(
    oversizedSourceFiles.length === 0,
    `Maintainability line budgets exceeded: ${oversizedSourceFiles
      .map(({ file, lineCount, maxLines }) => `${file} has ${lineCount}/${maxLines} lines`)
      .join("; ")}`,
  );

  failures.push(...rustUnwrapBudgetFailures(read, exists, listFiles));
  failures.push(...rustRatchetFailures(read, exists, listFiles));
  failures.push(...rustEventSeverityFailures(read));
  failures.push(...rustSeverityConsistencyFailures(read, listFiles));
  failures.push(...engineVocabFailures(read));
  failures.push(...ambientClockFailures(read, listFiles));
  failures.push(...browserPayloadFailures(read, listFiles, exists));
  failures.push(...scannerIdentityFailures(read, listFiles));
  failures.push(...capabilityManifestFailures(read, listFiles));
  failures.push(...npmCliPackageFailures(read));
  failures.push(...engineArtifactFailures(read, listFiles));
  failures.push(...scanScopeFailures(read));
  failures.push(...verifiedGoodFailures(read));
  failures.push(...engineStampFailures(read));
  failures.push(...coverageFailures(read));
  failures.push(...severityPolicyChokepointFailures(read, listFiles));
  failures.push(...displayImplLogReentrancyFailures(read, listFiles));
  failures.push(...rustlsCryptoProviderFailures(read, listFiles));
  failures.push(...scanSchedulerPersistPathFailures(read));
  failures.push(...coreLayeringFailures(read, listFiles));
  failures.push(...emptyTestBodyFailures(read, listFiles));

  // Web collection remains internal to the execution orchestrator.
  {
    const webScanSource = read("apps/desktop/src-tauri/src/commands/scan/web_scan.rs");
    check(
      webScanSource.includes("pub(crate) async fn scan_url_for_execution(") &&
        webScanSource.includes("pub(crate) async fn post_scan_persist(") &&
        !webScanSource.includes("pub async fn scan_url(") &&
        !webScanSource.includes("#[tauri::command]"),
      "web_scan.rs must expose only the internal execution collector + persistence helper; the public scan_url command must stay retired.",
    );
  }

  failures.push(...inlineDurationFailures(read, exists, listFiles));

  failures.push(...releaseArtifactSafetyFailures(read, exists, listFiles));
  failures.push(...desktopOAuthSafetyFailures(read));
  failures.push(...privateStorageSafetyFailures(read));

  failures.push(...documentationSafetyFailures(read, exists, listFiles));
  failures.push(...emDashFailures(read, exists, listFiles));
  failures.push(...supportEmailLiteralFailures(read, exists, listFiles));
  failures.push(...pricingConsistencyFailures(read, exists));
  failures.push(...integrationUrlSecretFailures(read, exists, listFiles));
  failures.push(...scanPersistOffThreadFailures(read, exists));
  failures.push(...asyncCommandDbBlockingFailures(read, listFiles));
  const retiredDesktopTrialCommandSources = [
    "apps/desktop/src/hooks/useTier.tsx",
    "apps/desktop/src/lib/tauri-invoke.ts",
    "apps/desktop/src-tauri/build.rs",
    "apps/desktop/src-tauri/src/lib.rs",
    "apps/desktop/src-tauri/src/licensing/mod.rs",
    "apps/desktop/src-tauri/src/commands/privileged_command_broker/external_connectors.rs",
    "apps/desktop/src-tauri/src/commands/privileged_command_broker/data_admin.rs",
    "apps/desktop/src-tauri/permissions/default.toml",
    "apps/desktop/src-tauri/permissions/external_connectors.toml",
    "apps/desktop/src-tauri/permissions/data_admin.toml",
  ].map((file) => ({ file, source: read(file) }));
  const retiredDesktopTrialMatches = retiredDesktopTrialCommandSources
    .filter(({ source }) =>
      /\b(start_trial|get_trial_state|cancel_trial|validate_trial|StartTrialDialog|StartupTrialPrompt|TrialCountdownBanner|TrialEndedModal)\b/.test(
        source,
      ),
    )
    .map(({ file }) => file);
  check(
    retiredDesktopTrialMatches.length === 0,
    `Retired SiteCMD-managed trial commands and UI must not be reintroduced: ${retiredDesktopTrialMatches.join(", ")}`,
  );
  const sourceFiles = listFiles("apps/desktop/src", (file) => /\.(ts|tsx|css)$/.test(file));
  failures.push(...desktopCategoryLabelFailures(read, sourceFiles));
  failures.push(...desktopFrontendJsonSafetyFailures(read, sourceFiles));
  failures.push(...desktopFrontendDisplayFailures(read, sourceFiles));
  failures.push(...desktopFrontendStateFailures(read, sourceFiles));
  failures.push(...commandWrapperFailures(read, sourceFiles));
  failures.push(...queryLayerFailures(read, sourceFiles));
  failures.push(...eventFabricFailures(read, sourceFiles));
  failures.push(...appShellNavFailures(read, sourceFiles));
  failures.push(...desktopSecurityPageRemovalFailures(read, sourceFiles));
  failures.push(...desktopAnalyticsCacheFailures(read));
  failures.push(...desktopIssuesRetirementFailures(read, sourceFiles));
  failures.push(...issueStateSafetyFailures(read, exists, sourceFiles));
  failures.push(...verificationProvenanceFailures(read, exists));
  failures.push(...submissionOrderingFailures(read, exists, listFiles));
  failures.push(...connectedOutboxFailures(read, exists, listFiles));
  failures.push(...connectedBootstrapFailures(read, exists, listFiles));
  failures.push(...cliSurfaceFailures(read, exists, listFiles));
  failures.push(...publicationRecordFailures(read, exists, listFiles));
  failures.push(...syncPayloadFailures(read, exists, listFiles));
  failures.push(...unifiedScanArchitectureFailures(read, exists, listFiles));
  failures.push(...mcpSchemaParityFailures(read, listFiles));
  failures.push(...desktopDefensiveEmptyStatesFailures(read));
  failures.push(...desktopStyleConsistencyFailures(read, sourceFiles));
  failures.push(...handRolledDialogFailures(read, sourceFiles));
  failures.push(...desktopIssueStatusFailures(read, sourceFiles));
  failures.push(...reportScoreConsistencyFailures(read));
  failures.push(...desktopScanLabelFailures(read, sourceFiles));
  failures.push(...desktopScoreConsistencyFailures(read, sourceFiles));
  failures.push(...scoreArtifactLabelingFailures(read));
  failures.push(...desktopSeverityConsistencyFailures(read, sourceFiles));
  failures.push(...desktopSharedTypeFailures(read));
  failures.push(...desktopUpdateCommandFailures(read, sourceFiles));
  failures.push(...desktopUrlIdentityFailures(read, sourceFiles));
  const indexCss = read("apps/desktop/src/index.css");
  check(
    !/@import\s+url\(/.test(indexCss),
    "Do not import remote CSS/fonts from apps/desktop/src/index.css; bundle fonts/assets locally.",
  );

  failures.push(...invokeAclFailures(read, listFiles));

  const frontendLineBudgetOverrides = new Map([
    ["apps/desktop/src/index.css", 1905],
    ["apps/desktop/src/components/dashboard/SecurityPageSections.tsx", 990],
  ]);
  failures.push(
    ...frontendMaintainabilityFailures(read, listFiles, sourceFiles, frontendLineBudgetOverrides),
  );

  failures.push(...rustLineBudgetFailures(read, listFiles));

  failures.push(...desktopBoundaryFailures(read, readJson, exists, listFiles));

  failures.push(...crossSurfaceContractFailures(read));

  failures.push(...agentGuidanceFailures(read, exists, listFiles));
  failures.push(...versionSyncFailures(read));
  failures.push(...testWiringFailures(read, { root }));
  failures.push(...publicFaceFailures(read, exists, listFiles));

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
