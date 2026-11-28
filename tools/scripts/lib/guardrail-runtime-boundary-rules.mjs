import { sitecmdArtifactFailures } from "./guardrail-sitecmd-artifact-rules.mjs";
import { codeScanSecurityFailures } from "./guardrail-code-scan-security-rules.mjs";
import { releaseWorkflowSafetyFailures } from "./guardrail-release-workflow-rules.mjs";
import { tracingInstrumentAttributes } from "./guardrail-text-utils.mjs";
import { functionBodyContains } from "./guardrail-rust-function.mjs";

export function runtimeBoundaryFailures(
  read,
  listFiles,
  extraRoots = [],
  { releaseWorkflow = true } = {},
) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };

  const nativeRustFiles = ["apps/desktop/src-tauri/src", ...extraRoots].flatMap((dir) =>
    listFiles(dir, (file) => file.endsWith(".rs")),
  );
  const unsafeTracingFields = [];
  const unsafeTracingFieldNames = [
    "raw",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "authorization",
    "database_url",
    "db_url",
    "path",
    "src_path",
    "dest_path",
    "source_path",
    "project_path",
    "project_root",
    "root",
    "env_file_path",
    "working_dir",
    "dir",
    "url",
    "site_url",
    "page_url",
    "env_url",
    "environment_url",
    "monitor_url",
    "sitemap_url",
  ];
  for (const file of nativeRustFiles) {
    const source = read(file);
    for (const attribute of tracingInstrumentAttributes(source)) {
      const normalizedAttribute = attribute.text.toLowerCase().replace(/\s+/g, "");
      const hasUnsafeTracingField =
        normalizedAttribute.includes("fields(") &&
        unsafeTracingFieldNames.some(
          (field) =>
            normalizedAttribute.includes(`fields(${field}=`) ||
            normalizedAttribute.includes(`,${field}=`),
        );
      if (hasUnsafeTracingField) unsafeTracingFields.push(`${file}:${attribute.line}`);
    }
  }
  check(
    unsafeTracingFields.length === 0,
    `tracing::instrument fields must not record raw or secret-like values; use skip(...) and log parsed safe metadata instead: ${unsafeTracingFields.join(", ")}`,
  );

  const releaseWorkflowFailures = releaseWorkflowSafetyFailures(read, { releaseWorkflow });
  check(
    releaseWorkflowFailures.length === 0,
    `Release workflow guardrails failed: ${releaseWorkflowFailures.join("; ")}`,
  );
  failures.push(...codeScanSecurityFailures(read), ...sitecmdArtifactFailures(read, listFiles));

  const transactionalDbWrites = [
    ["apps/desktop/src-tauri/src/db/scan_runs.rs", "persist_run_batch"],
    ["apps/desktop/src-tauri/src/db/scan_executions.rs", "admit_scan_execution"],
    ["apps/desktop/src-tauri/src/db/scan_executions.rs", "finish_scan_execution_component"],
  ];
  const nonTransactionalWrites = transactionalDbWrites
    .filter(
      ([file, functionName]) => !functionBodyContains(read(file), functionName, ".transaction("),
    )
    .map(([file, functionName]) => `${file}::${functionName}`);
  check(
    nonTransactionalWrites.length === 0,
    `Multi-step DB writes must run inside a transaction: ${nonTransactionalWrites.join(", ")}`,
  );

  const packageJson = JSON.parse(read("package.json"));
  const guardrailTestSweep = packageJson.scripts?.["guardrails:repo:test"] ?? "";
  check(
    packageJson.scripts?.test?.includes("pnpm run guardrails:repo:test") &&
      guardrailTestSweep.startsWith("vitest run ") &&
      guardrailTestSweep.split(/\s+/).includes("tools/scripts"),
    "Repo guardrails must run the full tools/scripts vitest sweep from root pnpm test.",
  );

  return failures;
}
