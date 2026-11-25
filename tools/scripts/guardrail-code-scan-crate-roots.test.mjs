import { ENGINE_CRATES } from "./lib/publication-history-rules.mjs";
import { expect, test } from "vitest";
import { exportedTree, realRead, ROOT } from "./guardrail-test-support.mjs";
import { codeScanHostBoundaryFailures } from "./lib/guardrail-code-scan-host-boundary.mjs";
import { runtimeBoundaryFailures } from "./lib/guardrail-runtime-boundary-rules.mjs";
import { overlayIo } from "./lib/repo-overlay-io.mjs";

const releaseCheck = { releaseWorkflow: !exportedTree };

test.each(ENGINE_CRATES.map((name) => name.replaceAll("-", "_")))(
  "autofix refuses direct imports from %s",
  (crate) => {
    // Bug: Outbound autofix text can rely on a private crate's redaction.
    const file = "apps/desktop/src-tauri/src/cli/autofix/exit_check.rs";
    const message = `Autofix must use public engine host and protocol APIs: ${file}`;
    const original = overlayIo(ROOT, new Map());
    expect(codeScanHostBoundaryFailures(original.read, original.listFiles)).not.toContain(message);
    const io = overlayIo(
      ROOT,
      new Map([[file, `${realRead(file)}\nuse ${crate} as private_crate;`]]),
    );
    expect(codeScanHostBoundaryFailures(io.read, io.listFiles)).toContain(message);
  },
);

test("requires scan run persistence to use a transaction", () => {
  // Bug: A failed projection update could leave a run committed without its findings.
  const file = "apps/desktop/src-tauri/src/db/scan_runs.rs";
  const source = realRead(file);
  const io = overlayIo(ROOT, new Map([[file, source.replace("conn.transaction()?", "conn")]]));
  expect(runtimeBoundaryFailures(io.read, io.listFiles, [], releaseCheck).join("\n")).toContain(
    `${file}::persist_run_batch`,
  );
});

test.each([
  [
    "admit_scan_execution",
    `let tx = conn
                    .transaction()
                    .map_err(|error| ScanAdmissionError::Storage(error.to_string()))?;`,
  ],
  ["finish_scan_execution_component", "let tx = conn.transaction()?;"],
])("requires %s to use a transaction", (operation, transaction) => {
  // Bug: Removing the transaction could commit only part of the execution update.
  const file = "apps/desktop/src-tauri/src/db/scan_executions.rs";
  const source = realRead(file);
  const withoutTransaction = source.replace(transaction, "let tx = conn;");
  expect(withoutTransaction).not.toBe(source);
  const io = overlayIo(ROOT, new Map([[file, withoutTransaction]]));
  expect(runtimeBoundaryFailures(io.read, io.listFiles, [], releaseCheck)).toContain(
    `Multi-step DB writes must run inside a transaction: ${file}::${operation}`,
  );
});
