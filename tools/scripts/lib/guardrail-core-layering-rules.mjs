import { walkProdLines } from "./guardrail-rust-rules.mjs";

const CORE_DIRS = ["apps/desktop/src-tauri/src/core"];

function isTestFile(file) {
  if (/[/\\]tests[/\\]/.test(file)) return true;
  const name = file.split(/[/\\]/).pop();
  return /(_tests?\.rs|^tests\.rs)$/.test(name);
}

export function coreLayeringFailures(read, listFiles, extraRoots = []) {
  const failures = [];
  const files = [...CORE_DIRS, ...extraRoots].flatMap((dir) =>
    listFiles(dir, (file) => file.endsWith(".rs") && !isTestFile(file)),
  );
  for (const file of files) {
    walkProdLines(read(file), (line, index) => {
      // Only executable references violate the dependency boundary.
      if (line.trim().startsWith("//")) return;
      if (line.includes("crate::commands")) {
        failures.push(
          `${file}:${index + 1} - src/core must not reference crate::commands (layering inversion audit 5.1). Move the shared logic into core, or have the command handler pass it in.`,
        );
      }
    });
  }
  return failures;
}
