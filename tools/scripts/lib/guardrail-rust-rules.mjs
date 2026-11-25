export function walkProdLines(source, onLine) {
  const lines = source.split("\n");
  let inTestMod = 0;
  let pendingTestMod = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*#\[cfg\(test\)\]/.test(line)) {
      pendingTestMod = true;
      continue;
    }
    if (pendingTestMod) {
      if (/\bmod\b.*\{/.test(line)) {
        inTestMod = 1;
        pendingTestMod = false;
        continue;
      }
      if (/[a-zA-Z]/.test(line.trim())) pendingTestMod = false;
    }
    if (inTestMod > 0) {
      for (const ch of line) {
        if (ch === "{") inTestMod++;
        else if (ch === "}") inTestMod--;
        if (inTestMod === 0) break;
      }
      continue;
    }
    onLine(line, i, lines);
  }
}

function countBareUnwrapsExcludingTests(source) {
  let count = 0;
  walkProdLines(source, (line) => {
    if (line.includes(".unwrap()") && !line.includes("// allow-unwrap")) count++;
  });
  return count;
}

const RUST_PROD_DIRS = ["apps/desktop/src-tauri/src/core", "apps/desktop/src-tauri/src/db"];

// Collect production sources for the Rust count ratchets.
export function collectProdRustFiles(_exists, listFiles, directories = RUST_PROD_DIRS) {
  return [
    ...directories.flatMap((dir) =>
      listFiles(dir, (file) => {
        if (!file.endsWith(".rs")) return false;
        if (/[/\\]tests[/\\]/.test(file)) return false;
        const name = file.split(/[/\\]/).pop();
        return !/(_tests?\.rs|^tests\.rs)$/.test(name);
      }),
    ),
  ];
}

export function rustUnwrapBudgetFailures(
  read,
  exists,
  listFiles,
  {
    directories,
    unwrapBudgets = new Map(),
    budgetFile = "tools/scripts/lib/guardrail-rust-rules.mjs",
  } = {},
) {
  const files = collectProdRustFiles(exists, listFiles, directories);
  const failures = [];
  for (const file of files) {
    const count = countBareUnwrapsExcludingTests(read(file));
    const budget = unwrapBudgets.get(file) ?? 0;
    if (count > budget) {
      failures.push(
        `${file}: ${count} bare \`.unwrap()\` (budget ${budget}); use \`.expect("static reason")\` or reduce the budget in ${budgetFile}`,
      );
    }
  }
  return failures;
}
