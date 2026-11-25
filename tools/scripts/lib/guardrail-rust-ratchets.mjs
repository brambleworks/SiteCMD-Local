import { collectProdRustFiles, walkProdLines } from "./guardrail-rust-rules.mjs";

function countBareExpectsExcludingTests(source) {
  let count = 0;
  walkProdLines(source, (line) => {
    if (/\.expect\(/.test(line) && !line.includes("// allow-expect")) count++;
  });
  return count;
}

const INLINE_DURATION_RE = /Duration::from_(secs|millis|micros|nanos)\(/;

function countInlineDurationsExcludingTests(source) {
  let count = 0;
  walkProdLines(source, (line, i, lines) => {
    if (!INLINE_DURATION_RE.test(line)) return;
    if (line.includes("// allow-inline-duration")) return;
    let j = i - 1;
    while (j >= 0 && lines[j].trim() === "") j--;
    if (j >= 0 && lines[j].includes("// allow-inline-duration")) return;
    count++;
  });
  return count;
}

// Override an intentional panic with `// allow-expect:` and a reason.
const EXPECT_BUDGETS = new Map([["apps/desktop/src-tauri/src/db/test_helpers.rs", 4]]);

// Inline durations require an `allow-inline-duration` reason on the call or
// immediately preceding non-empty line.
const INLINE_DURATION_BUDGETS = new Map([
  ["apps/desktop/src-tauri/src/core/git.rs", 4],
  ["apps/desktop/src-tauri/src/dns_cache.rs", 2],
  ["apps/desktop/src-tauri/src/cli/watch.rs", 1],
]);

export function rustRatchetFailures(
  read,
  exists,
  listFiles,
  {
    directories,
    expectBudgets = EXPECT_BUDGETS,
    budgetFile = "tools/scripts/lib/guardrail-rust-ratchets.mjs",
  } = {},
) {
  const files = collectProdRustFiles(exists, listFiles, directories);
  const failures = [];
  for (const file of files) {
    const source = read(file);
    const expectCount = countBareExpectsExcludingTests(source);
    const expectBudget = expectBudgets.get(file) ?? 0;
    if (expectCount > expectBudget) {
      failures.push(
        `${file}: ${expectCount} bare \`.expect()\` (budget ${expectBudget}); recover the error or add \`// allow-expect:\` with a justification, or reduce the budget in ${budgetFile}`,
      );
    }
    const durationCount = countInlineDurationsExcludingTests(source);
    const durationBudget = INLINE_DURATION_BUDGETS.get(file) ?? 0;
    if (durationCount > durationBudget) {
      failures.push(
        `${file}: ${durationCount} inline \`Duration::from_*\` outside constants.rs (budget ${durationBudget}); move to constants.rs or add \`// allow-inline-duration:\` with a justification, or reduce the budget in ${budgetFile}`,
      );
    }
  }
  return failures;
}
