export const guardrailScriptLineBudgets = new Map([
  ["tools/scripts/check-repo-guardrails.mjs", 550],
  ["tools/scripts/lib/guardrail-rust-loc-rules.mjs", 50],
  ["tools/scripts/lib/guardrail-script-budgets.mjs", 80],
  ["tools/scripts/lib/guardrail-code-scan-security-rules.mjs", 90],
  ["tools/scripts/lib/guardrail-doc-rules.mjs", 170],
  ["tools/scripts/lib/guardrail-update-rules.mjs", 60],
  ["tools/scripts/lib/guardrail-release-rules.mjs", 180],
  ["tools/scripts/lib/guardrail-release-workflow-rules.mjs", 70],
  ["tools/scripts/lib/guardrail-rust-rules.mjs", 120],
  ["tools/scripts/lib/guardrail-rust-ratchets.mjs", 120],
  ["tools/scripts/lib/guardrail-text-utils.mjs", 250],
  ["tools/scripts/lib/guardrail-workflow-rules.mjs", 190],
]);

export function checkGuardrailScriptLineBudgets(
  read,
  listFiles,
  check,
  directory = "tools/scripts/lib",
  budgets = guardrailScriptLineBudgets,
) {
  const effectiveGuardrailScriptLineBudgets = new Map(budgets);
  for (const file of listFiles(directory, (file) => /guardrail-[^/]+\.mjs$/.test(file))) {
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
}
