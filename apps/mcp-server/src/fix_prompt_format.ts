import { formatCausalityBlock } from "./causal_graph.js";
import type { FixPromptRow } from "./db.js";
import { formatBoundedEntries } from "./output_budget.js";
import { quoteUntrustedText } from "./untrusted.js";

const MAX_BODY_CHARS = 24000;

/** Identical guidance is shared; prompts with distinct occurrence context remain separate. */
export function uniqueFixPrompts(prompts: FixPromptRow[]): FixPromptRow[] {
  const seen = new Set<string>();
  return prompts.filter((prompt) => {
    const key = JSON.stringify([
      prompt.check_id,
      prompt.title,
      prompt.severity,
      prompt.category,
      prompt.fix_prompt,
    ]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Bound the escaped batch, including metadata and causal context. */
export function formatFixPromptBatch(prompts: FixPromptRow[], activeCheckIds: Set<string>) {
  return formatBoundedEntries(
    prompts,
    (prompt) => {
      const causal = formatCausalityBlock(prompt.check_id, activeCheckIds);
      const blocks = [
        `## ${quoteUntrustedText(prompt.title, 500)}`,
        `**Severity:** ${quoteUntrustedText(prompt.severity, 100)} | **Category:** ${quoteUntrustedText(prompt.category, 100)} | **Check:** ${quoteUntrustedText(prompt.check_id, 200)}`,
      ];
      if (causal) blocks.push("", causal);
      blocks.push("", quoteUntrustedText(prompt.fix_prompt, 20000), "", "---");
      return blocks.join("\n");
    },
    MAX_BODY_CHARS,
  );
}
