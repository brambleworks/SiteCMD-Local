import { parseProviderTranscript, terminalProviderEvent } from "./workflow-provider-transcript.mjs";
import { claudeUsage, codexUsage } from "./workflow-usage.mjs";

/** Account for terminal provider receipts independently of process exit status. */
export function trialUsage(
  agent,
  transcript,
  { agentInvoked = true, evidenceComplete = true } = {},
) {
  const unknown = {
    inputTokens: null,
    outputTokens: null,
    cacheReadTokens: null,
    cacheWriteTokens: null,
    includesAllAgents: false,
    costUsd: null,
    costBasis: "subscription",
    incrementalCostUsd: null,
    apiEquivalentCostUsd: null,
    receipt: "usage.json",
  };
  if (!agentInvoked)
    return {
      ...unknown,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      includesAllAgents: true,
      incrementalCostUsd: 0,
    };
  const { events, invalidLines } = parseProviderTranscript(transcript);
  const terminal = terminalProviderEvent(agent, events);
  if (!evidenceComplete || invalidLines.length || !terminal) return unknown;
  const options = { noSubagents: true, billingMode: "subscription", incrementalCostUsd: 0 };
  return agent === "claude" ? claudeUsage(terminal, options) : codexUsage(terminal, options);
}
