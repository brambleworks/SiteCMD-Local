import assert from "node:assert/strict";
import { test } from "node:test";
import { trialUsage } from "./workflow-trial-usage.mjs";
import { totalTokens } from "./workflow-usage.mjs";

const jsonl = (...events) => events.map((event) => JSON.stringify(event)).join("\n");
const start = [{ type: "thread.started" }, { type: "turn.started" }];
const terminal = {
  type: "turn.completed",
  usage: { input_tokens: 100, cached_input_tokens: 60, output_tokens: 20 },
};

test("a completed turn accounts for cached inputs exactly once", () => {
  const usage = trialUsage("codex", jsonl(...start, terminal));
  assert.equal(usage.inputTokens, 40);
  assert.equal(usage.cacheReadTokens, 60);
  assert.equal(totalTokens(usage), 120);
  assert.equal(usage.incrementalCostUsd, 0);
});

test("partial, contradictory, duplicated, or truncated streams remain unmeasured", () => {
  for (const transcript of [
    "",
    jsonl(...start),
    jsonl(terminal),
    jsonl(start[1], start[0], terminal),
    jsonl(...start, { type: "turn.failed" }, terminal),
    jsonl(...start, terminal, terminal),
    jsonl(...start, terminal, ...start),
    jsonl(...start, terminal, { type: "item.completed" }),
    `${jsonl(...start, terminal)}\n{`,
    `${jsonl(...start, terminal)}\nnull`,
  ]) {
    const usage = trialUsage("codex", transcript);
    assert.equal(totalTokens(usage), null, transcript);
    assert.equal(usage.includesAllAgents, false);
    assert.equal(usage.incrementalCostUsd, null);
  }
  assert.equal(
    totalTokens(trialUsage("codex", jsonl(...start, terminal), { evidenceComplete: false })),
    null,
  );
});

test("Claude error results retain complete usage without becoming successful responses", () => {
  const result = {
    type: "result",
    subtype: "error_max_turns",
    is_error: true,
    modelUsage: {
      "claude-opus-5": {
        inputTokens: 100,
        outputTokens: 20,
        cacheReadInputTokens: 60,
        cacheCreationInputTokens: 10,
      },
    },
  };
  assert.equal(totalTokens(trialUsage("claude", jsonl(result))), 190);
  assert.equal(totalTokens(trialUsage("claude", jsonl(result, result))), null);
  assert.equal(totalTokens(trialUsage("claude", jsonl(result, { type: "assistant" }))), null);
});

test("only a controller-confirmed uninvoked client receives zero usage", () => {
  const denial = jsonl({ type: "error", message: "Unauthorized" }, { type: "turn.failed" });
  assert.equal(totalTokens(trialUsage("codex", denial)), null);
  assert.equal(totalTokens(trialUsage("codex", denial, { agentInvoked: false })), 0);
});

test("malformed terminal token fields cannot produce a total", () => {
  for (const usage of [
    {},
    { input_tokens: 100, cached_input_tokens: 101, output_tokens: 20 },
    { input_tokens: 100, cached_input_tokens: 60, output_tokens: -1 },
    { input_tokens: "100", cached_input_tokens: 60, output_tokens: 20 },
  ])
    assert.equal(totalTokens(trialUsage("codex", jsonl(...start, { ...terminal, usage }))), null);
});
