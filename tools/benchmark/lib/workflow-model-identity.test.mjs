import assert from "node:assert/strict";
import { test } from "node:test";
import { summarizeModelIdentity } from "./workflow-model-identity.mjs";
import { digest } from "./workflow-plan.mjs";

const requested = "claude-opus-5";
const jsonl = (...events) => events.map((event) => JSON.stringify(event)).join("\n");

test("identity evidence identifies the response fields and their transcript lines", () => {
  const transcript = jsonl(
    { type: "system", subtype: "init", model: requested },
    { type: "assistant", message: { id: "message-1", model: requested } },
    {
      type: "result",
      subtype: "success",
      is_error: false,
      modelUsage: { [requested]: { inputTokens: 4, outputTokens: 2 } },
    },
  );
  const result = summarizeModelIdentity("claude", requested, transcript, true);
  assert.equal(result.transcriptSha256, digest(transcript));
  assert.deepEqual(result.observed, [requested]);
  assert.deepEqual(result.configured, [requested]);
  assert.deepEqual(result.observations, [
    { line: 2, source: "assistant.message.model", model: requested },
    { line: 3, source: "result.modelUsage", model: requested },
  ]);
  assert.equal(result.verified, true);
});

test("partial transcripts cannot establish identity for the complete invocation", () => {
  const response = { type: "assistant", message: { id: "message-1", model: requested } };
  const terminal = { type: "result", subtype: "success", is_error: false };
  for (const transcript of [
    jsonl(response),
    jsonl(response, { ...terminal, is_error: true }),
    jsonl(response, terminal, terminal),
    `${jsonl(response, terminal)}\n{`,
    `${jsonl(response, terminal)}\nnull`,
  ]) {
    assert.equal(summarizeModelIdentity("claude", requested, transcript, true).verified, false);
  }
  assert.equal(
    summarizeModelIdentity("claude", requested, jsonl(response, terminal), false).verified,
    false,
  );
});

test("error messages and invalid response metadata cannot verify identity", () => {
  for (const event of [
    { type: "assistant", error: "model_not_found", message: { id: "error", model: requested } },
    { type: "assistant", message: { model: requested } },
    { type: "result", modelUsage: { [requested]: null } },
  ]) {
    const result = summarizeModelIdentity("claude", requested, jsonl(event), true);
    assert.equal(result.verified, false, JSON.stringify(event));
    assert.deepEqual(result.observed, []);
    assert.deepEqual(result.unidentifiedResponseLines, [1]);
  }
});

test("Codex configuration echoes and foreign event formats stay unverified", () => {
  const model = "gpt-5.6-sol";
  const transcript = jsonl(
    { type: "thread.started", model },
    { type: "turn.completed", model, usage: { input_tokens: 1 } },
    { type: "assistant", message: { id: "foreign-message", model } },
    { type: "result", subtype: "success", is_error: false, modelUsage: { [model]: {} } },
  );
  const result = summarizeModelIdentity("codex", model, transcript, true);
  assert.deepEqual(result.configured, [model]);
  assert.deepEqual(result.observed, []);
  assert.equal(result.verified, false);
});

test("a complete Codex stream verifies the strict CLI selection without inventing response metadata", () => {
  const model = "gpt-daybreak-blue-latest";
  const transcript = jsonl(
    { type: "thread.started", thread_id: "thread-1" },
    { type: "turn.started" },
    { type: "item.completed", item: { type: "agent_message", text: "Done" } },
    { type: "turn.completed", usage: { input_tokens: 10, output_tokens: 2 } },
  );
  const result = summarizeModelIdentity("codex", model, transcript, true);
  assert.equal(result.providerCompleted, true);
  assert.equal(result.assurance, "explicit-cli-selection");
  assert.equal(result.verified, true);
  assert.deepEqual(result.observed, []);
});

test("a missing response identity or a conflicting model blocks verification", () => {
  const terminal = {
    type: "result",
    subtype: "success",
    is_error: false,
    modelUsage: { [requested]: {} },
  };
  for (const event of [
    { type: "assistant", message: { id: "missing-model" } },
    { type: "assistant", message: { id: "different-response", model: "different-model" } },
    { type: "system", subtype: "init", model: "different-model" },
  ]) {
    assert.equal(
      summarizeModelIdentity("claude", requested, jsonl(event, terminal), true).verified,
      false,
    );
  }
});

test("aggregate model usage alone cannot prove a complete response trace", () => {
  const transcript = jsonl({
    type: "result",
    subtype: "success",
    is_error: false,
    modelUsage: { [requested]: { inputTokens: 4, outputTokens: 2 } },
  });
  const result = summarizeModelIdentity("claude", requested, transcript, true);
  assert.deepEqual(result.observed, [requested]);
  assert.equal(result.verified, false);
});

test("out-of-order or reopened invocations cannot verify a complete model selection", () => {
  const start = { type: "thread.started" };
  const turn = { type: "turn.started" };
  const end = { type: "turn.completed" };
  for (const events of [
    [turn, start, end],
    [start, turn, { type: "turn.failed" }, end],
    [start, turn, end, { type: "item.completed" }],
  ])
    assert.equal(
      summarizeModelIdentity("codex", "gpt-6-astra", jsonl(...events), true).verified,
      false,
    );
});
