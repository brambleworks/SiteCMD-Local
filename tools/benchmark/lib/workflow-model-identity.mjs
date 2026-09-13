import { digest } from "./workflow-plan.mjs";
import { parseProviderTranscript, terminalProviderEvent } from "./workflow-provider-transcript.mjs";

const modelName = (value) => typeof value === "string" && /^[a-zA-Z0-9][\w.-]{0,199}$/.test(value);
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function modelClaims(agent, event) {
  const configured = [];
  const observations = [];
  let unidentifiedResponse = false;
  if (!object(event)) return { configured, observations, unidentifiedResponse };
  if (agent === "claude") {
    if (event.type === "system" && event.subtype === "init" && modelName(event.model))
      configured.push(event.model);
    if (event.type === "assistant") {
      if (!event.error && modelName(event.message?.id) && modelName(event.message?.model))
        observations.push({ source: "assistant.message.model", model: event.message.model });
      else unidentifiedResponse = true;
    }
    if (event.type === "result" && object(event.modelUsage))
      for (const model of Object.keys(event.modelUsage)) {
        if (modelName(model) && object(event.modelUsage[model]))
          observations.push({ source: "result.modelUsage", model });
        else unidentifiedResponse = true;
      }
  } else if (
    agent === "codex" &&
    ["thread.started", "turn.started", "turn.completed"].includes(event.type) &&
    modelName(event.model)
  )
    configured.push(event.model);
  return { configured, observations, unidentifiedResponse };
}

export function summarizeModelIdentity(agent, requested, transcript, evidenceComplete) {
  const configured = new Set();
  const observations = [];
  const unidentifiedResponseLines = [];
  const { events, invalidLines } = parseProviderTranscript(transcript);
  for (const { event, line } of events) {
    const claims = modelClaims(agent, event);
    claims.configured.forEach((model) => configured.add(model));
    observations.push(...claims.observations.map((claim) => ({ line, ...claim })));
    if (claims.unidentifiedResponse) unidentifiedResponseLines.push(line);
  }
  const observed = [...new Set(observations.map(({ model }) => model))].sort();
  const terminal = terminalProviderEvent(agent, events);
  const providerCompleted =
    terminal !== null &&
    (agent === "codex" || (terminal.subtype === "success" && terminal.is_error === false));
  const assurance = agent === "codex" ? "explicit-cli-selection" : "provider-response-metadata";
  const configuredMatches = [...configured].every((model) => model === requested);
  const verified =
    agent === "codex"
      ? evidenceComplete === true &&
        providerCompleted &&
        invalidLines.length === 0 &&
        observed.length === 0 &&
        configuredMatches
      : evidenceComplete === true &&
        providerCompleted &&
        invalidLines.length === 0 &&
        unidentifiedResponseLines.length === 0 &&
        observations.some(({ source }) => source === "assistant.message.model") &&
        observed.length === 1 &&
        observed[0] === requested &&
        configuredMatches;
  return {
    schemaVersion: 1,
    agent,
    requested,
    transcriptSha256: digest(transcript),
    evidenceComplete: evidenceComplete === true,
    providerCompleted,
    assurance,
    configured: [...configured].sort(),
    observed,
    observations,
    unidentifiedResponseLines,
    invalidLines,
    verified,
  };
}
