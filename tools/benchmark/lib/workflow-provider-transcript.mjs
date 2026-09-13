export function parseProviderTranscript(transcript) {
  const events = [];
  const invalidLines = [];
  for (const [index, line] of transcript.split("\n").entries()) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line);
      if (!event || typeof event !== "object" || Array.isArray(event))
        throw new Error("Not a provider event");
      events.push({ event, line: index + 1 });
    } catch {
      invalidLines.push(index + 1);
    }
  }
  return { events, invalidLines };
}

/** A final receipt must close one invocation, with no unaccounted events after it. */
export function terminalProviderEvent(agent, events) {
  const last = events.at(-1)?.event;
  if (agent === "claude")
    return last?.type === "result" &&
      events.filter(({ event }) => event.type === "result").length === 1
      ? last
      : null;
  if (agent !== "codex" || last?.type !== "turn.completed") return null;
  const lifecycle = events
    .map(({ event }) => event.type)
    .filter((type) =>
      ["thread.started", "turn.started", "turn.completed", "turn.failed"].includes(type),
    );
  return JSON.stringify(lifecycle) === '["thread.started","turn.started","turn.completed"]'
    ? last
    : null;
}
