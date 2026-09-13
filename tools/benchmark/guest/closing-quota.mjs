import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { evaluateQuota } from "../lib/workflow-quota.mjs";

export async function closingQuota({
  baseline,
  currentPath,
  billing,
  provider,
  endedAt,
  log,
  now = Date.now,
  wait = delay,
  read = (file) => JSON.parse(readFileSync(file)),
}) {
  const deadline = now() + billing.quotaMaxAgeSeconds * 1000;
  while (now() < deadline) {
    try {
      const current = read(currentPath);
      if (Date.parse(current.capturedAt) >= endedAt) {
        const result = evaluateQuota(baseline, current, billing, now(), provider);
        log("quota-events.jsonl", { closing: true, current, result });
        return result;
      }
    } catch {
      // An incomplete operator update is not quota evidence.
    }
    await wait(1000);
  }
  const result = {
    quotaAllowed: false,
    blockers: ["Fresh post-trial quota readings were not supplied; batch paused"],
  };
  log("quota-events.jsonl", { closing: true, result });
  return result;
}
