import assert from "node:assert/strict";
import { test } from "node:test";
import { closingQuota } from "../guest/closing-quota.mjs";
import { pilotPolicy } from "./workflow-pilot.mjs";

test("a pre-trial reading cannot stand in for post-trial quota evidence", async () => {
  const events = [];
  let time = 10000;
  const result = await closingQuota({
    baseline: {},
    currentPath: "fixture",
    billing: { quotaMaxAgeSeconds: 2 },
    endedAt: 9000,
    log: (...args) => events.push(args),
    now: () => time,
    wait: async () => {
      time += 1000;
    },
    read: () => ({ capturedAt: new Date(8000).toISOString() }),
  });
  assert.equal(result.quotaAllowed, false);
  assert.equal(time, 12000);
  assert.equal(events.length, 1);
});

test("fresh inactive-session evidence preserves the post-trial weekly allowance check", async () => {
  const now = Date.now();
  const baseline = {
    schemaVersion: 1,
    capturedAt: new Date(now - 120000).toISOString(),
    source: "Unit fixture, not provider evidence",
    accounts: ["codex", "claude"].map((provider) => ({
      provider,
      account: `${provider}-fixture`,
      authMode: "subscription",
      extraUsageEnabled: false,
      windows: [
        {
          id: "weekly",
          kind: "weekly",
          usedPercent: 10,
          resetsAt: new Date(now + 86400000).toISOString(),
        },
      ],
    })),
  };
  baseline.accounts[1].windows.push({
    id: "session",
    kind: "session",
    usedPercent: 34,
    resetsAt: new Date(now - 60000).toISOString(),
  });
  const current = structuredClone(baseline);
  current.capturedAt = new Date(now).toISOString();
  Object.assign(current.accounts[1].windows[1], {
    usedPercent: 0,
    resetsAt: null,
    inactive: true,
  });
  const check = (billing = pilotPolicy.billing, provider) =>
    closingQuota({
      baseline,
      currentPath: "fixture",
      billing,
      provider,
      endedAt: now - 500,
      log: () => {},
      now: () => now,
      read: () => current,
    });
  assert.equal((await check()).quotaAllowed, true);
  current.accounts[1].windows[0].usedPercent = 30;
  const result = await check();
  assert.equal(result.quotaAllowed, false);
  assert.match(result.blockers.join(" "), /20 percentage points/);
  const scoped = { ...pilotPolicy.billing, quotaScope: "active-provider" };
  assert.equal((await check(scoped, "codex")).quotaAllowed, true);
  assert.equal((await check(scoped, "claude")).quotaAllowed, false);
});
