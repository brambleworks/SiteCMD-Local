import assert from "node:assert/strict";
import { test } from "node:test";
import {
  carryForwardQuotaUsage,
  evaluateQuota,
  verifyQuotaUsageContinuity,
} from "./workflow-quota.mjs";
import { pilotPolicy } from "./workflow-pilot.mjs";

const NOW = Date.parse("2026-09-03T16:00:00Z");
function snapshot(capturedAt = "2026-09-03T16:00:00Z") {
  return {
    schemaVersion: 1,
    capturedAt,
    source: "Test fixture, not an account reading",
    accounts: ["codex", "claude"].map((provider) => ({
      provider,
      account: `${provider}-test-account`,
      authMode: "subscription",
      extraUsageEnabled: false,
      windows: [
        { id: "weekly", kind: "weekly", usedPercent: 10, resetsAt: "2026-09-07T00:00:00Z" },
        { id: "session", kind: "session", usedPercent: 20, resetsAt: "2026-09-03T18:00:00Z" },
      ],
    })),
  };
}

test("the pilot allows only forty-five assignments, exact models, and no additional spending", () => {
  assert.equal(
    pilotPolicy.caseCount *
      pilotPolicy.models.length *
      pilotPolicy.arms.length *
      pilotPolicy.repeats,
    45,
  );
  assert.deepEqual(
    pilotPolicy.models.map((item) => item.model),
    ["gpt-5.6-sol", "claude-opus-5", "gpt-6-astra"],
  );
  assert.equal(pilotPolicy.limits.studyCostUsd, 0);
  assert.equal(pilotPolicy.limits.trialSeconds, 1200);
  assert.equal(pilotPolicy.limits.submissions, 3);
});

test("quota checks both subscriptions and pauses when either weekly allocation is consumed", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const current = snapshot();
  const check = () => evaluateQuota(baseline, current, pilotPolicy.billing, NOW);
  assert.equal(check().quotaAllowed, true);
  current.accounts[1].windows[0].usedPercent = 30;
  assert.equal(check().quotaAllowed, false);
  assert.match(check().blockers.join("\n"), /claude.*20 percentage points/);
  current.accounts[1].windows[0].usedPercent = 29;
  current.accounts[0].windows[1].usedPercent = 71;
  assert.match(check().blockers.join("\n"), /codex.*30%/);
});

test("active-provider budgets do not interrupt a trial for an unrelated account limit", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const current = snapshot();
  const billing = { ...pilotPolicy.billing, quotaScope: "active-provider" };
  current.accounts[1].windows[1].usedPercent = 95;
  current.accounts[1].windows[0].usedPercent = 50;
  assert.equal(evaluateQuota(baseline, current, billing, NOW, "codex").quotaAllowed, true);
  assert.equal(evaluateQuota(baseline, current, billing, NOW, "claude").quotaAllowed, false);
  assert.equal(evaluateQuota(baseline, current, billing, NOW).quotaAllowed, false);
  assert.equal(
    evaluateQuota(baseline, current, pilotPolicy.billing, NOW, "codex").quotaAllowed,
    false,
  );
  current.accounts[0].windows[0].usedPercent = 30;
  assert.equal(evaluateQuota(baseline, current, billing, NOW, "codex").quotaAllowed, false);
});

test("provider-scoped budgets retain identity, freshness, and no-paid-usage checks", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const billing = { ...pilotPolicy.billing, quotaScope: "active-provider" };
  for (const change of [
    (value) => {
      value.accounts[1].extraUsageEnabled = true;
    },
    (value) => {
      value.accounts[1].authMode = "api";
    },
    (value) => {
      value.accounts[1].account = "another-account";
    },
    (value) => {
      value.capturedAt = "2026-09-03T15:30:00Z";
    },
  ]) {
    const current = snapshot();
    change(current);
    assert.equal(evaluateQuota(baseline, current, billing, NOW, "codex").quotaAllowed, false);
  }
  assert.throws(() => evaluateQuota(baseline, snapshot(), billing, NOW, "unknown"), /provider/i);
  assert.throws(
    () => evaluateQuota(baseline, snapshot(), { ...billing, quotaScope: "none" }, NOW),
    /scope/i,
  );
});

test("unknown, stale, reset, and differently authenticated quotas cannot authorize a trial", () => {
  for (const [change, message] of [
    [
      (item) => {
        item.capturedAt = "2026-09-03T15:54:59Z";
      },
      /stale/,
    ],
    [
      (item) => {
        item.capturedAt = "2026-09-03T16:00:01Z";
      },
      /future/,
    ],
    [
      (item) => {
        item.accounts[0].windows[0].usedPercent = null;
      },
      /unknown/,
    ],
    [
      (item) => {
        item.accounts[0].windows[0].resetsAt = null;
      },
      /unknown/,
    ],
    [
      (item) => {
        item.accounts[0].windows[0].resetsAt = "2026-09-14T00:00:00Z";
      },
      /rebase/,
    ],
    [
      (item) => {
        item.accounts[0].windows[0].usedPercent = 9;
      },
      /decreased/,
    ],
    [
      (item) => {
        item.accounts[0].account = "replacement-account";
      },
      /account changed/,
    ],
    [
      (item) => {
        item.accounts[1].authMode = "api";
      },
      /authentication/,
    ],
    [
      (item) => {
        item.accounts[1].extraUsageEnabled = null;
      },
      /verified disabled/,
    ],
    [
      (item) => {
        item.accounts[1].extraUsageEnabled = true;
      },
      /verified disabled/,
    ],
    [
      (item) => {
        item.accounts[0].windows.pop();
      },
      /missing/,
    ],
  ]) {
    const baseline = snapshot("2026-09-03T15:00:00Z");
    const current = snapshot();
    change(current);
    const result = evaluateQuota(baseline, current, pilotPolicy.billing, NOW);
    assert.equal(result.quotaAllowed, false);
    assert.match(result.blockers.join("\n"), message);
  }
});

test("malformed or missing accounts and windows fail closed", () => {
  for (const change of [
    (item) => {
      item.accounts.pop();
    },
    (item) => {
      item.accounts[1] = item.accounts[0];
    },
    (item) => {
      item.accounts[0].windows.pop();
      item.accounts[0].windows[0].kind = "session";
    },
    (item) => {
      item.accounts[0].windows[0].usedPercent = 101;
    },
    (item) => {
      delete item.accounts[0].windows[0].usedPercent;
    },
    (item) => {
      item.accounts[0].windows.push(item.accounts[0].windows[0]);
    },
  ]) {
    const current = snapshot();
    change(current);
    assert.throws(() => evaluateQuota(snapshot(), current, pilotPolicy.billing, NOW));
  }
});

test("a real session reset does not replenish the frozen weekly budget", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const current = snapshot("2026-09-03T18:01:00Z");
  for (const account of current.accounts) {
    account.windows[1].usedPercent = 0;
    account.windows[1].resetsAt = "2026-09-03T23:00:00Z";
  }
  const later = Date.parse(current.capturedAt);
  assert.equal(evaluateQuota(baseline, current, pilotPolicy.billing, later).quotaAllowed, true);
  current.accounts[0].windows[0].usedPercent = 30;
  assert.equal(evaluateQuota(baseline, current, pilotPolicy.billing, later).quotaAllowed, false);
});

test("a reset session can be explicitly inactive without inventing a reset date", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const current = snapshot("2026-09-03T18:01:00Z");
  current.accounts[0].windows[1].resetsAt = "2026-09-03T23:00:00Z";
  Object.assign(current.accounts[1].windows[1], {
    usedPercent: 0,
    resetsAt: null,
    inactive: true,
  });
  const result = evaluateQuota(
    baseline,
    current,
    pilotPolicy.billing,
    Date.parse(current.capturedAt),
  );
  assert.deepEqual(result.blockers, []);
  assert.equal(result.quotaAllowed, true);
});

test("an inactive baseline session can stay idle and later start a new session", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  Object.assign(baseline.accounts[1].windows[1], {
    usedPercent: 0,
    resetsAt: null,
    inactive: true,
  });
  const current = structuredClone(baseline);
  current.capturedAt = "2026-09-03T16:00:00Z";
  const check = () => evaluateQuota(baseline, current, pilotPolicy.billing, NOW);
  assert.equal(check().quotaAllowed, true);
  Object.assign(current.accounts[1].windows[1], {
    usedPercent: 5,
    resetsAt: "2026-09-03T21:00:00Z",
  });
  delete current.accounts[1].windows[1].inactive;
  assert.equal(check().quotaAllowed, true);
  current.accounts[1].windows[1].usedPercent = 71;
  assert.match(check().blockers.join("\n"), /30% remaining/);
});

test("inactive sessions do not exempt weekly limits, evidence freshness or reset chronology", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const current = snapshot("2026-09-03T18:01:00Z");
  current.accounts[0].windows[1].resetsAt = "2026-09-03T23:00:00Z";
  Object.assign(current.accounts[1].windows[1], {
    usedPercent: 0,
    resetsAt: null,
    inactive: true,
  });
  const later = Date.parse(current.capturedAt);
  for (const [change, pattern] of [
    [
      (item) => {
        item.accounts[1].windows[0].usedPercent = 30;
      },
      /20 percentage points/,
    ],
    [
      (item) => {
        item.accounts[0].windows[0].usedPercent = 71;
      },
      /30% remaining/,
    ],
    [
      (item) => {
        item.capturedAt = "2026-09-03T17:59:59Z";
      },
      /before its recorded reset/,
    ],
    [
      (item) => {
        item.capturedAt = "2026-09-03T18:06:01Z";
      },
      /future/,
    ],
    [
      (item) => {
        delete item.accounts[1].windows[1].inactive;
      },
      /unknown/,
    ],
    [
      (item) => {
        item.accounts[1].windows[0].resetsAt = "2026-09-14T00:00:00Z";
      },
      /rebase/,
    ],
  ]) {
    const changed = structuredClone(current);
    change(changed);
    const result = evaluateQuota(baseline, changed, pilotPolicy.billing, later);
    assert.equal(result.quotaAllowed, false);
    assert.match(result.blockers.join("\n"), pattern);
  }
  assert.match(
    evaluateQuota(baseline, current, pilotPolicy.billing, later + 301000).blockers.join("\n"),
    /stale/,
  );
});

test("contradictory inactive quota markers fail closed", () => {
  for (const change of [
    (window) => {
      window.usedPercent = 1;
    },
    (window) => {
      window.usedPercent = null;
    },
    (window) => {
      window.resetsAt = "2026-09-03T18:00:00Z";
    },
    (window) => {
      window.kind = "weekly";
    },
    (window) => {
      window.inactive = "true";
    },
  ]) {
    const current = snapshot();
    Object.assign(current.accounts[1].windows[1], {
      usedPercent: 0,
      resetsAt: null,
      inactive: true,
    });
    change(current.accounts[1].windows[1]);
    assert.throws(() => evaluateQuota(snapshot(), current, pilotPolicy.billing, NOW), /Inactive/);
  }
});

test("weekly quota epochs carry consumed allowance across a rolling window", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const current = snapshot();
  Object.assign(current.accounts[0].windows[0], {
    usedPercent: 3,
    resetsAt: "2026-09-06T00:00:00Z",
    accountingEpochs: [
      {
        resetsAt: "2026-09-07T00:00:00Z",
        startUsedPercent: 10,
        peakUsedPercent: 12,
      },
      {
        resetsAt: "2026-09-06T00:00:00Z",
        startUsedPercent: 0,
        peakUsedPercent: 3,
      },
    ],
  });
  assert.equal(evaluateQuota(baseline, current, pilotPolicy.billing, NOW).quotaAllowed, true);
  current.accounts[0].windows[0].usedPercent = 18;
  current.accounts[0].windows[0].accountingEpochs[1].peakUsedPercent = 18;
  const blocked = evaluateQuota(baseline, current, pilotPolicy.billing, NOW);
  assert.equal(blocked.quotaAllowed, false);
  assert.match(blocked.blockers.join("\n"), /20 percentage points/);
});

test("weekly quota epoch accounting fails closed when its history is incomplete", () => {
  for (const change of [
    (epochs) => {
      epochs[0].startUsedPercent = 9;
    },
    (epochs) => {
      epochs[0].resetsAt = "2026-09-05T00:00:00Z";
    },
    (epochs) => {
      epochs[1].resetsAt = "2026-09-05T00:00:00Z";
    },
    (epochs) => {
      epochs[1].startUsedPercent = 1;
    },
    (epochs) => {
      epochs[1].peakUsedPercent = 2;
    },
    (epochs) => {
      epochs.push(structuredClone(epochs[1]));
    },
  ]) {
    const baseline = snapshot("2026-09-03T15:00:00Z");
    const current = snapshot();
    Object.assign(current.accounts[0].windows[0], {
      usedPercent: 3,
      resetsAt: "2026-09-06T00:00:00Z",
      accountingEpochs: [
        {
          resetsAt: "2026-09-07T00:00:00Z",
          startUsedPercent: 10,
          peakUsedPercent: 12,
        },
        {
          resetsAt: "2026-09-06T00:00:00Z",
          startUsedPercent: 0,
          peakUsedPercent: 3,
        },
      ],
    });
    change(current.accounts[0].windows[0].accountingEpochs);
    assert.throws(() => evaluateQuota(baseline, current, pilotPolicy.billing, NOW));
  }
});

test("quota carry-forward appends rolling epochs and never lowers their peaks", () => {
  const baseline = snapshot("2026-09-03T15:00:00Z");
  const beforeRollover = snapshot("2026-09-03T15:30:00Z");
  beforeRollover.accounts[0].windows[0].usedPercent = 12;
  const afterRollover = snapshot();
  Object.assign(afterRollover.accounts[0].windows[0], {
    usedPercent: 2,
    resetsAt: "2026-09-06T00:00:00Z",
  });
  const carried = carryForwardQuotaUsage(baseline, beforeRollover, afterRollover);
  assert.deepEqual(carried.accounts[0].windows[0].accountingEpochs, [
    {
      resetsAt: "2026-09-07T00:00:00Z",
      startUsedPercent: 10,
      peakUsedPercent: 12,
    },
    {
      resetsAt: "2026-09-06T00:00:00Z",
      startUsedPercent: 0,
      peakUsedPercent: 2,
    },
  ]);

  const later = snapshot("2026-09-03T16:01:00Z");
  Object.assign(later.accounts[0].windows[0], {
    usedPercent: 3,
    resetsAt: "2026-09-06T00:00:00Z",
  });
  const advanced = carryForwardQuotaUsage(baseline, carried, later);
  assert.equal(advanced.accounts[0].windows[0].accountingEpochs[1].peakUsedPercent, 3);

  const roundedDown = snapshot("2026-09-03T16:02:00Z");
  Object.assign(roundedDown.accounts[0].windows[0], {
    usedPercent: 2,
    resetsAt: "2026-09-06T00:00:00Z",
  });
  const conservative = carryForwardQuotaUsage(baseline, advanced, roundedDown);
  assert.equal(conservative.accounts[0].windows[0].accountingEpochs[1].peakUsedPercent, 3);
  assert.equal(verifyQuotaUsageContinuity(baseline, advanced, conservative), conservative);

  const revisited = snapshot("2026-09-03T16:03:00Z");
  revisited.accounts[0].windows[0].usedPercent = 12;
  const oscillating = carryForwardQuotaUsage(baseline, conservative, revisited);
  assert.equal(oscillating.accounts[0].windows[0].accountingEpochs.length, 2);
  assert.equal(oscillating.accounts[0].windows[0].accountingEpochs[0].peakUsedPercent, 12);
  assert.equal(
    evaluateQuota(baseline, oscillating, pilotPolicy.billing, Date.parse(revisited.capturedAt))
      .quotaAllowed,
    true,
  );

  const tampered = structuredClone(conservative);
  tampered.accounts[0].windows[0].accountingEpochs[0].peakUsedPercent = 11;
  assert.throws(() => verifyQuotaUsageContinuity(baseline, advanced, tampered), /history changed/);
});
