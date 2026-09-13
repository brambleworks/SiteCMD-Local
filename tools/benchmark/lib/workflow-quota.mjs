import {
  requireCondition,
  requireNumber,
  requireText,
  validateSubscriptionBilling,
} from "./workflow-contract.mjs";

function timestamp(value, label) {
  requireCondition(
    typeof value === "string" && /Z$/.test(value),
    `${label} must be a UTC timestamp`,
  );
  const parsed = Date.parse(value);
  requireCondition(Number.isFinite(parsed), `${label} must be a UTC timestamp`);
  return parsed;
}

function validateEpochs(window) {
  if (window.accountingEpochs === undefined) return;
  requireCondition(
    window.kind === "weekly" &&
      Array.isArray(window.accountingEpochs) &&
      window.accountingEpochs.length > 0 &&
      window.accountingEpochs.length <= 100,
    "Quota accounting epochs require a bounded weekly history",
  );
  const resets = new Set();
  for (const epoch of window.accountingEpochs) {
    timestamp(epoch.resetsAt, "accounting epoch resetsAt");
    requireNumber(epoch.startUsedPercent, "accounting epoch startUsedPercent");
    requireNumber(epoch.peakUsedPercent, "accounting epoch peakUsedPercent");
    requireCondition(
      epoch.startUsedPercent <= epoch.peakUsedPercent && epoch.peakUsedPercent <= 100,
      "Quota accounting epoch percentages are invalid",
    );
    requireCondition(!resets.has(epoch.resetsAt), "Duplicate quota accounting epoch");
    resets.add(epoch.resetsAt);
  }
}

function validateSnapshot(snapshot) {
  requireCondition(snapshot?.schemaVersion === 1, "quota schemaVersion must be 1");
  const capturedAt = timestamp(snapshot.capturedAt, "capturedAt");
  requireText(snapshot.source, "quota evidence source");
  requireCondition(Array.isArray(snapshot.accounts), "quota accounts are required");
  requireCondition(
    JSON.stringify(snapshot.accounts.map((item) => item.provider).sort()) === '["claude","codex"]',
    "quota requires exactly one Codex and one Claude account",
  );
  for (const account of snapshot.accounts) {
    requireText(account.account, "stable account label");
    requireCondition(
      Array.isArray(account.windows) && account.windows.length > 0,
      "quota windows are required",
    );
    const ids = new Set();
    for (const window of account.windows) {
      requireText(window.id, "quota window id");
      requireCondition(!ids.has(window.id), "duplicate quota window");
      ids.add(window.id);
      requireCondition(["weekly", "session"].includes(window.kind), "invalid quota window kind");
      if (window.usedPercent !== null) {
        requireNumber(window.usedPercent, "usedPercent");
        requireCondition(window.usedPercent <= 100, "usedPercent must not exceed 100");
      }
      if (window.resetsAt !== null) timestamp(window.resetsAt, "resetsAt");
      validateEpochs(window);
      if (window.inactive !== undefined)
        requireCondition(
          window.inactive === true &&
            window.kind === "session" &&
            window.usedPercent === 0 &&
            window.resetsAt === null,
          "Inactive quota requires an explicit zero-usage session without a reset date",
        );
    }
    requireCondition(
      account.windows.some((window) => window.kind === "weekly"),
      "weekly quota is required",
    );
  }
  return capturedAt;
}

function weeklyConsumption(before, current, label, blockers) {
  const epochs = current.accountingEpochs;
  if (epochs === undefined) {
    if (before.resetsAt !== current.resetsAt) {
      blockers.push(`${label}: reset changed; preserve prior usage before any rebase`);
      return null;
    }
    if (current.usedPercent < before.usedPercent) {
      blockers.push(`${label}: usage decreased within the same window`);
      return null;
    }
    return current.usedPercent - before.usedPercent;
  }
  const active = epochs.find((epoch) => epoch.resetsAt === current.resetsAt);
  requireCondition(
    epochs[0].resetsAt === before.resetsAt &&
      epochs[0].startUsedPercent === before.usedPercent &&
      active?.peakUsedPercent >= current.usedPercent,
    `${label}: quota accounting epochs do not match the frozen baseline and current reading`,
  );
  for (const epoch of epochs.slice(1))
    requireCondition(
      epoch.startUsedPercent === 0,
      `${label}: later quota accounting epochs must start at zero`,
    );
  return epochs.reduce((sum, epoch) => sum + epoch.peakUsedPercent - epoch.startUsedPercent, 0);
}

function checkWindow(before, current, label, policy, capturedAt, now, blockers) {
  if (before.kind !== current.kind) blockers.push(`${label}: quota window kind changed`);
  if (current.usedPercent === null || before.usedPercent === null) {
    blockers.push(`${label}: usage is unknown`);
    return;
  }
  const reset = current.resetsAt === null ? NaN : timestamp(current.resetsAt, "resetsAt");
  const previousReset = before.resetsAt === null ? NaN : timestamp(before.resetsAt, "resetsAt");
  if (current.inactive) {
    if (!before.inactive && (!Number.isFinite(previousReset) || capturedAt < previousReset))
      blockers.push(`${label}: session became inactive before its recorded reset`);
    return;
  }
  if (
    !Number.isFinite(reset) ||
    (!before.inactive && !Number.isFinite(previousReset)) ||
    reset <= now
  ) {
    blockers.push(`${label}: reset time is unknown or the window has expired`);
    return;
  }
  const sameWindow = before.resetsAt === current.resetsAt;
  let consumed = null;
  if (current.kind === "weekly") consumed = weeklyConsumption(before, current, label, blockers);
  else {
    if (!before.inactive && !sameWindow && (capturedAt < previousReset || reset <= previousReset))
      blockers.push(`${label}: reset changed; do not silently rebase the approved budget`);
    if (sameWindow && current.usedPercent < before.usedPercent)
      blockers.push(`${label}: usage decreased within the same window`);
  }
  if (100 - current.usedPercent < policy.minimumRemainingPercent)
    blockers.push(`${label}: less than ${policy.minimumRemainingPercent}% remaining`);
  if (
    current.kind === "weekly" &&
    consumed !== null &&
    consumed >= policy.weeklyBudgetPercentagePoints
  )
    blockers.push(
      `${label}: ${policy.weeklyBudgetPercentagePoints} percentage points of weekly allowance consumed`,
    );
}

function sameWindowShape(before, current, label) {
  requireCondition(before.provider === current.provider, `${label}: provider changed`);
  requireCondition(before.account === current.account, `${label}: account changed`);
  requireCondition(before.authMode === current.authMode, `${label}: authentication changed`);
  requireCondition(
    before.extraUsageEnabled === current.extraUsageEnabled,
    `${label}: extra usage changed`,
  );
  const shape = (account) =>
    account.windows
      .map(({ id, kind }) => `${id}:${kind}`)
      .sort()
      .join("\n");
  requireCondition(shape(before) === shape(current), `${label}: quota windows changed`);
}

/** Ensure a refreshed snapshot retains every previously observed weekly high-water mark. */
export function verifyQuotaUsageContinuity(baseline, previous, current) {
  const baselineAt = validateSnapshot(baseline);
  const previousAt = validateSnapshot(previous);
  const currentAt = validateSnapshot(current);
  requireCondition(
    baselineAt <= previousAt && previousAt < currentAt,
    "Quota snapshots must advance in capture order",
  );
  for (const account of current.accounts) {
    const beforeAccount = baseline.accounts.find((item) => item.provider === account.provider);
    const previousAccount = previous.accounts.find((item) => item.provider === account.provider);
    sameWindowShape(beforeAccount, previousAccount, account.provider);
    sameWindowShape(beforeAccount, account, account.provider);
    for (const window of account.windows) {
      if (window.kind !== "weekly") continue;
      const before = beforeAccount.windows.find((item) => item.id === window.id);
      const prior = previousAccount.windows.find((item) => item.id === window.id);
      const label = `${account.provider}/${window.id}`;
      weeklyConsumption(before, window, label, []);
      if (!prior.accountingEpochs) {
        if (!window.accountingEpochs) {
          requireCondition(
            prior.resetsAt === window.resetsAt && prior.usedPercent <= window.usedPercent,
            `${label}: weekly usage continuity is unavailable`,
          );
          continue;
        }
        requireCondition(
          window.accountingEpochs.length <= 2 &&
            window.accountingEpochs[0].peakUsedPercent >= prior.usedPercent,
          `${label}: initial accounting history omitted prior usage`,
        );
        continue;
      }
      requireCondition(
        window.accountingEpochs &&
          [prior.accountingEpochs.length, prior.accountingEpochs.length + 1].includes(
            window.accountingEpochs.length,
          ),
        `${label}: accounting history changed`,
      );
      for (const [index, oldEpoch] of prior.accountingEpochs.entries()) {
        const epoch = window.accountingEpochs[index];
        requireCondition(
          epoch.resetsAt === oldEpoch.resetsAt &&
            epoch.startUsedPercent === oldEpoch.startUsedPercent &&
            epoch.peakUsedPercent >= oldEpoch.peakUsedPercent,
          `${label}: accounting history changed`,
        );
      }
    }
  }
  return current;
}

/** Preserve conservative weekly high-water usage when provider quota epochs change. */
export function carryForwardQuotaUsage(baseline, previous, current) {
  const baselineAt = validateSnapshot(baseline);
  const previousAt = validateSnapshot(previous);
  const currentAt = validateSnapshot(current);
  requireCondition(
    baselineAt <= previousAt && previousAt < currentAt,
    "Quota snapshots must advance in capture order",
  );
  const result = structuredClone(current);
  for (const account of result.accounts) {
    const beforeAccount = baseline.accounts.find((item) => item.provider === account.provider);
    const previousAccount = previous.accounts.find((item) => item.provider === account.provider);
    sameWindowShape(beforeAccount, previousAccount, account.provider);
    sameWindowShape(beforeAccount, account, account.provider);
    for (const window of account.windows) {
      if (window.kind !== "weekly") continue;
      requireCondition(
        window.accountingEpochs === undefined,
        `${account.provider}/${window.id}: fresh readings must not replace accounting history`,
      );
      const before = beforeAccount.windows.find((item) => item.id === window.id);
      const prior = previousAccount.windows.find((item) => item.id === window.id);
      let epochs;
      if (prior.accountingEpochs) {
        weeklyConsumption(before, prior, `${account.provider}/${window.id}`, []);
        epochs = structuredClone(prior.accountingEpochs);
      } else {
        requireCondition(
          prior.resetsAt === before.resetsAt,
          `${account.provider}/${window.id}: prior rolling usage history is unavailable`,
        );
        epochs = [
          {
            resetsAt: before.resetsAt,
            startUsedPercent: before.usedPercent,
            peakUsedPercent: Math.max(before.usedPercent, prior.usedPercent),
          },
        ];
      }
      const active = epochs.find((epoch) => epoch.resetsAt === window.resetsAt);
      if (active) active.peakUsedPercent = Math.max(active.peakUsedPercent, window.usedPercent);
      else {
        epochs.push({
          resetsAt: window.resetsAt,
          startUsedPercent: 0,
          peakUsedPercent: window.usedPercent,
        });
      }
      window.accountingEpochs = epochs;
    }
  }
  validateSnapshot(result);
  verifyQuotaUsageContinuity(baseline, previous, result);
  return result;
}

/** Evaluate supplied account readings; this does not fetch quotas or stop an agent process. */
export function evaluateQuota(baseline, current, policy, now = Date.now(), provider) {
  validateSubscriptionBilling(policy);
  requireCondition(
    provider === undefined || ["codex", "claude"].includes(provider),
    "invalid active quota provider",
  );
  const baselineAt = validateSnapshot(baseline);
  const capturedAt = validateSnapshot(current);
  requireNumber(now, "current time");
  const blockers = [];
  if (capturedAt < baselineAt || baselineAt > now || capturedAt > now)
    blockers.push("Quota evidence timestamps are out of order or in the future");
  if (now - capturedAt > policy.quotaMaxAgeSeconds * 1000)
    blockers.push("Current quota evidence is stale");
  for (const account of current.accounts) {
    const before = baseline.accounts.find((item) => item.provider === account.provider);
    const label = account.provider;
    if (before.account !== account.account) blockers.push(`${label}: account changed`);
    if (before.authMode !== "subscription" || account.authMode !== "subscription")
      blockers.push(`${label}: subscription authentication is unverified`);
    if (before.extraUsageEnabled !== false || account.extraUsageEnabled !== false)
      blockers.push(`${label}: additional paid usage must be verified disabled`);
    const ids = (item) =>
      item.windows
        .map((window) => window.id)
        .sort()
        .join("\n");
    if (ids(before) !== ids(account)) {
      blockers.push(`${label}: quota windows changed or are missing`);
      continue;
    }
    if (policy.quotaScope === "active-provider" && provider && account.provider !== provider)
      continue;
    for (const window of account.windows) {
      const previous = before.windows.find((item) => item.id === window.id);
      if (previous.resetsAt !== null && timestamp(previous.resetsAt, "resetsAt") <= baselineAt)
        blockers.push(`${label}/${window.id}: baseline window had already expired`);
      checkWindow(previous, window, `${label}/${window.id}`, policy, capturedAt, now, blockers);
    }
  }
  return { quotaAllowed: blockers.length === 0, blockers, capturedAt: current.capturedAt };
}
