import { requireCondition, requireHash, requireText, validateTrial } from "./workflow-contract.mjs";
import { validateUsage, totalTokens, accountedSpend } from "./workflow-usage.mjs";

export function validateResult(record, assignment, study) {
  validateTrial(record, assignment, study);
  requireCondition(
    (study.billing?.mode === "subscription") === (record.usage?.costBasis === "subscription"),
    "subscription accounting must match the frozen billing mode",
  );
  validateUsage(record.usage);
  requireCondition(
    Array.isArray(record.reviews),
    "reviews must be an array, including when pending",
  );
  const reviewers = new Set();
  for (const review of record.reviews) {
    requireHash(review.patchSha256, "reviewed patch digest");
    requireCondition(
      record.submissions.some((item) => item.patchSha256 === review.patchSha256),
      "review does not match a submitted patch",
    );
    requireText(review.reviewer, "reviewer identity");
    requireText(review.reason, "review reason");
    requireText(review.receipt, "review receipt artifact");
    requireCondition(review.blinded === true, "review must be blinded to the assigned workflow");
    requireCondition(["accept", "reject"].includes(review.decision), "invalid review decision");
    const key = `${review.patchSha256}:${review.reviewer}`;
    requireCondition(!reviewers.has(key), "duplicate reviewer for a patch");
    reviewers.add(key);
  }
  return record;
}

export function submissionOutcome(submission, reviews) {
  if (!submission.acceptancePass || !submission.regressionsPass || !submission.integrityPass)
    return "failed";
  const decisions = reviews.filter((review) => review.patchSha256 === submission.patchSha256);
  if (decisions.length === 0) return "pending_review";
  if (decisions.some((review) => review.decision === "reject")) return "failed";
  return "accepted";
}

export function trialOutcome(record, limits) {
  if (!record) return { recorded: false, first: false, eventual: false, pendingReview: false };
  const outcomes = record.submissions.map((submission) => ({
    outcome: submissionOutcome(submission, record.reviews),
    withinTime: submission.elapsedMs <= limits.trialSeconds * 1000,
  }));
  const tokens = totalTokens(record.usage);
  const spend = accountedSpend(record.usage);
  const unexpectedModel = record.modelSelection?.observed.some(
    (model) => model !== record.modelSelection.requested,
  );
  const modelVerified =
    record.fixture === true ||
    (record.modelSelection?.verified === true && Boolean(record.modelSelection.receipt));
  const overBudget =
    (limits.trialTokens !== null && tokens !== null && tokens > limits.trialTokens) ||
    (spend !== null && spend > limits.trialCostUsd);
  const accepted = (entry) =>
    entry?.outcome === "accepted" &&
    entry.withinTime &&
    !overBudget &&
    !unexpectedModel &&
    modelVerified;
  return {
    recorded: true,
    first: accepted(outcomes[0]) || false,
    eventual: record.status === "completed" && (accepted(outcomes.at(-1)) || false),
    pendingReview: outcomes.some((entry) => entry.outcome === "pending_review"),
    regression: record.submissions.some((submission) => !submission.regressionsPass),
    integrityFailure: record.submissions.some((submission) => !submission.integrityPass),
    overBudget,
    tokens,
  };
}

export function summarizeArm(assignments, records, limits) {
  const rows = assignments.map((assignment) => {
    const record = records.get(assignment.id);
    return { record, outcome: trialOutcome(record, limits) };
  });
  const recorded = rows.filter((row) => row.record);
  const count = (test) => rows.filter(test).length;
  const firstAccepted = count((row) => row.outcome.first);
  const accepted = count((row) => row.outcome.eventual);
  const pendingReview = count((row) => row.outcome.pendingReview);
  const complete = recorded.length === assignments.length && pendingReview === 0;
  const tokensKnown = complete && recorded.every((row) => row.outcome.tokens !== null);
  const costsKnown =
    complete &&
    recorded.every(
      (row) => row.record.usage.costUsd !== null && row.record.usage.includesAllAgents,
    );
  const tokens = tokensKnown ? recorded.reduce((sum, row) => sum + row.outcome.tokens, 0) : null;
  const costUsd = costsKnown
    ? recorded.reduce((sum, row) => sum + row.record.usage.costUsd, 0)
    : null;
  const statuses = {};
  for (const { record } of recorded) statuses[record.status] = (statuses[record.status] ?? 0) + 1;
  const knownSpendUsd = recorded.reduce(
    (sum, row) => sum + (accountedSpend(row.record.usage) ?? 0),
    0,
  );
  return {
    assigned: assignments.length,
    recorded: recorded.length,
    missing: assignments.length - recorded.length,
    pendingReview,
    firstAccepted,
    accepted,
    firstAttemptRate:
      complete && assignments.length > 0 ? firstAccepted / assignments.length : null,
    completionRate: complete && assignments.length > 0 ? accepted / assignments.length : null,
    regressions: count((row) => row.outcome.regression),
    integrityFailures: count((row) => row.outcome.integrityFailure),
    overBudget: count((row) => row.outcome.overBudget),
    statuses,
    tokens,
    costUsd,
    knownSpendUsd,
    missingUsage: count((row) => row.record && row.outcome.tokens === null),
    missingCost: count(
      (row) =>
        row.record &&
        (accountedSpend(row.record.usage) === null || !row.record.usage.includesAllAgents),
    ),
    tokensPerAccepted: tokens !== null && accepted > 0 ? tokens / accepted : null,
    costPerAccepted: costUsd !== null && accepted > 0 ? costUsd / accepted : null,
    elapsedMs: complete ? recorded.reduce((sum, row) => sum + row.record.elapsedMs, 0) : null,
    humanActiveMs:
      complete && recorded.every((row) => row.record.humanActiveMs !== null)
        ? recorded.reduce((sum, row) => sum + row.record.humanActiveMs, 0)
        : null,
    costBases: [...new Set(recorded.map((row) => row.record.usage.costBasis))].sort(),
    setupModes: [...new Set(recorded.map((row) => row.record.setup))].sort(),
  };
}
