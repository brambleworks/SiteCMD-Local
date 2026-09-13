import assert from "node:assert/strict";
import { test } from "node:test";
import { createPlan } from "./workflow-plan.mjs";
import { fixtureStudy, fixtureRecord } from "./workflow-fixture.mjs";
import { analyzeStudy, renderWorkflowReport } from "./workflow-report.mjs";
import { trialOutcome, validateResult } from "./workflow-results.mjs";

const setup = () => {
  const plan = createPlan(fixtureStudy());
  return { plan, records: plan.assignments.map((assignment) => fixtureRecord(plan, assignment)) };
};
const analyze = (plan, records) => analyzeStudy(plan, records, { bootstrapSamples: 100 });
const repairs = (analysis) => analysis.groups.find((group) => group.kind === "repair");

test("unverified real trials cannot count a passing first submission", () => {
  const { plan, records } = setup();
  const record = records.find((item) => trialOutcome(item, plan.study.limits).first);
  assert.ok(record);
  record.fixture = false;
  record.status = "agent_error";
  const selection = {
    requested: record.model,
    observed: [record.model],
    source: "explicit-cli-request",
    receipt: "model-identity.json",
    verified: true,
  };
  for (const value of [
    undefined,
    { ...selection, verified: false },
    { ...selection, receipt: "" },
  ]) {
    record.modelSelection = value;
    assert.equal(trialOutcome(record, plan.study.limits).first, false);
  }
  record.modelSelection = selection;
  assert.equal(trialOutcome(record, plan.study.limits).first, true);
  assert.equal(trialOutcome(record, plan.study.limits).eventual, false);
});

test("fixture runs never become confirmatory evidence and negative controls are separate", () => {
  const { plan, records } = setup();
  const analysis = analyze(plan, records);
  assert.equal(analysis.claimReviewReady, false);
  assert.equal(analysis.groups.length, 2);
  assert.equal(repairs(analysis).arms.mcp.assigned, 2);
  assert.match(
    renderWorkflowReport(plan, analysis),
    /correct triage decisions, not repaired defects/,
  );
  assert.match(renderWorkflowReport(plan, analysis), /Not ready for marketing claims/);
});

test("legacy model labels cannot produce confirmatory claims without response receipts", () => {
  const study = fixtureStudy();
  Object.assign(study, {
    phase: "confirmatory",
    registration: "Synthetic registration",
    sampleSizeRationale: "Test only",
  });
  study.sitecmd.dirty = false;
  study.tasks.forEach((task) => {
    task.holdout = true;
  });
  const plan = createPlan(study);
  const records = plan.assignments.map((assignment) => ({
    ...fixtureRecord(plan, assignment),
    fixture: false,
  }));
  assert.equal(analyze(plan, records).claimReviewReady, false);
  for (const record of records) {
    record.modelSelection = {
      requested: record.model,
      observed: [record.model],
      source: "explicit-cli-request",
    };
  }
  assert.equal(analyze(plan, records).claimReviewReady, false);
  for (const record of records) {
    Object.assign(record.modelSelection, { receipt: "model-identity.json", verified: true });
  }
  assert.equal(analyze(plan, records).claimReviewReady, true);
  records[0].modelSelection.verified = false;
  assert.equal(analyze(plan, records).claimReviewReady, false);
});

test("a completed strict Codex selection can be claim-ready without provider response metadata", () => {
  const study = fixtureStudy();
  Object.assign(study, {
    phase: "confirmatory",
    registration: "Synthetic registration",
    sampleSizeRationale: "Test only",
  });
  study.sitecmd.dirty = false;
  study.configurations[0].agent = "codex";
  study.tasks.forEach((task) => {
    task.holdout = true;
  });
  const plan = createPlan(study);
  const records = plan.assignments.map((assignment) => {
    const record = { ...fixtureRecord(plan, assignment), fixture: false, model: null };
    record.modelSelection = {
      requested: "no-model",
      observed: [],
      source: "explicit-cli-request",
      receipt: "model-identity.json",
      assurance: "explicit-cli-selection",
      verified: true,
    };
    return record;
  });
  assert.equal(analyze(plan, records).claimReviewReady, true);
});

for (const id of [
  "sitecmd-repository-confirmatory-v1",
  "sitecmd-repository-confirmatory-v2",
  "sitecmd-repository-confirmatory-v2-supplemental",
])
  test(`invalidated study ${id} can never become claim-ready`, () => {
    const study = fixtureStudy();
    Object.assign(study, {
      id,
      phase: "confirmatory",
      registration: "Retired registration",
      sampleSizeRationale: "Historical design only",
    });
    study.sitecmd.dirty = false;
    study.configurations[0].agent = "codex";
    study.tasks.forEach((task) => {
      task.holdout = true;
    });
    const plan = createPlan(study);
    const records = plan.assignments.map((assignment) => {
      const record = { ...fixtureRecord(plan, assignment), fixture: false, model: null };
      record.modelSelection = {
        requested: "no-model",
        observed: [],
        source: "explicit-cli-request",
        receipt: "model-identity.json",
        assurance: "explicit-cli-selection",
        verified: true,
      };
      return record;
    });

    const analysis = analyze(plan, records);
    assert.equal(analysis.claimReviewReady, false);
    assert.match(analysis.blockers.join("\n"), /invalidated|diagnostic/i);
  });

test("missing assignments withhold rates and spending estimates", () => {
  const { plan, records } = setup();
  const missing = records.findIndex(
    (record) => plan.assignments.find((item) => item.id === record.trialId).task === "repair-a",
  );
  const arm = plan.assignments.find((item) => item.id === records[missing].trialId).arm;
  records.splice(missing, 1);
  const analysis = analyze(plan, records);
  assert.equal(repairs(analysis).arms[arm].missing, 1);
  assert.equal(repairs(analysis).arms[arm].firstAttemptRate, null);
  assert.equal(repairs(analysis).arms[arm].tokensPerAccepted, null);
});

test("failed trials stay in denominators and efficiency includes their spending", () => {
  const { plan, records } = setup();
  const assignment = plan.assignments.find(
    (item) => item.arm === "normal" && item.task === "repair-a",
  );
  const failed = records.find((item) => item.trialId === assignment.id);
  Object.assign(failed, {
    status: "timeout",
    failure: "Deadline reached",
    submissions: [],
    reviews: [],
  });
  const group = repairs(analyze(plan, records));
  assert.equal(group.arms.normal.firstAttemptRate, 0.5);
  assert.equal(group.arms.normal.tokensPerAccepted, 300);
  assert.equal(group.arms.normal.costPerAccepted, 0.002);
  const comparison = group.comparisons.find(
    (item) => item.baselineArm === "normal" && item.treatmentArm === "mcp",
  );
  assert.equal(comparison.point.firstAttemptDifference, 0.5);
  assert.equal(comparison.point.firstAttemptRelativeLift, 1);
  assert.equal(comparison.point.tokenReduction, 0.5);
  assert.equal(comparison.confidenceIntervals.tokenReduction, null);
  assert.deepEqual(analyze(plan, records), analyze(plan, records));
});

test("failed first submissions cannot be relabeled by a later passing submission", () => {
  const { plan, records } = setup();
  const record = records[0];
  record.submissions.unshift({ ...record.submissions[0], elapsedMs: 100, acceptancePass: false });
  assert.equal(trialOutcome(record, plan.study.limits).first, false);
  assert.equal(trialOutcome(record, plan.study.limits).eventual, true);
  record.submissions[1].regressionsPass = false;
  assert.equal(trialOutcome(record, plan.study.limits).eventual, false);
});

test("a later regression cannot leave the final result accepted", () => {
  const { plan, records } = setup();
  const record = records[0];
  record.submissions.push({ ...record.submissions[0], regressionsPass: false, elapsedMs: 950 });
  assert.equal(trialOutcome(record, plan.study.limits).first, true);
  assert.equal(trialOutcome(record, plan.study.limits).eventual, false);
});

test("scanner clearance or passing tests alone cannot replace independent review", () => {
  const { plan, records } = setup();
  const record = records[0];
  record.reviews = [];
  const outcome = trialOutcome(record, plan.study.limits);
  assert.equal(outcome.pendingReview, true);
  assert.equal(outcome.eventual, false);
  assert.ok(analyze(plan, records).blockers.some((blocker) => blocker.includes("blinded review")));
});

test("unknown usage, zero successes, budgets, and setup differences cannot produce savings claims", () => {
  const { plan, records } = setup();
  for (const record of records) {
    record.submissions = [];
    record.reviews = [];
    record.usage.cacheReadTokens = null;
  }
  const analysis = analyze(plan, records);
  for (const arm of Object.values(repairs(analysis).arms)) {
    assert.equal(arm.tokensPerAccepted, null);
    assert.equal(arm.costPerAccepted, null);
  }
  const fresh = setup();
  fresh.records[0].usage.costUsd = 99;
  fresh.records[1].setup = "cold";
  const blockers = analyze(fresh.plan, fresh.records).blockers.join("\n");
  assert.match(blockers, /budget was exceeded/);
  assert.match(blockers, /setup/);
});

test("unknown trials, duplicates, changed models, graders, and fixture flags are rejected", () => {
  const { plan, records } = setup();
  assert.throws(() => analyze(plan, [...records, records[0]]), /Duplicate/);
  assert.throws(() => analyze(plan, [{ ...records[0], trialId: "unknown" }]), /Unknown/);
  for (const change of [
    (record) => {
      record.model = "different-model";
    },
    (record) => {
      record.fixture = false;
    },
    (record) => {
      record.submissions[0].graderSha256 = "f".repeat(64);
    },
    (record) => {
      record.reviews[0].blinded = false;
    },
  ]) {
    const record = structuredClone(records[0]);
    change(record);
    assert.throws(() => validateResult(record, plan.assignments[0], plan.study));
  }
});

test("baseline MCP contamination and mixed cost bases are flagged", () => {
  const { plan, records } = setup();
  const assignment = plan.assignments.find(
    (item) => item.arm === "normal" && item.task === "repair-a",
  );
  const record = records.find((item) => item.trialId === assignment.id);
  record.mcp = { serverSha256: plan.study.sitecmd.mcpSha256, trace: "mcp.jsonl" };
  assert.throws(() => analyze(plan, records), /only the mcp workflow/);
  delete record.mcp;
  record.usage.costBasis = "billed";
  assert.ok(analyze(plan, records).blockers.some((blocker) => blocker.includes("costs are mixed")));
});

test("a preregistered fixed model mixture is pooled without hiding per-model groups", () => {
  const study = fixtureStudy();
  study.analysis = { configurationAggregation: "equal-weight-fixed-requested-set" };
  study.configurations.push({
    ...study.configurations[0],
    id: "fixture-two",
    model: "no-model-two",
  });
  const plan = createPlan(study);
  const records = plan.assignments.map((assignment) => {
    const record = fixtureRecord(plan, assignment);
    const configuration = study.configurations.find((item) => item.id === assignment.configuration);
    record.model = configuration.model;
    record.agentVersion = configuration.agentVersion;
    return record;
  });
  const analysis = analyze(plan, records);
  const pooled = analysis.groups.find(
    (group) => group.configuration === "pooled-fixed-configurations" && group.kind === "repair",
  );
  assert.ok(pooled);
  assert.equal(pooled.arms.normal.assigned, 4);
  assert.equal(
    analysis.groups.filter((group) => group.kind === "repair" && !group.pooled).length,
    2,
  );
  const report = renderWorkflowReport(plan, analysis);
  assert.match(report, /equal-weight average across the fixed requested configurations/);
  assert.match(report, /Per-configuration results remain separate/);
});
