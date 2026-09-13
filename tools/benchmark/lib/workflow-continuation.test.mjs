import assert from "node:assert/strict";
import { test } from "node:test";
import { createPlan, digest, validatePlan } from "./workflow-plan.mjs";
import { fixtureStudy } from "./workflow-fixture.mjs";
import { writeFixtureEvidence } from "./workflow-fixture.mjs";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createStudyRun, importTrial, writeNewJson } from "./workflow-store.mjs";
import {
  describeContinuation,
  describeSupplementalContinuation,
  verifyContinuation,
} from "./workflow-continuation.mjs";
import { analyzeStudy, renderWorkflowReport } from "./workflow-report.mjs";

function continuedStudy() {
  const source = createPlan(fixtureStudy());
  const study = structuredClone(source.study);
  study.continuation = {
    sourceRun: "/owned/earlier-run",
    sourceStudySha256: source.studySha256,
    baselineSha256: digest("original allowance"),
    reason: "Sandbox bookkeeping correction; no replacement trials",
    retained: source.assignments.slice(0, 2).map(({ id, ...assignment }) => ({
      ...assignment,
      trialId: id,
      recordSha256: digest(id),
    })),
  };
  return { source, study };
}

test("a continuation schedules only the unrun suffix and preserves the original population", () => {
  const { source, study } = continuedStudy();
  const plan = createPlan(study);
  assert.equal(plan.plannedTrials, source.plannedTrials - 2);
  const key = ({ task, configuration, repeat, arm }) => ({ task, configuration, repeat, arm });
  assert.deepEqual(plan.assignments.map(key), source.assignments.slice(2).map(key));
  assert.equal(plan.plannedTrials + study.continuation.retained.length, source.plannedTrials);
  assert.equal(validatePlan(plan), plan);
});

function storedPrefix(t, study = fixtureStudy()) {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-continuation-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const sourceRun = path.join(root, "source");
  const source = createStudyRun(study, sourceRun);
  for (const [index, assignment] of source.assignments.slice(0, 2).entries()) {
    const input = writeFixtureEvidence(path.join(root, `evidence-${index}`), source, assignment, {
      acceptance: { status: 0, log: "Synthetic check" },
      regressions: { status: 0, log: "Synthetic check" },
    });
    if (index === 1) {
      const record = JSON.parse(readFileSync(input));
      record.status = "infrastructure_error";
      record.failure = "Synthetic interruption";
      writeFileSync(input, JSON.stringify(record));
    }
    importTrial(sourceRun, input);
  }
  const baseline = { synthetic: true, allowance: "not provider evidence" };
  writeNewJson(path.join(sourceRun, "quota-baseline.json"), baseline);
  writeFileSync(path.join(sourceRun, "quota-baseline.sha256"), digest(baseline));
  return { root, sourceRun, source, baseline };
}

test("continuation registration retains failures and verifies their original evidence and allowance", (t) => {
  const { root, sourceRun, source, baseline } = storedPrefix(t);
  const study = structuredClone(source.study);
  study.runnerSha256 = digest("corrected runner");
  study.continuation = describeContinuation(sourceRun, study, "Correct sandbox bookkeeping");
  assert.equal(study.continuation.retained.length, 2);
  assert.equal(study.continuation.retained[1].trialId, source.assignments[1].id);
  const run = path.join(root, "continued");
  const plan = createStudyRun(study, run);
  writeNewJson(path.join(run, "quota-baseline.json"), baseline);
  assert.equal(verifyContinuation(run, plan), 2);
  writeFileSync(
    path.join(run, "quota-baseline.json"),
    JSON.stringify({ allowance: "replenished" }),
  );
  assert.throws(() => verifyContinuation(run, plan), /allowance/);
});

test("supplemental completion retains the frozen prefix with a fresh allowance", (t) => {
  const sourceStudy = fixtureStudy();
  sourceStudy.phase = "confirmatory";
  sourceStudy.registration = "synthetic registration";
  sourceStudy.sampleSizeRationale = "Synthetic continuation test";
  sourceStudy.sitecmd.dirty = false;
  sourceStudy.tasks = sourceStudy.tasks.map((task) => ({ ...task, holdout: true }));
  sourceStudy.billing = {
    mode: "subscription",
    paidFallback: false,
    automaticResets: false,
    weeklyBudgetPercentagePoints: 20,
    minimumRemainingPercent: 30,
    quotaMaxAgeSeconds: 300,
  };
  sourceStudy.limits = {
    ...sourceStudy.limits,
    trialTokens: null,
    trialCostUsd: 0,
    studyCostUsd: 0,
  };
  const { root, sourceRun, source } = storedPrefix(t, sourceStudy);
  const study = structuredClone(source.study);
  study.id = `${study.id}-supplemental`;
  study.phase = "calibration";
  study.billing = {
    ...study.billing,
    weeklyBudgetPercentagePoints: 100,
    minimumRemainingPercent: 1,
  };
  const baseline = { synthetic: true, allowance: "operator-approved supplemental quota" };
  const authorization = {
    schemaVersion: 1,
    kind: "supplemental-completion",
    sourceStudySha256: source.studySha256,
    approvedAt: "2026-09-10T06:30:00.000Z",
    approvedBy: "operator",
    reason: "Complete the frozen suffix after the original allowance closed",
    billing: study.billing,
  };

  study.continuation = describeSupplementalContinuation(sourceRun, study, baseline, authorization);

  assert.equal(study.continuation.kind, "supplemental-completion");
  assert.equal(study.continuation.retained.length, 2);
  assert.equal(study.continuation.baselineSha256, digest(baseline));
  assert.equal(study.continuation.authorizationSha256, digest(authorization));
  assert.equal(createPlan(study).plannedTrials, source.plannedTrials - 2);

  const supplementalRun = path.join(root, "supplemental");
  const supplementalPlan = createStudyRun(study, supplementalRun);
  writeNewJson(path.join(supplementalRun, "quota-baseline.json"), baseline);
  writeFileSync(path.join(supplementalRun, "quota-baseline.sha256"), digest(baseline));
  writeNewJson(path.join(supplementalRun, "supplemental-authorization.json"), authorization);
  writeFileSync(
    path.join(supplementalRun, "supplemental-authorization.sha256"),
    digest(authorization),
  );
  assert.equal(verifyContinuation(supplementalRun, supplementalPlan), 2);

  const automaticResetStudy = structuredClone(study);
  automaticResetStudy.billing.automaticResets = true;
  const automaticResetAuthorization = {
    ...authorization,
    billing: automaticResetStudy.billing,
  };
  assert.throws(
    () =>
      describeSupplementalContinuation(
        sourceRun,
        automaticResetStudy,
        baseline,
        automaticResetAuthorization,
      ),
    /automatic quota resets/,
  );

  writeFileSync(path.join(sourceRun, "quota-baseline.sha256"), digest("changed"));
  assert.throws(
    () => describeSupplementalContinuation(sourceRun, study, baseline, authorization),
    /source allowance baseline changed/,
  );
});

test("continuation reports disclose the retained population and never pool runner versions", () => {
  const { source, study } = continuedStudy();
  const plan = createPlan(study);
  const report = analyzeStudy(plan, []);
  assert.equal(report.originalAssigned, source.plannedTrials);
  assert.equal(report.retainedAssigned, 2);
  assert.equal(report.claimReviewReady, false);
  assert.match(renderWorkflowReport(plan, report), /2 earlier assignments.*retained/);
  assert.match(report.blockers.join("\n"), /runner versions.*separately/);
});

test("removing a failed predecessor cannot authorize rerunning its assignment", (t) => {
  const { root, sourceRun, source, baseline } = storedPrefix(t);
  const study = structuredClone(source.study);
  study.continuation = describeContinuation(sourceRun, study, "Runner correction");
  study.continuation.retained.pop();
  const run = path.join(root, "continued");
  const plan = createStudyRun(study, run);
  writeNewJson(path.join(run, "quota-baseline.json"), baseline);
  assert.throws(() => verifyContinuation(run, plan), /Retained continuation evidence changed/);
});

test("continuations reject changed tasks, quotas, models and prior artifacts", (t) => {
  const { sourceRun, source } = storedPrefix(t);
  for (const change of [
    (study) => {
      study.tasks[0].prompt += " easier task";
    },
    (study) => {
      study.limits.trialCostUsd += 1;
    },
    (study) => {
      study.configurations[0].model = "another-model";
    },
    (study) => {
      study.configurations[0].environment = "different hardware";
    },
  ]) {
    const study = structuredClone(source.study);
    change(study);
    assert.throws(
      () => describeContinuation(sourceRun, study, "Runner correction"),
      /Continuation changed/,
    );
  }
  writeFileSync(
    path.join(sourceRun, "trials", source.assignments[1].id, "artifacts", "transcript.txt"),
    "modified evidence",
  );
  assert.throws(
    () => describeContinuation(sourceRun, source.study, "Runner correction"),
    /artifact digests/,
  );
});

test("a second correction preserves every earlier runner's records and only schedules unrun assignments", (t) => {
  const { root, sourceRun, source, baseline } = storedPrefix(t);
  const study = structuredClone(source.study);
  study.runnerSha256 = digest("first correction");
  study.continuation = describeContinuation(sourceRun, study, "First correction");
  const middleRun = path.join(root, "middle");
  const middle = createStudyRun(study, middleRun);
  writeNewJson(path.join(middleRun, "quota-baseline.json"), baseline);
  writeFileSync(path.join(middleRun, "quota-baseline.sha256"), digest(baseline));
  const input = writeFixtureEvidence(
    path.join(root, "middle-evidence"),
    middle,
    middle.assignments[0],
    {
      acceptance: { status: 0, log: "Synthetic check" },
      regressions: { status: 0, log: "Synthetic check" },
    },
  );
  importTrial(middleRun, input);
  const next = structuredClone(study);
  next.runnerSha256 = digest("second correction");
  next.continuation = describeContinuation(middleRun, next, "Second correction");
  const nextRun = path.join(root, "next");
  const plan = createStudyRun(next, nextRun);
  writeNewJson(path.join(nextRun, "quota-baseline.json"), baseline);
  assert.equal(verifyContinuation(nextRun, plan), 3);
  assert.equal(plan.plannedTrials, source.plannedTrials - 3);
  assert.deepEqual(
    next.continuation.retained.map((row) => row.trialId),
    [...source.assignments.slice(0, 2).map((row) => row.id), middle.assignments[0].id],
  );
  const key = ({ task, configuration, repeat, arm }) => ({ task, configuration, repeat, arm });
  assert.deepEqual(plan.assignments.map(key), source.assignments.slice(3).map(key));
  writeFileSync(
    path.join(sourceRun, "trials", source.assignments[1].id, "artifacts", "transcript.txt"),
    "changed",
  );
  assert.throws(() => verifyContinuation(nextRun, plan), /artifact digests/);
});
