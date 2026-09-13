import assert from "node:assert/strict";
import { test } from "node:test";
import { createPlan, validatePlan, digest } from "./workflow-plan.mjs";
import { validateStudy } from "./workflow-contract.mjs";
import { fixtureStudy } from "./workflow-fixture.mjs";

test("paired plans are reproducible and contain each workflow exactly once per block", () => {
  const study = fixtureStudy();
  study.repeats = 3;
  const plan = createPlan(study);
  assert.deepEqual(createPlan(structuredClone(study)), plan);
  assert.equal(plan.assignments.length, 27);
  assert.equal(new Set(plan.assignments.map((item) => item.id)).size, 27);
  for (let index = 0; index < plan.assignments.length; index += 3) {
    const block = plan.assignments.slice(index, index + 3);
    assert.equal(
      new Set(block.map((item) => `${item.task}/${item.configuration}/${item.repeat}`)).size,
      1,
    );
    assert.deepEqual(block.map((item) => item.arm).sort(), ["mcp", "normal", "report"]);
  }
  assert.notDeepEqual(createPlan({ ...study, seed: 9 }).assignments, plan.assignments);
  assert.equal(plan.maximumConfiguredSpendUsd, 27);
});

test("canonical study digests ignore object key order", () => {
  assert.equal(digest({ a: 1, b: [2, 3] }), digest({ b: [2, 3], a: 1 }));
  assert.notEqual(digest({ a: [1, 2] }), digest({ a: [2, 1] }));
});

test("frozen study mutations and reordered assignments fail validation", () => {
  const plan = createPlan(fixtureStudy());
  plan.study.limits.trialTokens++;
  assert.throws(() => validatePlan(plan), /changed/);
  const reordered = createPlan(fixtureStudy());
  reordered.assignments.reverse();
  assert.throws(() => validatePlan(reordered), /changed/);
});

test("a calibration case must reproduce a defect and have a working reference", () => {
  for (const change of [
    (study) => {
      study.tasks[0].baseline.acceptancePass = true;
    },
    (study) => {
      study.tasks[0].reference.regressionsPass = false;
    },
    (study) => {
      study.tasks[0].sourceSha256 = "bad";
    },
    (study) => {
      study.tasks[0].runtimeSha256 = "bad";
    },
    (study) => {
      study.configurations.push(study.configurations[0]);
    },
    (study) => {
      study.limits.trialCostUsd = 0;
    },
    (study) => {
      study.repeats = 1.5;
    },
    (study) => {
      study.id = undefined;
    },
  ]) {
    const study = fixtureStudy();
    change(study);
    assert.throws(() => validateStudy(study));
  }
});

test("confirmatory studies require registration, held-out tasks, and a clean build", () => {
  const study = fixtureStudy();
  study.phase = "confirmatory";
  assert.throws(() => validateStudy(study), /clean/);
  study.sitecmd.dirty = false;
  assert.throws(() => validateStudy(study), /preregistration/);
  study.registration = "Registered protocol before any trials";
  study.sampleSizeRationale = "Power analysis with repository clustering";
  assert.throws(() => validateStudy(study), /held out/);
  study.tasks.forEach((task) => {
    task.holdout = true;
  });
  assert.equal(validateStudy(study), study);
});
