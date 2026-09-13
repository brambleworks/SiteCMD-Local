import assert from "node:assert/strict";
import { test } from "node:test";
import { fixtureStudy } from "./workflow-fixture.mjs";
import { digest } from "./workflow-plan.mjs";
import {
  buildSupplementalStudy,
  normalizeSupplementalBaseline,
  supplementalStudyPolicy,
} from "./workflow-supplemental-study.mjs";

test("supplemental construction changes only its disclosure, allowance and runner", () => {
  const source = fixtureStudy();
  source.id = supplementalStudyPolicy.sourceStudyId;
  source.phase = "confirmatory";
  source.billing = {
    mode: "subscription",
    paidFallback: false,
    automaticResets: false,
    weeklyBudgetPercentagePoints: 20,
    minimumRemainingPercent: 30,
    quotaMaxAgeSeconds: 300,
  };
  source.runnerSha256 = digest("source runner");
  source.configurations[0].environment += `; controller ${source.runnerSha256}`;
  const original = structuredClone(source);
  const continuation = {
    kind: "supplemental-completion",
    sourceRun: "/frozen/source",
  };
  const runnerSha256 = digest("supplemental runner");

  const study = buildSupplementalStudy(source, continuation, runnerSha256);

  assert.deepEqual(source, original);
  assert.equal(study.id, supplementalStudyPolicy.studyId);
  assert.equal(study.phase, "calibration");
  assert.deepEqual(study.billing, supplementalStudyPolicy.billing);
  assert.equal(study.runnerSha256, runnerSha256);
  assert.equal(study.continuation, continuation);
  assert.match(study.configurations[0].environment, new RegExp(`${runnerSha256}$`));
  assert.deepEqual(study.tasks, source.tasks);
  assert.deepEqual(study.sitecmd, source.sitecmd);

  assert.throws(
    () => buildSupplementalStudy({ ...source, phase: "calibration" }, continuation, runnerSha256),
    /confirmatory source/,
  );
});

test("a supplemental baseline starts accounting at the fresh provider reading", () => {
  const snapshot = {
    accounts: [
      {
        windows: [
          {
            id: "weekly",
            usedPercent: 66,
            accountingEpochs: [{ startUsedPercent: 39, peakUsedPercent: 66, resetsAt: "later" }],
          },
        ],
      },
    ],
  };

  const baseline = normalizeSupplementalBaseline(snapshot);

  assert.notEqual(baseline, snapshot);
  assert.equal(baseline.accounts[0].windows[0].usedPercent, 66);
  assert.equal(baseline.accounts[0].windows[0].accountingEpochs, undefined);
  assert.equal(snapshot.accounts[0].windows[0].accountingEpochs.length, 1);
});
