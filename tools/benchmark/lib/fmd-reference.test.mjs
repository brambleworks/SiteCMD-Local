import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isValidFmdReferenceRun,
  stabilizeFmdReferenceRuns,
} from "../guest/replacement-fmd-reference.mjs";

function referenceRun(passed = true) {
  return {
    exitCode: 0,
    error: null,
    result: {
      passed,
      setupError: null,
      checks: Array.from({ length: 82 }),
      observations: Array.from({ length: 10 }),
      pendingActionSamples: Array.from({ length: 10 }, () => ({
        completed: true,
        samples: [{}],
      })),
      earlyRenderSamples: Array.from({ length: 10 }, () => ({
        samples: [{}, {}, {}],
        settleSamples: [{}, {}, {}],
      })),
    },
  };
}

test("FMD reference capture leaves valid runs untouched", async () => {
  const initial = [referenceRun(), referenceRun(), referenceRun()];
  let calls = 0;
  const result = await stabilizeFmdReferenceRuns(initial, async () => {
    calls += 1;
    return referenceRun();
  });
  assert.deepEqual(result, { runs: initial, retries: [] });
  assert.equal(calls, 0);
});

test("FMD reference capture retries only failed trusted runs once", async () => {
  const failed = referenceRun(false);
  const replacement = referenceRun();
  const initial = [referenceRun(), failed, referenceRun()];
  const result = await stabilizeFmdReferenceRuns(initial, async () => replacement);
  assert.equal(isValidFmdReferenceRun(result.runs[1]), true);
  assert.deepEqual(result.retries, [{ index: 1, initial: failed, retry: replacement }]);
});

test("FMD reference capture fails closed after a repeated failure", async () => {
  const failed = referenceRun(false);
  let calls = 0;
  const result = await stabilizeFmdReferenceRuns(
    [failed, referenceRun(false), referenceRun()],
    async () => {
      calls += 1;
      return referenceRun(false);
    },
  );
  assert.equal(calls, 1);
  assert.equal(isValidFmdReferenceRun(result.runs[0]), false);
  assert.equal(result.retries.length, 1);
});
