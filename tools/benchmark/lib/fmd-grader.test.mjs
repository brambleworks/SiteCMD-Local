import assert from "node:assert/strict";
import { test } from "node:test";
import {
  fmdAcceptanceCheckNames,
  fmdCaseId,
  fmdCheckNames,
  gradeFmdRepository,
  normalizeFmdGrade,
} from "../guest/replacement-fmd-grader.mjs";
import { gradeRepository } from "../guest/repository-grader.mjs";

const acceptance = new Set(fmdAcceptanceCheckNames);

function run(checks, passed = checks.every((check) => check.passed)) {
  return {
    exitCode: 0,
    error: null,
    stderr: "",
    result: {
      passed,
      setupError: null,
      checks,
      observations: Array.from({ length: 10 }, () => ({ pageOverrideInstalled: false })),
      pendingActionSamples: Array.from({ length: 10 }, () => ({
        completed: true,
        samples: 1,
      })),
      earlyRenderSamples: Array.from({ length: 10 }, () => ({
        samples: 3,
        settleSamples: 3,
      })),
    },
  };
}

function output({ repaired = true } = {}) {
  const referenceChecks = Array.from({ length: 82 }, (_value, index) => ({
    name: `reference check ${index}`,
    passed: true,
  }));
  const candidateChecks = fmdCheckNames.map((name) => ({
    name,
    passed: repaired || !acceptance.has(name),
  }));
  return {
    candidate: run(candidateChecks),
    references: {
      primary: Array.from({ length: 3 }, () => run(referenceChecks)),
      details: Array.from({ length: 3 }, () => run(referenceChecks)),
      retries: { primary: [], details: [] },
      fixtureSha256: "a".repeat(64),
      transitionSha256: "b".repeat(64),
    },
  };
}

test("FMD grading separates provider safety from page compatibility", () => {
  assert.equal(fmdCheckNames.length, 112);
  assert.equal(fmdAcceptanceCheckNames.length, 42);
  const baseline = normalizeFmdGrade(output({ repaired: false }));
  assert.equal(baseline.acceptancePass, false);
  assert.equal(baseline.regressionsPass, true);
  assert.equal(baseline.acceptance.length, 42);
  assert.equal(baseline.regressions.length, 70);
  const reference = normalizeFmdGrade(output());
  assert.equal(reference.acceptancePass, true);
  assert.equal(reference.regressionsPass, true);
  assert.deepEqual(reference.observed.referenceRetries, {
    primary: 0,
    details: 0,
    sha256: "71596f42a4f30ae552591a65f633907fe5d488e522a5d822f618e94aa4d5f8f1",
  });
});

test("FMD grading retains bounded reference retry evidence", () => {
  const value = output();
  const initial = structuredClone(value.references.primary[0]);
  initial.result.passed = false;
  value.references.retries.primary.push({
    index: 0,
    initial,
    retry: value.references.primary[0],
  });
  const grade = normalizeFmdGrade(value);
  assert.equal(grade.acceptancePass, true);
  assert.equal(grade.regressionsPass, true);
  assert.equal(grade.observed.referenceRetries.primary, 1);
  assert.equal(grade.observed.referenceRetries.details, 0);
  assert.match(grade.observed.referenceRetries.sha256, /^[a-f0-9]{64}$/);
});

test("FMD grading fails closed on malformed, forged, or inconsistent evidence", () => {
  const missingCheck = output();
  missingCheck.candidate.result.checks.pop();
  const duplicateCheck = output();
  duplicateCheck.candidate.result.checks[1] = duplicateCheck.candidate.result.checks[0];
  const pageOverride = output();
  pageOverride.candidate.result.observations[0].pageOverrideInstalled = true;
  const missingReference = output();
  missingReference.references.primary.pop();
  const invalidRetry = output();
  const failedInitial = structuredClone(invalidRetry.references.primary[0]);
  failedInitial.result.passed = false;
  const mismatchedRetry = structuredClone(invalidRetry.references.primary[0]);
  mismatchedRetry.exitCode = 1;
  invalidRetry.references.retries.primary.push({
    index: 0,
    initial: failedInitial,
    retry: mismatchedRetry,
  });
  const inconsistent = output();
  inconsistent.candidate.result.passed = false;
  for (const value of [
    null,
    { error: "FmdControllerError", message: "blocked" },
    missingCheck,
    duplicateCheck,
    pageOverride,
    missingReference,
    invalidRetry,
    inconsistent,
  ]) {
    const grade = normalizeFmdGrade(value);
    assert.equal(grade.acceptancePass, false);
    assert.equal(grade.regressionsPass, false);
    assert.match(grade.probeError, /.+/);
  }
});

test("repository grading dispatches FMD through the browser controller", () => {
  const browserRuntime = { frozen: true };
  const item = { id: fmdCaseId, browserRuntime, runtime: "node" };
  const execute = (context, candidate, input) => {
    assert.equal(context.fmdAdapter, true);
    assert.deepEqual(context.browserRuntime, browserRuntime);
    assert.equal(candidate, "/candidate");
    assert.deepEqual(input, { operation: fmdCaseId });
    return output();
  };
  assert.equal(gradeFmdRepository(item, "/candidate", execute).acceptancePass, true);
  assert.equal(gradeRepository(item, "/candidate", execute).acceptancePass, true);
});
