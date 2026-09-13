import assert from "node:assert/strict";
import { test } from "node:test";
import {
  gradeOnekeyRepository,
  normalizeOnekeyGrade,
  onekeyCaseId,
} from "../guest/replacement-onekey-grader.mjs";
import { gradeRepository } from "../guest/repository-grader.mjs";
import { digest } from "./workflow-plan.mjs";

const acceptanceNames = ["untrusted", "wrong-host", "expired"].flatMap((server) => [
  `${server} get attempt 1 rejects the certificate`,
  `${server} get attempt 2 rejects the certificate`,
  `${server} post attempt 3 rejects the certificate`,
  `${server} post attempt 4 rejects the certificate`,
]);
const regressionNames = [
  "context manager preserves client identity",
  "trusted get preserves request and binary response",
  "trusted get preserves timeout contract",
  "plain get preserves request and binary response",
  "plain get preserves timeout contract",
  "trusted post preserves request and binary response",
  "trusted post preserves timeout contract",
  "plain post preserves request and binary response",
  "plain post preserves timeout contract",
  "HTTP error status remains a response",
  "concurrent requests preserve binary responses",
  "ordinary delayed responses remain usable",
  "context manager closes the production transport",
  "context manager propagates body exceptions",
  "exceptional context closes the production transport",
  "explicit close is idempotent and closes the production transport",
  "lifecycle operations complete without errors",
];

function probeResult({ secure = true, isolation = true } = {}) {
  return {
    setupError: null,
    judgeIsolation: {
      judgeUid: 0,
      candidateUid: isolation ? 65534 : 0,
      candidateSuppliesVerdict: false,
    },
    checks: [
      ...regressionNames.map((name) => ({ name, passed: true })),
      ...acceptanceNames.map((name) => ({ name, passed: secure })),
    ],
  };
}

test("OneKey grading separates TLS acceptance from client compatibility", () => {
  const baseline = normalizeOnekeyGrade(probeResult({ secure: false }));
  assert.equal(baseline.acceptancePass, false);
  assert.equal(baseline.regressionsPass, true);
  const reference = normalizeOnekeyGrade(probeResult());
  assert.equal(reference.acceptancePass, true);
  assert.equal(reference.regressionsPass, true);
  assert.equal(reference.acceptance.length, 12);
  assert.equal(reference.regressions.length, 17);
});

test("OneKey grading fails closed on forged, incomplete, or unisolated results", () => {
  for (const value of [
    null,
    { error: "CandidateProcessError", message: "blocked" },
    probeResult({ isolation: false }),
    { ...probeResult(), checks: probeResult().checks.slice(1) },
    { ...probeResult(), checks: [...probeResult().checks, probeResult().checks[0]] },
  ]) {
    const grade = normalizeOnekeyGrade(value);
    assert.equal(grade.acceptancePass, false);
    assert.equal(grade.regressionsPass, false);
    assert.match(grade.probeError, /.+/);
  }
});

test("repository grading dispatches OneKey through its privileged judge adapter", () => {
  const runtime = { frozen: true };
  const item = { id: onekeyCaseId, repositoryRuntime: runtime, runtime: "python" };
  const execute = (context, candidate, input) => {
    assert.equal(context.onekeyAdapter, true);
    assert.deepEqual(context.repositoryRuntime, runtime);
    assert.equal(candidate, "/candidate");
    assert.deepEqual(input, { operation: onekeyCaseId });
    return probeResult();
  };
  const direct = gradeOnekeyRepository(item, "/candidate", execute);
  const dispatched = gradeRepository(item, "/candidate", execute);
  assert.equal(direct.acceptancePass, true);
  assert.equal(dispatched.acceptancePass, true);
  assert.equal(direct.runtimeSha256, digest(runtime));
  assert.equal(dispatched.runtimeSha256, digest(runtime));
});
