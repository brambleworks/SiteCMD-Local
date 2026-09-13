import assert from "node:assert/strict";
import { test } from "node:test";
import { candidateAdapterProfile } from "../guest/candidate-sandbox.mjs";
import {
  isReplacementControlCase,
  replacementControlCaseIds,
  replacementControlDefinition,
} from "../guest/replacement-control-cases.mjs";
import {
  gradeReplacementControlRepository,
  normalizeReplacementControlGrade,
} from "../guest/replacement-control-grader.mjs";
import { controlTreeEvidence } from "../guest/replacement-control-hash.mjs";
import { gradeRepository } from "../guest/repository-grader.mjs";

const caseId = replacementControlCaseIds[0];
const definition = replacementControlDefinition(caseId);
const observed = (overrides = {}) => ({
  isolation: { uid: 65534, candidateSuppliesVerdict: false },
  targetSha256: definition.targetSha256,
  treeSha256: definition.treeSha256,
  fileCount: definition.fileCount,
  bytes: definition.bytes,
  ...overrides,
});

test("replacement control manifest pins all eight qualified controls", () => {
  assert.equal(replacementControlCaseIds.length, 8);
  assert.equal(new Set(replacementControlCaseIds).size, 8);
  for (const id of replacementControlCaseIds) {
    assert.equal(isReplacementControlCase(id), true);
    assert.match(replacementControlDefinition(id).treeSha256, /^[a-f0-9]{64}$/);
  }
  assert.equal(isReplacementControlCase("unknown"), false);
  assert.throws(() => replacementControlDefinition("unknown"), /Unsupported/);
});

test("replacement controls pass only for a byte-for-byte unchanged tree", () => {
  const unchanged = normalizeReplacementControlGrade(observed(), definition);
  assert.equal(unchanged.acceptancePass, true);
  assert.equal(unchanged.regressionsPass, true);
  for (const changed of [
    { targetSha256: "0".repeat(64), treeSha256: "1".repeat(64) },
    { treeSha256: "1".repeat(64) },
    { fileCount: definition.fileCount + 1, treeSha256: "1".repeat(64) },
    { bytes: definition.bytes + 1, treeSha256: "1".repeat(64) },
    { targetSha256: null, treeSha256: "1".repeat(64), fileCount: definition.fileCount - 1 },
  ]) {
    const grade = normalizeReplacementControlGrade(observed(changed), definition);
    assert.equal(grade.acceptancePass, false);
    assert.equal(grade.regressionsPass, false);
    assert.equal(grade.probeError, undefined);
  }
});

test("replacement controls fail closed on malformed or unisolated evidence", () => {
  for (const value of [
    null,
    { error: "CandidateProcessError", message: "blocked" },
    observed({ isolation: { uid: 0, candidateSuppliesVerdict: false } }),
    observed({ isolation: { uid: 65534, candidateSuppliesVerdict: true } }),
    observed({ treeSha256: "invalid" }),
    observed({ fileCount: -1 }),
  ]) {
    const grade = normalizeReplacementControlGrade(value, definition);
    assert.equal(grade.acceptancePass, false);
    assert.equal(grade.regressionsPass, false);
    assert.match(grade.probeError, /.+/);
  }
});

test("control tree evidence covers paths, modes, content, and byte counts", () => {
  const files = [
    { name: "b.txt", mode: "100644", contents: Buffer.from("second") },
    { name: "a.txt", mode: "100755", contents: Buffer.from("first") },
  ];
  const baseline = controlTreeEvidence(files);
  assert.deepEqual(controlTreeEvidence([...files].reverse()), baseline);
  assert.equal(baseline.fileCount, 2);
  assert.equal(baseline.bytes, 11);
  for (const changed of [
    files.map((file) => ({ ...file, contents: Buffer.from(`${file.contents}!`) })),
    files.map((file, index) => (index ? file : { ...file, name: "renamed.txt" })),
    files.map((file, index) => (index ? file : { ...file, mode: "100755" })),
    files.slice(1),
  ]) {
    assert.notEqual(controlTreeEvidence(changed).treeSha256, baseline.treeSha256);
  }
});

test("repository grading dispatches controls through the isolated hash adapter", () => {
  const item = { id: caseId, repository: "example/control", runtime: "node" };
  const execute = (context, candidate, input) => {
    assert.equal(context.controlAdapter, true);
    assert.equal(candidate, "/candidate");
    assert.deepEqual(input, { operation: caseId, targetPath: definition.targetPath });
    return observed();
  };
  assert.equal(gradeReplacementControlRepository(item, "/candidate", execute).acceptancePass, true);
  assert.equal(gradeRepository(item, "/candidate", execute).acceptancePass, true);
  const profile = candidateAdapterProfile({ ...item, controlAdapter: true });
  assert.equal(profile.control, true);
  assert.equal(profile.node, true);
  assert.equal(profile.adapter, "replacement-control-candidate.mjs");
  assert.deepEqual(profile.supportFiles, ["replacement-control-hash.mjs"]);
});
