import assert from "node:assert/strict";
import { test } from "node:test";
import { repositoryGraderFiles, repositoryGraderIdentity } from "./repository-grader-identity.mjs";
import { replacementCaseIds } from "../guest/replacement-cases.mjs";
import { replacementControlCaseIds } from "../guest/replacement-control-cases.mjs";

test("Whoogle grader identity excludes runner files but covers grader dependencies", () => {
  const files = Object.fromEntries(
    repositoryGraderFiles("whoogle-named-config-path").map((name) => [name, `bytes:${name}`]),
  );
  files["guest/run-trial.mjs"] = "old runner";
  const original = repositoryGraderIdentity(files, "whoogle-named-config-path");
  files["guest/run-trial.mjs"] = "new runner";
  assert.equal(repositoryGraderIdentity(files, "whoogle-named-config-path"), original);
  files["guest/whoogle-grader.mjs"] = "changed grader";
  assert.notEqual(repositoryGraderIdentity(files, "whoogle-named-config-path"), original);
});

test("grader identity rejects missing files and unknown cases", () => {
  assert.throws(
    () => repositoryGraderIdentity({}, "whoogle-named-config-path"),
    /Missing grader file/,
  );
  assert.throws(() => repositoryGraderFiles("unknown"), /Unsupported repository grader/);
});

test("confirmatory grader identities include the behavioral adapter and compiler", () => {
  for (const id of [
    "claude-code-templates-shell-boundary",
    "material-search-suggestion-text",
    "yamcs-extension-element-construction",
    "claude-code-templates-loopback-control",
    "liveatlas-entity-decoder-control",
  ]) {
    const selected = repositoryGraderFiles(id);
    assert.ok(selected.includes("guest/confirmatory-grader.mjs"));
    assert.ok(selected.includes("guest/confirmatory-node-candidate.mjs"));
    assert.ok(selected.includes("vendor/typescript.cjs"));
  }
  for (const id of [
    "lightrag-wildcard-cors-credentials",
    "glances-configurable-cors-credentials",
    "sagemaker-triton-tls-verification",
  ]) {
    const python = repositoryGraderFiles(id);
    assert.ok(python.includes("guest/confirmatory-grader.mjs"));
    assert.ok(python.includes("guest/confirmatory-python-candidate.py"));
    assert.ok(!python.includes("vendor/typescript.cjs"));
  }
});

test("replacement grader identities cover every isolated adapter dependency", () => {
  const expected = [
    "guest/candidate-sandbox.mjs",
    "guest/replacement-cases.mjs",
    "guest/replacement-dom.mjs",
    "guest/replacement-grader.mjs",
    "guest/replacement-node-candidate.mjs",
    "guest/replacement-redirect-python.py",
    "guest/replacement-redirect.mjs",
    "guest/replacement-tls-python.py",
    "guest/replacement-tls.mjs",
    "guest/replacement-unsafe-html.mjs",
    "guest/repository-grader.mjs",
    "vendor/typescript.cjs",
  ];
  for (const caseId of replacementCaseIds) {
    const files = repositoryGraderFiles(caseId);
    assert.equal(new Set(files).size, files.length);
    for (const name of expected) assert.ok(files.includes(name), `${caseId} omits ${name}`);
  }
});

test("OneKey grader identity covers its judge, worker, fixtures, and runtime manifest", () => {
  const files = repositoryGraderFiles("onekey-http-client-tls-verification");
  for (const name of [
    "cases/onekey-runtime.json",
    "guest/replacement-onekey-candidate.py",
    "guest/replacement-onekey-fixtures.py",
    "guest/replacement-onekey-grader.mjs",
    "guest/replacement-onekey-probe.py",
    "guest/replacement-onekey-runtime.mjs",
  ]) {
    assert.ok(files.includes(name), `OneKey grader omits ${name}`);
  }
});

test("FMD grader identity covers its browser judge and frozen runtime inputs", () => {
  const files = repositoryGraderFiles("fmd-device-text");
  for (const name of [
    "cases/fmd-runtime.json",
    "guest/replacement-fmd-actions.js",
    "guest/replacement-fmd-controller.mjs",
    "guest/replacement-fmd-executor.mjs",
    "guest/replacement-fmd-fixture.mjs",
    "guest/replacement-fmd-grader.mjs",
    "guest/replacement-fmd-path.mjs",
    "guest/replacement-fmd-probe.py",
    "guest/replacement-fmd-reference.mjs",
    "guest/replacement-fmd-runtime.mjs",
  ]) {
    assert.ok(files.includes(name), `FMD grader omits ${name}`);
  }
});

test("control grader identities cover the hash judge and frozen definitions", () => {
  for (const caseId of replacementControlCaseIds) {
    const files = repositoryGraderFiles(caseId);
    for (const name of [
      "guest/replacement-control-candidate.mjs",
      "guest/replacement-control-cases.mjs",
      "guest/replacement-control-grader.mjs",
      "guest/replacement-control-hash.mjs",
    ]) {
      assert.ok(files.includes(name), `${caseId} omits ${name}`);
    }
  }
});
