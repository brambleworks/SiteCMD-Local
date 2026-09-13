import assert from "node:assert/strict";
import { test } from "node:test";
import {
  repositoryQualificationRuntime,
  repositoryQualificationRuntimeBinding,
  validateRepositoryQualificationRuntime,
} from "./repository-qualification-runtime.mjs";

function variants(field, value) {
  return Object.fromEntries(
    ["baseline", "reference"].map((name) => [
      name,
      { grades: Array.from({ length: 3 }, () => ({ [field]: value })) },
    ]),
  );
}

test("qualification evidence binds OneKey grades to its repository runtime", () => {
  const runtime = { kind: "onekey", frozen: true };
  const runtimeSha256 = "31".repeat(32);
  const mismatched = variants("runtimeSha256", runtimeSha256);
  const evidence = repositoryQualificationRuntime(
    "onekey-http-client-tls-verification",
    { repositoryRuntime: runtime },
    mismatched,
  );
  assert.equal(evidence.runtimePassed, false);
  for (const variant of Object.values(mismatched)) {
    for (const grade of variant.grades) grade.runtimeSha256 = evidence.runtimeSha256;
  }
  const matched = repositoryQualificationRuntime(
    "onekey-http-client-tls-verification",
    { repositoryRuntime: runtime },
    mismatched,
  );
  assert.equal(matched.runtimePassed, true);
  assert.equal(
    validateRepositoryQualificationRuntime("onekey-http-client-tls-verification", {
      ...matched,
      variants: mismatched,
    }),
    true,
  );
  assert.deepEqual(
    repositoryQualificationRuntimeBinding("onekey-http-client-tls-verification", {
      ...matched,
      variants: mismatched,
    }),
    {
      runtimeField: "repositoryRuntime",
      digestField: "runtimeSha256",
      runtime,
      sha256: matched.runtimeSha256,
    },
  );
});

test("qualification evidence binds FMD grades to its browser runtime", () => {
  const runtime = { kind: "fmd-browser-v1", frozen: true };
  const evidence = repositoryQualificationRuntime(
    "fmd-device-text",
    { browserRuntime: runtime },
    variants("browserRuntimeSha256", "00".repeat(32)),
  );
  assert.equal(evidence.runtimePassed, false);
  assert.equal(
    validateRepositoryQualificationRuntime("fmd-device-text", {
      ...evidence,
      variants: variants("browserRuntimeSha256", evidence.runtimeSha256),
      runtimePassed: true,
    }),
    true,
  );
  const receipt = {
    ...evidence,
    variants: variants("browserRuntimeSha256", evidence.runtimeSha256),
    runtimePassed: true,
  };
  assert.deepEqual(repositoryQualificationRuntimeBinding("fmd-device-text", receipt), {
    runtimeField: "browserRuntime",
    digestField: "browserRuntimeSha256",
    runtime,
    sha256: evidence.runtimeSha256,
  });
});

test("qualification runtime checks reject missing special-case evidence", () => {
  assert.throws(() =>
    repositoryQualificationRuntime(
      "fmd-device-text",
      {},
      variants("browserRuntimeSha256", "00".repeat(32)),
    ),
  );
  assert.equal(repositoryQualificationRuntime("generic-case", {}, {}), undefined);
  assert.equal(validateRepositoryQualificationRuntime("generic-case", {}), true);
  assert.equal(repositoryQualificationRuntimeBinding("generic-case", {}), undefined);
  assert.throws(
    () => repositoryQualificationRuntimeBinding("fmd-device-text", {}),
    /runtime.*missing|runtime evidence.*invalid/i,
  );
});
