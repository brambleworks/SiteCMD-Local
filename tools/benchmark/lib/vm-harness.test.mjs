import assert from "node:assert/strict";
import { test } from "node:test";
import { harnessFiles } from "./vm-harness.mjs";

test("VM harness deploys FMD JavaScript actions and runtime manifest", () => {
  const files = harnessFiles();
  assert.match(files["guest/replacement-fmd-actions.js"], /__SITECMD_EXPECTED_ROUTE__/);
  assert.equal(JSON.parse(files["cases/fmd-runtime.json"]).caseId, "fmd-device-text");
});
