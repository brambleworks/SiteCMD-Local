import assert from "node:assert/strict";
import { test } from "node:test";
import { confirmatoryQualificationPath } from "../guest/confirmatory-qualification-path.mjs";

test("confirmatory qualification paths stay under the isolated workspace", () => {
  assert.equal(
    confirmatoryQualificationPath("0123456789abcdef0123456789abcdef", "fmd-device-text"),
    "/srv/sitecmd-benchmark/confirmatory-qualification/0123456789abcdef0123456789abcdef/fmd-device-text",
  );
});

test("confirmatory qualification paths reject unsafe identities", () => {
  for (const runId of [undefined, "", "ABCDEF0123456789abcdef0123456789", "../trials"])
    assert.throws(() => confirmatoryQualificationPath(runId, "safe-case"));
  for (const caseId of [undefined, "", "../trials", "case/name", "case.name"])
    assert.throws(() => confirmatoryQualificationPath("0123456789abcdef0123456789abcdef", caseId));
});
