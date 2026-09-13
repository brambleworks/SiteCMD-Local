import assert from "node:assert/strict";
import { test } from "node:test";
import { isApprovedFmdCandidatePath } from "../guest/replacement-fmd-path.mjs";

test("FMD candidate paths cover each isolated execution workspace", () => {
  for (const root of [
    "/srv/sitecmd-benchmark/trials",
    "/srv/sitecmd-benchmark/replacement-qualification",
    "/srv/sitecmd-benchmark/confirmatory-qualification",
  ]) {
    assert.equal(isApprovedFmdCandidatePath(`${root}/run/fmd-device-text/baseline`), true);
  }
});

test("FMD candidate paths reject roots, siblings, traversal, and relative paths", () => {
  for (const candidate of [
    "/srv/sitecmd-benchmark/trials",
    "/srv/sitecmd-benchmark/trials-archive/run/candidate",
    "/srv/sitecmd-benchmark/trials/../secrets",
    "/tmp/candidate",
    "trials/run/candidate",
  ]) {
    assert.equal(isApprovedFmdCandidatePath(candidate), false, candidate);
  }
});
