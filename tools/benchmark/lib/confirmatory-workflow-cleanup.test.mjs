import assert from "node:assert/strict";
import { test } from "node:test";
import {
  confirmatoryWorkflowStatePaths,
  removeConfirmatoryWorkflowState,
} from "../guest/confirmatory-workflow-cleanup.mjs";

const sessionId = "0123456789abcdef0123456789abcdef";
const state = {
  workspace: `/srv/sitecmd-benchmark/workspaces/${sessionId}`,
  mounted: `/home/sitecmd/projects/${sessionId}`,
  data: `/srv/sitecmd-benchmark/app-data/${sessionId}`,
};

test("confirmatory workflow cleanup accepts only its exact session paths", () => {
  assert.deepEqual(confirmatoryWorkflowStatePaths(sessionId, state), Object.values(state));
  for (const candidate of [
    { ...state, workspace: "/srv/sitecmd-benchmark/workspaces" },
    { ...state, mounted: "/home/sitecmd/projects" },
    { ...state, data: "/srv/sitecmd-benchmark/app-data/other" },
    { ...state, unexpected: "/tmp/path" },
  ]) {
    assert.throws(() => confirmatoryWorkflowStatePaths(sessionId, candidate));
  }
  assert.throws(() => confirmatoryWorkflowStatePaths("../trials", state));
});

test("confirmatory workflow cleanup removes each validated target", () => {
  const removed = [];
  removeConfirmatoryWorkflowState(sessionId, state, (target, options) =>
    removed.push({ target, options }),
  );
  assert.deepEqual(
    removed,
    Object.values(state).map((target) => ({
      target,
      options: { recursive: true, force: true },
    })),
  );
});
