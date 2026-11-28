import { it } from "vitest";
import {
  expectGuardrailFailure,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";
const { ciCostSafetyFailures } = rules;

it("rejects a release workflow without per-job timeout caps or run cancellation", () => {
  expectGuardrailFailure(
    ciCostSafetyFailures,
    (fixtureRoot) => {
      const workflowPath = ".github/workflows/release.yml";
      const source = readFixtureFile(fixtureRoot, workflowPath);
      writeFixtureFile(fixtureRoot, workflowPath, source.replace("    timeout-minutes: 75\n", ""));
    },
    "release.yml must declare timeout-minutes on every job",
  );

  expectGuardrailFailure(
    ciCostSafetyFailures,
    (fixtureRoot) => {
      const workflowPath = ".github/workflows/release.yml";
      const source = readFixtureFile(fixtureRoot, workflowPath);
      writeFixtureFile(
        fixtureRoot,
        workflowPath,
        source.replace("  cancel-in-progress: true\n", ""),
      );
    },
    "release.yml must keep a concurrency group with cancel-in-progress",
  );
});
