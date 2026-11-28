import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { releasePinStepIsComplete } from "./lib/guardrail-engine-pin-workflow-rules.mjs";

it("release_workflow_has_no_capability_manifest_job", () => {
  // The CLI release still tries to publish the private engine capability manifest.
  const workflow = readFileSync(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  expect(workflow).not.toContain("publish-capability-manifest");
});

it("release_workflow_verifies_the_pin", () => {
  // Release verification can publish an archive without checking its embedded module.
  const workflow = readFileSync(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  const verify = workflow.slice(
    workflow.indexOf("\n  verify-release:"),
    workflow.indexOf("\n  publish-release:"),
  );
  expect(releasePinStepIsComplete(verify)).toBe(true);
});
