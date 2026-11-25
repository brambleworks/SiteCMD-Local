import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const COVERAGE_SUITES = [
  "repo-guardrail-coverage-product.test.mjs",
  "repo-guardrail-coverage-quality.test.mjs",
  "repo-guardrail-coverage-security.test.mjs",
];

function readTest(name) {
  return fs.readFileSync(path.join(ROOT, "tools/scripts", name), "utf8");
}

describe("guardrail test architecture", () => {
  it("keeps mutation coverage on the in-process path", () => {
    for (const suite of COVERAGE_SUITES) {
      const source = readTest(suite);
      expect(source).toContain("expectGuardrailFailure");
      expect(source).not.toContain("runGuardrails(");
      expect(source).not.toContain("copyRepoFixture(");
      expect(source).not.toContain("spawnSync(");
    }
  });

  it("isolates the three subprocess checks in the end-to-end suite", () => {
    const source = readTest("repo-guardrail-runner-e2e.test.mjs");
    expect(source).toContain("copyRepoFixture");
    expect(source.split("await runGuardrails(").length - 1).toBe(3);
  });
});
