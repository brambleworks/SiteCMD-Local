import fs from "node:fs";
import { describe, expect, it } from "vitest";
import {
  GUARDRAIL_TEST_TIMEOUT_MS,
  ROOT,
  copyRepoFixture,
  runGuardrails,
  writeFixtureFile,
} from "./guardrail-test-support.mjs";

describe.concurrent(
  "the guardrail runner end to end",
  { timeout: GUARDRAIL_TEST_TIMEOUT_MS },
  () => {
    it("scans a real tree from the command line and exits 0", async () => {
      const fixtureRoot = copyRepoFixture();
      try {
        const result = await runGuardrails(fixtureRoot);

        expect(`${result.stdout}\n${result.stderr}`).toContain("Repo guardrails passed.");
        expect(result.status).toBe(0);
      } finally {
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
      }
    });

    it("exits 1 and reports the aggregated failures on stderr", async () => {
      const fixtureRoot = copyRepoFixture();
      try {
        writeFixtureFile(fixtureRoot, ".github/allowed-signers", "# every key removed\n");
        const result = await runGuardrails(fixtureRoot, { cwd: ROOT });

        expect(result.status).toBe(1);
        expect(result.stderr).toContain("Repo guardrails failed:");
        expect(result.stderr).toContain(
          ".github/allowed-signers must list at least one signing key",
        );
      } finally {
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
      }
    });

    it("walks nested directories to find a file nothing names", async () => {
      const fixtureRoot = copyRepoFixture();
      try {
        const emDash = String.fromCharCode(0x2014);
        writeFixtureFile(
          fixtureRoot,
          "apps/desktop/src-tauri/src/core/guardrail_probe.rs",
          `// discovered by the directory walk, not by name em${emDash}dash\n`,
        );
        const result = await runGuardrails(fixtureRoot);

        expect(result.status).toBe(1);
        expect(result.stderr).toContain("guardrail_probe.rs");
      } finally {
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
      }
    });
  },
);
