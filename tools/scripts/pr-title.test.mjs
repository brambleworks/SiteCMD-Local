import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

import { gitEnv } from "./lib/git-env.mjs";
import { readWorkflow } from "./lib/guardrail-workflow-yaml.mjs";

const script = fileURLToPath(new URL("./pr-title.mjs", import.meta.url));

function check({ title = "Add verified site baselines", body = "", author = "maintainer" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "sitecmd-pr-title-"));
  try {
    const file = join(directory, "body.txt");
    writeFileSync(file, body);
    return spawnSync(
      process.execPath,
      [script, `--title=${title}`, "--body-file", file, "--author", author],
      {
        encoding: "utf8",
        env: gitEnv(),
      },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

it("applies the commit subject rules to the title", () => {
  const result = check({ title: "fix: Changed things." });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("Remove the Conventional Commit prefix.");
  expect(check({ title: "Add baselines\nAnother subject" }).status).toBe(1);
});

it("applies the body rules to the PR body", () => {
  const result = check({ body: "# First\nSecond\nThird\nFourth\nFifth" });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("Keep the body at 4 non-empty lines or fewer.");
  expect(check({ body: "x".repeat(401) }).stderr).toContain("400 characters");
});

it("counts CRLF as one line break", () => {
  const body = Array(4).fill("x".repeat(99)).join("\r\n");
  expect(check({ body }).status).toBe(0);
});

it("accepts an empty body", () => {
  expect(check().status).toBe(0);
});

it("exempts only dependabot[bot]", () => {
  const invalid = { title: "Bump", body: "x".repeat(401) };
  expect(check({ ...invalid, author: "dependabot[bot]" }).status).toBe(0);
  expect(check({ ...invalid, author: "dependabot" }).status).toBe(1);
  expect(check({ ...invalid, author: "renovate[bot]" }).status).toBe(1);
});

it("does not exempt a human title starting with Bump", () => {
  const result = check({
    title:
      "Bump a-very-long-dependency-name from 1.0.0 to 2.0.0 in the development-dependencies group",
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("60 characters");
});

it("reports a rule error for a title that starts with a hyphen", () => {
  const run = check({ title: "-Add verified site baselines" });
  expect(run.status).toBe(1);
  expect(run.stderr).toContain("capitalized imperative verb");

  const { jobs } = readWorkflow(readFileSync(".github/workflows/ci.yml", "utf8"));
  expect(jobs["pr-title"].steps.at(-1).run).toContain('--title="$PR_TITLE"');
});
