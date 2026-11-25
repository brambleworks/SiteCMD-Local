import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { gitEnv } from "./lib/git-env.mjs";

const path = "tools/scripts/ci-verdict.mjs";
const repository = "owner/repository";
const runList = `/repos/${repository}/actions/workflows/ci.yml/runs?event=merge_group&status=success&per_page=50`;
const mergeSha = "a".repeat(40);
const otherTree = "b".repeat(40);
const sha = spawnSync("git", ["rev-parse", "HEAD"], {
  encoding: "utf8",
  env: gitEnv(),
}).stdout.trim();
const tree = spawnSync("git", ["rev-parse", `${sha}^{tree}`], {
  encoding: "utf8",
  env: gitEnv(),
}).stdout.trim();
const directories = [];

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function run(id, head = mergeSha, overrides = {}) {
  return {
    id,
    head_sha: head,
    event: "merge_group",
    status: "completed",
    conclusion: "success",
    ...overrides,
  };
}

function lookup(runs, trees = {}, failAt = "", laterRuns = []) {
  const directory = mkdtempSync(join(tmpdir(), "ci-verdict-"));
  directories.push(directory);
  const callsPath = join(directory, "calls");
  writeFileSync(callsPath, "");
  writeFileSync(
    join(directory, "gh"),
    `#!/usr/bin/env node
const { appendFileSync, readFileSync } = require("node:fs");
const [command, endpoint, ...args] = process.argv.slice(2);
appendFileSync(process.env.FIXTURE_CALLS, endpoint + "\\n");
if (command !== "api" || process.env.GH_TOKEN !== "fixture-token" || endpoint === process.env.FIXTURE_FAIL_AT) {
  console.error("fixture API error");
  process.exit(1);
}
if (endpoint === ${JSON.stringify(runList)} && args.length === 0) {
  const count = readFileSync(process.env.FIXTURE_CALLS, "utf8").split("\\n").filter((call) => call === endpoint).length;
  const responses = JSON.parse(process.env.FIXTURE_RUNS);
  console.log(JSON.stringify({ workflow_runs: responses[Math.min(count - 1, responses.length - 1)] }));
} else {
  const match = /^\\/?repos\\/owner\\/repository\\/git\\/commits\\/([0-9a-f]{40})$/.exec(endpoint);
  const tree = match && JSON.parse(process.env.FIXTURE_TREES)[match[1]];
  if (!tree || args.join(" ") !== "--jq .tree.sha") process.exit(1);
  console.log(tree);
}
`,
    { mode: 0o700 },
  );

  const sleepsPath = join(directory, "sleeps");
  writeFileSync(sleepsPath, "");
  writeFileSync(join(directory, "sleep"), '#!/bin/sh\nprintf "%s\\n" "$1" >> "$FIXTURE_SLEEPS"\n', {
    mode: 0o700,
  });
  const result = spawnSync(process.execPath, [path, "--sha", sha], {
    encoding: "utf8",
    env: {
      ...gitEnv(),
      PATH: `${directory}:${process.env.PATH}`,
      GH_TOKEN: "fixture-token",
      GITHUB_REPOSITORY: repository,
      FIXTURE_CALLS: callsPath,
      FIXTURE_RUNS: JSON.stringify([runs, ...laterRuns]),
      FIXTURE_SLEEPS: sleepsPath,
      FIXTURE_TREES: JSON.stringify(trees),
      FIXTURE_FAIL_AT: failAt,
    },
  });
  return {
    ...result,
    calls: readFileSync(callsPath, "utf8").trim().split("\n"),
    sleeps: readFileSync(sleepsPath, "utf8").split("\n").filter(Boolean),
  };
}

it("matches a merge_group run by tree, not sha", () => {
  const result = lookup([run(42)], { [mergeSha]: tree });
  expect(result).toMatchObject({ status: 0, stdout: "verdict=42\n" });
});

it("answers none when only the sha matches a different tree", () => {
  const result = lookup([run(42, sha)], { [sha]: otherTree });
  expect(result).toMatchObject({ status: 0, stdout: "verdict=none\n" });
});

it("ignores failed, cancelled and pull_request runs", () => {
  const result = lookup([
    run(41, mergeSha, { conclusion: "failure" }),
    run(42, mergeSha, { conclusion: "cancelled" }),
    run(43, mergeSha, { event: "pull_request" }),
    run(44, mergeSha, { status: "in_progress" }),
  ]);
  expect(result).toMatchObject({
    status: 0,
    stdout: "verdict=none\n",
    calls: Array(4).fill(runList),
  });
});

it.each(["list", "commit"])("exits 1 on an API error reading the %s", (source) => {
  const result = lookup(
    [run(42)],
    { [mergeSha]: tree },
    source === "list" ? runList : `/repos/${repository}/git/commits/${mergeSha}`,
  );
  expect(result).toMatchObject({ status: 1, stdout: "" });
  expect(result.stderr).toContain("fixture API error");
  expect(result.sleeps).toEqual([]);
});

it("looks at no more than 50 runs", () => {
  const runs = Array.from({ length: 50 }, (_, index) => run(index + 1));
  const result = lookup([...runs, run(51, sha)], { [mergeSha]: otherTree, [sha]: tree });
  expect(result).toMatchObject({ status: 0, stdout: "verdict=none\n" });
  expect(result.calls).not.toContain(`/repos/${repository}/git/commits/${sha}`);
});

it("re-queries when the merge queue run is not finalized yet", () => {
  const result = lookup([], { [mergeSha]: tree }, "", [[], [run(42)]]);
  expect(result).toMatchObject({ status: 0, stdout: "verdict=42\n", sleeps: ["20", "20"] });
  expect(result.calls.filter((endpoint) => endpoint === runList)).toHaveLength(3);
});

it("answers none after three re-queries over 60 seconds", () => {
  const result = lookup([]);
  expect(result).toMatchObject({
    status: 0,
    stdout: "verdict=none\n",
    calls: Array(4).fill(runList),
    sleeps: ["20", "20", "20"],
  });
});

it("keeps the shared verdict script byte-for-byte", () => {
  const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
  expect(digest).toBe("d0b814ed489c294ba3be31f774a3e0e02ab7121bb64424e1d7f72c142461ad6c");
});
