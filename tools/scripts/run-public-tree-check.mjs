import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const guard = "tools/scripts/check-publication-history.mjs";
const selector = "tools/scripts/run-public-tree-check.mjs";
const files = [
  guard,
  "tools/scripts/lib/publication-history-rules.mjs",
  "tools/scripts/lib/toml-fields.mjs",
];
const commitId = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const git = (...args) => execFileSync("git", args, { encoding: "utf8" });

function guardSources(base, head) {
  const required = [selector, ...files];
  const listed = (commit) =>
    git("ls-tree", "-z", "--name-only", commit, "--", ...required)
      .split("\0")
      .filter(Boolean);
  const baseFiles = listed(base);
  // A base without the selector predates this guard: the pull request that adds it brings its own.
  if (!baseFiles.includes(selector)) return files.map((file) => git("show", `${head}:${file}`));
  if (!required.every((file) => baseFiles.includes(file))) {
    throw new Error("Base commit has an incomplete public tree guard.");
  }
  const headFiles = listed(head);
  if (!required.every((file) => headFiles.includes(file))) {
    throw new Error("Pull request removes part of the public tree guard.");
  }
  const baseGuard = git("show", `${base}:${guard}`);
  if (!/["']--pull-request["']/.test(baseGuard)) {
    throw new Error("Base commit's public tree guard lacks pull request support.");
  }
  return [baseGuard, ...files.slice(1).map((file) => git("show", `${base}:${file}`))];
}

function run(base, head) {
  if (!commitId.test(base ?? "") || !commitId.test(head ?? "")) {
    throw new Error("Supply the base and head commit IDs.");
  }
  const sources = guardSources(base, head);
  const gitDir = git("rev-parse", "--absolute-git-dir").trimEnd();
  const directory = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), "public-tree-"));
  try {
    for (const [index, file] of files.entries()) {
      const target = join(directory, file);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, sources[index]);
    }
    const result = spawnSync(
      process.execPath,
      [join(directory, guard), "--pull-request", base, head],
      {
        env: { ...process.env, GIT_DIR: gitDir, GIT_WORK_TREE: process.cwd() },
        stdio: "inherit",
      },
    );
    if (result.status === null)
      throw result.error ?? new Error(`Guard terminated by ${result.signal}.`);
    return result.status;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

try {
  process.exitCode = run(process.argv[2], process.argv[3]);
} catch (error) {
  process.stderr.write(`Public tree check failed: ${error.message}\n`);
  process.exitCode = 2;
}
