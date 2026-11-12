import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";

const SCRIPT = path.resolve("tools/scripts/gate-pass.mjs");
const LEFTHOOK = path.resolve("node_modules/.bin/lefthook");
// Scratch Git must not inherit the outer repository's GIT_DIR or GIT_WORK_TREE.
const gitEnv = () =>
  Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")));
let root;
afterEach(() => rmSync(root, { recursive: true, force: true }));

it("keeps the pre-push hook skipping only a tree the gate already passed", () => {
  // Bug: the push ran the whole gate after connecting to GitHub, which dropped the
  // idle connection, so the push failed after every check had passed.
  root = mkdtempSync(path.join(tmpdir(), "sitecmd-gate-pass-"));
  expect(readFileSync("lefthook.yml", "utf8")).toMatch(
    /^pre-push:\n(?: {2}#.*\n)* {2}skip:\n {4}- run: node tools\/scripts\/gate-pass\.mjs check\n(?! {4}-)/m,
  );
  const work = path.join(root, "work");
  const runs = path.join(root, "gate-runs.log");
  const env = {
    ...gitEnv(),
    PATH: `${path.dirname(LEFTHOOK)}${path.delimiter}${process.env.PATH}`,
  };
  const git = (...args) =>
    execFileSync(
      "git",
      [
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "-c",
        "commit.gpgsign=false",
        ...args,
      ],
      {
        cwd: work,
        env,
        stdio: "ignore",
      },
    );
  execFileSync("git", ["init", "-q", "--bare", path.join(root, "remote.git")], { env });
  execFileSync("git", ["init", "-q", work], { env });
  writeFileSync(
    path.join(work, "lefthook.yml"),
    `pre-push:\n  skip:\n    - run: node '${SCRIPT}' check\n  commands:\n    gate:\n      run: echo ran >> '${runs}'\n`,
  );
  git("add", "lefthook.yml");
  git("commit", "-q", "-m", "start");
  git("remote", "add", "origin", path.join(root, "remote.git"));
  execFileSync(LEFTHOOK, ["install"], { cwd: work, env, stdio: "ignore" });
  const gate = () =>
    spawnSync(process.execPath, [SCRIPT, "run"], { cwd: work, env, encoding: "utf8" });
  const gateRuns = () =>
    existsSync(runs) ? readFileSync(runs, "utf8").trim().split("\n").length : 0;

  writeFileSync(path.join(work, "draft.txt"), "uncommitted\n");
  expect(gate().status).toBe(1);
  expect(gateRuns()).toBe(0);
  rmSync(path.join(work, "draft.txt"));

  expect(gate().status).toBe(0);
  expect(gateRuns()).toBe(1);
  git("push", "-q", "origin", "HEAD:refs/heads/first");
  expect(gateRuns()).toBe(1);

  writeFileSync(path.join(work, "change.txt"), "new\n");
  git("add", "change.txt");
  git("commit", "-q", "-m", "change");
  git("push", "-q", "origin", "HEAD:refs/heads/second");
  expect(gateRuns()).toBe(2);
});
