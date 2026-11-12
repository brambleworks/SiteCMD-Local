import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";

const SCRIPT = path.resolve("tools/scripts/gate-pass.mjs");
const LEFTHOOK = path.resolve("node_modules/.bin/lefthook");
// Scratch Git must not inherit the outer repository's GIT_DIR or GIT_WORK_TREE.
const gitEnv = () =>
  Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")));
let root;
afterEach(() => {
  if (root) rmSync(root, { recursive: true, force: true });
  root = undefined;
});

/** A checkout whose pre-push hook is the gate-pass check, beside a bare remote. */
function checkout() {
  root = mkdtempSync(path.join(tmpdir(), "sitecmd-gate-pass-"));
  const work = path.join(root, "work");
  const remote = path.join(root, "remote.git");
  const runs = path.join(root, "gate-runs.log");
  const env = {
    ...gitEnv(),
    PATH: `${path.dirname(LEFTHOOK)}${path.delimiter}${process.env.PATH}`,
  };
  // LEFTHOOK=0 skips every hook, as the documented emergency bypass does.
  const off = { ...env, LEFTHOOK: "0" };
  const git = (...args) =>
    spawnSync(
      "git",
      [
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
        ...args,
      ],
      { cwd: work, env, encoding: "utf8" },
    );
  execFileSync("git", ["init", "-q", "--bare", remote], { env });
  execFileSync("git", ["init", "-q", "-b", "main", work], { env });
  writeFileSync(
    path.join(work, "lefthook.yml"),
    `pre-push:\n  commands:\n    gate-pass:\n      use_stdin: true\n      run: node '${SCRIPT}' check\ngate:\n  commands:\n    work:\n      run: echo ran >> '${runs}'\n`,
  );
  writeFileSync(path.join(work, ".gitignore"), "node_modules\n");
  mkdirSync(path.join(work, "node_modules", ".bin"), { recursive: true });
  symlinkSync(LEFTHOOK, path.join(work, "node_modules", ".bin", "lefthook"));
  git("add", ".");
  git("commit", "-q", "-m", "start");
  git("remote", "add", "origin", remote);
  execFileSync(LEFTHOOK, ["install"], { cwd: work, env, stdio: "ignore" });
  return {
    work,
    git,
    start: git("rev-parse", "HEAD").stdout.trim(),
    push: (...refs) => git("push", "-q", "origin", ...refs).status,
    bypassPush: (ref) =>
      spawnSync("git", ["push", "-q", "origin", ref], { cwd: work, env: off }).status,
    gate: () => spawnSync(process.execPath, [SCRIPT, "run"], { cwd: work, env }).status,
    gateWithLefthookOff: () =>
      spawnSync(process.execPath, [SCRIPT, "run"], { cwd: work, env: off }).status,
    gateRuns: () => (existsSync(runs) ? readFileSync(runs, "utf8").trim().split("\n").length : 0),
    pushed: (ref) =>
      execFileSync("git", ["ls-remote", remote, ref], { env, encoding: "utf8" }) !== "",
    record: (commit, passed) => {
      mkdirSync(path.join(work, ".git", "sitecmd-gate"), { recursive: true });
      writeFileSync(
        path.join(work, ".git", "sitecmd-gate", commit),
        `${JSON.stringify({ commit, passed: passed.toISOString() })}\n`,
      );
    },
  };
}

it("pins pre-push to the recorded-pass check and keeps the gate in its own hook", () => {
  const config = readFileSync("lefthook.yml", "utf8");
  expect(config).toMatch(
    /^pre-push:\n(?: {2}#.*\n)* {2}commands:\n {4}gate-pass:\n {6}use_stdin: true\n {6}run: node tools\/scripts\/gate-pass\.mjs check\n(?! )/m,
  );
  expect(config).toMatch(/^gate:\n/m);
});

it("refuses a push without a pass, never running the gate inside it, and lets a passed one through", () => {
  // Bug: the push ran the whole gate after connecting to GitHub, which dropped the
  // idle connection, so the push failed after every check had passed.
  const repo = checkout();
  expect(repo.push("HEAD:refs/heads/first")).not.toBe(0);
  expect(repo.gateRuns()).toBe(0);
  expect(repo.pushed("refs/heads/first")).toBe(false);

  writeFileSync(path.join(repo.work, "draft.txt"), "uncommitted\n");
  expect(repo.gate()).toBe(1);
  expect(repo.gateRuns()).toBe(0);
  rmSync(path.join(repo.work, "draft.txt"));

  // LEFTHOOK=0 would make lefthook exit 0 without running a job.
  expect(repo.gateWithLefthookOff()).toBe(0);
  expect(repo.gateRuns()).toBe(1);
  expect(repo.push("HEAD:refs/heads/first")).toBe(0);
  expect(repo.pushed("refs/heads/first")).toBe(true);
  // A push with nothing to send gives the hook no refs.
  expect(repo.push("HEAD:refs/heads/first")).toBe(0);
  expect(repo.gateRuns()).toBe(1);
});

it("refuses another branch, a same-files commit and an expired pass", () => {
  const repo = checkout();
  repo.record(repo.start, new Date());
  repo.git("checkout", "-q", "-b", "other");
  writeFileSync(path.join(repo.work, "other.txt"), "other\n");
  repo.git("add", "other.txt");
  repo.git("commit", "-q", "-m", "other");
  repo.git("checkout", "-q", "main");
  expect(repo.push("other")).not.toBe(0);

  repo.git("commit", "-q", "--allow-empty", "-m", "same files");
  expect(repo.push("HEAD:refs/heads/second")).not.toBe(0);

  repo.git("reset", "-q", "--hard", repo.start);
  repo.record(repo.start, new Date(Date.now() - 2 * 864e5));
  expect(repo.push("HEAD:refs/heads/third")).not.toBe(0);
});

it("lets a commit or tag the remote already has through without a pass", () => {
  // A squash merge reaches main from GitHub, and a release tag points at it.
  const repo = checkout();
  expect(repo.bypassPush("HEAD:refs/heads/merged")).toBe(0);
  repo.git("tag", "-a", "v1", "-m", "v1");
  expect(repo.push("v1")).toBe(0);
  expect(repo.push("HEAD:refs/heads/release")).toBe(0);
  expect(repo.gateRuns()).toBe(0);
});
