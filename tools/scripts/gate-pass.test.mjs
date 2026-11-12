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
afterEach(() => rmSync(root, { recursive: true, force: true }));

it("pins pre-push to the recorded-pass check and keeps the gate in its own hook", () => {
  root = mkdtempSync(path.join(tmpdir(), "sitecmd-gate-pass-"));
  const config = readFileSync("lefthook.yml", "utf8");
  expect(config).toMatch(
    /^pre-push:\n(?: {2}#.*\n)* {2}commands:\n {4}gate-pass:\n {6}use_stdin: true\n {6}run: node tools\/scripts\/gate-pass\.mjs check\n(?! )/m,
  );
  expect(config).toMatch(/^gate:\n/m);
});

it("refuses a push of any commit without a recent gate pass, and never runs the gate inside it", () => {
  // Bug: the push ran the whole gate after connecting to GitHub, which dropped the
  // idle connection, so the push failed after every check had passed.
  root = mkdtempSync(path.join(tmpdir(), "sitecmd-gate-pass-"));
  const work = path.join(root, "work");
  const remote = path.join(root, "remote.git");
  const runs = path.join(root, "gate-runs.log");
  const env = {
    ...gitEnv(),
    PATH: `${path.dirname(LEFTHOOK)}${path.delimiter}${process.env.PATH}`,
  };
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
  const gate = () => spawnSync(process.execPath, [SCRIPT, "run"], { cwd: work, env });
  const gateRuns = () =>
    existsSync(runs) ? readFileSync(runs, "utf8").trim().split("\n").length : 0;
  const pushed = (ref) =>
    execFileSync("git", ["ls-remote", remote, ref], { env, encoding: "utf8" }) !== "";
  const start = git("rev-parse", "HEAD").stdout.trim();

  expect(git("push", "-q", "origin", "HEAD:refs/heads/first").status).not.toBe(0);
  expect(gateRuns()).toBe(0);
  expect(pushed("refs/heads/first")).toBe(false);

  writeFileSync(path.join(work, "draft.txt"), "uncommitted\n");
  expect(gate().status).toBe(1);
  expect(gateRuns()).toBe(0);
  rmSync(path.join(work, "draft.txt"));

  // LEFTHOOK=0 would make lefthook exit 0 without running a job.
  const off = { ...env, LEFTHOOK: "0" };
  expect(spawnSync(process.execPath, [SCRIPT, "run"], { cwd: work, env: off }).status).toBe(0);
  expect(gateRuns()).toBe(1);
  expect(git("push", "-q", "origin", "HEAD:refs/heads/first").status).toBe(0);
  expect(gateRuns()).toBe(1);
  expect(pushed("refs/heads/first")).toBe(true);
  expect(git("push", "-q", "origin", ":refs/heads/first").status).toBe(0);

  // Another branch rides on nothing the checkout passed.
  git("checkout", "-q", "-b", "other");
  writeFileSync(path.join(work, "other.txt"), "other\n");
  git("add", "other.txt");
  git("commit", "-q", "-m", "other");
  git("checkout", "-q", "main");
  expect(git("push", "-q", "origin", "other").status).not.toBe(0);

  // A commit with the same files as the passed one, but its own history.
  git("commit", "-q", "--allow-empty", "-m", "same files");
  expect(git("push", "-q", "origin", "HEAD:refs/heads/second").status).not.toBe(0);
  git("reset", "-q", "--hard", start);

  const record = path.join(work, ".git", "sitecmd-gate", start);
  writeFileSync(
    record,
    `${JSON.stringify({ commit: start, passed: new Date(Date.now() - 2 * 864e5).toISOString() })}\n`,
  );
  expect(git("push", "-q", "origin", "HEAD:refs/heads/third").status).not.toBe(0);
  expect(gateRuns()).toBe(1);
});
