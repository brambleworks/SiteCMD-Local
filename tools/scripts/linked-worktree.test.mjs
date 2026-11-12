import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";

const PREPARE = JSON.parse(readFileSync("package.json", "utf8")).scripts.prepare;
// Scratch Git must not inherit the outer repository's GIT_DIR or GIT_WORK_TREE.
const gitEnv = () =>
  Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")));
let root;
afterEach(() => rmSync(root, { recursive: true, force: true }));

it("prevents a linked worktree's install taking over the shared hooks", () => {
  // Bugs: `pnpm install` in a worktree ran `lefthook install`, which pointed every
  // checkout's hooks at that worktree's binary; and a prepare that hid lefthook
  // inside a script left the code scan reading lefthook as an unused dependency.
  root = mkdtempSync(path.join(tmpdir(), "sitecmd-install-hooks-"));
  expect(PREPARE).toMatch(/\|\| lefthook install$/);
  const main = path.join(root, "main");
  const linked = path.join(root, "linked");
  const log = path.join(root, "installs.log");
  const git = (cwd, ...args) => execFileSync("git", args, { cwd, env: gitEnv(), stdio: "ignore" });
  git(root, "init", "-q", main);
  // The checkout carries the probe at the path prepare names, so prepare runs unchanged.
  mkdirSync(path.join(main, "tools", "scripts"), { recursive: true });
  writeFileSync(
    path.join(main, "tools", "scripts", "linked-worktree.mjs"),
    readFileSync("tools/scripts/linked-worktree.mjs"),
  );
  git(main, "add", "tools");
  git(
    main,
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.com",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-q",
    "-m",
    "start",
  );
  git(main, "worktree", "add", "-q", linked);
  const bin = path.join(root, "bin");
  mkdirSync(bin);
  writeFileSync(path.join(bin, "lefthook"), `#!/bin/sh\npwd >> '${log}'\n`);
  chmodSync(path.join(bin, "lefthook"), 0o755);
  // pnpm runs the script through the shell from the checkout's root.
  const install = (cwd) =>
    execFileSync("sh", ["-c", PREPARE], {
      cwd,
      encoding: "utf8",
      env: { ...gitEnv(), PATH: `${bin}${path.delimiter}${process.env.PATH}` },
    });

  expect(install(linked)).toContain("Skipped lefthook install");
  install(main);
  expect(
    readFileSync(log, "utf8")
      .trim()
      .split("\n")
      .map((line) => path.basename(line)),
  ).toEqual(["main"]);
});
