#!/usr/bin/env node
// `lefthook install` writes the hooks folder every worktree of this repository
// shares, with an absolute path to the installing checkout's own binary. Only
// the main checkout installs, so a linked worktree never takes over the hooks.
import { execFileSync } from "node:child_process";

let linked = false;
try {
  const [gitDir, commonDir] = execFileSync(
    "git",
    ["rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  )
    .trim()
    .split("\n");
  linked = gitDir !== commonDir;
} catch {
  // Outside a Git checkout, lefthook reports the problem itself.
}
if (linked)
  console.log("Skipped lefthook install: this worktree shares the main checkout's hooks.");
else execFileSync("lefthook", ["install"], { stdio: "inherit" });
