#!/usr/bin/env node
// Exits 0 only inside a linked worktree, so `prepare` runs `lefthook install`
// from the main checkout alone. The install writes the hooks folder every
// worktree shares, with an absolute path to the installing checkout's binary.
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
process.exitCode = linked ? 0 : 1;
