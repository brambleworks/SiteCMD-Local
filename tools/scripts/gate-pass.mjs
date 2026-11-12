#!/usr/bin/env node
// Records the checked-out trees that passed the full pre-push gate. A push opens
// its connection to GitHub before the hook runs, and GitHub drops one left idle
// for about six minutes, so a long gate run inside the push can lose the push.
// `pnpm gate` (`run`) runs the gate on a clean checkout ahead of the push and
// records the tree; the pre-push hook skips only when `check` finds that record.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const git = (...args) =>
  execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

/** The checked-out tree, or null while any tracked or untracked file differs from it. */
function cleanTree() {
  if (git("status", "--porcelain", "--untracked-files=all") !== "") return null;
  return git("rev-parse", "HEAD^{tree}");
}

// Worktrees share the record: a tree hash names the same files in every checkout.
const recordPath = (tree) =>
  path.join(git("rev-parse", "--path-format=absolute", "--git-common-dir"), "sitecmd-gate", tree);

function check() {
  try {
    const tree = cleanTree();
    if (tree && fs.existsSync(recordPath(tree))) {
      console.error(
        `Skipped the pre-push gate: tree ${tree.slice(0, 12)} passed it under pnpm gate.`,
      );
      return 0;
    }
  } catch {
    // Anything unreadable runs the gate.
  }
  return 1;
}

function run() {
  const tree = cleanTree();
  if (!tree) {
    console.error(
      "pnpm gate needs a clean checkout, because the gate tests the files on disk. Commit or remove every change first.",
    );
    return 1;
  }
  if (fs.existsSync(recordPath(tree))) {
    console.log(`Tree ${tree.slice(0, 12)} already passed the gate.`);
    return 0;
  }
  const gate = spawnSync("lefthook", ["run", "pre-push", "--all-files"], { stdio: "inherit" });
  if (gate.status !== 0) return gate.status ?? 1;
  if (cleanTree() !== tree) {
    console.error("The checkout changed while the gate ran, so no pass was recorded.");
    return 1;
  }
  fs.mkdirSync(path.dirname(recordPath(tree)), { recursive: true });
  fs.writeFileSync(
    recordPath(tree),
    `${JSON.stringify({ commit: git("rev-parse", "HEAD"), passed: new Date().toISOString() })}\n`,
  );
  console.log(
    `Recorded a gate pass for tree ${tree.slice(0, 12)}. Pushing it skips the pre-push gate.`,
  );
  return 0;
}

const command = { check, run }[process.argv[2]];
if (!command) {
  console.error("Usage: gate-pass.mjs check|run");
  process.exitCode = 2;
} else process.exitCode = command();
