#!/usr/bin/env node
// A push connects to GitHub before its pre-push hook runs, and GitHub drops a
// push left idle for about six minutes, so the 20-minute gate cannot run inside
// the push. `run` (`pnpm gate`) runs lefthook's `gate` hook on a clean checkout
// and records the commit that passed. `check` is the whole pre-push hook: it
// reads the pushed refs and refuses any commit without a record from the last
// day, unless a remote already has it.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// Some gate checks read the network, such as dependency advisories, so a pass goes stale.
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const NO_OBJECT = /^0+$/;

const git = (...args) =>
  execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

// Worktrees share records: a commit names the same files and history in every checkout.
const recordPath = (commit) =>
  path.join(git("rev-parse", "--path-format=absolute", "--git-common-dir"), "sitecmd-gate", commit);

function passedRecently(commit) {
  try {
    const age =
      Date.now() - Date.parse(JSON.parse(fs.readFileSync(recordPath(commit), "utf8")).passed);
    return age >= 0 && age < MAX_AGE_MS;
  } catch {
    return false;
  }
}

/** HEAD, or null while any tracked or untracked file differs from it. */
function cleanCommit() {
  if (git("status", "--porcelain", "--untracked-files=all") !== "") return null;
  return git("rev-parse", "HEAD");
}

/** Whether a remote-tracking ref already reaches the commit, which the gate passed
 *  or the remote made, such as a squash merge, when it got there. */
function onRemote(commit) {
  try {
    return git("rev-list", "-n", "1", commit, "--not", "--remotes") === "";
  } catch {
    return false;
  }
}

// Each line is `<local ref> <local object> <remote ref> <remote object>`. A push
// with nothing to send, such as `Everything up-to-date`, gets no lines.
function check(input) {
  const missing = [];
  for (const line of input.split("\n").filter((entry) => entry.trim() !== "")) {
    const [localRef, object = ""] = line.trim().split(/\s+/);
    // A deletion pushes no commit.
    if (NO_OBJECT.test(object)) continue;
    let commit = object;
    try {
      commit = git("rev-parse", "--verify", `${object}^{commit}`);
    } catch {
      // Not a commit: no record can match it.
    }
    if (!onRemote(commit) && !passedRecently(commit))
      missing.push(`${localRef} (${object.slice(0, 12)})`);
  }
  if (missing.length === 0) return 0;
  console.error(
    `No gate pass from the last day for ${missing.join(", ")}. Check out each one, run pnpm gate, then push again.`,
  );
  return 1;
}

function run() {
  const commit = cleanCommit();
  if (!commit) {
    console.error(
      "pnpm gate needs a clean checkout, because the gate tests the files on disk. Commit or remove every change first.",
    );
    return 1;
  }
  if (passedRecently(commit)) {
    console.log(`Commit ${commit.slice(0, 12)} passed the gate within the last day.`);
    return 0;
  }
  // LEFTHOOK=0, LEFTHOOK_EXCLUDE and LEFTHOOK_CONFIG would skip jobs and still exit 0.
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("LEFTHOOK")),
  );
  const lefthook = path.join(
    git("rev-parse", "--show-toplevel"),
    "node_modules",
    ".bin",
    "lefthook",
  );
  const gate = spawnSync(lefthook, ["run", "gate", "--all-files"], { stdio: "inherit", env });
  if (gate.error) {
    console.error(`Could not run ${lefthook}: ${gate.error.message}. Run pnpm install first.`);
    return 1;
  }
  if (gate.status !== 0) return gate.status ?? 1;
  if (cleanCommit() !== commit) {
    console.error("The checkout changed while the gate ran, so no pass was recorded.");
    return 1;
  }
  fs.mkdirSync(path.dirname(recordPath(commit)), { recursive: true });
  fs.writeFileSync(
    recordPath(commit),
    `${JSON.stringify({ commit, passed: new Date().toISOString() })}\n`,
  );
  console.log(`Recorded a gate pass for commit ${commit.slice(0, 12)}. Push it within a day.`);
  return 0;
}

const command = process.argv[2];
if (command === "check") process.exitCode = check(fs.readFileSync(0, "utf8"));
else if (command === "run") process.exitCode = run();
else {
  console.error("Usage: gate-pass.mjs check|run");
  process.exitCode = 2;
}
