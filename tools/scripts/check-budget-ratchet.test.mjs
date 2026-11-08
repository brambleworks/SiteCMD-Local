import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = path.join(ROOT, "tools/scripts/check-budget-ratchet.mjs");

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "budget-ratchet-"));
  git(dir, "init", "--quiet");
  git(dir, "config", "user.email", "test@example.com");
  git(dir, "config", "user.name", "Test");
  fs.mkdirSync(path.join(dir, "tools", "scripts", "lib"), { recursive: true });
  return dir;
}

function write(repoDir, relativePath, contents) {
  const full = path.join(repoDir, relativePath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, contents);
}

function commit(repoDir, message) {
  git(repoDir, "add", "-A");
  git(repoDir, "commit", "--quiet", "-m", message);
}

function stageOnly(repoDir, relativePath) {
  git(repoDir, "add", relativePath);
}

function runScript(repoDir, args = ["--staged"]) {
  return spawnSync("node", [SCRIPT, ...args], { cwd: repoDir, encoding: "utf8" });
}

function setCommitMessage(repoDir, message) {
  const file = path.join(repoDir, ".git", "COMMIT_EDITMSG");
  fs.writeFileSync(file, message);
}

const SAMPLE_BUDGET_FILE = `export const guardrailScriptLineBudgets = new Map([
  ["tools/scripts/check-repo-guardrails.mjs", 1800],
  ["tools/scripts/lib/guardrail-rust-rules.mjs", 120],
]);
`;

describe("check-budget-ratchet", () => {
  let repo;
  let extraWorktree;

  beforeEach(() => {
    repo = makeRepo();
    extraWorktree = null;
    write(repo, "tools/scripts/lib/guardrail-script-budgets.mjs", SAMPLE_BUDGET_FILE);
    commit(repo, "initial budgets");
  });

  afterEach(() => {
    if (extraWorktree) {
      try {
        git(repo, "worktree", "remove", "--force", extraWorktree);
      } catch {
        // Best effort: the temp-directory removal below still reclaims disk
        // state even if the worktree metadata cleanup itself fails.
      }
      fs.rmSync(extraWorktree, { recursive: true, force: true });
    }
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it("passes when staged budget file has no threshold changes", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE + "// trailing comment, no threshold change\n",
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    const result = runScript(repo);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("passes when a threshold DECREASES (ratcheting tighter)", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 100',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    const result = runScript(repo);
    expect(result.status).toBe(0);
  });

  it("does not treat quoted source assertions as budget declarations", () => {
    const rulePath = "tools/scripts/lib/guardrail-code-scan-security-rules.mjs";
    write(
      repo,
      rulePath,
      'constants.includes("pub const CODE_SCAN_MAX_TEXT_BYTES: u64 = 64_000_000;");\n',
    );
    stageOnly(repo, rulePath);
    const result = runScript(repo);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("FAILS when a threshold value is raised", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(repo, "Refactor the scanner scheduler\n");
    const result = runScript(repo);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/refusing to raise guardrail thresholds/);
    expect(result.stderr).toMatch(/guardrail-rust-rules\.mjs.*120 -> 220/);
  });

  it("FAILS when a new threshold entry is added", () => {
    const withNewOverride = SAMPLE_BUDGET_FILE.replace(
      '["tools/scripts/lib/guardrail-rust-rules.mjs", 120],',
      '["tools/scripts/lib/guardrail-rust-rules.mjs", 120],\n  ["tools/scripts/lib/guardrail-new-thing.mjs", 999],',
    );
    write(repo, "tools/scripts/lib/guardrail-script-budgets.mjs", withNewOverride);
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(repo, "wip\n");
    const result = runScript(repo);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/new threshold/);
    expect(result.stderr).toMatch(/guardrail-new-thing\.mjs/);
  });

  it("does NOT accept the bypass token when it's the documentation placeholder", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(
      repo,
      "Document the budget override\n\nUse [budget-raised: <reason>] to allow legitimate raises.\n",
    );
    const result = runScript(repo);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/refusing to raise/);
  });

  it("does NOT accept the bypass token when it appears mid-paragraph (prose, not intent)", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(
      repo,
      "Split the scanner scheduler\n\nThe phrase [budget-raised: example phrase] should NOT bypass the check when buried in prose.\n",
    );
    const result = runScript(repo);
    expect(result.status).toBe(1);
  });

  it("allows a raise when the commit message contains the bypass token + issue ref", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(
      repo,
      "refactor(guardrails): legitimate raise\n\n[budget-raised: needed to land the new ratchet helpers; split deferred (#42)]\n",
    );
    const result = runScript(repo);
    expect(result.status).toBe(0);
    expect(result.stderr).toMatch(/authorized via \[budget-raised:\]/);
  });

  it("REJECTS a bypass token that lacks an issue or PR reference", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(
      repo,
      "refactor(guardrails): raise\n\n[budget-raised: temporarily widening to land a refactor]\n",
    );
    const result = runScript(repo);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/tracked issue or PR/);
  });

  it("accepts alternate issue-reference shapes (PR-123, GH-9, fixes #1)", () => {
    write(
      repo,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-script-budgets.mjs");
    setCommitMessage(
      repo,
      "raise: bigger budget\n\n[budget-raised: needs follow-up split, see PR-42]\n",
    );
    const result = runScript(repo);
    expect(result.status).toBe(0);
  });

  it("ignores staged files that aren't budget files", () => {
    write(repo, "some/other/file.mjs", "export const X = 999;\n");
    stageOnly(repo, "some/other/file.mjs");
    const result = runScript(repo);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("detects raises in the maxLines object-property shape", () => {
    const objectBudgetFile = `const sourceSizeBudgets = [
  { file: "apps/desktop/src/foo.tsx", maxLines: 800 },
];
`;
    write(repo, "tools/scripts/check-repo-guardrails.mjs", objectBudgetFile);
    commit(repo, "initial check-repo-guardrails");
    write(
      repo,
      "tools/scripts/check-repo-guardrails.mjs",
      objectBudgetFile.replace("maxLines: 800", "maxLines: 1500"),
    );
    stageOnly(repo, "tools/scripts/check-repo-guardrails.mjs");
    setCommitMessage(repo, "wip\n");
    const result = runScript(repo);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/foo\.tsx.*800 -> 1500/);
  });

  it.each(["", "export "])("detects raises in %sconst *_LIMIT declarations", (prefix) => {
    const constFile = `${prefix}const RUST_FILE_LINE_LIMIT = 800;
export function rustLineBudgetFailures() {}
`;
    write(repo, "tools/scripts/lib/guardrail-rust-loc-rules.mjs", constFile);
    commit(repo, "initial loc rules");
    write(
      repo,
      "tools/scripts/lib/guardrail-rust-loc-rules.mjs",
      constFile.replace("RUST_FILE_LINE_LIMIT = 800", "RUST_FILE_LINE_LIMIT = 1200"),
    );
    stageOnly(repo, "tools/scripts/lib/guardrail-rust-loc-rules.mjs");
    setCommitMessage(repo, "wip\n");
    const result = runScript(repo);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/const:RUST_FILE_LINE_LIMIT.*800 -> 1200/);
  });

  it.each(["", "pub ", "pub(crate) "])("enforces Rust %sconst budget declarations", (prefix) => {
    const rustPath = "apps/desktop/src-tauri/src/lib_tests.rs";
    const rustFile = `${prefix}const STRING_RESULT_COMMAND_BUDGET: usize = 100;\n`;
    write(repo, rustPath, rustFile);
    commit(repo, "initial rust ratchet");

    write(repo, rustPath, rustFile.replace("usize = 100", "usize = 150"));
    stageOnly(repo, rustPath);
    setCommitMessage(repo, "wip\n");
    const refused = runScript(repo);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/refusing to raise guardrail thresholds/);
    expect(refused.stderr).toMatch(/const:STRING_RESULT_COMMAND_BUDGET.*100 -> 150/);

    setCommitMessage(
      repo,
      "Widen the migration ratchet\n\n[budget-raised: measured count moved during a rebase (#11)]\n",
    );
    const authorized = runScript(repo);
    expect(authorized.status).toBe(0);
    expect(authorized.stderr).toMatch(/authorized via \[budget-raised:\]/);
  });

  it("finds the pending commit message inside a linked worktree", () => {
    // `.git` is a gitlink file, not a directory, inside a linked worktree, so
    // a hardcoded `.git/COMMIT_EDITMSG` join misses the real file and this
    // must fall back to the PREVIOUS commit's message instead of the pending
    // one, refusing a raise even when the pending message carries the token.
    const rustPath = "apps/desktop/src-tauri/src/lib_tests.rs";
    const rustFile = `const STRING_RESULT_COMMAND_BUDGET: usize = 100;\n`;
    write(repo, rustPath, rustFile);
    commit(repo, "initial rust ratchet");

    const worktreeParent = fs.mkdtempSync(path.join(os.tmpdir(), "budget-ratchet-worktree-"));
    const worktreeDir = path.join(worktreeParent, "wt");
    git(repo, "worktree", "add", "--quiet", worktreeDir, "-b", "wt-branch");

    try {
      write(worktreeDir, rustPath, rustFile.replace("usize = 100", "usize = 150"));
      stageOnly(worktreeDir, rustPath);

      // Set the pending message the same way git itself locates it, via the
      // real per-worktree path rather than a `<cwd>/.git/...` guess.
      const messageFile = git(worktreeDir, "rev-parse", "--git-path", "COMMIT_EDITMSG").trim();
      fs.writeFileSync(
        messageFile,
        "Widen the migration ratchet\n\n[budget-raised: measured count moved during a rebase (#11)]\n",
      );
      const authorized = runScript(worktreeDir);
      expect(authorized.status).toBe(0);
      expect(authorized.stderr).toMatch(/authorized via \[budget-raised:\]/);
    } finally {
      git(repo, "worktree", "remove", "--force", worktreeDir);
      fs.rmSync(worktreeParent, { recursive: true, force: true });
    }
  });

  it("supports a --range mode for CI hard-gate checks", () => {
    const tipPath = "tools/scripts/lib/guardrail-script-budgets.mjs";
    write(
      repo,
      tipPath,
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 999',
      ),
    );
    commit(repo, "bumped rust-rules budget");
    const result = runScript(repo, ["--range", "HEAD~1..HEAD"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/120 -> 999/);
  });

  it("reads the bypass token from a worktree checkout, not the main gitdir", () => {
    // In a worktree, ".git" is a file pointing at the shared gitdir, not a
    // directory, so a naive path.join(".git", "COMMIT_EDITMSG") never
    // resolves. This reproduces that layout: a real `git worktree add`
    // off the fixture repo, with the pending commit message written to
    // wherever `git rev-parse --git-path COMMIT_EDITMSG` says it lives
    // (never `<worktree>/.git/COMMIT_EDITMSG`, which does not exist).
    extraWorktree = fs.mkdtempSync(path.join(os.tmpdir(), "budget-ratchet-worktree-"));
    git(repo, "worktree", "add", "--quiet", "-b", "budget-ratchet-worktree-branch", extraWorktree);

    write(
      extraWorktree,
      "tools/scripts/lib/guardrail-script-budgets.mjs",
      SAMPLE_BUDGET_FILE.replace(
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 120',
        '"tools/scripts/lib/guardrail-rust-rules.mjs", 220',
      ),
    );
    stageOnly(extraWorktree, "tools/scripts/lib/guardrail-script-budgets.mjs");

    const messageFile = git(extraWorktree, "rev-parse", "--git-path", "COMMIT_EDITMSG").trim();
    expect(messageFile).not.toBe(path.join(extraWorktree, ".git", "COMMIT_EDITMSG"));
    fs.writeFileSync(
      messageFile,
      "refactor(guardrails): legitimate raise\n\n" +
        "[budget-raised: needed to land the new ratchet helpers; split deferred (#42)]\n",
    );

    const result = runScript(extraWorktree);
    expect(result.status).toBe(0);
    expect(result.stderr).toMatch(/authorized via \[budget-raised:\]/);
  });
});
