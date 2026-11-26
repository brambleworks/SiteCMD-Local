import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPT = "tools/scripts/audit/check-agents-md.mjs";
const GUIDE = ".github/AGENTS.md";
const TRIGGER = ".github/workflows/ci.yml";
const GUIDANCE = "# CI\n\n## Guide triggers\n\n- `workflows/*.yml`\n- `/package.json`\n";

describe("check-agents-md", () => {
  let repo;

  function write(file, source) {
    fs.mkdirSync(path.dirname(path.join(repo, file)), { recursive: true });
    fs.writeFileSync(path.join(repo, file), source);
  }

  function git(...args) {
    return execFileSync("git", args, { cwd: repo, encoding: "utf8" });
  }

  function commit(message) {
    git("add", "-A");
    git("commit", "--quiet", "-m", message);
  }

  function run(...args) {
    return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: repo, encoding: "utf8" });
  }

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-guides-"));
    git("init", "--quiet");
    git("config", "user.email", "test@example.com");
    git("config", "user.name", "Test");
    write(".gitignore", "/tools/scripts\n");
    write(SCRIPT, fs.readFileSync(SCRIPT, "utf8"));
    fs.symlinkSync(path.resolve("tools/scripts/lib"), path.join(repo, "tools/scripts/lib"));
    write("package.json", '{"name":"guide-fixture","scripts":{"root-check":"echo root"}}\n');
    write(GUIDE, GUIDANCE);
    write(TRIGGER, "name: CI\n");
  });

  afterEach(() => fs.rmSync(repo, { recursive: true, force: true }));

  it.each([
    [
      "a relative path also present at the root",
      "`workflows/other.yml`",
      "missing path",
      "workflows/other.yml",
    ],
    ["a bare filename", "`missing.ini`", "missing path", "missing.ini"],
    ["a root path", "`/docs/missing.md`", "missing path", "/docs/missing.md"],
    ["a path glob", "`workflows/*.xml`", "missing path", "workflows/*.xml"],
    ["a local Markdown link", "[Missing](missing.md)", "missing linked path", "missing.md"],
    [
      "a local Markdown anchor",
      "[Valid](help.md#valid-heading) [Dead](help.md#missing)",
      "missing anchor",
      "help.md#missing",
    ],
    ["an inline script", "`pnpm run invented`", "missing pnpm script", "invented"],
    ["a fenced script", "```bash\npnpm invented\n```", "missing pnpm script", "invented"],
    [
      "a filtered script from the wrong package",
      "`pnpm --filter @example/tools run root-check`",
      "missing pnpm script",
      "root-check",
    ],
  ])("rejects %s in a dot-folder guide", (_case, reference, diagnostic, target) => {
    write("workflows/other.yml", "name: Other\n");
    write("docs/README.md", "# Docs\n");
    write(".github/help.md", "# Valid heading!\n");
    write("pnpm-workspace.yaml", 'packages:\n  - "packages/*"\n');
    write("packages/tools/package.json", '{"name":"@example/tools"}\n');
    write(GUIDE, `${GUIDANCE}\n## Notes\n\n${reference}\n`);
    const result = run();
    expect(result.stderr.trim().split("\n").slice(1)).toEqual([
      expect.stringContaining(`${GUIDE}: references ${diagnostic} \`${target}\``),
    ]);
    expect(result.status).toBe(1);
  });

  it("checks the dot-folder guide and skips an absolute URL route", () => {
    write(GUIDE, `The service exposes \`/v1/sites\` and \`/health\`.\n\n${GUIDANCE}`);
    const result = run();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("passed (1 files)");
  });

  it("requires a Guide triggers section", () => {
    write(GUIDE, "# CI\n");
    const result = run();
    expect(result.stderr).toContain(`${GUIDE}: missing ## Guide triggers section`);
    expect(result.status).toBe(1);
  });

  it("requires each trigger glob to match a file", () => {
    fs.mkdirSync(path.join(repo, ".github/workflows/empty"));
    write(GUIDE, `${GUIDANCE}- \`workflows/empty*\`\n`);
    const result = run();
    expect(result.stderr).toContain(`${GUIDE}: trigger \`workflows/empty*\` matches no files`);
    expect(result.status).toBe(1);
  });

  it("names an unchanged guide and all the files that triggered it", () => {
    commit("Add guide and workflow");
    fs.rmSync(path.join(repo, TRIGGER));
    write("package.json", '{"name":"guide-fixture"}\n');
    commit("Change CI inputs");
    const result = run("--range", "HEAD~1..HEAD");
    expect(result.stderr).toContain(`${GUIDE}: ${TRIGGER}, package.json`);
    expect(result.status).toBe(1);
  });

  it("accepts a change to a triggered guide", () => {
    commit("Add guide and workflow");
    write(TRIGGER, "name: Verify\n");
    write(GUIDE, `${GUIDANCE}\nCI runs verification.\n`);
    commit("Describe renamed workflow");
    const result = run("--range", "HEAD~1..HEAD");
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Guide trigger check passed");
  });

  it.each([
    [
      "a PR body file",
      "body",
      "Update workflow",
      "[guide-unchanged: Rename the workflow\nfor clarity (#42)]\n",
    ],
    [
      "merge-queue commits",
      null,
      "Update workflow\n\n[guide-unchanged: Rename the workflow (PR-42)]",
      "",
    ],
    [
      "the local commit hook",
      "message",
      null,
      "Update workflow\n\n[guide-unchanged: Rename the workflow (#42)]\n",
    ],
  ])("accepts a tracked override from %s", (_source, messageFile, message, contents) => {
    commit("Add guide and workflow");
    write(TRIGGER, "name: Verify\n");
    if (message) commit(message);
    else git("add", TRIGGER);
    if (messageFile) write(messageFile, contents);
    const mode = message ? ["--range", "HEAD~1..HEAD"] : ["--staged"];
    const result = run(...mode, ...(messageFile ? ["--message-file", messageFile] : []));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toContain("authorized via [guide-unchanged:]");
    expect(result.stderr).toContain(`${GUIDE}: ${TRIGGER}`);
  });

  it("requires an issue reference in the PR override even if a commit has one", () => {
    commit("Add guide and workflow");
    write(TRIGGER, "name: Verify\n");
    commit("Update workflow\n\n[guide-unchanged: Rename the workflow (#42)]");
    write("body", "[guide-unchanged: Rename the workflow]\n");
    const result = run("--range", "HEAD~1..HEAD", "--message-file", "body");
    expect(result.stderr).toContain("must reference a tracked issue or PR");
    expect(result.status).toBe(1);
  });
});
