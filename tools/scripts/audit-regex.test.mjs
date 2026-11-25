// Bug: the regex audit listed folders on disk, so leftover untracked app folders made it
// pass locally while a clean CI checkout found one root and failed, and tracked scripts
// outside its hand-picked folders were never scanned (2026-11-23).
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { trackedSources } from "./audit-regex.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");
let directory;
afterEach(() => directory && rmSync(directory, { recursive: true, force: true }));

function git(cwd, ...args) {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
  );
  const result = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  expect(result.status, result.stderr).toBe(0);
}

function write(name, text = "") {
  mkdirSync(path.dirname(path.join(directory, name)), { recursive: true });
  writeFileSync(path.join(directory, name), text);
}

it("scans every tracked source, never untracked or ignored folders", () => {
  directory = mkdtempSync(path.join(tmpdir(), "audit-regex-"));
  const tracked = [
    "tools/scripts/check.mjs",
    "tools/release/sign.mjs",
    "apps/web/build.ts",
    // Third-party code: a vendored minified library and a sample bundle a test scans.
    "apps/web/vendor/lib.min.js",
    "apps/web/tests/fixtures/bundle.js",
    "README.md",
  ];
  for (const name of tracked) write(name);
  write(".gitignore", "apps/leftover/\n");
  git(directory, "init", "--quiet");
  git(directory, "add", "--", ".gitignore", ...tracked);
  // Leftovers a clean checkout doesn't have: one untracked, one ignored.
  write("apps/web/src/main.ts");
  write("apps/leftover/src/index.ts");
  expect(trackedSources(directory)).toEqual([
    "apps/web/build.ts",
    "tools/release/sign.mjs",
    "tools/scripts/check.mjs",
  ]);
});

it("scans this repository's own scripts", () => {
  const files = trackedSources(ROOT);
  expect(files).toContain("tools/scripts/audit-regex.mjs");
  expect(files).toContain("tools/scripts/audit-regex.test.mjs");
  expect(files.some((file) => /(?:^|\/)node_modules\//.test(file))).toBe(false);
});
