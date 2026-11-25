import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const TEST_FILE_PATTERN = /\.(?:test|spec)\.[cm]?[jt]sx?$/;

// Workspace roots used to resolve package filter names.
const WORKSPACE_DIRECTORIES = ["apps", "packages"];

/** Maps package names used by `--filter` to workspace directories. */
function workspaceDirectoriesByName(listDirectories, read) {
  const byName = new Map();
  for (const parent of WORKSPACE_DIRECTORIES) {
    for (const entry of listDirectories(parent)) {
      const dir = `${parent}/${entry}`;
      let manifest;
      try {
        manifest = JSON.parse(read(`${dir}/package.json`));
      } catch {
        continue;
      }
      if (manifest.name) byName.set(manifest.name, dir);
    }
  }
  return byName;
}

/** Returns test paths reached by package scripts. */
export function coveredTestPaths(scripts, workspaceDirs) {
  const covered = new Set();

  for (const command of Object.values(scripts ?? {})) {
    // `pnpm --filter a --filter b run test` covers each named workspace.
    if (/\brun\s+test\b/.test(command)) {
      for (const match of command.matchAll(/--filter\s+(\S+)/g)) {
        const dir = workspaceDirs.get(match[1]);
        if (dir) covered.add(dir);
      }
    }

    for (const pattern of [/\bvitest\s+run\s+([^&|]*)/g, /\bnode\s+--test\s+([^&|]*)/g]) {
      for (const invocation of command.matchAll(pattern)) {
        for (const token of invocation[1].trim().split(/\s+/)) {
          // Stop at the first flag so `--reporter=json` is not read as a path.
          if (token === "" || token.startsWith("-")) break;
          // A file glob (`dir/*.test.mjs`) covers the directory holding it.
          const path = token.includes("*") ? token.slice(0, token.indexOf("*")) : token;
          covered.add(path.replace(/\/+$/, ""));
        }
      }
    }
  }

  return [...covered];
}

function isCovered(file, coveredPaths) {
  return coveredPaths.some((covered) => file === covered || file.startsWith(`${covered}/`));
}

/** Returns tracked paths, or null outside a Git checkout. */
function gitTrackedFiles(root) {
  try {
    return execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .split("\0")
      .filter(Boolean);
  } catch {
    return null;
  }
}

function directoriesIn(root, relativePath) {
  const target = path.join(root, relativePath);
  if (!fs.existsSync(target)) return [];
  return fs
    .readdirSync(target, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

/**
 * @param {(file: string) => string} read
 * @param {{root?: string, listTrackedFiles?: () => string[],
 *          listDirectories?: (dir: string) => string[]}} [options]
 */
export function testWiringFailures(read, options = {}) {
  const root = options.root ?? process.cwd();
  const listTrackedFiles =
    options.listTrackedFiles ??
    (() => gitTrackedFiles(root)?.filter((file) => fs.existsSync(path.join(root, file))) ?? null);
  const listDirectories = options.listDirectories ?? ((dir) => directoriesIn(root, dir));
  const failures = [];

  let rootManifest;
  try {
    rootManifest = JSON.parse(read("package.json"));
  } catch {
    return ["unable to parse package.json while checking test wiring"];
  }

  const trackedFiles = listTrackedFiles();
  // Outside a git checkout there is no tracked-file set to reason about.
  if (trackedFiles === null) return [];

  const workspaceDirs = workspaceDirectoriesByName(listDirectories, read);
  const coveredPaths = coveredTestPaths(rootManifest.scripts, workspaceDirs);

  if (coveredPaths.length === 0) {
    return [
      "no test runner paths could be derived from package.json scripts; the test-wiring guardrail cannot verify anything.",
    ];
  }

  for (const file of new Set(trackedFiles)) {
    if (!TEST_FILE_PATTERN.test(file)) continue;
    if (isCovered(file, coveredPaths)) continue;
    failures.push(
      `${file} is a tracked test file that no package.json test script collects (runners cover: ${coveredPaths.sort().join(", ")}). An uncollected test asserts nothing while reading as coverage - wire it into a runner or delete it.`,
    );
  }

  return failures;
}
