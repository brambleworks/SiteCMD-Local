#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isTestSourceFile } from "./test-file-classification.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

const SCAN_ROOTS = ["apps/desktop/src-tauri/src"];

const SKIP_DIRS = new Set(["node_modules", "dist", "target", ".next", ".svelte-kit", "build"]);

const EXTENSIONS = new Map([
  [".rs", "rust"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
  [".js", "javascript"],
  [".mjs", "javascript"],
  [".cjs", "javascript"],
]);

function countLines(absPath) {
  const text = fs.readFileSync(absPath, "utf8");
  if (!text) return 0;
  return text.endsWith("\n") ? text.split("\n").length - 1 : text.split("\n").length;
}

function walk(absDir, results, rootPrefix) {
  for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.name.startsWith(".") && entry.name !== ".") continue;
    const absPath = path.join(absDir, entry.name);
    if (entry.isDirectory()) {
      walk(absPath, results, rootPrefix);
      continue;
    }
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name);
    const language = EXTENSIONS.get(ext);
    if (!language) continue;
    const relPath = path.relative(ROOT, absPath).replaceAll(path.sep, "/");
    const loc = countLines(absPath);
    results.push({ path: relPath, language, loc, isTest: isTestSourceFile(relPath) });
  }
}

function parseArgs(argv) {
  const args = { json: false, threshold: 600, top: 30 };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--json") args.json = true;
    else if (arg === "--threshold") args.threshold = Number(argv[++i]);
    else if (arg === "--top") args.top = Number(argv[++i]);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const all = [];
  for (const root of SCAN_ROOTS) {
    const abs = path.join(ROOT, root);
    if (!fs.existsSync(abs)) continue;
    walk(abs, all, root);
  }
  all.sort((a, b) => b.loc - a.loc);

  const totals = { rust: 0, typescript: 0, javascript: 0 };
  const totalsNonTest = { rust: 0, typescript: 0, javascript: 0 };
  for (const f of all) {
    totals[f.language] += f.loc;
    if (!f.isTest) totalsNonTest[f.language] += f.loc;
  }

  const overThreshold = all.filter((f) => f.loc > args.threshold);
  const overThresholdNonTest = overThreshold.filter((f) => !f.isTest);

  if (args.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          totals,
          totalsNonTest,
          fileCount: all.length,
          threshold: args.threshold,
          overThreshold: overThresholdNonTest,
          topFiles: all.slice(0, args.top),
        },
        null,
        2,
      )}\n`,
    );
    return;
  }

  process.stdout.write("File-size report\n");
  process.stdout.write(`================\n\n`);
  process.stdout.write(`Total files scanned: ${all.length}\n`);
  process.stdout.write(`Rust LOC:        ${totals.rust} (non-test ${totalsNonTest.rust})\n`);
  process.stdout.write(
    `TypeScript LOC:  ${totals.typescript} (non-test ${totalsNonTest.typescript})\n`,
  );
  process.stdout.write(
    `JavaScript LOC:  ${totals.javascript} (non-test ${totalsNonTest.javascript})\n`,
  );
  process.stdout.write(
    `\nFiles > ${args.threshold} LOC (non-test): ${overThresholdNonTest.length}\n`,
  );
  for (const f of overThresholdNonTest) {
    process.stdout.write(`  ${String(f.loc).padStart(5)}  ${f.path}\n`);
  }
  process.stdout.write(`\nTop ${args.top} largest files (incl. tests):\n`);
  for (const f of all.slice(0, args.top)) {
    const tag = f.isTest ? " [test]" : "";
    process.stdout.write(`  ${String(f.loc).padStart(5)}  ${f.path}${tag}\n`);
  }
}

main();
