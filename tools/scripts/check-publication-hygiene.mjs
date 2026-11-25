#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { publicationHygieneFailures } from "./lib/publication-hygiene-rules.mjs";
import { toolingEntries } from "./lib/tooling-entries.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function snapshotPaths() {
  const output = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  return [...new Set(output.split("\0").filter(Boolean))]
    .filter((relativePath) => {
      const absolutePath = path.join(ROOT, relativePath);
      return fs.existsSync(absolutePath) && fs.lstatSync(absolutePath).isFile();
    })
    .sort();
}

const paths = snapshotPaths();
const files = paths.map((relativePath) => ({
  path: relativePath,
  size: fs.statSync(path.join(ROOT, relativePath)).size,
}));
const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");
const additionalRootFiles = paths.includes(".github/ci-job-visibility.json")
  ? await toolingEntries(ROOT, "publicationRootFiles")
  : [];
const failures = publicationHygieneFailures(files, read, { additionalRootFiles });

if (failures.length > 0) {
  process.stderr.write("Publication hygiene failed:\n");
  for (const failure of failures) {
    process.stderr.write(`- ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write(`Publication hygiene passed (${files.length} files checked).\n`);
