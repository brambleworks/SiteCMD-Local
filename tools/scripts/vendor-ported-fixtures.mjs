#!/usr/bin/env node

// Vendor the parity corpora for the logic Connect ports from this repository's
// Rust: event correlation, the regression-blame decision, work-item
// regressions with the check alias table, and the fix brief. Connect's ports
// replay these bytes; the record names the commit that wrote them.

import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

import {
  cargoRoot,
  engineTreeSuffix,
  outDirFrom,
  repoRoot,
  run,
  sha256,
  vendorSet,
} from "./lib/wasm-vendor.mjs";

const parityDir = path.join(cargoRoot, "tests", "fixtures", "parity");
const PORTED = [
  { source: "event_correlations.json", name: "event-correlations-golden.json" },
  {
    source: "event_correlations_boundaries.json",
    name: "event-correlations-boundaries-golden.json",
  },
  { source: "regression_blame.json", name: "regression-blame-golden.json" },
  { source: "work_item_projection.json", name: "work-item-projection-golden.json" },
  {
    source: "work_item_projection_boundaries.json",
    name: "work-item-projection-boundaries-golden.json",
  },
  { source: "fix_brief.json", name: "fix-brief-golden.json" },
  { source: "check_aliases.json", name: "check-aliases.json" },
];

const args = process.argv.slice(2);
const allowDirty = args.includes("--allow-dirty");
const outDir = outDirFrom(args, ["SiteCMD-Connect", "apps", "sitecmd-connect", "src", "ported"]);
const dirtySuffix = engineTreeSuffix(allowDirty, [
  "apps/desktop/src-tauri/src/core",
  "apps/desktop/src-tauri/tests/fixtures/parity",
]);

const files = PORTED.map(({ source, name }) => ({
  name,
  bytes: readFileSync(path.join(parityDir, source)),
}));

vendorSet({
  outDir,
  files,
  record: {
    engine_commit: run("git", ["rev-parse", "HEAD"], { cwd: repoRoot }) + dirtySuffix,
    files: Object.fromEntries(files.map((file) => [file.name, sha256(file.bytes)])),
  },
  recordName: "ported-fixtures.json",
});
