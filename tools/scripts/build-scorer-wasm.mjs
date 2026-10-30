#!/usr/bin/env node

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

import { checkCategories } from "./lib/check-categories.mjs";
import {
  buildWasmArtifact,
  cargoRoot,
  engineTreeSuffix,
  outDirFrom,
  repoRoot,
  run,
  sha256,
  vendorSet,
  WASM_PROFILE,
  WASM_RUSTFLAGS,
  WASM_TARGET,
} from "./lib/wasm-vendor.mjs";

const corpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "score", "golden.json");
const severityCorpusPath = path.join(
  cargoRoot,
  "crates",
  "engine",
  "fixtures",
  "severity",
  "golden.json",
);

const args = process.argv.slice(2);
const allowDirty = args.includes("--allow-dirty");
const outDir = outDirFrom(args, ["SiteCMD-Connect", "apps", "sitecmd-connect", "src", "scorer"]);

const dirtySuffix = engineTreeSuffix(allowDirty, ["apps/desktop/src-tauri", "tools/scripts"]);
const artifactPath = buildWasmArtifact();

const artifact = readFileSync(artifactPath);
const corpus = readFileSync(corpusPath);
const severityCorpus = readFileSync(severityCorpusPath);

// Generate categories from the same source revision as the scorer artifact.
const readRepo = (file) => readFileSync(path.join(repoRoot, file), "utf8");
function listRepoFiles(dir, predicate, files = []) {
  for (const entry of readdirSync(path.join(repoRoot, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "target") continue;
    const relative = `${dir}/${entry.name}`;
    if (entry.isDirectory()) listRepoFiles(relative, predicate, files);
    else if (predicate(relative)) files.push(relative);
  }
  return files;
}
const categories = Buffer.from(
  `${JSON.stringify(checkCategories(readRepo, listRepoFiles), null, 2)}\n`,
);

const provenance = {
  crate: "sitecmd-engine-wasm",
  engine_commit: run("git", ["rev-parse", "HEAD"], { cwd: repoRoot }) + dirtySuffix,
  rustc: run("rustc", ["--version"], { cwd: cargoRoot }),
  target: WASM_TARGET,
  profile: WASM_PROFILE,
  rustflags: WASM_RUSTFLAGS,
  artifact_sha256: sha256(artifact),
  corpus_sha256: sha256(corpus),
  severity_corpus_sha256: sha256(severityCorpus),
  categories_sha256: sha256(categories),
};

vendorSet({
  outDir,
  files: [
    { name: "scorer.wasm", bytes: artifact },
    { name: "golden.json", bytes: corpus },
    { name: "severity-golden.json", bytes: severityCorpus },
    { name: "check-categories.json", bytes: categories },
  ],
  record: provenance,
  recordName: "scorer-artifact.json",
});
