#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

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

// Vendor the exact corpus replayed by the native engine tests.
const corpusPath = path.join(cargoRoot, "crates", "engine", "fixtures", "checks", "golden.json");
const stackCorpusPath = path.join(
  cargoRoot,
  "crates",
  "engine",
  "fixtures",
  "stack",
  "golden.json",
);
const sessionCorpusPath = path.join(
  cargoRoot,
  "crates",
  "engine",
  "fixtures",
  "session",
  "golden.json",
);
const manifestPath = path.join(
  cargoRoot,
  "crates",
  "engine",
  "manifest",
  "capability_manifest.json",
);
const browserPath = path.join(cargoRoot, "crates", "engine", "browser");

// Warn on bundle growth without silently dropping checks.
const SIZE_NOTICE_BYTES = 5 * 1024 * 1024;

const args = process.argv.slice(2);
const allowDirty = args.includes("--allow-dirty");
const outDir = outDirFrom(args, ["SiteCMD-Connect", "apps", "sitecmd-scan", "src", "engine"]);

const dirtySuffix = engineTreeSuffix(allowDirty, ["apps/desktop/src-tauri", "tools/scripts"]);
const artifactPath = buildWasmArtifact({ features: ["checks"] });

const artifact = readFileSync(artifactPath);
const corpus = readFileSync(corpusPath);
const stackCorpus = readFileSync(stackCorpusPath);
const sessionCorpus = readFileSync(sessionCorpusPath);
const manifestBytes = readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const axeCore = readFileSync(path.join(browserPath, "axe.min.js"), "utf8");
const cwvObserver = readFileSync(path.join(browserPath, "cwv_observer.js"), "utf8");
const cwvRead = readFileSync(path.join(browserPath, "cwv_read.js"), "utf8");
const browserPayload = JSON.parse(
  run("cargo", ["run", "--quiet", "-p", "sitecmd-engine", "--example", "emit_browser_payload"], {
    cwd: cargoRoot,
  }),
);
if (
  typeof browserPayload.axe_core_version !== "string" ||
  typeof browserPayload.axe_run_script !== "string"
) {
  throw new Error("emit_browser_payload returned an invalid browser payload");
}
const browserAssets = Buffer.from(
  `${JSON.stringify(
    {
      axe_core_version: browserPayload.axe_core_version,
      axe_core_script: axeCore,
      axe_run_script: browserPayload.axe_run_script,
      cwv_observer_script: cwvObserver,
      cwv_read_script: cwvRead,
    },
    null,
    2,
  )}\n`,
);

const provenance = {
  crate: "sitecmd-engine-wasm",
  features: ["checks"],
  engine_commit: run("git", ["rev-parse", "HEAD"], { cwd: repoRoot }) + dirtySuffix,
  rustc: run("rustc", ["--version"], { cwd: cargoRoot }),
  target: WASM_TARGET,
  profile: WASM_PROFILE,
  rustflags: WASM_RUSTFLAGS,
  artifact_sha256: sha256(artifact),
  corpus_sha256: sha256(corpus),
  stack_corpus_sha256: sha256(stackCorpus),
  session_corpus_sha256: sha256(sessionCorpus),
  browser_assets_sha256: sha256(browserAssets),
  manifest_digest: manifest.manifest_digest,
  capability_manifest_sha256: sha256(manifestBytes),
};

vendorSet({
  outDir,
  files: [
    { name: "checks.wasm", bytes: artifact },
    { name: "capability_manifest.json", bytes: manifestBytes },
    { name: "golden.json", bytes: corpus },
    { name: "stack-golden.json", bytes: stackCorpus },
    { name: "session-golden.json", bytes: sessionCorpus },
    { name: "browser-assets.json", bytes: browserAssets },
  ],
  record: provenance,
  recordName: "checks-artifact.json",
});

console.log(`  manifest digest ${provenance.manifest_digest}`);
if (artifact.length > SIZE_NOTICE_BYTES) {
  console.warn(
    `\nNOTICE: checks.wasm is ${(artifact.length / 1024 / 1024).toFixed(2)} MB, past the ${(
      SIZE_NOTICE_BYTES /
      1024 /
      1024
    ).toFixed(
      0,
    )} MB notice threshold. Workers enforce a bundle ceiling; decide what to do about it deliberately rather than by trimming checks.`,
  );
}
