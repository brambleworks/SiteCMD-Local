// The asset sample's size and the hosted check count come from the engine's producers.

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { productFacts } from "./lib/product-facts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => readFileSync(path.join(ROOT, relative), "utf8");
const ASSETS = "apps/desktop/src-tauri/crates/engine/src/checks/performance/assets/mod.rs";

function listFiles(dir, predicate, files = []) {
  for (const entry of readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "target") continue;
    const relative = `${dir}/${entry.name}`;
    if (entry.isDirectory()) listFiles(relative, predicate, files);
    else if (predicate(relative)) files.push(relative);
  }
  return files;
}

/** The facts the generator writes from the tree with one file's text changed. */
function factsWith(file, change) {
  return productFacts((name) => (name === file ? change(read(name)) : read(name)), listFiles);
}

describe("the performance facts the engine publishes", () => {
  it("publishes the asset sample's size from the engine that requests it", () => {
    const changed = factsWith(ASSETS, (source) =>
      source.replace("ASSET_SAMPLE_LIMIT: usize = 30;", "ASSET_SAMPLE_LIMIT: usize = 31;"),
    );
    expect(changed.scannerIdentity.limits.assetSampleLimit).toBe(31);
  });

  it("counts each performance check the engine's probes produce", () => {
    // Excluding any produced performance check must reduce the hosted count.
    const PROBES = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
    const published = productFacts(read, listFiles).hostedCheckCounts.web;
    for (const id of [
      "performance.asset_caching",
      "performance.asset_weight",
      "performance.broken_images",
      "performance.compression",
      "performance.images.heavy",
      "performance.redirect_chain",
      "performance.ttfb",
    ]) {
      const excluded = factsWith(PROBES, (source) =>
        source.replace(
          "pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[",
          `pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[\n    ("${id}", "excluded for this case"),`,
        ),
      );
      expect(excluded.hostedCheckCounts.web, id).toBe(published - 1);
    }
  });
});
