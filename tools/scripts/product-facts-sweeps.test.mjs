// The scanner page's directory list drifts from the paths the engine requests.

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { productFacts } from "./lib/product-facts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DIRS = "apps/desktop/src-tauri/crates/engine/src/checks/security/directory_listing.rs";
const read = (file) => readFileSync(path.join(ROOT, file), "utf8");
function listFiles(dir, predicate, files = []) {
  for (const entry of readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "target") continue;
    const relative = `${dir}/${entry.name}`;
    if (entry.isDirectory()) listFiles(relative, predicate, files);
    else if (predicate(relative)) files.push(relative);
  }
  return files;
}

it("publishes the engine's directory paths in their request order", () => {
  const paths = [
    ...read(DIRS)
      .match(/PROBE_DIRS: &[\s\S]*?= &\[([\s\S]*?)\n\];/)[1]
      .matchAll(/"(\/[^"]+)"/g),
  ].map(([, value]) => value);
  expect(paths).toHaveLength(19);
  expect(productFacts(read, listFiles).scannerIdentity.directoryProbePaths).toEqual(paths);
});

it("refuses to generate facts without the directory table", () => {
  expect(() => productFacts((file) => (file === DIRS ? "" : read(file)), listFiles)).toThrow(
    /PROBE_DIRS/,
  );
});

it("publishes the stylesheet sample limit from the engine's counter module", () => {
  // A relocated limit must still bind the published count to the engine's sample.
  const counts = "apps/desktop/src-tauri/crates/engine/src/checks/polish/css_counts.rs";
  const changed = (file) =>
    file === counts
      ? read(file).replace(
          "STYLESHEET_SAMPLE_LIMIT: usize = 8",
          "STYLESHEET_SAMPLE_LIMIT: usize = 7",
        )
      : read(file);
  expect(productFacts(read, listFiles).scannerIdentity.limits.stylesheetMaxCount).toBe(8);
  expect(productFacts(changed, listFiles).scannerIdentity.limits.stylesheetMaxCount).toBe(7);
});
