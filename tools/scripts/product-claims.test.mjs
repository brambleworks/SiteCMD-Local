import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  PRODUCT_FACTS_FILE,
  deriveCheckCounts,
  productFacts,
  productionHalf,
} from "./lib/product-facts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => readFileSync(path.join(ROOT, relative), "utf8");

function listFiles(dir, predicate, files = []) {
  for (const entry of readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "target") continue;
    const relative = `${dir}/${entry.name}`;
    if (entry.isDirectory()) listFiles(relative, predicate, files);
    else if (predicate(relative)) files.push(relative);
  }
  return files;
}

describe("derivable check count", () => {
  const counts = deriveCheckCounts(read, listFiles);

  it("extracts each component from the engine source", () => {
    expect(counts.web, "web-scan check ids").toBeGreaterThanOrEqual(100);
    expect(counts.polish, "polish signals").toBeGreaterThanOrEqual(25);
    expect(counts.codeScan, "code-scan registry entries").toBeGreaterThanOrEqual(150);
  });

  it("totals its components", () => {
    expect(counts.total).toBe(
      counts.web + counts.polish + counts.codeScan + counts.axe + counts.dependencyEcosystems,
    );
  });
});

describe("productionHalf", () => {
  it("cuts at the first inline test module, not at any cfg(test) attribute", () => {
    const source = [
      "#[cfg(test)]",
      "use super::CollectedAsset;",
      "", // separator line, matching real formatting
      'pub const CHECK_ID: &str = "example.production";',
      "",
      "#[cfg(test)]",
      "mod tests {",
      '    const FIXTURE: &str = "example.fixture";',
      "}",
    ].join("\n");
    const production = productionHalf(source);
    expect(production).toContain("example.production");
    expect(production).not.toContain("example.fixture");
  });

  it("keeps everything below a test module DECLARED in another file", () => {
    for (const declaration of ["mod tests;", '#[path = "example_tests.rs"]\nmod tests;']) {
      const source = [
        "#[cfg(test)]",
        declaration,
        "mod validate;",
        "",
        'pub const CHECK_ID: &str = "example.production";',
      ].join("\n");
      expect(productionHalf(source), declaration).toContain("example.production");
    }
  });

  it("still cuts inline test modules holding fixture ids", () => {
    const source = [
      'pub const CHECK_ID: &str = "example.production";',
      "",
      "#[cfg(test)]",
      "mod tests {",
      '    const FIXTURE: &str = "example.fixture";',
      "}",
    ].join("\n");
    const production = productionHalf(source);
    expect(production).toContain("example.production");
    expect(production).not.toContain("example.fixture");
  });
});

describe("check-id extraction", () => {
  it("reads the web count from the generated inventory snapshot", () => {
    const sources = {
      // The registries generate this file (`cargo test checks::inventory`);
      // deriveCheckCounts reads it rather than regex-scraping id constants,
      // so a runner shell's sub-ids (e.g. security.headers.csp) count once
      // each instead of once for the shell.
      "apps/desktop/src-tauri/check-inventory.json": JSON.stringify({
        web: ["performance.lcp"],
      }),
      "apps/desktop/src-tauri/src/checks/polish/mod.rs":
        "pub fn run_all_signals(ctx: &Ctx) -> Vec<Signal> {\n    vec![\n        signals::one(ctx),\n    ]\n}",
      "apps/desktop/src-tauri/crates/engine/src/code_rules.rs": '    d("example-rule"),',
    };
    const fakeRead = (file) => sources[file] ?? "";
    const fakeList = (dir) =>
      Object.keys(sources).filter((file) => file.startsWith(dir) && file.endsWith(".rs"));

    const counts = deriveCheckCounts(fakeRead, fakeList);
    expect(counts.web, "web count comes from the inventory snapshot's length").toBe(1);
  });
});

describe("published product facts", () => {
  const committed = JSON.parse(read(PRODUCT_FACTS_FILE));

  it("matches what the sources currently say", () => {
    expect(committed).toEqual(productFacts(read, listFiles));
  });

  it("publishes the connected-service commercial boundary without invented prices", () => {
    expect(committed.commercialModel).toEqual({
      billableUnit: "connected_production_site",
      connectedServiceAccess: "comped_beta",
      localWorkbench: "free_complete",
      meteredOverages: false,
      paidBoundary: "connected_service",
      planShape: "flat_bundles",
      publicPricing: "not_set",
    });
    expect(committed).not.toHaveProperty("tierPricing");
  });

  it("publishes a surface status for every documented surface", () => {
    for (const [surface, status] of Object.entries(committed.productSurfaceStatus)) {
      expect(["available", "planned"], `${surface} status`).toContain(status);
    }
  });
});

describe("the scanner identity SiteCMD-Web publishes at /scanner", () => {
  const AGENT = "apps/desktop/src-tauri/crates/engine/src/agent.rs";
  const EXPOSED = "apps/desktop/src-tauri/crates/engine/src/checks/security/exposed_files.rs";

  const substituting = (file, replace) => (asked) =>
    asked === file ? replace(read(asked)) : read(asked);

  const identity = productFacts(read, listFiles).scannerIdentity;

  it("publishes the URL the engine actually advertises", () => {
    expect(read(AGENT)).toContain(`SCANNER_DOCS_URL: &str = "${identity.docsUrl}"`);
    expect(identity.userAgentFormat).toContain("{version}");
    expect(identity.userAgentFormat).toContain(identity.docsUrl);
  });

  it("carries every path the exposed-files check probes", () => {
    const block = read(EXPOSED).match(/SENSITIVE_PATHS[\s\S]*?\n\];/)[0];
    expect(identity.sensitivePaths.length).toBe([...block.matchAll(/Severity::/g)].length);
  });

  it("refuses to publish an empty path list when the constant moves", () => {
    const renamed = substituting(EXPOSED, (source) =>
      source.replace("SENSITIVE_PATHS: &[(&str, &str, Severity)]", "PROBED_PATHS: &[(&str, &str)]"),
    );
    expect(() => productFacts(renamed, listFiles)).toThrow(/SENSITIVE_PATHS/);
  });

  it("refuses to publish an identity the engine no longer builds that way", () => {
    const rewritten = substituting(AGENT, (source) =>
      source.replace(/format!\("[^"]+"\)/, "String::from(version)"),
    );
    expect(() => productFacts(rewritten, listFiles)).toThrow(/User-Agent format/);
  });
});
