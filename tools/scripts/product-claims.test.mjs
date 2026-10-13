import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { deriveHostedCheckCounts } from "./lib/hosted-check-counts.mjs";
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

describe("the scanner identity published at /scanner", () => {
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

describe("the hosted check count", () => {
  const facts = productFacts(read, listFiles);
  const INVENTORY = "apps/desktop/src-tauri/check-inventory.json";
  const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
  const RUNNERS_SEO = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_seo.rs";
  const PROBES = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
  const SITEMAP = "apps/desktop/src-tauri/crates/engine/src/checks/seo/sitemap.rs";
  const SITEMAP_DOCUMENT =
    "apps/desktop/src-tauri/crates/engine/src/checks/seo/sitemap_document.rs";
  const CONSTANTS = "apps/desktop/src-tauri/src/constants.rs";
  const tree = {
    [INVENTORY]: JSON.stringify({
      web: [
        "seo.a",
        "seo.b",
        "seo.bb",
        "seo.browser",
        "seo.c",
        "seo.d",
        "security.exposed_files.x",
      ],
    }),
    [MANIFEST]: JSON.stringify({
      entries: [
        { check: "accessibility.axe.", hosted: "browser", scope: "page", family: true },
        { check: "security.exposed_files.", hosted: "probe_adapter", scope: "page", family: true },
        { check: "seo.a", hosted: "artifact", scope: "page" },
        { check: "seo.b", hosted: "probe_adapter", scope: "origin" },
        { check: "seo.bb", hosted: "probe_adapter", scope: "origin" },
        { check: "seo.browser", hosted: "browser", scope: "page" },
        { check: "seo.c", hosted: "unsupported", scope: "page" },
        { check: "seo.d", hosted: "artifact", scope: "session" },
        { check: "seo.group", hosted: "artifact", scope: "page" },
      ],
    }),
    [RUNNERS_SEO]: "pub const EXCLUDED_ARTIFACT_CHECKS: &[(&str, &str)] = &[\n];",
    [PROBES]: [
      "pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[",
      '    ("security.exposed_files.", "the desktop shell owns the candidate-path sweep"),',
      "];",
    ].join("\n"),
  };
  const counts = (overrides = {}) =>
    deriveHostedCheckCounts(
      (file) => ({ ...tree, ...overrides })[file] ?? "",
      facts.checkCounts.axe,
    );
  const manifest = (entries) => ({ [MANIFEST]: JSON.stringify({ entries }) });

  it("counts the web checks a hosted lane produces, with the axe rules", () => {
    expect(counts()).toEqual({
      web: 5,
      crossPage: 1,
      axe: facts.checkCounts.axe,
      total: 5 + facts.checkCounts.axe,
    });
  });

  it("leaves out a check whose producer this build excludes", () => {
    const excluded = [
      "pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[",
      '    ("security.exposed_files.", "the desktop shell owns the candidate-path sweep"),',
      '    ("seo.b", "the desktop shell owns the robots.txt fetch"),',
      "];",
    ].join("\n");
    expect(counts({ [PROBES]: excluded })).toEqual({
      web: 4,
      crossPage: 1,
      axe: facts.checkCounts.axe,
      total: 4 + facts.checkCounts.axe,
    });
  });

  it("leaves out an artifact check whose producer this build excludes", () => {
    expect(
      counts({
        [RUNNERS_SEO]:
          'pub const EXCLUDED_ARTIFACT_CHECKS: &[(&str, &str)] = &[\n    ("seo.d", "this build has no producer"),\n];',
      }),
    ).toEqual({
      web: 4,
      crossPage: 0,
      axe: facts.checkCounts.axe,
      total: 4 + facts.checkCounts.axe,
    });
  });

  it("refuses to count when an exclusion table or a manifest entry is missing", () => {
    expect(() => counts({ [PROBES]: "" })).toThrow(/EXCLUDED_PROBE_CHECKS/);
    expect(() => counts({ [RUNNERS_SEO]: "" })).toThrow(/EXCLUDED_ARTIFACT_CHECKS/);
    expect(() => counts({ [INVENTORY]: JSON.stringify({ web: ["seo.unregistered"] }) })).toThrow(
      /seo\.unregistered/,
    );
    expect(() => counts({ [INVENTORY]: JSON.stringify({ web: ["seo.group.x"] }) })).toThrow(
      /seo\.group\.x/,
    );
  });

  it("uses an exact entry before its longest matching family", () => {
    const entries = [
      { check: "seo.", hosted: "unsupported", scope: "page", family: true },
      { check: "seo.group.", hosted: "artifact", scope: "session", family: true },
      { check: "seo.group.exact", hosted: "unsupported", scope: "page" },
    ];
    expect(
      counts({
        ...manifest(entries),
        [INVENTORY]: JSON.stringify({ web: ["seo.group.exact", "seo.group.other"] }),
      }),
    ).toEqual({ web: 1, crossPage: 1, axe: 0, total: 1 });
  });

  it("omits axe rules when their family has no hosted lane", () => {
    const { entries } = JSON.parse(tree[MANIFEST]);
    expect(
      counts(
        manifest(
          entries.map((entry) =>
            entry.check === "accessibility.axe." ? { ...entry, hosted: "unsupported" } : entry,
          ),
        ),
      ),
    ).toEqual({ web: 5, crossPage: 1, axe: 0, total: 5 });
  });

  it("derives the published hosted count from the inventory", () => {
    const inventory = JSON.parse(read(INVENTORY));
    expect(inventory.web).toContain("seo.title");
    const changed = productFacts(
      (file) =>
        file === INVENTORY
          ? JSON.stringify({ ...inventory, web: inventory.web.filter((id) => id !== "seo.title") })
          : read(file),
      listFiles,
    );
    expect(changed.hostedCheckCounts.web).toBe(facts.hostedCheckCounts.web - 1);
  });

  it("publishes the count beside the total, never above it", () => {
    const hosted = facts.hostedCheckCounts;
    expect(hosted.total).toBe(hosted.web + hosted.axe);
    expect(hosted.crossPage).toBeLessThan(hosted.web);
    expect(hosted.total).toBeLessThan(facts.checkCounts.total);
  });

  it("publishes the sitemap walk the engine makes", () => {
    const { sitemapWalk, limits } = facts.scannerIdentity;
    expect(sitemapWalk.candidatePaths[0]).toBe("/sitemap.xml");
    expect(sitemapWalk.declaredLimit).toBeGreaterThan(0);
    expect(limits.sitemapBodyMaxBytes).toBeGreaterThan(limits.probeBodyMaxBytes);
  });

  it("follows changed sitemap constants and candidate paths", () => {
    const { sitemapWalk, limits } = JSON.parse(read(PRODUCT_FACTS_FILE)).scannerIdentity;
    const declaredLimit = sitemapWalk.declaredLimit * 2;
    const sitemapBodyMaxBytes = limits.sitemapBodyMaxBytes + 1;
    const sources = {
      [SITEMAP]: read(SITEMAP).replace(
        /(SITEMAP_DECLARATION_PROBE_LIMIT: usize = )\d+/,
        `$1${declaredLimit}`,
      ),
      [SITEMAP_DOCUMENT]: read(SITEMAP_DOCUMENT).replace("/sitemap.xml", "/custom-sitemap.xml"),
      [CONSTANTS]: read(CONSTANTS).replace(
        /(MAX_SITEMAP_SIZE: u64 = )[^;]+/,
        `$1${sitemapBodyMaxBytes}`,
      ),
    };
    const changed = productFacts((file) => sources[file] ?? read(file), listFiles).scannerIdentity;
    expect(changed.sitemapWalk).toEqual({
      declaredLimit,
      candidatePaths: sitemapWalk.candidatePaths.map((candidate) =>
        candidate === "/sitemap.xml" ? "/custom-sitemap.xml" : candidate,
      ),
    });
    expect(changed.limits.sitemapBodyMaxBytes).toBe(sitemapBodyMaxBytes);
  });

  it("refuses to publish sitemap facts when their constants disappear", () => {
    for (const [file, name] of [
      [SITEMAP, "SITEMAP_DECLARATION_PROBE_LIMIT"],
      [SITEMAP_DOCUMENT, "SITEMAP_CANDIDATE_PATHS"],
      [CONSTANTS, "MAX_SITEMAP_SIZE"],
    ]) {
      expect(() =>
        productFacts(
          (asked) =>
            asked === file ? read(asked).replaceAll(name, "MISSING_CONSTANT") : read(asked),
          listFiles,
        ),
      ).toThrow(name);
    }
    expect(() =>
      productFacts(
        (file) =>
          file === SITEMAP_DOCUMENT
            ? read(file).replace(/(SITEMAP_CANDIDATE_PATHS: \[&str; \d+\] = \[)[\s\S]*?\];/, "$1];")
            : read(file),
        listFiles,
      ),
    ).toThrow(/no SITEMAP_CANDIDATE_PATHS/);
  });
});
