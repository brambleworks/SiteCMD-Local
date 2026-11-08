// A site check ships that only the CLI's live-site scan runs, so proof plus the CLI no longer covers every check.

import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

import { describe, expect, it, vi } from "vitest";

import * as hostedCounts from "./lib/hosted-check-counts.mjs";
import * as laneParsing from "./lib/guardrail-engine-lane-parsing.mjs";
import { deriveCheckCounts, productFacts, webCheckIdSources } from "./lib/product-facts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => readFileSync(path.join(ROOT, relative), "utf8");
const TABLE = "apps/desktop/src-tauri/crates/engine/src/checks/polish/mod.rs";
const OLD_TABLE = "apps/desktop/src-tauri/src/checks/polish/mod.rs";
const SIGNAL_MANIFEST = "apps/desktop/src/generated/polish_signal_manifest.json";
const MANIFEST = "apps/desktop/src-tauri/crates/engine/manifest/capability_manifest.json";
const INVENTORY = "apps/desktop/src-tauri/check-inventory.json";
const RUNNERS_SEO = "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_seo.rs";
const PROBES = "apps/desktop/src-tauri/crates/engine/src/evaluation/probes.rs";
const CHECKS = "apps/desktop/src-tauri/crates/engine/src/checks";

function listFiles(dir, predicate, files = []) {
  for (const entry of readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "target") continue;
    const relative = `${dir}/${entry.name}`;
    if (entry.isDirectory()) listFiles(relative, predicate, files);
    else if (predicate(relative)) files.push(relative);
  }
  return files;
}

const row = (id, reads = false) =>
  [
    "    PolishSignal {",
    `        id: "${id}",`,
    "        category: SignalCategory::HtmlQuality,",
    "        weight: SignalWeight::Low,",
    `        reads_stylesheets: ${reads},`,
    `        run: html_quality::${id.replaceAll("-", "_")},`,
    "    },",
  ].join("\n");
const table = (rows) => `pub const POLISH_SIGNALS: &[PolishSignal] = &[\n${rows.join("\n")}\n];\n`;

describe("the polish count", () => {
  it("is the engine table's length, as the signal manifest the runtime writes from it", () => {
    const facts = JSON.parse(read("product-facts.json"));
    expect(facts.checkCounts.polish).toBe(JSON.parse(read(SIGNAL_MANIFEST)).signals.length);
    expect(facts.checkCounts.polish).toBe([...read(TABLE).matchAll(/^ {8}id: "/gm)].length);
  });

  it("follows a row added to the engine table, not the runtime's old module", () => {
    const changed = deriveCheckCounts(
      (file) => (file === TABLE ? table([row("a"), row("b")]) : read(file)),
      listFiles,
    );
    expect(changed.polish).toBe(2);
    const oldModule = deriveCheckCounts(
      (file) =>
        file === OLD_TABLE
          ? "pub fn run_all_signals(ctx: &Ctx) -> Vec<Signal> {\n    vec![\n        a::b(ctx),\n    ]\n}"
          : read(file),
      listFiles,
    );
    expect(oldModule.polish).toBe(JSON.parse(read(SIGNAL_MANIFEST)).signals.length);
  });

  it("refuses to count when the engine table is gone", () => {
    expect(() =>
      deriveCheckCounts((file) => (file === TABLE ? "" : read(file)), listFiles),
    ).toThrow(/POLISH_SIGNALS/);
  });
});

describe("every site check is hosted or preview-only", () => {
  const tree = {
    [INVENTORY]: JSON.stringify({ web: ["seo.a"] }),
    [MANIFEST]: JSON.stringify({
      entries: [
        { check: "seo.a", hosted: "artifact", scope: "page" },
        { check: "polish.page-only", hosted: "artifact", scope: "page" },
        { check: "polish.reads-css", hosted: "probe_adapter", scope: "origin" },
        { check: "polish.planned", hosted: "probe_adapter", scope: "origin" },
      ],
    }),
    [RUNNERS_SEO]: "pub const EXCLUDED_ARTIFACT_CHECKS: &[(&str, &str)] = &[\n];",
    [PROBES]: "pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[\n];",
    [TABLE]: table([row("page-only"), row("reads-css", true), row("planned", true)]),
  };
  const counts = (overrides = {}, sources = new Map()) =>
    hostedCounts.deriveHostedCheckCounts(
      (file) => ({ ...tree, ...overrides })[file] ?? "",
      3,
      sources,
    );
  const unsupportedWeb = {
    [MANIFEST]: JSON.stringify({
      entries: [{ check: "seo.a", hosted: "unsupported", scope: "page" }],
    }),
    [TABLE]: table([]),
  };

  it("counts every hosted polish row in the total", () => {
    // A hosted polish signal is omitted from the public total.
    expect(counts()).toEqual({
      web: 1,
      previewCheckCount: 0,
      crossPage: 0,
      axe: 0,
      polish: 3,
      total: 4,
    });
  });

  it.each([
    ["outside predeploy", [`${CHECKS}/seo/a.rs`]],
    ["in both predeploy and live checks", [`${CHECKS}/predeploy/mod.rs`, `${CHECKS}/seo/a.rs`]],
    ["in the runtime's predeploy directory", ["apps/desktop/src-tauri/src/checks/predeploy/a.rs"]],
    ["with no known emitter", []],
  ])("refuses an unsupported web check %s", (_name, files) => {
    // An unsupported live-site check is silently counted as a preview check.
    expect(() => counts(unsupportedWeb, new Map([["seo.a", files]]))).toThrow(
      "seo.a runs neither on the hosted lane nor as a preview check",
    );
  });

  it("refuses an unsupported web check with no source entry", () => {
    // A missing emitter is mistaken for proof that a check is preview-only.
    expect(() => counts(unsupportedWeb)).toThrow(
      "seo.a runs neither on the hosted lane nor as a preview check",
    );
  });

  it("accepts an unsupported web check emitted only by engine preview checks", () => {
    // A valid preview check is rejected or added to the hosted total.
    expect(
      counts(
        unsupportedWeb,
        new Map([["seo.a", [`${CHECKS}/predeploy/mod.rs`, `${CHECKS}/predeploy/content.rs`]]]),
      ),
    ).toEqual({ web: 0, previewCheckCount: 1, crossPage: 0, axe: 0, polish: 0, total: 0 });
  });

  it.each([
    ["no capability-manifest entry", [], {}],
    ["unsupported in the capability manifest", [{ check: "seo.a", hosted: "unsupported" }], {}],
    [
      "listed in EXCLUDED_PROBE_CHECKS",
      [{ check: "seo.a", hosted: "probe_adapter" }],
      {
        [PROBES]:
          'pub const EXCLUDED_PROBE_CHECKS: &[(&str, &str)] = &[\n    ("seo.a", "excluded"),\n];',
      },
    ],
    [
      "listed in EXCLUDED_ARTIFACT_CHECKS",
      [{ check: "seo.a", hosted: "artifact" }],
      {
        [RUNNERS_SEO]:
          'pub const EXCLUDED_ARTIFACT_CHECKS: &[(&str, &str)] = &[\n    ("seo.a", "excluded"),\n];',
      },
    ],
  ])("names the coverage cause: %s", (cause, entries, overrides) => {
    // A coverage error hides which manifest row or exclusion needs repair.
    expect(() =>
      counts({ [TABLE]: table([]), [MANIFEST]: JSON.stringify({ entries }), ...overrides }),
    ).toThrow(
      new Error(
        `product-facts: seo.a runs neither on the hosted lane nor as a preview check (${cause})`,
      ),
    );
  });

  it.each([
    [PROBES, "EXCLUDED_PROBE_CHECKS", "polish.reads-css"],
    [RUNNERS_SEO, "EXCLUDED_ARTIFACT_CHECKS", "polish.page-only"],
    [PROBES, "EXCLUDED_PROBE_CHECKS", "polish."],
  ])("refuses a polish exclusion in %s for %s: %s", (file, name, id) => {
    // An excluded polish signal silently disappears from the hosted count.
    const missing = id.endsWith(".") ? "polish.reads-css" : id;
    expect(() =>
      counts({ [file]: `pub const ${name}: &[(&str, &str)] = &[\n    ("${id}", "excluded"),\n];` }),
    ).toThrow(`${missing} runs neither on the hosted lane nor as a preview check`);
  });

  it("refuses unsupported polish even when its emitter is under predeploy", () => {
    // The preview exception incorrectly exempts a polish signal from hosted coverage.
    expect(() =>
      counts(
        {
          ...unsupportedWeb,
          [INVENTORY]: '{"web":[]}',
          [TABLE]: table([row("a")]),
          [MANIFEST]: JSON.stringify({ entries: [{ check: "polish.a", hosted: "unsupported" }] }),
        },
        new Map([["polish.a", [`${CHECKS}/predeploy/mod.rs`]]]),
      ),
    ).toThrow("polish.a runs neither on the hosted lane nor as a preview check");
  });

  it("refuses a polish signal with no manifest row", () => {
    // A polish signal with no capability entry is omitted from accounting.
    expect(() => counts({ [TABLE]: table([row("page-only"), row("unlisted")]) })).toThrow(
      "polish.unlisted runs neither on the hosted lane nor as a preview check",
    );
  });

  it("refuses a web check with no manifest row", () => {
    // A missing web capability entry fails without the required coverage diagnostic.
    expect(() => counts({ [INVENTORY]: '{"web":["seo.unlisted"]}' })).toThrow(
      "seo.unlisted runs neither on the hosted lane nor as a preview check",
    );
  });

  it("refuses to publish a polish signal without a hosted lane", () => {
    // Changing a polish lane to unsupported silently lowers the published count.
    const published = JSON.parse(read("product-facts.json")).hostedCheckCounts;
    expect(published.total).toBe(published.web + published.axe + published.polish);
    const manifest = JSON.parse(read(MANIFEST));
    const first = manifest.entries.find(
      (entry) => entry.check.startsWith("polish.") && entry.hosted === "artifact",
    );
    expect(() =>
      productFacts(
        (file) =>
          file === MANIFEST
            ? JSON.stringify({
                ...manifest,
                entries: manifest.entries.map((entry) =>
                  entry === first ? { ...entry, hosted: "unsupported" } : entry,
                ),
              })
            : read(file),
        listFiles,
      ),
    ).toThrow(`${first.check} runs neither on the hosted lane nor as a preview check`);
  });

  it("accounts for every real web check and polish signal in generated and published facts", () => {
    // A live-site check ships without hosted coverage or a preview-only emitter.
    for (const facts of [productFacts(read, listFiles), JSON.parse(read("product-facts.json"))]) {
      expect
        .soft(facts.checkCounts.web)
        .toBe(facts.hostedCheckCounts.web + facts.previewCheckCount);
      expect.soft(facts.checkCounts.polish).toBe(facts.hostedCheckCounts.polish);
    }
  });

  it("does not label an unclassified exemption as a preview check", () => {
    // Subtraction labels a new unclassified return-null path as a preview exemption.
    const normal = productFacts(read, listFiles);
    const source = read("tools/scripts/lib/hosted-check-counts.mjs");
    const branch = "const entry = manifestEntry(entries, id);";
    expect(source).toContain(branch);
    const scratch = source
      .replace(/^import[\s\S]*?from "[^"]+";\n/m, "")
      .replace("export function deriveHostedCheckCounts", "function deriveHostedCheckCounts")
      .replace(branch, `if (id === "seo.title") return null;\n${branch}`);
    const derive = runInNewContext(`${scratch}\nderiveHostedCheckCounts;`, { ...laneParsing });
    const skipped = vi.spyOn(hostedCounts, "deriveHostedCheckCounts").mockImplementation(derive);
    try {
      const changed = productFacts(read, listFiles);
      expect(changed.hostedCheckCounts.web).toBe(normal.hostedCheckCounts.web - 1);
      expect(changed.previewCheckCount).toBe(normal.previewCheckCount);
      expect(changed.hostedCheckCounts.web + changed.previewCheckCount).not.toBe(
        changed.checkCounts.web,
      );
    } finally {
      skipped.mockRestore();
    }
  });

  it("refuses facts when a preview check gains a live-site emitter", () => {
    // A second emitter lets a live-site check hide behind the preview exception.
    const inventory = JSON.parse(read(INVENTORY)).web;
    const { entries } = JSON.parse(read(MANIFEST));
    const sources = webCheckIdSources(read, listFiles);
    const id = inventory.findLast(
      (check) =>
        entries.find((entry) => entry.check === check)?.hosted === "unsupported" &&
        laneParsing.isPreviewOnlySources(sources.get(check)),
    );
    const extra = `${CHECKS}/seo/extra.rs`;
    const withExtra = (file) => (file === extra ? `fn id(&self) -> &str { "${id}" }` : read(file));
    const files = (dir, predicate) => [
      ...listFiles(dir, predicate),
      ...(dir === CHECKS && predicate(extra) ? [extra] : []),
    ];
    expect(id).toBeDefined();
    expect(() => productFacts(withExtra, files)).toThrow(
      `${id} runs neither on the hosted lane nor as a preview check`,
    );
  });
});
