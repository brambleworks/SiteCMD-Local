import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import { deriveCheckCounts, productFacts, productionHalf } from "./lib/product-facts.mjs";

const read = (file) => readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
const PAYLOAD = "apps/desktop/src-tauri/crates/engine/src/browser/payload.rs";
const BUNDLE = "apps/desktop/src-tauri/crates/engine/browser/axe.min.js";
const TAGS = ["wcag2a", "wcag2aa", "wcag21a"];
const FIXTURE_RULES = [
  { id: "enabled", tags: ["wcag2a"], enabled: true },
  { id: "disabled-selected", tags: ["wcag2aa"], enabled: false },
  { id: "disabled-unselected", tags: ["best-practice"], enabled: false },
  { id: "experimental", tags: ["wcag2a", "experimental"], enabled: true },
  { id: "deprecated", tags: ["wcag2aa", "deprecated"], enabled: false },
  { id: "page-level", tags: ["wcag21a"], enabled: true, pageLevel: true },
];
const FIXTURE_BUNDLE = `${read(BUNDLE)}\nmodule.exports._audit.rules = ${JSON.stringify(FIXTURE_RULES)};`;
const DECLARATION = /pub const AXE_RUN_TAGS:[^=]*=\s*\[[\s\S]*?\];/;

function declaration(tags) {
  return `pub const AXE_RUN_TAGS: [&str; ${tags.length}] = ${JSON.stringify(tags)};`;
}

function fixtureRead(payload = declaration(TAGS)) {
  return (file) => {
    if (file === PAYLOAD) return read(PAYLOAD).replace(DECLARATION, payload);
    if (file === BUNDLE) return FIXTURE_BUNDLE;
    return read(file);
  };
}

function realAuditCount(readSource = read) {
  const sandbox = { module: { exports: {} }, setTimeout, clearTimeout };
  runInNewContext(readSource(BUNDLE), sandbox);
  const axe = sandbox.module.exports;
  const tags = JSON.parse(
    productionHalf(readSource(PAYLOAD))
      .match(/AXE_RUN_TAGS:[^=]*=\s*(\[[\s\S]*?\]);/)[1]
      .replace(/,\s*\]$/, "]"),
  );
  const options = { runOnly: { type: "tag", values: tags } };
  axe._audit.normalizeOptions(options);
  return axe._audit.rules.filter((rule) => axe.utils.ruleShouldRun(rule, { page: true }, options))
    .length;
}

describe("the axe rules the engine runs", () => {
  it.each([
    ["counts selected disabled rules and excludes unselected and experimental rules", TAGS, 3],
    ["includes experimental rules when their tag is selected", [...TAGS, "experimental"], 4],
    ["includes deprecated rules when their tag is selected", [...TAGS, "deprecated"], 4],
    ["selects the other disabled rule when its tag is named", ["best-practice"], 1],
  ])("%s", (_name, tags, expected) => {
    expect(deriveCheckCounts(fixtureRead(declaration(tags))).axe).toBe(expected);
  });

  it("matches the real audit selection in the derivation and generated facts", () => {
    const selected = realAuditCount();
    const published = JSON.parse(read("product-facts.json"));

    expect.soft(deriveCheckCounts(read).axe).toBe(selected);
    expect.soft(published.checkCounts.axe).toBe(selected);
    expect.soft(published.hostedCheckCounts.axe).toBe(selected);
  });

  it("follows the declared tag list", () => {
    const changed = (file) =>
      file === PAYLOAD ? read(file).replace(DECLARATION, declaration(["wcag22aa"])) : read(file);
    const published = JSON.parse(read("product-facts.json"));

    expect(deriveCheckCounts(changed).axe).not.toBe(published.checkCounts.axe);
  });

  it("reads multiline tags with a trailing comma in the real-bundle reference", () => {
    const multiline = read(PAYLOAD).replace(
      DECLARATION,
      'pub const AXE_RUN_TAGS: [&str; 5] = [\n    "wcag2a",\n    "wcag2aa",\n    "wcag21a",\n    "wcag21aa",\n    "wcag22aa",\n];',
    );
    const changed = (file) => (file === PAYLOAD ? multiline : read(file));
    const selected = realAuditCount(changed);
    expect(deriveCheckCounts(changed).axe).toBe(selected);
    expect(JSON.parse(read("product-facts.json")).checkCounts.axe).toBe(selected);
  });

  it.each([
    ["the audit", "module.exports = {};"],
    ["normalizeOptions", `${read(BUNDLE)}\nmodule.exports._audit.normalizeOptions = undefined;`],
    ["ruleShouldRun", `${read(BUNDLE)}\nmodule.exports.utils = {};`],
  ])("names the bundle when it no longer exposes %s", (_name, bundle) => {
    const changed = (file) => (file === BUNDLE ? bundle : read(file));
    expect(() => deriveCheckCounts(changed)).toThrow(
      `product-facts: ${BUNDLE} no longer exposes axe's rule selector (_audit.normalizeOptions, utils.ruleShouldRun); update lib/product-facts.mjs`,
    );
  });

  it.each([
    [
      "uses an element context",
      (source) => source.replace("axe.run(document,", "axe.run(document.body,"),
    ],
    ["uses rule selection", (source) => source.replace("type: 'tag'", "type: 'rule'")],
    ["renames runOnly", (source) => source.replace("runOnly:", "ignored_runOnly:")],
    ["uses literal tags", (source) => source.replace("values: [{tags}]", "values: ['wcag2a']")],
    [
      "builds tags from another list",
      (source) => source.replace("let tags = AXE_RUN_TAGS", "let tags = OTHER_TAGS"),
    ],
    [
      "overrides rules",
      (source) => source.replace("iframes: false", "rules: {{ }}, iframes: false"),
    ],
    [
      "only calls axe in tests",
      (source) => {
        const start = source.indexOf("pub fn axe_run_script");
        return `${source.slice(0, start)}\n#[cfg(test)]\nmod tests {\n${source.slice(start)}\n}`;
      },
    ],
  ])("refuses a payload that %s", (_name, change) => {
    const changed = (file) => (file === PAYLOAD ? change(read(file)) : read(file));
    expect(() => deriveCheckCounts(changed)).toThrow(
      /product-facts:.*payload\.rs.*axe\.run\(document\).*runOnly.*AXE_RUN_TAGS/,
    );
  });

  it.each([
    ["is missing", ""],
    ["has a different type", 'pub const AXE_RUN_TAGS: &str = "wcag2a";'],
    ["contains a non-string", 'pub const AXE_RUN_TAGS: [&str; 2] = ["wcag2a", 1];'],
    ["has a mismatched length", 'pub const AXE_RUN_TAGS: [&str; 2] = ["wcag2a"];'],
    ["is empty", "pub const AXE_RUN_TAGS: [&str; 0] = [];"],
  ])("fails with a named error when AXE_RUN_TAGS %s", (_name, payload) => {
    expect(() => productFacts(fixtureRead(payload))).toThrow(/product-facts:.*AXE_RUN_TAGS/);
  });
});
