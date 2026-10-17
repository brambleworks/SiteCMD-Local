import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { deriveCheckCounts, productionHalf } from "./lib/product-facts.mjs";

const read = (file) => readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
const TYPES = "apps/desktop/src-tauri/src/updates/types.rs";

function withEnum(source) {
  return (file) => (file === TYPES ? source : read(file));
}

function referenceEcosystemCount(readSource) {
  const body = productionHalf(readSource(TYPES)).match(/pub enum Ecosystem\s*\{([^}]*)\}/)[1];
  return body
    .replace(/\/\/.*$/gm, "")
    .split(",")
    .filter((variant) => variant.trim().length > 0).length;
}

describe("the updater's dependency ecosystems", () => {
  it("counts a plain fixture enum's unit variants", () => {
    const source = `
pub enum Ecosystem {
    Npm,
    Python,
    Rust,
}
#[cfg(test)]
mod tests {
    pub enum Ecosystem { FixtureOnly, }
}
`;
    expect(deriveCheckCounts(withEnum(source)).dependencyEcosystems).toBe(3);
  });

  it("counts variants with line and doc comments, including commas", () => {
    const source = `
pub enum Ecosystem {
    /// The npm registry, including scopes.
    Npm,
    Python, // The Python index, including wheels.
    // Additional ecosystems, supported locally.
    Rust,
}
`;
    const changed = withEnum(source);
    expect.soft(referenceEcosystemCount(changed)).toBe(3);
    expect(deriveCheckCounts(changed).dependencyEcosystems).toBe(3);
  });

  it("names a struct variant as an unsupported enum shape", () => {
    const source = "pub enum Ecosystem { Npm { version: String }, }";
    expect(() => deriveCheckCounts(withEnum(source))).toThrow(
      `product-facts: Ecosystem in ${TYPES} is no longer a plain list of unit variants; update lib/product-facts.mjs`,
    );
  });

  it.each([
    ["is missing", "pub enum Other { Npm, }"],
    [
      "only exists in tests",
      "#[cfg(test)]\nmod tests {\n    pub enum Ecosystem {\n        Npm,\n    }\n}",
    ],
    ["has a tuple variant", "pub enum Ecosystem { Npm(String), }"],
    ["has a discriminant", "pub enum Ecosystem { Npm = 1, }"],
    [
      "has a conditional variant",
      '#[derive(Clone)]\npub enum Ecosystem { Npm, #[cfg(feature = "rust")] Rust, }',
    ],
    ["is empty", "pub enum Ecosystem {}"],
  ])("fails with a named error when Ecosystem %s", (_name, source) => {
    expect(() => deriveCheckCounts(withEnum(source))).toThrow(/product-facts:.*Ecosystem/);
  });

  it("matches the real updater enum and generated facts", () => {
    const variants = referenceEcosystemCount(read);
    const published = JSON.parse(read("product-facts.json"));

    expect.soft(deriveCheckCounts(read).dependencyEcosystems).toBe(variants);
    expect.soft(published.checkCounts.dependencyEcosystems).toBe(variants);
  });
});
