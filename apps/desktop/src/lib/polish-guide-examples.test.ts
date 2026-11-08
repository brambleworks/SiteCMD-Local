import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { POLISH_FIX_GUIDES } from "./fix-guides/polish";

describe("polish marketing examples", () => {
  it("keeps marketing-term examples in the recorded dictionary", () => {
    // A guide can name an example the marketing dictionary no longer recognizes.
    const lists = JSON.parse(
      readFileSync(resolve("src-tauri/crates/engine/src/checks/polish/word_lists.json"), "utf8"),
    );
    const terms = new Set(
      lists.marketing_terms.map((term: { value: string }) => term.value.toLowerCase()),
    );
    let examples = 0;
    for (const guide of Object.values(POLISH_FIX_GUIDES)) {
      for (const step of guide.default) {
        for (const match of step.matchAll(/terms such as ([\w-]+)/g)) {
          examples += 1;
          expect(terms.has(match[1].toLowerCase()), match[1]).toBe(true);
        }
      }
    }
    expect(examples).toBeGreaterThan(0);
  });
});
