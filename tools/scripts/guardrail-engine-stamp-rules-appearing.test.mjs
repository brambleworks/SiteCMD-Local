import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { engineStampFailures } from "./lib/guardrail-engine-stamp-rules.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const BLAME = "apps/desktop/src-tauri/src/core/regression_blame.rs";
const read = (file) => readFileSync(path.join(ROOT, file), "utf8");
const failures = (source) => engineStampFailures((file) => (file === BLAME ? source : read(file)));
const FILTER = ".filter(|issue| !input.active_check_ids.contains(&issue.check_id))";

describe("appearing checks have one definition", () => {
  it("accepts the shared appearing predicate", () => {
    expect(failures(read(BLAME))).toEqual([]);
  });

  it("rejects a third inline filter", () => {
    const source = read(BLAME);
    const mutant = `${source}\nfn other_issues(input: &BlameInput) { input.current_issues.iter()${FILTER}; }\n`;
    expect(mutant).not.toEqual(source);
    expect(failures(mutant).join(" ")).toContain(
      "must define the appearing predicate exactly once",
    );
  });

  it("rejects a filter after the shared helper", () => {
    const source = read(BLAME);
    const mutant = source.replace(
      "let appeared = appearing_issues(input);",
      `let appeared = appearing_issues(input).into_iter()${FILTER}.collect();`,
    );
    expect(mutant).not.toEqual(source);
    expect(failures(mutant).join(" ")).toContain(
      "must define the appearing predicate exactly once",
    );
  });
});
