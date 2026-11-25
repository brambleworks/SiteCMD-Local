// Bug: A single column loses the value needed for a verified-good comparison.
import { expect, it } from "vitest";
import { verifiedGoodSchemaFailures } from "./lib/guardrail-verified-good-schema-rules.mjs";

it("fails when good and the differing value share a column", () => {
  // Bug: A shared column could discard one of the two values needed to compare drift.
  const schema = "good_value_json TEXT,\ndrift_value_json TEXT\n";
  expect(verifiedGoodSchemaFailures(() => schema)).toEqual([]);
  const collapsed = schema.replace("drift_value_json TEXT\n", "");
  expect(verifiedGoodSchemaFailures(() => collapsed).join(" ")).toContain("separate columns");
});
