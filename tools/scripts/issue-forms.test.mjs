import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), "utf8");

describe("the false-positive issue form", () => {
  const form = () => read(".github/ISSUE_TEMPLATE/false_positive.yml");
  const contractLabels = () =>
    JSON.parse(read(".github/repository-labels.json")).labels.map((label) => label.name);

  it("collects what an accuracy triage needs", () => {
    for (const id of ["check_id", "scan_type", "version", "evidence", "expected"]) {
      expect(form(), `field ${id}`).toMatch(new RegExp(`^    id: ${id}$`, "m"));
    }
    expect(form()).toContain("        - Web Scan");
    expect(form()).toContain("        - Code Scan");
  });

  it("applies labels the repository contract defines", () => {
    for (const label of ["false-positive", "check-accuracy"]) {
      expect(form()).toMatch(new RegExp(`^  - ${label}$`, "m"));
      expect(contractLabels()).toContain(label);
    }
  });
});

describe("the issue chooser", () => {
  it("routes questions to Discussions Q&A", () => {
    expect(read(".github/ISSUE_TEMPLATE/config.yml")).toContain(
      "https://github.com/brambleworks/SiteCMD-Local/discussions/categories/q-a",
    );
  });
});
