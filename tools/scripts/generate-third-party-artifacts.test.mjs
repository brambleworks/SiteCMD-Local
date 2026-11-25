import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const inventory = JSON.parse(
  readFileSync(path.join(ROOT, "THIRD_PARTY_DEPENDENCIES.json"), "utf8"),
);

describe("third-party artifact coverage", () => {
  it("lists only the CLI dependency scope", () => {
    // The shipped license artifacts still listed dependencies for removed applications.
    expect(inventory.generatedFrom).toEqual([
      "apps/desktop/src-tauri/Cargo.lock",
      "apps/desktop/src-tauri/Cargo.toml",
      "apps/desktop/src-tauri/crates/cli/Cargo.toml",
    ]);
    expect([...new Set(inventory.packages.flatMap(({ scopes }) => scopes))]).toEqual(["cli-rust"]);
  });

  it("includes every shipped dependency root", () => {
    expect(inventory.generatedFrom).toContain("apps/desktop/src-tauri/crates/cli/Cargo.toml");
    const cliDependency = inventory.packages.find(
      (pkg) => pkg.ecosystem === "cargo" && pkg.name === "env_logger",
    );
    expect(cliDependency?.scopes).toContain("cli-rust");
  });

  it("records license evidence for every production dependency", () => {
    const missing = inventory.packages.filter(
      (pkg) => !pkg.license && (!Array.isArray(pkg.licenseFiles) || pkg.licenseFiles.length === 0),
    );
    expect(missing).toEqual([]);
  });
});
